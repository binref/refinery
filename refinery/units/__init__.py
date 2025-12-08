"""
This package contains all refinery units. To write an executable refinery unit, it is sufficient to
write a class inheriting from `refinery.units.Unit` and implements `refinery.units.Unit.process`.
If the operation implemented by this unit should be reversible, then a method called `reverse` with
the same signature has to be implemented. For example, the following would be a minimalistic
approach to implement `refinery.hex`:

    from refinery import Unit

    class hex(Unit):
        def process(self, data): return bytes.fromhex(data.decode('ascii'))
        def reverse(self, data): return data.hex().encode(self.codec)

The above script can be run from the command line. Since `hex` is not marked as abstract, its
inherited `refinery.units.Unit.run` method will be invoked when the script is executed.

### Command Line Parameters

If you want your custom refinery unit to accept command line parameters, you can write an
initialization routine. For example, the following unit implements a very simple XOR unit (less
versatile than the already existing `refinery.xor`):

    from refinery import Unit, Arg
    import itertools

    class myxor (Unit):
        def __init__(self, key: Arg(help='Encryption key')):
            pass

        def process(self, data: bytearray):
            key = itertools.cycle(self.args.key)
            for k, b in enumerate(data):
                data[k] ^= next(key)
            return data

The `refinery.units.Arg` decorator is optional and only used here to provide a help message on the
command line. The example also shows that the `__init__` code can be left empty: In this case,
refinery automatically adds boilerplate code that copies all `__init__` parameters to the `args`
member variable of the unit. In this case, the constructor will be completed to have the following
code:

        def __init__(self, key: Arg(help='Encryption key')):
            super().__init__(key=key)

The option of writing an empty `__init__` was added because it is rarely needed to perform any
processing of the input arguments. The command line help for this unit will look as follows:

    usage: myxor [-h] [-Q] [-0] [-v] key

    positional arguments:
      key            Encryption key

    generic options:
      ...

### Refinery Syntax in Code

Refinery units can be used in Python code (and a Python repl) in nearly the same way as on the
command line. As one example, consider the following unit that can decode base64 with a custom
alphabet using `refinery.map` and `refinery.b64`:

    from refinery import Unit, b64, map

    class b64custom(Unit):
        _b64alphabet = (
            B'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
            B'abcdefghijklmnopqrstuvwxyz'
            B'0123456789+/'
        )

        def __init__(self, alphabet=_b64alphabet):
            if len(alphabet) != 64:
                raise ValueError('Alphabet size must be 64')
            super().__init__(alphabet=alphabet)

        def process(self, data):
            return data | map(self.args.alphabet, self._b64alphabet) | b64

        def reverse(self, data):
            return data | -b64 | map(self._b64alphabet, self.args.alphabet)

The syntax does not work exactly as on the command line, but it was designed to be as similar as
possible:

- The binary or operator `|` can be used to combine units into pipelines.
- Combining a pipeline from the left with a byte string or io stream object will feed this byte
  string into the unit.
- Unary negation of a reversible unit is equivalent to using the `-R` switch for reverse mode.
- A pipeline is an iterable of output chunks, but there is quite a selection of objects that can
  be connected to a pipeline from the right using `|` for various different output options. See
  below for details.

If you want to use frames in code, simply omit any pipe before a square bracket. For example, the
first example from the `refinery.lib.frame` documentation translates to the following Python code:

    >>> from refinery import *
    >>> B'OOOOOOOO' | chop(2) [ ccp(B'F') | cca(B'.') ]| ...
    >>> bytearray(b'FOO.FOO.FOO.FOO.')

In the above example, the pipeline is piped to a literal ellipsis (`...`) to get the final result.
The following section lists the other output options.

### Output Options in Code

You can connect a pipeline to any binary i/o stream, and the output of the pipeline will be written
to that stream. Example:

    with open('output', 'wb') as stream:
        B'BINARY REFINERY' | xor(0x13) | stream

Furthermore, you can connect pipelines to any callable, and you can always use a literal ellipsis
(`...`) to represent the identity function. The result of this is that you receive the raw output
from the pipeline:

    >>> B'BINARY REFINERY' | xor(0x13) | ...
    bytearray(b'QZ]RAJ3AVUZ]VAJ')

You can also connect to sets and lists containing a single callable. In this case, the callable
will be applied to each output chunk and all results will be collected in a list or set,
respectively. Examples:

    >>> B'ABABCBABABCHB' | rex('.B') | [str]
    ['AB', 'AB', 'CB', 'AB', 'AB', 'HB']
    >>> B'ABABCBABABCHB' | rex('.B') | {str}
    {'AB', 'CB', 'HB'}

You can also consume into a dictionary in a similar way:

    >>> B'ABABCBABABCHB' | rex('.(?P<k>.)B') | {'k': str}
    {A: ['BAB', 'BAB'], H: ['CHB']}

Here, the dictionary is expected to contain exactly one key-value pair. The key is the name of a
meta variable and the value is a conversion function. The result will be a dictionary where all
converted results have been grouped under the respective value of their meta variable. With all of
the above options, it is always possible to use a literal ellipsis (`...`).

You can connect pipelines to `bytearray` and (writable) `memoryview` instances. In this case, the
output will be appended to the end of this buffer. Finally, if you connect a pipeline to `None`,
this will execute the unit but discard all output. This is useful for using units with side
effects, like `refinery.peek`, in a REPL.
"""
from __future__ import annotations

import abc
import copy
import inspect
import os
import sys

from abc import ABCMeta
from argparse import ONE_OR_MORE, OPTIONAL, REMAINDER, ZERO_OR_MORE, ArgumentTypeError, Namespace
from collections import OrderedDict
from enum import Enum
from functools import partial, wraps
from threading import Lock
from typing import (
    TYPE_CHECKING,
    Any,
    BinaryIO,
    Callable,
    ClassVar,
    Collection,
    Generator,
    Iterable,
    Iterator,
    Mapping,
    Optional,
    Type,
    TypeVar,
    Union,
    cast,
    no_type_check,
    overload,
)

from refinery.lib.annotations import evaluate
from refinery.lib.argparser import ArgparseError, ArgumentParserWithKeywordHooks
from refinery.lib.dependencies import dependency_accessor
from refinery.lib.environment import Logger, LogLevel, environment, logger
from refinery.lib.exceptions import (
    RefineryCriticalException,
    RefineryException,
    RefineryImportError,
    RefineryImportMissing,
    RefineryPartialResult,
    RefineryPotentialUserError,
)
from refinery.lib.frame import MAGIC, MSIZE, Chunk, Framed, generate_frame_header
from refinery.lib.structures import MemoryFile
from refinery.lib.types import buf

if TYPE_CHECKING:
    from argparse import _MutuallyExclusiveGroup
    from io import BufferedReader, BufferedWriter
    from typing import Self

    DataType = TypeVar('DataType', bound=buf)
    ProcType = Callable[['Unit', Chunk], Optional[Union[DataType, Iterable[DataType]]]]

    ByteIO = MemoryFile[DataType]

    _T = TypeVar('_T')
    _F = TypeVar('_F', bound=Callable)
    _B = TypeVar('_B', bound=Union[BufferedWriter, ByteIO, BinaryIO])
    _E = TypeVar('_E', bound=Enum)

from refinery.lib.argformats import (
    ParserVariableMissing,
    VariableMissing,
    manifest,
    multibin,
    number,
    numseq,
    pathvar,
    pending,
    percent,
    regexp,
    sliceobj,
)
from refinery.lib.tools import (
    autoinvoke,
    documentation,
    exception_to_string,
    isbuffer,
    isstream,
    lookahead,
    normalize_to_display,
    normalize_to_identifier,
    one,
    skipfirst,
)


class Entry:
    """
    An empty class marker. Any entry point unit (i.e. any unit that can be executed
    via the command line) is an instance of this class.
    """


class Argument:
    """
    This class implements an abstract argument to a Python function, including positional
    and keyword arguments. Passing an `Argument` to a Python function can be done via the
    matrix multiplication operator: The syntax `function @ Argument(a, b, kwd=c)` is
    equivalent to the call `function(a, b, kwd=c)`.
    """
    __slots__ = 'args', 'kwargs'

    args: list[Any]
    kwargs: dict[str, Any]

    def __init__(self, *args, **kwargs):
        self.args = list(args)
        self.kwargs = kwargs

    def __rmatmul__(self, method):
        return method(*self.args, **self.kwargs)

    def __repr__(self):
        def rep(v):
            r = repr(v)
            if r.startswith('<'):
                try:
                    return v.__name__
                except AttributeError:
                    pass
                try:
                    return v.__class__.__name__
                except AttributeError:
                    pass
            return r
        arglist = [repr(a) for a in self.args]
        arglist.extend(F'{key!s}={rep(value)}' for key, value in self.kwargs.items())
        return ', '.join(arglist)


class Arg(Argument):
    """
    This class is specifically an argument for the `add_argument` method of an `ArgumentParser` from
    the `argparse` module. It can also be used as a decorator or annotation for the constructor of a
    refinery unit to better control the argument parser of that unit's command line interface.
    Example:
    ```
    class prefixer(Unit):
        def __init__(
            self,
            prefix: Arg.Binary(help='This data will be prepended to the input.')
        ): ...
        def process(self, data):
            return self.args.prefix + data
    ```
    Note that when the init of a unit has a return annotation that is a base class of itself, then
    all its parameters will automatically be forwarded to that base class.
    """

    class delete:
        """
        A sentinel class to mark deleted arguments for the argument parser.
        """

    class omit:
        """
        A sentinel class to mark arguments as omitted for the argument parser.
        """

    args: list[str]

    __slots__ = 'args', 'group', 'guessed'

    def __init__(
        self, *args: str,
        action   : type[omit] | str                       = omit,  # noqa
        choices  : type[omit] | Iterable[Any]             = omit,  # noqa
        const    : type[omit] | Any                       = omit,  # noqa
        default  : type[omit] | Any                       = omit,  # noqa
        dest     : type[omit] | str                       = omit,  # noqa
        help     : type[omit] | str                       = omit,  # noqa
        metavar  : type[omit] | str                       = omit,  # noqa
        nargs    : type[omit] | type[delete] | int | str  = omit,  # noqa
        required : type[omit] | bool                      = omit,  # noqa
        type     : type[omit] | type | Callable           = omit,  # noqa
        group    : str | None                             = None,  # noqa
        guessed  : set[str] | None                        = None,  # noqa
    ) -> None:
        kwargs = dict(action=action, choices=choices, const=const, default=default, dest=dest,
            help=help, metavar=metavar, nargs=nargs, required=required, type=type)
        kwargs = {key: value for key, value in kwargs.items() if value is not self.omit}
        self.group = group
        self.guessed = set(guessed or ())
        super().__init__(*args, **kwargs)

    def update_help(self):
        """
        This method is called to format the help text of the argument retroactively. The primary
        purpose is to fill in default arguments via the formatting symbol `{default}`. These
        default values are not necessarily part of the `refinery.units.Arg` object itself: They
        may be a default value in the `__init__` function of the `refinery.units.Unit` subclass.
        Therefore, it is necessary to format the help text after all information has been
        compiled.
        """
        class formatting(dict):
            arg = self

            def __missing__(self, key):
                if key == 'choices':
                    return ', '.join(self.arg.kwargs['choices'])
                if key == 'default':
                    default: bytes | int | str | slice = self.arg.kwargs['default']
                    if isinstance(default, (list, tuple, set)):
                        if not default:
                            return 'empty'
                        elif len(default) == 1:
                            default = next(iter(default))
                    if isinstance(default, slice):
                        parts = [default.start or '', default.stop or '', default.step]
                        default = ':'.join(str(x) for x in parts if x is not None)
                    if isinstance(default, int):
                        return default
                    if isinstance(default, str) or not isbuffer(default):
                        return default
                    default = bytes(default)
                    if default.isalnum():
                        return default.decode('latin-1')
                    return F'H:{default.hex()}'
                if key == 'varname':
                    return self.arg.kwargs.get('metavar', self.arg.destination)

        try:
            help_string: str = self.kwargs['help']
            self.kwargs.update(
                help=help_string.format_map(formatting()))
        except Exception:
            pass

    def __rmatmul__(self, method):
        self.update_help()
        return super().__rmatmul__(method)

    @staticmethod
    def AsRegExp(
        codec: str,
        regex: str | buf,
        flags: int = 0
    ):
        import re
        if isinstance(regex, str):
            regex = regex.encode(codec)
        else:
            regex = bytes(regex)
        return re.compile(regex, flags=flags)

    @overload
    @staticmethod
    def AsOption(value: _E, cls: type[_E]) -> _E:
        ...

    @overload
    @staticmethod
    def AsOption(value: type[None], cls: type[_E]) -> None:
        ...

    @overload
    @staticmethod
    def AsOption(value: str | None | _E, cls: type[_E]) -> _E:
        ...

    @staticmethod
    def AsOption(value, cls: type[_E]) -> _E | None:
        """
        This method converts the input `value` to an instance of the enum `cls`. It is intended to
        be used on values that are passed as an argument marked with the `refinery.units.Arg.Option`
        decorator. If the input value is `None` or already an instance of `cls`, it is returned
        unchanged. Otherwise, the function attempts to find an element of the enumeration that
        matches the input, either by name or by value.
        """
        if value is None or isinstance(value, cls):
            return value
        if isinstance(value, str):
            try:
                return cls[value]
            except KeyError:
                pass
            needle = normalize_to_identifier(value).casefold()
            for item in cls.__members__:
                if not isinstance(item, str):
                    break
                if item.casefold() == needle:
                    return cls[item]
        try:
            return cls(value)
        except Exception as E:
            choices = ', '.join(normalize_to_display(m) for m in cls.__members__)
            raise ValueError(F'Could not transform {value} into {cls.__name__}; the choices are: {choices}') from E

    @classmethod
    def Delete(cls):
        """
        This should be specified when the argument is present for a (potentially abstract) parent
        unit but should be removed on the child.
        """
        return cls(nargs=cls.delete)

    @classmethod
    def Counts(
        cls,
        *args   : str,
        help    : type[omit] | str = omit,
        dest    : type[omit] | str = omit,
        group   : str | None = None,
    ):
        """
        A convenience method to add argparse arguments that introduce a counter.
        """
        return cls(*args, group=group, help=help, dest=dest, action='count')

    @classmethod
    def Switch(
        cls,
        *args   : str, off=False,
        help    : type[omit] | str = omit,
        dest    : type[omit] | str = omit,
        group   : str | None = None,
    ):
        """
        A convenience method to add argparse arguments that change a boolean value from True to False or
        vice versa. By default, a switch will have a False default and change it to True when specified.
        """
        return cls(*args, group=group, help=help, dest=dest, action='store_false' if off else 'store_true')

    @classmethod
    def FsPath(
        cls,
        *args   : str,
        help    : type[omit] | str = omit,
        dest    : type[omit] | str = omit,
        nargs   : type[omit] | int | str = omit,
        metavar : type[omit] | str = omit,
        group   : str | None = None,
    ):
        """
        Used to add argparse arguments that contain path patterns.
        """
        if metavar is cls.omit and any('-' in a for a in args):
            metavar = 'B'
        return cls(*args, group=group, help=help, dest=dest, nargs=nargs, type=pathvar, metavar=metavar)

    @classmethod
    def Binary(
        cls,
        *args   : str,
        help    : type[omit] | str = omit,
        dest    : type[omit] | str = omit,
        nargs   : type[omit] | int | str = omit,
        metavar : type[omit] | str = omit,
        group   : str | None = None,
    ):
        """
        Used to add argparse arguments that contain binary data.
        """
        if metavar is cls.omit and any('-' in a for a in args):
            metavar = 'B'
        return cls(*args, group=group, help=help, dest=dest, nargs=nargs, type=multibin, metavar=metavar)

    @classmethod
    def String(
        cls,
        *args   : str,
        help    : type[omit] | str = omit,
        dest    : type[omit] | str = omit,
        nargs   : type[omit] | int | str = omit,
        metavar : type[omit] | str = omit,
        default : type[omit] | str | tuple[str, ...] = omit,
        group   : str | None = None,
    ):
        """
        Used to add argparse arguments that contain string data.
        """
        if metavar is cls.omit and any('-' in a for a in args):
            metavar = 'STR'
        return cls(*args, group=group, default=default, help=help, dest=dest, nargs=nargs, type=str, metavar=metavar)

    @classmethod
    def RegExp(
        cls,
        *args   : str,
        help    : type[omit] | str = omit,
        dest    : type[omit] | str = omit,
        nargs   : type[omit] | int | str = omit,
        metavar : type[omit] | str = omit,
        group   : str | None = None,
    ):
        """
        Used to add argparse arguments that contain a regular expression.
        """
        if metavar is None and any('-' in a for a in args):
            metavar = 'REGEX'
        return cls(*args, group=group, help=help, dest=dest, nargs=nargs, type=regexp, metavar=metavar)

    @classmethod
    def NumSeq(
        cls,
        *args   : str,
        help    : type[omit] | str = omit,
        dest    : type[omit] | str = omit,
        nargs   : type[omit] | int | str = omit,
        metavar : type[omit] | str = omit,
        check   : bool = True,
        group   : str | None = None,
    ):
        """
        Used to add argparse arguments that contain a numeric sequence.
        """
        t = numseq if check else partial(numseq, typecheck=False)
        return cls(*args, group=group, help=help, nargs=nargs, dest=dest, type=t, metavar=metavar)

    @classmethod
    def Bounds(
        cls,
        *args   : str,
        help    : type[omit] | str | None = None,
        dest    : type[omit] | str = omit,
        nargs   : type[omit] | int | str = omit,
        default : type[omit] | Any = omit,
        intok   : bool = False,
        metavar : type[omit] | str = 'start:end:step',
        group   : str | None = None,
    ):
        """
        Used to add argparse arguments that contain a slice.
        """
        def parser(t: str):
            return sliceobj(t, intok=intok)
        if help is None:
            help = 'Specify start:end:step in Python slice syntax.'
            if default is not cls.omit:
                help = F'{help} The default is {{default}}.'
        return cls(*args, group=group, help=help, default=default, nargs=nargs, dest=dest, type=parser, metavar=metavar)

    @classmethod
    def Double(
        cls,
        *args   : str,
        help    : type[omit] | str = omit,
        dest    : type[omit] | str = omit,
        metavar : type[omit] | str = omit,
        group   : str | None = None,
    ):
        """
        Used to add argparse arguments that contain a floating point number.
        """
        return cls(*args, group=group, help=help, dest=dest, type=percent, metavar=metavar)

    @classmethod
    def Number(
        cls,
        *args   : str,
        bound   : type[omit] | tuple[int, int] = omit,
        help    : type[omit] | str = omit,
        dest    : type[omit] | str = omit,
        metavar : type[omit] | str = omit,
        group   : str | None = None,
    ):
        """
        Used to add argparse arguments that contain a number.
        """
        nt = number
        if bound is not cls.omit:
            assert isinstance(bound, tuple)
            lower, upper = bound
            nt = nt[lower:upper]
        if metavar is cls.omit:
            metavar = 'N'
        return cls(*args, group=group, help=help, dest=dest, type=nt, metavar=metavar)

    @classmethod
    def Option(
        cls,
        *args   : str,
        choices : type[Enum],
        help    : type[omit] | str = omit,
        dest    : type[omit] | str = omit,
        metavar : type[omit] | str = omit,
        group   : str | None = None,
    ):
        """
        Used to add argparse arguments with a fixed set of options, based on an enumeration.
        """
        cnames = [normalize_to_display(c).casefold() for c in choices.__members__]
        metavar = metavar or choices.__name__
        return cls(*args, group=group, help=help, metavar=metavar, dest=dest, choices=cnames, type=str.casefold)

    @classmethod
    def Choice(
        cls,
        *args   : str,
        choices : list[str],
        help    : type[omit] | str = omit,
        metavar : type[omit] | str = omit,
        dest    : type[omit] | str = omit,
        type    : type | Callable = str.lower,
        nargs   : type[omit] | int | str = omit,
        group   : str | None = None,
    ):
        """
        Used to add argparse arguments with a fixed set of options, based on a list of strings.
        """
        return cls(*args, group=group, type=type, metavar=metavar, nargs=nargs,
            dest=dest, help=help, choices=choices)

    @property
    def positional(self) -> bool:
        """
        Indicates whether the argument is positional. This is crudely determined by whether it has
        a specifier that does not start with a dash.
        """
        return any(a[0] != '-' for a in self.args)

    @property
    def destination(self) -> str:
        """
        The name of the variable where the contents of this parsed argument will be stored.
        """
        for a in self.args:
            if a[0] != '-':
                return a
        try:
            return self.kwargs['dest']
        except KeyError:
            for a in self.args:
                if a.startswith('--'):
                    dest = normalize_to_identifier(a)
                    if dest.isidentifier():
                        return dest
            raise AttributeError(F'The argument with these values has no destination: {self!r}')

    @classmethod
    def Infer(cls, pt: inspect.Parameter, module: str | None = None):
        """
        This class method can be used to infer the argparse argument for a Python function
        parameter. This guess is based on the annotation, name, and default value.
        """

        def needs_type(item: dict[str, str]):
            return item.get('action', 'store') == 'store'

        def get_argp_type(at):
            if at is type(None):
                return None
            if issubclass(at, tuple):
                return numseq
            if issubclass(at, (bytes, bytearray, memoryview)):
                return multibin
            if issubclass(at, int):
                return number
            if issubclass(at, slice):
                return sliceobj
            if issubclass(at, float):
                return percent
            return at

        name = normalize_to_display(pt.name, False)
        default = pt.default
        empty = pt.empty
        guessed_pos_args = []
        guessed_kwd_args: dict[str, Any] = dict(dest=pt.name)
        guessed = set()
        annotation = pt.annotation

        def guess(key, value):
            try:
                return guessed_kwd_args[key]
            except KeyError:
                guessed_kwd_args[key] = value
                guessed.add(key)
                return value

        if isinstance(annotation, str):
            if module is None:
                _symbols = None
            else:
                __import__(module)
                _symbols = sys.modules[module].__dict__
            try:
                annotation = evaluate(annotation, _symbols)
            except Exception:
                pass

        if annotation is not empty:
            if isinstance(annotation, Arg):
                if annotation.kwargs.get('dest', pt.name) != pt.name:
                    raise ValueError(
                        F'Incompatible argument destination specified; parameter {pt.name} '
                        F'was annotated with {annotation!r}.')
                guessed_pos_args = annotation.args
                guessed_kwd_args.update(annotation.kwargs)
                guessed_kwd_args.update(group=annotation.group)
            elif isinstance(annotation, type):
                guessed.add('type')
                if not issubclass(annotation, bool) and needs_type(guessed_kwd_args):
                    guessed_kwd_args.update(type=get_argp_type(annotation))
                elif not isinstance(default, bool):
                    raise ValueError('Default value for boolean arguments must be provided.')

        if not guessed_pos_args:
            guessed_pos_args = guessed_pos_args or [F'--{name}' if pt.kind is pt.KEYWORD_ONLY else name]

        if pt.kind is pt.VAR_POSITIONAL:
            oldnargs = guess('nargs', ZERO_OR_MORE)
            if oldnargs not in (ONE_OR_MORE, ZERO_OR_MORE, REMAINDER):
                raise ValueError(F'Variadic positional arguments has nargs set to {oldnargs!r}')
            return cls(*guessed_pos_args, **guessed_kwd_args)

        if default is not empty:
            if isinstance(default, Enum):
                default = default.name

            guess('default', default)

            if isinstance(default, list):
                guess('nargs', ZERO_OR_MORE)
            elif pt.kind is pt.POSITIONAL_ONLY:
                guess('nargs', OPTIONAL)

            if isinstance(default, bool):
                guessed_kwd_args['action'] = F'store_{not default!s}'.lower()
            elif needs_type(guessed_kwd_args):
                if isinstance(default, list) and default:
                    default = default[0]
                guess('type', get_argp_type(type(default)))

        return cls(*guessed_pos_args, **guessed_kwd_args, guessed=guessed)

    def merge_args(self, them: Argument) -> None:
        """
        Merge the `args` component of another `refinery.units.Argument` into this one without
        overwriting or removing any of the `args` in this instance.
        """
        def iterboth():
            yield from them.args
            yield from self.args
        if not self.args:
            self.args = list(them.args)
            return
        sflag = None
        lflag = None
        for a in iterboth():
            if a[:2] == '--':
                lflag = lflag or a
            elif a[0] == '-':
                sflag = sflag or a
        self.args = []
        if sflag:
            self.args.append(sflag)
        if lflag:
            self.args.append(lflag)
        if not self.args:
            self.args = list(them.args)

    def merge_all(self, them: Arg) -> None:
        """
        Merge another `refinery.units.Arg` into the current instance. This is an additive process
        where no data on the present instance is destroyed unless `refinery.units.Arg.Delete` was
        used on `them` to explicitly remove an option.
        """
        for key, value in them.kwargs.items():
            if value is Arg.delete:
                self.kwargs.pop(key, None)
                self.guessed.discard(key)
                continue
            if key in them.guessed:
                if key not in self.guessed:
                    if key == 'type' and self.kwargs.get('action', None) != 'store':
                        continue
                    if key in self.kwargs:
                        continue
                self.guessed.add(key)
            self.kwargs[key] = value
        self.merge_args(them)
        self.group = them.group or self.group

    def __copy__(self):
        cls = self.__class__
        clone = cls.__new__(cls)
        clone.kwargs = dict(self.kwargs)
        clone.args = list(self.args)
        clone.group = self.group
        clone.guessed = set(self.guessed)
        return clone

    def __repr__(self) -> str:
        return F'{self.__class__.__name__}({super().__repr__()})'

    def __call__(self, init: Callable) -> Callable:
        parameters = inspect.signature(init).parameters
        try:
            inferred = Arg.Infer(parameters[self.destination])
            inferred.merge_all(self)
            init.__annotations__[self.destination] = inferred
        except KeyError:
            raise ValueError(F'Unable to decorate because no parameter with name {self.destination} exists.')
        return init


if TYPE_CHECKING:
    _ArgumentSpecificationBase = OrderedDict[str, Arg]
else:
    _ArgumentSpecificationBase = OrderedDict


class ArgumentSpecification(_ArgumentSpecificationBase):
    """
    A container object that stores `refinery.units.Arg` specifications.
    """

    def merge(self: dict[str, Arg], argument: Arg):
        """
        Insert or update the specification with the given argument.
        """
        dest = argument.destination
        if dest in self:
            self[dest].merge_all(argument)
            return
        self[dest] = argument


def _UnitProcessorBoilerplate(operation: ProcType[buf]) -> ProcType[Chunk]:
    @wraps(operation)
    def wrapped(self: Unit, data: buf | None) -> Chunk | Iterable[Chunk] | None:
        if data is None:
            data = Chunk()
        elif not isinstance(data, Chunk):
            data = Chunk(data)
        result = operation(self, data)
        if isinstance(result, Chunk):
            return result
        elif not inspect.isgenerator(result):
            return Chunk(cast(Optional[bytearray], result))
        return (Chunk.Wrap(r) for r in result)
    return wrapped


def _UnitFilterBoilerplate(
    operation : Callable[[Any, Iterable[Chunk]], Iterable[Chunk]]
) -> Callable[[Any, Iterable[Chunk]], Iterable[Chunk]]:
    @wraps(operation)
    def peekfilter(self, chunks: Iterable[Chunk]) -> Iterable[Chunk]:
        def _apply_args_to_head():
            it = iter(chunks)
            for chunk in it:
                if chunk.visible:
                    yield self.args @ chunk
                    break
                else:
                    yield chunk
            yield from it
        yield from operation(self, _apply_args_to_head())
    return peekfilter


class MissingFunction:
    """
    A singleton class that represents a missing function. Used internally to
    indicate that a unit does not implement a reverse operation.
    """
    def __init__(self, *_):
        pass

    def __call__(*_, **__):
        raise NotImplementedError('A non-invertible unit was operated in reverse.')

    @classmethod
    def Wrap(cls, _: _F) -> _F:
        return cast('_F', cls())


class Executable(ABCMeta):
    """
    This is the metaclass for refinery units. A class which is of this type is
    required to implement a method `run()`. If the class is created in the
    currently executing module, then an instance of the class is automatically
    created after it is defined and its `run()` method is invoked.
    """

    Entry = None
    """
    This variable stores the executable entry point. If more than one entry point
    are present, only the first one is executed and an error message is generated
    for the other ones.
    """

    _argument_specification: dict[str, Arg]

    def _infer_argspec(cls, parameters: Mapping[str, inspect.Parameter], args: ArgumentSpecification | None, module: str):

        if args is None:
            args = ArgumentSpecification()

        exposed = [pt.name for pt in skipfirst(parameters.values()) if pt.kind != pt.VAR_KEYWORD]
        # The arguments are added in reverse order to the argument parser later.
        # This is done to have a more intuitive use of decorator based argument configuration.
        exposed.reverse()

        for name in exposed:
            try:
                argument = Arg.Infer(parameters[name], module)
            except KeyError:
                continue
            args.merge(argument)

        for name in exposed:
            args.move_to_end(name)

        for known in args.values():
            kwargs = known.kwargs
            if known.positional:
                known.kwargs.pop('dest', None)
                if 'default' in kwargs and kwargs.get('action', 'store') == 'store':
                    kwargs.setdefault('nargs', OPTIONAL)
            elif not any(len(a) > 2 for a in known.args):
                flagname = normalize_to_display(known.destination, False)
                known.args.append(F'--{flagname}')
            action: str = kwargs.get('action', 'store')
            if action.startswith('store_'):
                kwargs.pop('default', None)
                continue
            if action == 'store':
                kwargs.setdefault('type', multibin)
        return args

    def __new__(mcs, name: str, bases: tuple[type, ...], nmspc: dict[str, Any], abstract=False, docs='{}'):
        def decorate(**decorations):
            for method, decorator in decorations.items():
                try:
                    old = nmspc[method]
                except KeyError:
                    continue
                if isinstance(old, MissingFunction):
                    continue
                if getattr(old, '__isabstractmethod__', False):
                    continue
                nmspc[method] = decorator(old)
        decorate(
            filter=_UnitFilterBoilerplate,
            process=_UnitProcessorBoilerplate,
            reverse=_UnitProcessorBoilerplate,
            __init__=no_type_check,
        )
        if not abstract and Entry not in bases:
            for b in bases:
                try:
                    if b.is_reversible:
                        break
                except AttributeError:
                    pass
            else:
                nmspc.setdefault('reverse', MissingFunction())
            bases = bases + (Entry,)
        nmspc.setdefault('__doc__', '')
        return super().__new__(mcs, name, bases, nmspc)

    def __init__(cls, name: str, bases: tuple[type, ...], nmspc: dict[str, Any], abstract=False, docs='{}'):
        super().__init__(name, bases, nmspc)
        cls._argument_specification = args = ArgumentSpecification()

        cls_init = cls.__init__
        sig_init = inspect.signature(cls_init)
        parameters = sig_init.parameters
        has_keyword = any(p.kind == p.VAR_KEYWORD for p in parameters.values())
        inherited = []

        for base in bases:
            try:
                base: Executable
                spec = base._argument_specification
            except AttributeError:
                continue
            for key, value in spec.items():
                if key in parameters:
                    args[key] = value.__copy__()

        if docs != '{}':
            mro = {b.__name__: inspect.cleandoc(b.__doc__) for b in cls.__mro__ if b.__doc__}
            cls.__doc__ = docs.format(*mro.values(), **mro, p='\n\n', s='\x20')
            cls.__doc__ = cls.__doc__.replace('<this>', cls.__name__)

        if not abstract and bases and has_keyword:
            for key, value in bases[0]._argument_specification.items():
                if key not in args:
                    args[key] = value.__copy__()
                    inherited.append(key)

        cls._infer_argspec(parameters, args, cls.__module__)

        if not abstract and has_keyword:
            cls__init__ = cls.__init__

            @wraps(cls__init__)
            def new__init__(self, *args, **kwargs):
                cls__init__(self, *args, **kwargs)

            params = [p for p in parameters.values() if p.kind != p.VAR_KEYWORD]
            if inherited:
                pp = inspect.signature(bases[0].__init__).parameters
                for name in inherited:
                    params.append(pp[name])

            setattr(new__init__, '__signature__', sig_init.replace(parameters=tuple(params)))
            setattr(cls, '__init__', new__init__)

        try:
            initcode = cls.__init__.__code__.co_code
        except AttributeError:
            initcode = None

        if initcode == (lambda: None).__code__.co_code:
            base = bases[0]
            head = []
            defs = {}
            tail = None

            for p in skipfirst(parameters.values()):
                if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD):
                    head.append(p.name)
                if p.kind in (p.KEYWORD_ONLY, p.POSITIONAL_OR_KEYWORD) and p.default is not p.empty:
                    defs[p.name] = p.default
                if p.kind is p.VAR_POSITIONAL:
                    tail = p.name

            @wraps(cls.__init__)
            def auto__init__(self, *args, **kw):
                for name, arg in zip(head, args):
                    kw[name] = arg
                if tail:
                    k = min(len(args), len(head))
                    kw[tail] = args[k:]
                for key in defs:
                    if key not in kw:
                        kw[key] = defs[key]
                base.__init__(self, **kw)

            setattr(cls, '__init__', auto__init__)

        if not abstract and sys.modules[cls.__module__].__name__ == '__main__':
            if not Executable.Entry:
                Executable.Entry = cls.name
                cast(Type[Unit], cls).run()

    def __getitem__(cls, other):
        return cls().__getitem__(other)

    def __or__(cls, other):
        return cls().__or__(other)

    def __pos__(cls):
        return cls()

    def __neg__(cls):
        unit: Unit = cls()
        unit.args.reverse = 1
        return unit

    def __ror__(cls, other) -> Unit:
        return cls().__ror__(other)

    @property
    def is_reversible(cls) -> bool:
        """
        This property is `True` if and only if the unit has a member function named `reverse`. By convention,
        this member function implements the inverse of `refinery.units.Unit.process`.
        """
        r = cast(Type[Unit], cls).reverse
        if isinstance(r, MissingFunction):
            return False
        return not getattr(r, '__isabstractmethod__', False)

    @property
    def codec(cls) -> str:
        """
        The default codec for encoding textual information between units. The value of this property is
        hardcoded to `UTF8`.
        """
        return 'UTF8'

    @property
    def name(cls) -> str:
        """
        The name of the unit as it would be used on the command line. This is the application of
        the function `refinery.lib.tools.normalize_to_display` to the class name.
        """
        return normalize_to_display(cls.__name__)

    @property
    def logger(cls) -> Logger:
        """
        The debug logger instance for the unit.
        """
        try:
            return cls._logger
        except AttributeError:
            pass
        cls._logger = _logger = logger(cls.name)
        return _logger

    @property
    def logger_locked(cls) -> bool:
        try:
            return cls._logger_locked
        except AttributeError:
            return False

    @logger_locked.setter
    def logger_locked(cls, value):
        cls._logger_locked = value


class DelayedArgumentProxy:
    """
    This class implements a proxy for the `args` member variable of `refinery.units.Unit`.
    Its primary purpose is to proxy `refinery.lib.argformats.DelayedArgument` values which
    can be computed only as soon as input data becomes available and which also have to be
    recomputed for each input.
    """
    _argv: Namespace
    _argo: list[str]
    _args: dict[str, Any]
    _done: bool
    _uuid: Any
    _lock: Lock

    def __copy__(self):
        cls = self.__class__
        clone = cls.__new__(cls)
        clone._store(
            _lock=Lock(),
            _argv=self._argv,
            _argo=list(self._argo),
            _args=dict(self._args),
            _done=self._done,
            _uuid=self._uuid,
        )
        return clone

    def __iter__(self):
        yield from self._args

    def __getitem__(self, key):
        return self._args[key]

    def __init__(self, argv: Namespace, argo: Iterable[str]):
        args = {}
        done = True
        for name, value in vars(argv).items():
            if not pending(value):
                args[name] = value
            else:
                done = False
        self._store(
            _lock=Lock(),
            _argv=argv,
            _argo=list(argo),
            _args=args,
            _done=done,
            _uuid=None,
        )

    def __call__(self, data: Chunk):
        """
        Update the current arguments for the input `data`, regardless of whether or not this chunk
        has already been used. In most cases, the matrix-multiplication syntax should be used instead
        of this direct call: If a multibin argument modifies the meta dictionary by being applied, a
        second interpretation of this argument with the same chunk might cause an error. For example,
        if an argument specifies to pop a meta variable from the meta dictionary, this variable will
        not be available for a second interpretation call.
        """
        for name in self._argo:
            if self._lock.locked():
                raise RuntimeError(F'Attempting to resolve {name} while an update for this argument is in flight')
            with self._lock:
                value = getattr(self._argv, name, None)
                if value and pending(value):
                    self._args[name] = manifest(value, data)
            self._store(_uuid=data.uuid)
        return data

    def __matmul__(self, data: Chunk):
        """
        Interpret the current arguments for the given input `data`.
        """
        if self._done:
            return data
        if self._uuid == data.uuid:
            return data
        return self(data)

    def _store(self, **kwargs):
        self.__dict__.update(kwargs)

    def __getattr__(self, name):
        try:
            return self._args[name]
        except KeyError:
            pass
        try:
            value = getattr(self._argv, name)
        except AttributeError as E:
            raise AttributeError(F'Argument {name} not set.') from E
        if not value or not pending(value):
            return value
        raise AttributeError(F'the value {name} cannot be accessed until data is available.')

    def __setattr__(self, name, value):
        if not hasattr(self._argv, name):
            self._argo.append(name)
        if pending(value):
            self._store(_done=False)
        else:
            self._args[name] = value
        return setattr(self._argv, name, value)


class UnitBase(metaclass=Executable, abstract=True):
    """
    This base class is an abstract interface specifying the abstract methods that have to be
    present on any unit. Units should inherit from its only child class `refinery.units.Unit`.
    """
    FilterEverything: ClassVar[bool] = False
    """
    This class variable can be enabled by a unit to register for filtering all chunks of the
    frame tree via `refinery.units.Unit.filter`.
    """

    @abc.abstractmethod
    def process(self, data: Chunk, /) -> None | buf | Iterable[buf]:
        """
        This routine is overridden by children of `refinery.units.Unit` to define how the unit
        processes a given chunk of binary data.
        """

    @MissingFunction.Wrap
    def reverse(self, data: Chunk, /) -> buf | None | Iterable[buf]:
        """
        If this routine is overridden by children of `refinery.units.Unit`, then it must implement
        an operation that reverses the `refinery.units.Unit.process` operation. The absence of an
        overload is ignored for non-abstract children of `refinery.units.UnitBase`.
        """

    @classmethod
    @abc.abstractmethod
    def handles(cls, data: buf) -> bool | None:
        """
        This tri-state routine returns `True` if the unit is certain that it can process the given
        input data, and `False` if it is convinced of the opposite. `None` is returned when no
        clear verdict is available.
        """

    @abc.abstractmethod
    def filter(self, chunks: Iterable[Chunk]) -> Iterable[Chunk]:
        """
        Receives an iterable of `refinery.lib.frame.Chunk`s and yields only those that should be
        processed. The default implementation returns the iterator without change; this member
        function is designed to be overloaded by child classes of `refinery.units.Unit` to allow
        inspection of an entire frame layer and altering it before `refinery.units.Unit.process`
        is called on the individual chunks.
        """

    @abc.abstractmethod
    def finish(self) -> Iterable[Chunk]:
        """
        Child classes of `refinery.units.Unit` can overwrite this method to generate a stream of
        chunks to be processed after the last frame has been processed.
        """


_SECRET_DEBUG_TIMING_FLAG = '--debug-timing'
_SECRET_DEBUG_TRACES_FLAG = '--debug-traces'
_SECRET_YAPPI_TIMING_FLAG = '--yappi-timing'


class Unit(UnitBase, abstract=True):
    """
    The base class for all refinery units. It implements a small set of globally
    available options and the handling for multiple inputs and outputs. All units
    implement the _framing_ syntax for producing multiple outputs and ingesting
    multiple inputs in a common format. For more details, see `refinery.lib.frame`.
    """
    required_dependencies: set[str] | None = None
    optional_dependencies: dict[str, set[str]] | None = None

    _buffer: buf
    _source: BinaryIO | None
    _target: BinaryIO | None
    _framed: Framed | None
    _chunks: Iterator[buf | Chunk] | None
    console: bool

    @property
    def mode(self) -> str:
        return 'rb'

    def close(self) -> None:
        if src := self.source:
            src.close()
        self._chunks = None

    @property
    def closed(self) -> bool:
        return self._chunks is None

    def fileno(self) -> int:
        return 0

    def flush(self) -> None:
        pass

    def writable(self) -> bool:
        return False

    def seekable(self) -> bool:
        return False

    def write(self, _):
        raise RuntimeError

    def writelines(self, lines):
        raise RuntimeError

    def seek(self, offset: int, whence: int = 0) -> int:
        raise RuntimeError

    def truncate(self, size: int | None = None) -> int:
        raise RuntimeError

    def tell(self) -> int:
        return 0

    def readable(self) -> bool:
        return True

    def readlines(self, hint: int = -1) -> list[bytes]:
        lines = []
        while line := self.readline():
            lines.append(line)
        return lines

    def readline(self, limit: int = -1) -> bytes:
        line = bytearray()
        while not line.endswith(B'\n') and (char := self.read1(1)):
            line.extend(char)
        return line

    def __enter__(self):
        return self

    def __exit__(self, *_) -> None:
        pass

    @staticmethod
    def Requires(distribution: str, _buckets: Collection[str] = (), info: str | None = None):
        """
        Proxy to `refinery.lib.dependencies.dependency_accessor`.
        """
        return dependency_accessor(distribution, _buckets, info)

    @property
    def is_reversible(self) -> bool:
        """
        Proxy to `refinery.units.Executable.is_reversible`.
        """
        cls = self.__class__
        assert isinstance(cls, Executable)
        return cls.is_reversible

    @property
    def codec(self) -> str:
        """
        Proxy to `refinery.units.Executable.codec`.
        """
        cls = self.__class__
        assert isinstance(cls, Executable)
        return cls.codec

    @property
    def logger(self):
        """
        Proxy to `refinery.units.Executable.logger`.
        """
        logger: Logger = self.__class__.logger
        return logger

    @property
    def name(self) -> str:
        """
        Proxy to `refinery.units.Executable.name`.
        """
        cls = self.__class__
        assert isinstance(cls, Executable)
        return cls.name

    @property
    def is_quiet(self) -> bool:
        """
        Returns whether the global `--quiet` flag is set, indicating that the unit should not
        generate any log output.
        """
        return getattr(self.args, 'quiet', False)

    @property
    def log_level(self) -> LogLevel:
        """
        Returns the current log level as an element of `refinery.lib.environment.LogLevel`.
        """
        if self.is_quiet:
            return LogLevel.NONE
        return LogLevel(self.logger.getEffectiveLevel())

    @log_level.setter
    def log_level(self, value: int | LogLevel) -> None:
        """
        Returns the current `refinery.lib.environment.LogLevel` that the unit adheres to.
        """
        if self.__class__.logger_locked:
            return
        if not isinstance(value, LogLevel):
            value = LogLevel.FromVerbosity(value)
        self.logger.setLevel(value)

    def log_detach(self) -> Self:
        """
        When a unit is created using the `refinery.units.Unit.assemble` method, it is attached to a
        logger by default (in less abstract terms, the `refinery.units.Unit.log_level` property is
        set to a positive value). This method detaches the unit from its logger, which also means that
        any exceptions that occur during runtime will be raised to the caller.
        """
        self.log_level = LogLevel.DETACHED
        return self

    def __iter__(self) -> Iterator[bytes | bytearray | Chunk]:
        return self

    @property
    def leniency(self) -> int:
        """
        Returns the value of the global `--lenient` flag.
        """
        return getattr(self.args, 'lenient', 0)

    def _exception_handler(self, exception: BaseException, data: buf | None):
        if isinstance(exception, RefineryPartialResult):
            if self.leniency >= 1:
                return exception.partial
            if self.log_level < LogLevel.DETACHED:
                self.log_warn(F'A partial result was returned, use the -L switch to retrieve it: {exception}')
                return None
            raise exception
        elif self.leniency >= 1 and data is not None:
            return data
        elif self.log_level >= LogLevel.DETACHED:
            raise exception
        elif isinstance(exception, RefineryCriticalException):
            self.log_warn(F'critical error, terminating: {exception}')
            raise exception
        elif isinstance(exception, RefineryPotentialUserError):
            self.log_warn(str(exception))
        elif isinstance(exception, VariableMissing):
            self.log_warn('critical error:', exception.args[0])
        elif isinstance(exception, GeneratorExit):
            raise exception
        elif isinstance(exception, RefineryImportError):
            if isinstance(exception, RefineryImportMissing):
                self.log_fail(F'dependency {exception.missing} is missing; run pip install {exception.install}')
            if info := exception.info:
                self.log_fail(info)
        elif isinstance(exception, RefineryException):
            self.log_fail(exception.args[0])
        else:
            try:
                explanation = exception.args[0]
            except (AttributeError, IndexError):
                explanation = exception
            if not isinstance(explanation, str):
                explanation = exception
            explanation = str(explanation).strip()
            message = F'exception of type {exception.__class__.__name__}'
            if explanation:
                message = F'{message}; {explanation!s}'
            if self.log_level <= LogLevel.INFO and data is not None:
                from refinery.units.sinks.peek import peek
                preview = data | peek(lines=2, decode=True, stdout=True) | [str]
                message = '\n'.join((message, *preview))
            self.log_fail(message)

        if self.log_debug():
            import traceback
            traceback.print_exc(file=sys.stderr)

    def output(self):
        if not self._chunks:
            self._chunks = iter(self._framehandler)
        return self._chunks

    def __next__(self) -> bytes | bytearray | Chunk:
        while True:
            try:
                chunk = next(self.output())
            except StopIteration:
                raise
            except RefineryCriticalException as R:
                raise StopIteration from R
            except BaseException as B:
                self._exception_handler(B, None)
                raise StopIteration from B
            if not self.console and len(chunk) == MSIZE and chunk[:len(MAGIC)] == MAGIC:
                continue
            return chunk

    @property
    def _framehandler(self) -> Framed:
        if self._framed:
            return self._framed

        def normalized_action(data: Chunk) -> Generator[Chunk]:
            try:
                yield from self.act(data)
            except KeyboardInterrupt:
                raise
            except BaseException as B:
                result = self._exception_handler(B, data)
                message = str(B).strip() or 'unknown'
                if result is not None:
                    yield self.labelled(result, error=message)

        self._framed = Framed(
            normalized_action,
            self.source,
            self.filter,
            self.finish,
            self.args.nesting,
            self.args.squeeze,
            self.console,
            self.FilterEverything,
        )
        return self._framed

    def finish(self) -> Iterable[Chunk]:
        yield from ()

    def filter(self, chunks: Iterable[Chunk]) -> Iterable[Chunk]:
        return chunks

    @classmethod
    def handles(cls, data: buf) -> bool | None:
        return None

    def reset(self):
        try:
            if isinstance(source := self._source, Unit):
                source.reset()
        except AttributeError:
            pass
        self._framed = None
        self._chunks = None

    @property
    def source(self):
        """
        Represents a unit or binary IO stream which has been attached to this unit as its
        source of input data.
        """
        try:
            return self._source
        except AttributeError:
            return None

    @source.setter
    def source(self, stream):
        if isinstance(stream, self.__class__.__class__):
            stream = stream()
        if not isinstance(stream, self.__class__):
            if not isstream(stream):
                raise TypeError(F'Cannot connect object of type {type(stream).__name__} to unit.')
            self.reset()
        self._source = cast(BinaryIO, stream)

    @property
    def nozzle(self) -> Unit:
        """
        The nozzle is defined recursively as the nozzle of `refinery.units.Unit.source`
        and `self` if no such thing exists. In other words, it is the leftmost unit in
        a pipeline, where data should be inserted for processing.
        """
        if not isinstance(source := self.source, Unit):
            return self
        return source.nozzle

    def __getitem__(self, unit: Unit | type[Unit] | slice):
        if isinstance(unit, type):
            unit = unit()
        alpha = self.__copy__()
        if isinstance(unit, slice):
            if unit.start or unit.stop or unit.step:
                raise ValueError
            alpha.args.squeeze = True
            return alpha
        omega = unit.__copy__()
        alpha.args.nesting += 1
        omega.args.nesting -= 1
        omega.nozzle.source = alpha
        return omega

    def __pos__(self):
        return self

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def __neg__(self) -> Unit:
        pipeline = []
        cursor = self
        while isinstance(cursor, Unit):
            reversed = copy.copy(cursor)
            reversed.args.reverse = 1
            reversed._source = None
            reversed.reset()
            pipeline.append(reversed)
            cursor = cursor._source
        reversed = None
        while pipeline:
            reversed = reversed | pipeline.pop()
        assert isinstance(reversed, Unit)
        return reversed

    def __ror__(self, stream: (
        Unit
        | None
        | BinaryIO
        | BufferedReader
        | str
        | int
        | buf
        | Chunk
        | tuple[str]
        | tuple[buf]
        | tuple[Chunk]
        | list[str]
        | list[buf]
        | list[Chunk]
    )):
        if stream is None:
            return self
        if isinstance(stream, Chunk):
            stream = [stream]
        if isinstance(stream, (list, tuple)):
            def tochunk(t: str | buf | Chunk):
                if isinstance(t, str):
                    t = t.encode(self.codec)
                return t if isinstance(t, Chunk) else Chunk(t)
            chunks = [tochunk(t) for t in stream]
            scopes = {t.scope for t in chunks}
            stream = MemoryFile()
            if len(scopes) != 1:
                raise ValueError('Inconsistent scopes in iterable input')
            chunk_scope = next(iter(scopes))
            frame_scope = max(chunk_scope, 1)
            delta = frame_scope - chunk_scope
            stream.write(generate_frame_header(frame_scope))
            for chunk in chunks:
                stream.write(chunk.pack(delta))
            if delta:
                self.args.nesting -= delta
            stream.seekset(0)
        elif not isstream(stream):
            if isinstance(stream, str):
                stream = stream.encode(self.codec)
            if isinstance(stream, int):
                if stream > 0:
                    stream = os.fdopen(stream, 'rb')
                else:
                    stream = open(os.devnull, 'rb')
            else:
                stream = MemoryFile(cast(buf, stream))
        self.reset()
        self.nozzle.source = stream
        return self

    def __str__(self):
        return self | str

    def __bytes__(self):
        return self | bytes

    @overload
    def __or__(self, stream: int | None) -> None:
        ...

    @overload
    def __or__(self, stream: type[bytearray]) -> bytearray:
        ...

    @overload
    def __or__(self, stream: type[str]) -> str:
        ...

    @overload
    def __or__(self, stream: type[Unit]) -> Unit:
        ...

    @overload
    def __or__(self, stream: Unit) -> Unit:
        ...

    @overload
    def __or__(self, stream: Callable[[buf], _T]) -> _T:
        ...

    @overload
    def __or__(self, stream: dict[str, type[Ellipsis]]) -> dict[str, bytearray]:
        ...

    @overload
    def __or__(self, stream: dict[str, type[_T]]) -> dict[str, _T]:
        ...

    @overload
    def __or__(self, stream: dict) -> dict:
        ...

    @overload
    def __or__(self, stream: list[type[_T]]) -> list[_T]:
        ...

    @overload
    def __or__(self, stream: set[type[_T]]) -> set[_T]:
        ...

    @overload
    def __or__(self, stream: bytearray) -> bytearray:
        ...

    @overload
    def __or__(self, stream: memoryview) -> memoryview:
        ...

    @overload
    def __or__(self, stream: _B) -> _B:
        ...

    def __or__(self, stream: (
        Unit
        | None
        | type[bytearray]
        | type[str]
        | Callable[[buf], _T]
        | type[Unit]
        | dict[str, type]
        | list
        | set
        | buf
        | int
        | BinaryIO
        | ByteIO
        | BufferedWriter
    )):
        def get_converter(it: Iterable):
            try:
                c = one(it)
            except LookupError:
                return None
            if ... is c:
                def identity(x):
                    return x
                return identity
            if isinstance(c, type):
                def converter(v):
                    return v if isinstance(v, c) else c(v)
                return converter
            if callable(c):
                return c

        if stream is None or isinstance(stream, int):
            if not stream:
                stream = open(os.devnull, 'wb')
            else:
                stream = os.fdopen(stream, 'wb')
            with stream:
                _ = self | stream
            return
        if isinstance(stream, type) and issubclass(stream, Entry):
            stream = cast(Type[Unit], stream)()
        if isinstance(stream, type(...)):
            def _id(c):
                return c
            stream = _id
        if isinstance(stream, Entry):
            assert isinstance(stream, Unit)
            return stream.__copy__().__ror__(self)
        elif isinstance(stream, list):
            converter = get_converter(stream)
            if converter is None:
                stream.extend(self)
                return stream
            return [converter(chunk) for chunk in self]
        elif isinstance(stream, set):
            if converter := get_converter(stream):
                def converted():
                    for chunk in self:
                        yield converter(chunk)
                return set(converted())
            else:
                stream.update(self)
                return stream
        elif isinstance(stream, dict):
            key, convert = one(stream.items())
            output = {}
            deconflict = None
            if isinstance(convert, list):
                deconflict = list
                convert = one(convert)
            elif isinstance(convert, set):
                deconflict = set
                convert = one(convert)
            for item in self:
                assert isinstance(item, Chunk)
                value = item.meta.get(key)
                if convert is not ...:
                    item = convert(item)
                if deconflict:
                    bag = output.setdefault(value, deconflict())
                    if isinstance(bag, list):
                        bag.append(item)
                    elif isinstance(bag, set):
                        bag.add(item)
                else:
                    output[value] = item
            return output
        elif isinstance(stream, (bytearray, memoryview)):
            with MemoryFile(stream) as stdout:
                return (self | stdout).getvalue()
        elif callable(stream):
            tmp = bytearray()
            with MemoryFile(tmp) as stdout:
                _ = self | stdout
                out = stdout.getvalue()
                if isinstance(stream, type) and isinstance(out, stream):
                    return out
                if isinstance(stream, type) and issubclass(stream, str):
                    import codecs
                    out = codecs.decode(out, self.codec)
                return cast(Callable[[Any], Any], stream)(out)

        stream = cast(BinaryIO, stream)

        if not stream.writable():
            raise ValueError('target stream is not writable')

        self._target = stream

        def cname(x: str):
            return x.lower().replace('-', '')

        recode = self.isatty() and cname(self.codec) != cname(sys.stdout.encoding)
        chunk = None

        for last, chunk in lookahead(self):
            if (
                not last
                and self._framehandler.framebreak
                and not chunk.endswith(B'\n')
            ):
                if not isinstance(chunk, bytearray):
                    chunk = bytearray(chunk)
                chunk.extend(B'\n')
            if recode:
                try:
                    import codecs
                    chunk = codecs.encode(codecs.decode(
                        chunk, self.codec, errors='backslashreplace'), sys.stdout.encoding)
                except Exception:
                    pass
            try:
                stream.write(chunk)
                stream.flush()
            except AttributeError:
                pass
            except (BrokenPipeError, OSError) as E:
                if isinstance(E, BrokenPipeError) or E.errno != 32:
                    # This happens when the next unit does not consume everything
                    # we send. For example, this can happen when a large file is
                    # read in chunks and the pick unit is used to select only the
                    # first few of these.
                    self.log_debug(F'cannot send to next unit: {E}')
                break

        try:
            if self.isatty() and chunk and not chunk.endswith(B'\n'):
                stream.write(B'\n')
                stream.flush()
        except (NameError, AttributeError):
            pass

        return stream

    def read(self, bytecount: int = -1) -> bytes:
        """
        Reads bytes from the output stream of this unit.
        """
        if not bytecount or bytecount < 0:
            return self.read1()
        bfr = bytearray(bytecount)
        offset = 0
        while offset < bytecount:
            tmp = self.read1(bytecount - offset)
            if not tmp:
                del bfr[offset:]
                break
            end = offset + len(tmp)
            bfr[offset:end] = tmp
            offset = end
        return bytes(bfr)

    def read1(self, bytecount: int = -1) -> bytes:
        """
        Performs a single read against the output stream of this unit and returns
        the result.
        """
        try:
            out = self._buffer or next(self.output())
            if isinstance(out, Chunk) and out.scope > 0:
                out = out.pack()
            if bytecount and bytecount > 0:
                out, self._buffer = out[:bytecount], out[bytecount:]
            elif self._buffer:
                self._buffer = B''
            return out
        except StopIteration:
            return B''

    def act(self, data: Chunk) -> Generator[Chunk]:
        cls = self.__class__
        iff = self.args.iff
        lvl = self.log_level

        if iff and not self.handles(data):
            if iff < 2:
                yield data
            return
        else:
            data = self.args @ data
            data = data

        self.log_level = lvl
        cls.logger_locked = True

        try:
            if self.args.reverse:
                it = self.reverse(data)
            else:
                it = self.process(data)
            assert it is not None
            if isinstance(it, (bytes, bytearray, memoryview)):
                it = (it,)
            for out in it:
                assert isinstance(out, Chunk)
                yield out
        finally:
            cls.logger_locked = False

    def __call__(self, data: buf | Chunk | None = None) -> buf:
        with MemoryFile(data) if data else open(os.devnull, 'rb') as stdin:
            with MemoryFile() as stdout:
                return (stdin | self | stdout).getvalue()
        return B''

    @classmethod
    @overload
    def labelled(cls, ___br___data: None, **meta) -> None:
        ...

    @classmethod
    @overload
    def labelled(cls, ___br___data: Chunk | buf, **meta) -> Chunk:
        ...

    @classmethod
    def labelled(cls, ___br___data: Chunk | buf | None, **meta) -> Chunk | None:
        """
        This class method can be used to label a chunk of binary output with metadata. This
        metadata will be visible inside pipeline frames, see `refinery.lib.frame`.
        """
        if ___br___data is None:
            return None
        elif not isinstance(___br___data, Chunk):
            ___br___data = Chunk(___br___data, meta=meta)
        elif meta:
            ___br___data.meta.update(meta)
        return ___br___data

    def process(self, data: Chunk, /) -> buf | None | Generator[buf]:
        return data

    @classmethod
    def log_fail(cls, *messages, clip=False) -> bool:
        """
        Log the message if and only if the current log level is at least `refinery.lib.environment.LogLevel.ERROR`.
        """
        rv = cls.logger.isEnabledFor(LogLevel.ERROR)
        if rv and messages:
            cls.logger.error(cls._output(*messages, clip=clip))
        return rv

    @classmethod
    def log_warn(cls, *messages, clip=False) -> bool:
        """
        Log the message if and only if the current log level is at least `refinery.lib.environment.LogLevel.WARN`.
        """
        rv = cls.logger.isEnabledFor(LogLevel.WARNING)
        if rv and messages:
            cls.logger.warning(cls._output(*messages, clip=clip))
        return rv

    @classmethod
    def log_always(cls, *messages, clip=False) -> bool:
        """
        Log the message always.
        """
        if messages:
            cls.logger.log(LogLevel.ALWAYS, cls._output(*messages, clip=clip))
        return True

    @classmethod
    def log_info(cls, *messages, clip=False) -> bool:
        """
        Log the message if and only if the current log level is at least `refinery.lib.environment.LogLevel.INFO`.
        """
        rv = cls.logger.isEnabledFor(LogLevel.INFO)
        if rv and messages:
            cls.logger.info(cls._output(*messages, clip=clip))
        return rv

    @classmethod
    def log_debug(cls, *messages, clip=False) -> bool:
        """
        Log the pmessage if and only if the current log level is at least `refinery.lib.environment.LogLevel.DEBUG`.
        """
        rv = cls.logger.isEnabledFor(LogLevel.DEBUG)
        if rv and messages:
            cls.logger.debug(cls._output(*messages, clip=clip))
        return rv

    def isatty(self) -> bool:
        try:
            return (t := self._target) is not None and t.isatty()
        except AttributeError:
            return False

    @classmethod
    def _output(cls, *messages, clip=False) -> str:
        def transform(message):
            if callable(message):
                message = message()
            if isinstance(message, Exception):
                message = exception_to_string(message)
            if isinstance(message, str):
                return message
            if isbuffer(message):
                import codecs
                assert isinstance(message, (bytes, bytearray, memoryview))
                pmsg: str = codecs.decode(message, cls.codec, 'surrogateescape')
                if not pmsg.isprintable():
                    pmsg = message.hex().upper()
                return pmsg
            else:
                import pprint
                return pprint.pformat(message)
        message = ' '.join(transform(msg) for msg in messages)
        if clip:
            from refinery.lib.tools import get_terminal_size
            length = get_terminal_size(75) - len(cls.name) - 27
            if len(message) > length:
                message = message[:length] + "..."
        return message

    @classmethod
    def _interface(cls, argp: ArgumentParserWithKeywordHooks) -> ArgumentParserWithKeywordHooks:
        """
        Receives a reference to an argument parser. This parser will be used to parse
        the command line for this unit into the member variable called `args`.
        """
        base = argp.add_argument_group('generic options')

        base.set_defaults(reverse=False, squeeze=False, iff=0)
        base.add_argument('-h', '--help', action='help', help='Show this help message and exit.')
        base.add_argument('-L', '--lenient', action='count', default=0,
            help='Increase the leniency, allowing partial results and ignoring more errors.')
        base.add_argument('-Q', '--quiet', action='store_true', help='Disables all log output.')
        base.add_argument('-0', '--devnull', action='store_true', help='Do not produce any output.')
        base.add_argument('-v', '--verbose', action='count', default=0,
            help='Specify up to two times to increase log level.')

        if cls.is_reversible:
            base.add_argument('-R', '--reverse', action='store_true',
                help='Use the reverse operation.')

        if cls.handles.__func__ is not Unit.handles.__func__:
            base.add_argument('-F', '--iff', action='count', default=0,
                help='Only apply unit if it can handle the input format. Specify twice to drop all other chunks.')

        groups: dict[str | None, (
            ArgumentParserWithKeywordHooks | _MutuallyExclusiveGroup)] = {None: argp}

        for argument in reversed(cls._argument_specification.values()):
            gp = argument.group
            if gp not in groups:
                _ = groups[gp] = argp.add_mutually_exclusive_group()
            try:
                _ = groups[gp].add_argument @ argument
            except Exception as E:
                raise RefineryCriticalException(F'Failed to queue argument: {argument!s}; {E!s}')

        return argp

    @classmethod
    def argparser(cls, **keywords):
        argp = ArgumentParserWithKeywordHooks(
            keywords, prog=cls.name, description=documentation(cls), add_help=False)
        argp.set_defaults(nesting=0)
        return cls._interface(argp)

    @staticmethod
    def superinit(spc, **keywords):
        """
        This function uses `refinery.lib.tools.autoinvoke` to call the `__init__` function of `super` with
        by taking all required parameters from `keywords`, ignoring the rest. Calling
        ```
        self.superinit(super(), **vars())
        ```
        will therefore perform initialization of the parent class without having to forward all parameters
        manually. This is a convenience feature which reduces code bloat when many parameters have to be
        forwarded, see e.g. `refinery.units.pattern.carve.carve` for an example.
        """
        my_own_args = iter(inspect.signature(spc.__thisclass__.__init__).parameters.values())
        parent_args = inspect.signature(spc.__init__).parameters
        keywords.pop(next(my_own_args).name, None)
        for a in my_own_args:
            if a.kind is a.VAR_KEYWORD:
                keywords.update(keywords.pop(a.name, {}))
        junk = [a for a in keywords]
        for a in parent_args.values():
            if a.kind is a.VAR_KEYWORD:
                junk = [j for j in junk if j.startswith('_')]
                break
            try:
                junk.remove(a.name)
            except ValueError:
                pass
        for j in junk:
            del keywords[j]
        try:
            if spc.__init__.__func__ is Unit.__init__:
                return spc.__init__(**keywords)
        except AttributeError:
            pass
        return autoinvoke(spc.__init__, keywords)

    @classmethod
    def assemble(cls, *_args: str, **keywords):
        """
        Creates a unit from the given arguments and keywords. The given keywords are used to overwrite any
        previously specified defaults for the argument parser of the unit, then this modified parser is
        used to parse the given list of arguments as though they were given on the command line. The parser
        results are used to construct an instance of the unit, this object is consequently returned.
        """
        argp = cls.argparser(**keywords)
        args = argp.parse_args_with_nesting(_args)

        try:
            unit = autoinvoke(cls, args.__dict__)
        except ValueError as E:
            argp.error(str(E))
        else:
            unit.args._store(_argo=argp.order)
            unit.args.quiet = args.quiet
            unit.args.iff = args.iff
            unit.args.lenient = args.lenient
            unit.args.squeeze = args.squeeze
            unit.args.nesting = args.nesting
            unit.args.reverse = args.reverse
            unit.args.devnull = args.devnull
            unit.args.verbose = args.verbose

            if args.quiet:
                unit.log_level = LogLevel.NONE
            else:
                unit.log_level = args.verbose

            return unit

    def __copy__(self):
        cls = self.__class__
        clone: Unit = cls.__new__(cls)
        clone.__dict__.update(self.__dict__)
    #   TODO: Preferably, units should keep all their information in args, making
    #         the above __dict__ update unnecessary.
    #   clone._buffer = self._buffer
    #   clone._source = self._source
        clone._target = None
        clone._framed = None
        clone._chunks = None
        clone.args = copy.copy(self.args)
        return clone

    def __init__(self, **keywords):
        self._buffer = B''
        self._source = None
        self._target = None
        self._framed = None
        self._chunks = None
        self.console = False

        for key, value in dict(
            nesting=0,
            iff=0,
            reverse=False,
            squeeze=False,
            devnull=False,
            verbose=0,
            lenient=0,
            quiet=False,
        ).items():
            keywords.setdefault(key, value)
        # Since Python 3.6, functions always preserve the order of the keyword
        # arguments passed to them (see PEP 468).
        self.args = DelayedArgumentProxy(Namespace(**keywords), list(keywords))
        self.log_detach()

    @classmethod
    def run(cls, argv=None, stream=None) -> None:
        """
        Implements command line execution. As `refinery.units.Unit` is an `refinery.units.Executable`,
        this method will be executed when a class inheriting from `refinery.units.Unit` is defined in
        the current `__main__` module.
        """
        if not environment.disable_ps1_bandaid.value:
            from refinery.lib import powershell
            ps1 = powershell.bandaid(cls.codec)
        else:
            ps1 = None

        try:
            sys.set_int_max_str_digits(0)
        except AttributeError:
            pass

        argv = argv if argv is not None else sys.argv[1:]
        clock = None
        yappi = None
        trace = False

        if _SECRET_DEBUG_TRACES_FLAG in argv:
            trace = True
            argv.remove(_SECRET_DEBUG_TRACES_FLAG)

        if _SECRET_DEBUG_TIMING_FLAG in argv:
            from time import process_time
            argv.remove(_SECRET_DEBUG_TIMING_FLAG)
            clock = process_time()
            cls.logger.log(LogLevel.PROFILE, f'starting clock: {clock:.4f}')
        else:
            def process_time():
                return 0.0

        if _SECRET_YAPPI_TIMING_FLAG in argv:
            argv.remove(_SECRET_YAPPI_TIMING_FLAG)
            try:
                import yappi as _yappi
            except ImportError:
                cls.logger.log(LogLevel.PROFILE, 'unable to start yappi; package is missing')
            else:
                yappi = _yappi

        if stream is None:
            stream = open(os.devnull, 'rb') if sys.stdin.isatty() else sys.stdin.buffer

        with stream as source:
            try:
                unit = cls.assemble(*argv)
            except ArgparseError as ap:
                ap.parser.error_commandline(str(ap))
                return
            except Exception as msg:
                if not trace:
                    cls.logger.critical(cls._output('initialization failed:', msg))
                else:
                    from traceback import format_exc
                    for line in format_exc().splitlines(keepends=False):
                        cls.logger.critical(cls._output(line))
                return

            if ps1:
                unit.log_debug(F'applying PowerShell band-aid for: {unit.name}')

            loglevel = environment.verbosity.value
            if loglevel:
                unit.log_level = loglevel

            if clock:
                cls.logger.log(LogLevel.PROFILE, f'unit launching: {clock:.4f}')

            if yappi is not None:
                yappi.set_clock_type('cpu')
                yappi.start()

            unit.console = True

            try:
                stream = open(os.devnull, 'wb') if unit.args.devnull else sys.stdout.buffer
                with stream as output:
                    _ = source | unit | output
            except ParserVariableMissing as E:
                unit.logger.error(F'the variable "{E!s}" was missing while trying to parse an expression')
            except ArgumentTypeError as E:
                unit.logger.error(F'delayed argument initialization failed: {E!s}')
            except KeyboardInterrupt:
                unit.logger.warning('aborting due to keyboard interrupt')
            except OSError:
                pass

            if yappi is not None:
                stats = yappi.get_func_stats()
                filename = F'{unit.name}.perf'
                stats.save(filename, type='CALLGRIND')
                cls.logger.log(LogLevel.PROFILE, F'wrote yappi results to file: {filename}')

            if clock:
                stop_clock = process_time()
                cls.logger.log(LogLevel.PROFILE, f'stopping clock: {stop_clock:.4f}')
                cls.logger.log(LogLevel.PROFILE, f'time delta was: {stop_clock - clock:.4f}')


__pdoc__ = {
    'Unit.is_reversible': Executable.is_reversible.__doc__,
    'Unit.codec': Executable.codec.__doc__,
}
