#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
This package contains all refinery units. To write an executable refinery unit,
it is sufficient to write a class that inherits from `refinery.units.Unit` and
implements `refinery.units.Unit.process`. If the operation implemented by this
unit should be reversible, then a method called `reverse` with the same
signature has to be implemented. For example, the following would be a
minimalistic approach to implement `refinery.hex`:

    from refinery import Unit

    class hex(Unit):
        def process(self, data): return bytes.fromhex(data.decode('ascii'))
        def reverse(self, data): return data.hex().encode(self.codec)

The above script can be run from the command line. Since `hex` is not marked as
abstract, its inherited `refinery.units.Unit.run` method will be invoked when
the script is executed.

### Command Line Parameters

If you want your custom refinery unit to accept command line parameters, you can
write an initialization routine. For example, the following unit implements a
very simple XOR unit (less versatile than the already existing `refinery.xor`):

    from refinery import Unit
    import itertools

    class myxor (Unit):
        def __init__(self, key: Unit.Arg.Binary(help='Encryption key')):
            pass

        def process(self, data: bytearray):
            key = itertools.cycle(self.args.key)
            for k, b in enumerate(data):
                data[k] ^= next(key)
            return data

The `refinery.units.Arg` decorator is optional and only used here to provide a
help message on the command line. It is also available as the `Arg` class property
of the `refinery.units.Unit` class for convenience. The example also shows that
the `__init__` code can be left empty: In this case, refinery automatically adds
boilerplate code that copies all `__init__` parameters to the `args` member
variable of the unit. In this case, the constructor will be completed to have
the following code:

        def __init__(self, key: Unit.Arg.Binary(help='Encryption key')):
            super().__init__(key=key)

The option of writing an empty `__init__` was added because it is rarely needed
to perform any processing of the input arguments. The command line help for this
unit will look as follows:

    usage: myxor [-h] [-Q] [-0] [-v] key

    positional arguments:
      key            Encryption key

    generic options:
      ...

### Refinery Syntax in Code

Refinery units can be used in Python code (and a Python repl) in nearly the same
way as on the command line. As one example, consider the following unit that can
decode base64 with a custom alphabet using `refinery.map` and `refinery.b64`:

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

The syntax does not work exactly as on the command line, but it was designed to
be as similar as possible:

- The binary or operator `|` can be used to combine units into pipelines.
- Combining a pipeline from the left with a byte string or io stream object will
  feed this byte string into the unit.
- Unary negation of a reversible unit is equivalent to using the `-R` switch for
  reverse mode.
- A pipeline is an iterable of output chunks, but there is quite a selection of
  objects that can be connected to a pipeline from the right using `|` for
  various different output options. See below for details.

If you want to use frames in code, simply omit any pipe before a square bracket.
For example, the first example from the `refinery.lib.frame` documentation
translates to the following Python code:

    >>> from refinery import *
    >>> B'OOOOOOOO' | chop(2) [ ccp(B'F') | cca(B'.') ]| ...
    >>> bytearray(b'FOO.FOO.FOO.FOO.')

In the above example, the pipeline is piped to a literal ellipsis (`...`) to get
the final result. The following section lists the other output options.

### Output Options in Code

You can connect a pipeline to any binary i/o stream, and the output of the
pipeline will be written to that stream. Example:

    with open('output', 'wb') as stream:
        B'BINARY REFINERY' | xor(0x13) | stream

Furthermore, you can connect pipelines to any callable, and you can always use
a literal ellipsis (`...`) to represent the identity function. The result of
this is that you receive the raw output from the pipeline:

    >>> B'BINARY REFINERY' | xor(0x13) | ...
    bytearray(b'QZ]RAJ3AVUZ]VAJ')

You can also connect to sets and lists containing a single callable. In this
case, the callable will be applied to each output chunk and all results will be
collected in a list or set, respectively. Examples:

    >>> B'ABABCBABABCHB' | rex('.B') | [str]
    ['AB', 'AB', 'CB', 'AB', 'AB', 'HB']
    >>> B'ABABCBABABCHB' | rex('.B') | {str}
    {'AB', 'CB', 'HB'}

You can also consume into a dictionary in a similar way:

    >>> B'ABABCBABABCHB' | rex('.(?P<k>.)B') | {'k': str}
    {A: ['BAB', 'BAB'], H: ['CHB']}

Here, the dictionary is expected to contain exactly one key-value pair. The key
is the name of a meta variable and the value is a conversion function. The
result will be a dictionary where all converted results have been grouped under
the respective value of their meta variable. With all of the above options, it
is always possible to use a literal ellipsis (`...`).

You can connect pipelines to `bytearray` and (writable) `memoryview` instances.
In this case, the output will be appended to the end of this buffer. Finally, if
you connect a pipeline to `None`, this will execute the unit but discard all
output. This is useful for using units with side effects, like `refinery.peek`,
in a REPL.
"""
from __future__ import annotations

import abc
import copy
import inspect
import os
import sys

from abc import ABCMeta
from enum import Enum
from functools import wraps
from collections import OrderedDict
from threading import Lock

from typing import (
    Dict,
    Iterable,
    Sequence,
    Set,
    Type,
    TypeVar,
    Union,
    List,
    Optional,
    Callable,
    ClassVar,
    Tuple,
    Any,
    Generator,
    overload,
    no_type_check,
    get_type_hints
)

from argparse import (
    ArgumentTypeError, Namespace,
    ONE_OR_MORE,
    OPTIONAL,
    REMAINDER,
    ZERO_OR_MORE
)

from refinery.lib.argparser import ArgumentParserWithKeywordHooks, ArgparseError
from refinery.lib.frame import generate_frame_header, Framed, Chunk, MAGIC, MSIZE
from refinery.lib.structures import MemoryFile
from refinery.lib.environment import LogLevel, Logger, environment, logger
from refinery.lib.types import ByteStr, Singleton

from refinery.lib.argformats import (
    manifest,
    multibin,
    number,
    numseq,
    ParserVariableMissing,
    pending,
    regexp,
    slicerange,
    sliceobj,
    VariableMissing,
)

from refinery.lib.tools import (
    autoinvoke,
    documentation,
    isbuffer,
    isstream,
    lookahead,
    normalize_to_display,
    normalize_to_identifier,
    exception_to_string,
    one,
    skipfirst,
)


ByteIO = MemoryFile[ByteStr]


class RefineryPartialResult(ValueError):
    """
    This exception indicates that a partial result is available.
    """
    def __init__(self, message: str, partial: ByteStr, rest: Optional[ByteStr] = None):
        super().__init__(message)
        self.message = message
        self.partial = partial
        self.rest = rest

    def __str__(self):
        return self.message


class RefineryImportMissing(ModuleNotFoundError):
    """
    A special variant of the `ModuleNotFoundError` exception which is raised when a dependency of a
    refinery unit is not installed in the current environment. The exception also provides hints
    about what package has to be installed in order to make that module available.
    """
    def __init__(self, missing: str, *dependencies: str):
        super().__init__()
        import shlex
        self.missing = missing
        self.install = ' '.join(shlex.quote(dist) for dist in dependencies)
        self.dependencies = dependencies


class RefineryCriticalException(RuntimeError):
    """
    If this exception is thrown, processing of the entire input stream
    is aborted instead of just aborting the processing of the current
    chunk.
    """
    pass


class RefineryPotentialUserError(RuntimeError):
    """
    This exception can be raised by a unit to inform the user about a
    suspected input error.
    """
    pass


class RefineryException(RuntimeError):
    """
    This is an exception that was not generated by an external library.
    """
    pass


class Entry:
    """
    An empty class marker. Any entry point unit (i.e. any unit that can be executed
    via the command line) is an instance of this class.
    """
    pass


class Argument:
    """
    This class implements an abstract argument to a Python function, including positional
    and keyword arguments. Passing an `Argument` to a Python function can be done via the
    matrix multiplication operator: The syntax `function @ Argument(a, b, kwd=c)` is
    equivalent to the call `function(a, b, kwd=c)`.
    """
    __slots__ = 'args', 'kwargs'

    args: List[Any]
    kwargs: Dict[str, Any]

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

    class delete: pass
    class omit: pass

    args: List[str]

    def __init__(
        self, *args: str,
            action   : Union[omit, str]           = omit, # noqa
            choices  : Union[omit, Iterable[Any]] = omit, # noqa
            const    : Union[omit, Any]           = omit, # noqa
            default  : Union[omit, Any]           = omit, # noqa
            dest     : Union[omit, str]           = omit, # noqa
            help     : Union[omit, str]           = omit, # noqa
            metavar  : Union[omit, str]           = omit, # noqa
            nargs    : Union[omit, int, str]      = omit, # noqa
            required : Union[omit, bool]          = omit, # noqa
            type     : Union[omit, type]          = omit, # noqa
            group    : Optional[str]              = None, # noqa
            guessed  : Optional[Set[str]]         = None, # noqa
    ) -> None:
        kwargs = dict(action=action, choices=choices, const=const, default=default, dest=dest,
            help=help, metavar=metavar, nargs=nargs, required=required, type=type)
        kwargs = {key: value for key, value in kwargs.items() if value is not Arg.omit}
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
                    default: Union[bytes, int, str, slice] = self.arg.kwargs['default']
                    if isinstance(default, (list, tuple, set)):
                        if not default:
                            return 'empty'
                        elif len(default) == 1:
                            default = default[0]
                    if isinstance(default, slice):
                        parts = [default.start or '', default.stop or '', default.step]
                        default = ':'.join(str(x) for x in parts if x is not None)
                    if isinstance(default, int):
                        return default
                    if not isbuffer(default):
                        return default
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
    def AsOption(value: Optional[Any], cls: Enum) -> Enum:
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
        help    : Union[omit, str] = omit,
        dest    : Union[omit, str] = omit,
        group   : Optional[str] = None,
    ):
        """
        A convenience method to add argparse arguments that introduce a counter.
        """
        return cls(*args, group=group, help=help, dest=dest, action='count')

    @classmethod
    def Switch(
        cls,
        *args   : str, off=False,
        help    : Union[omit, str] = omit,
        dest    : Union[omit, str] = omit,
        group   : Optional[str] = None,
    ):
        """
        A convenience method to add argparse arguments that change a boolean value from True to False or
        vice versa. By default, a switch will have a False default and change it to True when specified.
        """
        return cls(*args, group=group, help=help, dest=dest, action='store_false' if off else 'store_true')

    @classmethod
    def Binary(
        cls,
        *args   : str,
        help    : Union[omit, str] = omit,
        dest    : Union[omit, str] = omit,
        nargs   : Union[omit, int, str] = omit,
        metavar : Optional[str] = None,
        group   : Optional[str] = None,
    ):
        """
        Used to add argparse arguments that contain binary data.
        """
        if metavar is None and any('-' in a for a in args):
            metavar = 'B'
        return cls(*args, group=group, help=help, dest=dest, nargs=nargs, type=multibin, metavar=metavar)

    @classmethod
    def String(
        cls,
        *args   : str,
        help    : Union[omit, str] = omit,
        dest    : Union[omit, str] = omit,
        nargs   : Union[omit, int, str] = omit,
        metavar : Optional[str] = None,
        group   : Optional[str] = None,
    ):
        """
        Used to add argparse arguments that contain string data.
        """
        if metavar is None and any('-' in a for a in args):
            metavar = 'STR'
        return cls(*args, group=group, help=help, dest=dest, nargs=nargs, type=str, metavar=metavar)

    @classmethod
    def RegExp(
        cls,
        *args   : str,
        help    : Union[omit, str] = omit,
        dest    : Union[omit, str] = omit,
        nargs   : Union[omit, int, str] = omit,
        metavar : Optional[str] = None,
        group   : Optional[str] = None,
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
        help    : Union[omit, str] = omit,
        dest    : Union[omit, str] = omit,
        nargs   : Union[omit, int, str] = omit,
        metavar : Optional[str] = None,
        group   : Optional[str] = None,
    ):
        """
        Used to add argparse arguments that contain a numeric sequence.
        """
        return cls(*args, group=group, help=help, nargs=nargs, dest=dest, type=numseq, metavar=metavar)

    @classmethod
    def Bounds(
        cls,
        *args   : str,
        help    : Optional[Union[omit, str]] = None,
        dest    : Union[omit, str] = omit,
        nargs   : Union[omit, int, str] = omit,
        default : Union[omit, Any] = omit,
        range   : bool = False,
        metavar : Optional[str] = 'start:end:step',
        group   : Optional[str] = None,
    ):
        """
        Used to add argparse arguments that contain a slice.
        """
        if help is None:
            help = 'Specify start:end:step in Python slice syntax.'
            if default is not cls.omit:
                help = F'{help} The default is {{default}}.'
        parser = slicerange if range else sliceobj
        return cls(*args, group=group, help=help, default=default, nargs=nargs, dest=dest, type=parser, metavar=metavar)

    @classmethod
    def Number(
        cls,
        *args   : str,
        bound   : Union[omit, Tuple[int, int]] = omit,
        help    : Union[omit, str] = omit,
        dest    : Union[omit, str] = omit,
        metavar : Optional[str] = None,
        group   : Optional[str] = None,
    ):
        """
        Used to add argparse arguments that contain a number.
        """
        nt = number
        if bound is not cls.omit:
            lower, upper = bound
            nt = nt[lower:upper]
        return cls(*args, group=group, help=help, dest=dest, type=nt, metavar=metavar or 'N')

    @classmethod
    def Option(
        cls,
        *args   : str,
        choices : Enum,
        help    : Union[omit, str] = omit,
        dest    : Union[omit, str] = omit,
        metavar : Optional[str] = None,
        group   : Optional[str] = None,
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
        choices : List[str],
        help    : Union[omit, str] = omit,
        metavar : Union[omit, str] = omit,
        dest    : Union[omit, str] = omit,
        type    : Type = str,
        nargs   : Union[omit, int, str] = omit,
        group   : Optional[str] = None,
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
    def Infer(cls, pt: inspect.Parameter, module: Optional[str] = None):
        """
        This class method can be used to infer the argparse argument for a Python function
        parameter. This guess is based on the annotation, name, and default value.
        """

        def needs_type(item: Dict[str, str]):
            try:
                return item['action'] == 'store'
            except KeyError:
                return True

        def get_argp_type(annotation_type):
            if issubclass(annotation_type, (bytes, bytearray, memoryview)):
                return multibin
            if issubclass(annotation_type, int):
                return number
            if issubclass(annotation_type, slice):
                return sliceobj
            return annotation_type

        name = normalize_to_display(pt.name, False)
        default = pt.default
        guessed_pos_args = []
        guessed_kwd_args = dict(dest=pt.name)
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
            symbols = None
            while symbols is not False:
                try:
                    annotation = eval(annotation, symbols)
                except NameError:
                    if symbols is not None or module is None:
                        break
                    try:
                        import importlib
                        symbols = importlib.import_module(module).__dict__
                    except Exception:
                        symbols = False
                except Exception:
                    pass
                else:
                    break

        if annotation is not pt.empty:
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

        if default is not pt.empty:
            if isinstance(default, Enum):
                default = default.name
            if isinstance(default, (list, tuple)):
                guess('nargs', ZERO_OR_MORE)
                if not pt.default:
                    default = pt.empty
                else:
                    guessed_kwd_args['default'] = pt.default
                    default = default[0]
            else:
                guessed_kwd_args['default'] = default
                if pt.kind is pt.POSITIONAL_ONLY:
                    guess('nargs', OPTIONAL)

        if default is not pt.empty:
            if isinstance(default, bool):
                action = 'store_false' if default else 'store_true'
                guessed_kwd_args['action'] = action
            elif needs_type(guessed_kwd_args):
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

    def __copy__(self) -> Argument:
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


class ArgumentSpecification(OrderedDict):
    """
    A container object that stores `refinery.units.Arg` specifications.
    """

    def merge(self: Dict[str, Arg], argument: Arg):
        """
        Insert or update the specification with the given argument.
        """
        dest = argument.destination
        if dest in self:
            self[dest].merge_all(argument)
            return
        self[dest] = argument


DataType = TypeVar('DataType', bound=ByteStr)
ProcType = Callable[['Unit', ByteStr], Optional[Union[DataType, Iterable[DataType]]]]

_T = TypeVar('_T')


def _UnitProcessorBoilerplate(operation: ProcType[ByteStr]) -> ProcType[Chunk]:
    @wraps(operation)
    def wrapped(self: Unit, data: ByteStr) -> Optional[Union[Chunk, Iterable[Chunk]]]:
        ChunkType = Chunk
        if data is None:
            data = B''
        typespec = get_type_hints(operation)
        typespec.pop('return', None)
        if typespec and len(typespec) == 1:
            SpecType = next(iter(typespec.values()))
            if isinstance(SpecType, str):
                try: SpecType = eval(SpecType)
                except Exception: pass
            if isinstance(SpecType, type):
                ChunkType = SpecType
        if not isinstance(data, ChunkType):
            data = ChunkType(data)
        result = operation(self, data)
        if isinstance(result, Chunk):
            return result
        elif not inspect.isgenerator(result):
            return Chunk(result)
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


class MissingFunction(metaclass=Singleton):
    """
    A singleton class that represents a missing function. Used internally to
    indicate that a unit does not implement a reverse operation.
    """
    def __call__(*_, **__):
        raise NotImplementedError


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

    _argument_specification: Dict[str, Arg]

    def _infer_argspec(cls, parameters: Dict[str, inspect.Parameter], args: Optional[Dict[str, Arg]], module: str):

        args: Dict[str, Arg] = ArgumentSpecification() if args is None else args

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
            if known.positional:
                known.kwargs.pop('dest', None)
                if 'default' in known.kwargs:
                    known.kwargs.setdefault('nargs', OPTIONAL)
            elif not any(len(a) > 2 for a in known.args):
                flagname = normalize_to_display(known.destination, False)
                known.args.append(F'--{flagname}')
            action: str = known.kwargs.get('action', 'store')
            if action.startswith('store_'):
                known.kwargs.pop('default', None)
                continue
            if action == 'store':
                known.kwargs.setdefault('type', multibin)
        return args

    def __new__(mcs, name: str, bases: Sequence[Executable], nmspc: Dict[str, Any], abstract=False, docs='{}'):
        def decorate(**decorations):
            for method, decorator in decorations.items():
                try:
                    old = nmspc[method]
                except KeyError:
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
                nmspc.setdefault('reverse', MissingFunction)
            bases = bases + (Entry,)
        nmspc.setdefault('__doc__', '')
        return super(Executable, mcs).__new__(mcs, name, bases, nmspc)

    def __init__(cls, name: str, bases: Sequence[Executable], nmspc: Dict[str, Any], abstract=False, docs='{}'):
        super(Executable, cls).__init__(name, bases, nmspc)
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
            mro = {b.__name__: inspect.cleandoc(b.__doc__) for b in cls.__mro__}
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
            new__init__.__signature__ = sig_init.replace(parameters=tuple(params))
            cls.__init__ = new__init__

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
            def cls__init__(self, *args, **kw):
                for name, arg in zip(head, args):
                    kw[name] = arg
                if tail:
                    k = min(len(args), len(head))
                    kw[tail] = args[k:]
                for key in defs:
                    if key not in kw:
                        kw[key] = defs[key]
                base.__init__(self, **kw)

            cls.__init__ = cls__init__

        if not abstract and sys.modules[cls.__module__].__name__ == '__main__':
            if not Executable.Entry:
                Executable.Entry = cls.name
                cls.run()

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
    def is_reversible(cls: Unit) -> bool:
        """
        This property is `True` if and only if the unit has a member function named `reverse`. By convention,
        this member function implements the inverse of `refinery.units.Unit.process`.
        """
        if cls.reverse is MissingFunction:
            return False
        return not getattr(cls.reverse, '__isabstractmethod__', False)

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
    _argo: List[str]
    _args: Dict[str, Any]
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
            return super().__getattr__(name)
        except AttributeError:
            pass
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
    This base class is an abstract interface specifying the abstract methods that have
    to be present on any unit. All actual units should inherit from its only child class
    `refinery.units.Unit`.
    """

    @abc.abstractmethod
    def process(self, data: ByteStr) -> Union[Optional[ByteStr], Iterable[ByteStr]]:
        """
        This routine is overridden by children of `refinery.units.Unit` to define how
        the unit processes a given chunk of binary data.
        """

    @abc.abstractmethod
    def reverse(self, data: ByteStr) -> Union[Optional[ByteStr], Iterable[ByteStr]]:
        """
        If this routine is overridden by children of `refinery.units.Unit`, then it must
        implement an operation that reverses the `refinery.units.Unit.process` operation.
        The absence of an overload for this function is ignored for non-abstract children of
        `refinery.units.UnitBase`.
        """

    @classmethod
    @abc.abstractmethod
    def handles(self, data: ByteStr) -> Optional[bool]:
        """
        This tri-state routine returns `True` if the unit is certain that it can process the
        given input data, and `False` if it is convinced of the opposite. `None` is returned
        when no clear verdict is available.
        """

    @abc.abstractmethod
    def filter(self, inputs: Iterable[Chunk]) -> Iterable[Chunk]:
        """
        Receives an iterable of `refinery.lib.frame.Chunk`s and yields only those that
        should be processed. The default implementation returns the iterator without
        change; this member function is designed to be overloaded by child classes of
        `refinery.units.Unit` to allow inspection of an entire frame layer and altering
        it before `refinery.units.Unit.process` is called on the individual chunks.
        """

    @abc.abstractmethod
    def finish(self) -> Iterable[Chunk]:
        """
        Child classes of `refinery.units.Unit` can overwrite this method to generate a
        stream of chunks to be processed after the last frame has been processed.
        """


class requirement(property):
    """
    An empty descendant of the builtin `property` class that is used to distinguish import
    requirements on units from other properties. When `refinery.units.Unit.Requires` is used to
    decorate a member function as an import, this member function becomes an instance of this
    class.
    """
    pass


class Unit(UnitBase, abstract=True):
    """
    The base class for all refinery units. It implements a small set of globally
    available options and the handling for multiple inputs and outputs. All units
    implement the _framing_ syntax for producing multiple outputs and ingesting
    multiple inputs in a common format. For more details, see `refinery.lib.frame`.
    """
    Arg = Arg

    required_dependencies: Optional[Set[str]] = None
    optional_dependencies: Optional[Dict[str, Set[str]]] = None

    @staticmethod
    def Requires(distribution: str, *_buckets: str):

        class Requirement(requirement):
            dependency: ClassVar[str] = distribution
            required: ClassVar[bool] = not _buckets

            def __init__(self, importer: Callable):
                super().__init__(importer)
                self.module = None

            def __set_name__(self, unit: Type[Unit], name: str):
                if self.required:
                    bucket = unit.required_dependencies
                    if bucket is None:
                        unit.required_dependencies = bucket = set()
                    buckets = [bucket]
                else:
                    optmap = unit.optional_dependencies
                    if optmap is None:
                        unit.optional_dependencies = optmap = {}
                    buckets = [optmap.setdefault(name, set()) for name in _buckets]
                for bucket in buckets:
                    bucket.add(self.dependency)

            def __get__(self, unit: Optional[Type[Unit]], tp: Optional[Type[Executable]] = None):
                if self.module is not None:
                    return self.module
                try:
                    self.module = module = self.fget()
                except ImportError as E:
                    deps = unit.optional_dependencies or {}
                    args = set()
                    for v in deps.values():
                        args.update(v)
                    raise RefineryImportMissing(self.dependency, *args) from E
                except Exception as E:
                    raise AttributeError(F'module import for distribution "{distribution}" failed: {E!s}')
                else:
                    return module

        Requirement.__qualname__ = F'Requirement({distribution!r})'
        return Requirement

    @property
    def is_reversible(self) -> bool:
        """
        Proxy to `refinery.units.Executable.is_reversible`.
        """
        return self.__class__.is_reversible

    @property
    def codec(self) -> str:
        """
        Proxy to `refinery.units.Executable.codec`.
        """
        return self.__class__.codec

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
        return self.__class__.name

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
    def log_level(self, value: Union[int, LogLevel]) -> None:
        """
        Returns the current `refinery.lib.environment.LogLevel` that the unit adheres to.
        """
        if self.__class__.logger_locked:
            return
        if not isinstance(value, LogLevel):
            value = LogLevel.FromVerbosity(value)
        self.logger.setLevel(value)

    def log_detach(self) -> None:
        """
        When a unit is created using the `refinery.units.Unit.assemble` method, it is attached to a
        logger by default (in less abstract terms, the `refinery.units.Unit.log_level` property is
        set to a positive value). This method detaches the unit from its logger, which also means that
        any exceptions that occur during runtime will be raised to the caller.
        """
        self.log_level = LogLevel.DETACHED
        return self

    def __iter__(self) -> Generator[Chunk, None, None]:
        return self

    @property
    def leniency(self) -> int:
        """
        Returns the value of the global `--lenient` flag.
        """
        return getattr(self.args, 'lenient', 0)

    def _exception_handler(self, exception: BaseException, data: Optional[ByteStr]):
        if data is not None and self.leniency > 1:
            try:
                return exception.partial
            except AttributeError:
                return data
        if isinstance(exception, RefineryPartialResult):
            if self.leniency >= 1:
                return exception.partial
            if self.log_level < LogLevel.DETACHED:
                self.log_warn(F'A partial result was returned, use the -L switch to retrieve it: {exception}')
                return None
            raise exception
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
        elif isinstance(exception, RefineryImportMissing):
            self.log_fail(F'dependency {exception.missing} is missing; run pip install {exception.install}')
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

    def __next__(self) -> Chunk:
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
            if not self.console and len(chunk) == MSIZE and chunk.startswith(MAGIC):
                continue
            return chunk

    @property
    def _framehandler(self) -> Framed:
        if self._framed:
            return self._framed

        def normalized_action(data: ByteStr) -> Generator[Chunk, None, None]:
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
            self.args.nesting,
            self.args.squeeze,
            self.filter,
            self.finish,
            self.console
        )
        return self._framed

    def finish(self) -> Iterable[Chunk]:
        yield from ()

    def filter(self, inputs: Iterable[Chunk]) -> Iterable[Chunk]:
        return inputs

    @classmethod
    def handles(self, data: bytearray) -> Optional[bool]:
        return None

    def reset(self):
        try:
            self._source.reset()
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
        return self._source

    @source.setter
    def source(self, stream):
        if isinstance(stream, self.__class__.__class__):
            stream = stream()
        if not isinstance(stream, self.__class__):
            if not isstream(stream):
                raise TypeError(F'Cannot connect object of type {type(stream).__name__} to unit.')
            self.reset()
        self._source = stream

    @property
    def nozzle(self) -> Unit:
        """
        The nozzle is defined recursively as the nozzle of `refinery.units.Unit.source`
        and `self` if no such thing exists. In other words, it is the leftmost unit in
        a pipeline, where data should be inserted for processing.
        """
        try:
            return self.source.nozzle
        except AttributeError:
            return self

    def __getitem__(self, unit: Union[Unit, Type[Unit], slice]):
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
            self.nozzle.source.close()
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
        return reversed

    def __ror__(self, stream: Union[str, Chunk, list[Chunk], ByteIO, ByteStr, None]):
        if stream is None:
            return self
        if isinstance(stream, Chunk):
            stream = [stream]
        if isinstance(stream, (list, tuple)):
            chunks = list(stream)
            scopes = set()
            stream = MemoryFile()
            for k, chunk in enumerate(chunks):
                if not isinstance(chunk, Chunk):
                    chunks[k] = chunk = Chunk(chunk)
                scopes.add(chunk.scope)
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
            if stream:
                stream = MemoryFile(stream)
            else:
                stream = open(os.devnull, 'rb')
        self.reset()
        self.nozzle.source = stream
        return self

    def __str__(self):
        return self | str

    def __bytes__(self):
        return self | bytes

    @overload
    def __or__(self, stream: Callable[[ByteStr], _T]) -> _T: ...

    @overload
    def __or__(self, stream: Type[str]) -> str: ...

    @overload
    def __or__(self, stream: Union[Unit, Type[Unit]]) -> Unit: ...

    @overload
    def __or__(self, stream: dict) -> dict: ...

    @overload
    def __or__(self, stream: Dict[str, Type[_T]]) -> Dict[str, _T]: ...

    @overload
    def __or__(self, stream: Dict[str, Type[Ellipsis]]) -> Dict[str, bytearray]: ...

    @overload
    def __or__(self, stream: List[Type[_T]]) -> List[_T]: ...

    @overload
    def __or__(self, stream: Set[Type[_T]]) -> Set[_T]: ...

    @overload
    def __or__(self, stream: bytearray) -> bytearray: ...

    @overload
    def __or__(self, stream: memoryview) -> memoryview: ...

    @overload
    def __or__(self, stream: Type[None]) -> None: ...

    @overload
    def __or__(self, stream: Type[bytearray]) -> bytearray: ...

    @overload
    def __or__(self, stream: ByteIO) -> ByteIO: ...

    def __or__(self, stream):
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

        if stream is None:
            with open(os.devnull, 'wb') as null:
                self | null
            return
        if isinstance(stream, type) and issubclass(stream, Entry):
            stream = stream()
        if isinstance(stream, type(...)):
            def stream(c): return c
        if isinstance(stream, Entry):
            return stream.__copy__().__ror__(self)
        elif isinstance(stream, list):
            converter = get_converter(stream)
            if converter is None:
                stream.extend(self)
                return stream
            return [converter(chunk) for chunk in self]
        elif isinstance(stream, set):
            converter = get_converter(stream)
            if converter is None:
                stream.update(self)
                return stream
            return {converter(chunk) for chunk in self}
        elif isinstance(stream, dict):
            key, convert = one(stream.items())
            output: Dict[Any, Union[List[Chunk], Set[Chunk]]] = {}
            deconflict = None
            if isinstance(convert, (list, set)):
                deconflict = type(convert)
                convert = one(convert)
            for item in self:
                try:
                    value = item.meta[key]
                except KeyError:
                    value = None
                if convert is not ...:
                    item = convert(item)
                if deconflict:
                    bag = output.setdefault(value, deconflict())
                    if isinstance(bag, list):
                        bag.append(item)
                    else:
                        bag.add(item)
                else:
                    output[value] = item
            return output
        elif isinstance(stream, (bytearray, memoryview)):
            with MemoryFile(stream) as stdout:
                return (self | stdout).getvalue()
        elif callable(stream):
            with MemoryFile(bytearray()) as stdout:
                self | stdout
                out: bytearray = stdout.getbuffer()
                if isinstance(stream, type) and isinstance(out, stream):
                    return out
                if isinstance(stream, type) and issubclass(stream, str):
                    out = out.decode(self.codec)
                return stream(out)

        stream: ByteIO

        if not stream.writable():
            raise ValueError('target stream is not writable')

        self._target = stream

        def cname(x: str):
            return x.lower().replace('-', '')

        recode = self.isatty and cname(self.codec) != cname(sys.stdout.encoding)
        chunk = None

        for last, chunk in lookahead(self):
            if (
                not last
                and self._framehandler.framebreak
                and not chunk.endswith(B'\n')
            ):
                chunk.extend(B'\n')
            if recode:
                try:
                    chunk = chunk.decode(chunk, self.codec, errors='backslashreplace').encode(sys.stdout.encoding)
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
            if self.isatty and chunk and not chunk.endswith(B'\n'):
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

    def act(self, data: Union[Chunk, ByteStr]) -> Generator[ByteStr, None, None]:
        cls = self.__class__
        iff = self.args.iff
        lvl = cls.log_level

        if iff and not self.handles(data):
            if iff < 2:
                yield data
            return
        else:
            data = self.args @ data
            data = data

        cls.log_level = lvl
        cls.logger_locked = True

        try:
            if self.args.reverse:
                it = self.reverse(data)
            else:
                it = self.process(data)
            if not inspect.isgenerator(it):
                it = (it,)
            for out in it:
                if out is not None:
                    yield out
        finally:
            cls.logger_locked = False

    def __call__(self, data: Optional[Union[ByteStr, Chunk]] = None) -> bytes:
        with MemoryFile(data) if data else open(os.devnull, 'rb') as stdin:
            stdin: ByteIO
            with MemoryFile() as stdout:
                return (stdin | self | stdout).getvalue()

    @classmethod
    def labelled(cls, ___br___data: Union[Chunk, ByteStr], **meta) -> Chunk:
        """
        This class method can be used to label a chunk of binary output with metadata. This
        metadata will be visible inside pipeline frames, see `refinery.lib.frame`.
        """
        if isinstance(___br___data, Chunk):
            ___br___data.meta.update(meta)
            return ___br___data
        return Chunk(___br___data, meta=meta)

    def process(self, data: ByteStr) -> Union[Optional[ByteStr], Generator[ByteStr, None, None]]:
        return data

    @classmethod
    def log_fail(cls: Union[Executable, Type[Unit]], *messages, clip=False) -> bool:
        """
        Log the message if and only if the current log level is at least `refinery.lib.environment.LogLevel.ERROR`.
        """
        rv = cls.logger.isEnabledFor(LogLevel.ERROR)
        if rv and messages:
            cls.logger.error(cls._output(*messages, clip=clip))
        return rv

    @classmethod
    def log_warn(cls: Union[Executable, Type[Unit]], *messages, clip=False) -> bool:
        """
        Log the message if and only if the current log level is at least `refinery.lib.environment.LogLevel.WARN`.
        """
        rv = cls.logger.isEnabledFor(LogLevel.WARNING)
        if rv and messages:
            cls.logger.warning(cls._output(*messages, clip=clip))
        return rv

    @classmethod
    def log_info(cls: Union[Executable, Type[Unit]], *messages, clip=False) -> bool:
        """
        Log the message if and only if the current log level is at least `refinery.lib.environment.LogLevel.INFO`.
        """
        rv = cls.logger.isEnabledFor(LogLevel.INFO)
        if rv and messages:
            cls.logger.info(cls._output(*messages, clip=clip))
        return rv

    @classmethod
    def log_debug(cls: Union[Executable, Type[Unit]], *messages, clip=False) -> bool:
        """
        Log the pmessage if and only if the current log level is at least `refinery.lib.environment.LogLevel.DEBUG`.
        """
        rv = cls.logger.isEnabledFor(LogLevel.DEBUG)
        if rv and messages:
            cls.logger.debug(cls._output(*messages, clip=clip))
        return rv

    @property
    def isatty(self) -> bool:
        try:
            return self._target.isatty()
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
                message: Union[bytes, bytearray, memoryview]
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
        base.add_argument('-L', '--lenient', action='count', default=0, help='Allow partial results as output.')
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

        groups = {None: argp}

        for argument in reversed(cls._argument_specification.values()):
            gp = argument.group
            if gp not in groups:
                groups[gp] = argp.add_mutually_exclusive_group()
            try:
                groups[gp].add_argument @ argument
            except Exception as E:
                raise RefineryCriticalException(F'Failed to queue argument: {argument!s}; {E!s}')
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
            try: junk.remove(a.name)
            except ValueError: pass
        for j in junk:
            del keywords[j]
        try:
            if spc.__init__.__func__ is Unit.__init__:
                return spc.__init__(**keywords)
        except AttributeError:
            pass
        return autoinvoke(spc.__init__, keywords)

    @classmethod
    def assemble(cls, *args, **keywords):
        """
        Creates a unit from the given arguments and keywords. The given keywords are used to overwrite any
        previously specified defaults for the argument parser of the unit, then this modified parser is
        used to parse the given list of arguments as though they were given on the command line. The parser
        results are used to construct an instance of the unit, this object is consequently returned.
        """
        argp = cls.argparser(**keywords)
        args = argp.parse_args_with_nesting(args)

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

    _SECRET_DEBUG_TIMING_FLAG = '--debug-timing'
    _SECRET_DEBUG_TRACES_FLAG = '--debug-traces'
    _SECRET_YAPPI_TIMING_FLAG = '--yappi-timing'

    @classmethod
    def run(cls: Union[Type[Unit], Executable], argv=None, stream=None) -> None:
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

        if cls._SECRET_DEBUG_TRACES_FLAG in argv:
            trace = True
            argv.remove(cls._SECRET_DEBUG_TRACES_FLAG)

        if cls._SECRET_DEBUG_TIMING_FLAG in argv:
            from time import process_time
            argv.remove(cls._SECRET_DEBUG_TIMING_FLAG)
            clock = process_time()
            cls.logger.log(LogLevel.PROFILE, 'starting clock: {:.4f}'.format(clock))

        if cls._SECRET_YAPPI_TIMING_FLAG in argv:
            argv.remove(cls._SECRET_YAPPI_TIMING_FLAG)
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
                cls.logger.log(LogLevel.PROFILE, 'unit launching: {:.4f}'.format(clock))

            if yappi is not None:
                yappi.set_clock_type('cpu')
                yappi.start()

            unit.console = True

            try:
                with open(os.devnull, 'wb') if unit.args.devnull else sys.stdout.buffer as output:
                    source | unit | output
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
                cls.logger.log(LogLevel.PROFILE, 'stopping clock: {:.4f}'.format(stop_clock))
                cls.logger.log(LogLevel.PROFILE, 'time delta was: {:.4f}'.format(stop_clock - clock))


__pdoc__ = {
    'Unit.is_reversible': Executable.is_reversible.__doc__,
    'Unit.codec': Executable.codec.__doc__
}
