#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
This package contains all refinery units. To write an executable refinery unit,
it is sufficient to write a class that inherits from `refinery.units.Unit` and
implements `refinery.units.Unit.process`. If the operation implemented by this
unit should be reversible, then a method called `reverse` with the same signature
has to be implemented. For example, the following would be a minimalistic
approach to implement `refinery.hex`:

    from refinery import Unit

    class hex(Unit):
        def process(self, data): return bytes.fromhex(data.decode('ascii'))
        def reverse(self, data): return data.hex().encode(self.codec)

The above script can be run from the command line. Since `hex` is not marked as
abstract, its inherited `refinery.units.Unit.run` method will be invoked when
the script is executed.

### Command Line Parameters

If you want your custom refinery unit to accept command line parameters, you can
write an initialization routine. For example, the following unit implements a very
simple XOR unit (albeit less versatile than the already existing `refinery.xor`):

    from refinery import Unit, arg
    import itertools

    class myxor (Unit):
        def __init__(self, key: arg(help='Encryption key')):
            pass

        def process(self, data: bytearray):
            key = itertools.cycle(self.args.key)
            for k, b in enumerate(data):
                data[k] ^= next(key)
            return data

The `refinery.arg` decorator is optional and only used here to provide a help
message on the command line. The example also shows that the `__init__` code can be
left empty: In this case, refinery automatically adds boilerplate code that copies
all `__init__` parameters to the `args` member variable of the unit. In this case,
the constructor will be completed to have the following code:

        def __init__(self, key: arg(help='Encryption key')):
            super().__init__(key=key)

The option of writing an empty `__init__` was added because it is rarely needed to
perform any processing of the input arguments. The command line help for this unit
will look as follows:

    usage: myxor [-h] [-Q] [-0] [-v] key

    positional arguments:
      key            Encryption key

    generic options:
      -h, --help     Show this help message and exit.
      -Q, --quiet    Disables all log output.
      -0, --devnull  Do not produce any output.
      -v, --verbose  Specify up to two times to increase log level.

### Refinery Syntax in Code

Refinery units can be used in Python code (and a Python repl) in nearly the same way
as on the command line. As one example, consider the following unit that can decode
base64 with a custom alphabet using `refinery.map` and `refinery.b64`:

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

The syntax does not work exactly as on the command line, but it has been designed to
be as similar as possible:

- The binary or operator `|` can be used to combine units into pipelines.
- Combining a pipeline from the left with a byte string or io stream object will
  invoke it, the result of the operation is the final output.
- Unary negation of a reversible unit is equivalent to using the `-R` switch for
  reverse mode.

If you want to use frames in code, simply omit any pipe before a square bracked. For
example, the first example from the `refinery.lib.frame` documentation translates to
the following Python code:

    In [1]: from refinery import *

    In [2]: B'OOOOOOOO' | chop(2) [ ccp(B'F') | cca(B'.') ]
    Out[2]: bytearray(b'FOO.FOO.FOO.FOO.')
"""
from __future__ import annotations

import abc
import copy
import sys
import os
import inspect

from abc import ABCMeta
from enum import IntEnum, Enum
from functools import wraps
from collections import OrderedDict
from typing import Iterable, BinaryIO, Type, TypeVar, Union, List, Optional, Callable, Tuple, Any, ByteString, no_type_check, get_type_hints
from argparse import (
    ArgumentTypeError, Namespace,
    ONE_OR_MORE,
    OPTIONAL,
    REMAINDER,
    SUPPRESS,
    ZERO_OR_MORE
)

from ..lib.argformats import pending, manifest, multibin, number, sliceobj, VariableMissing
from ..lib.argparser import ArgumentParserWithKeywordHooks, ArgparseError
from ..lib.tools import documentation, isstream, lookahead, autoinvoke, skipfirst, isbuffer
from ..lib.frame import Framed, Chunk
from ..lib.structures import MemoryFile


class RefineryPartialResult(ValueError):
    """
    This exception indicates that a partial result is available.
    """
    def __init__(self, message: str, partial: ByteString, rest: Optional[ByteString] = None):
        super().__init__(message)
        self.message = message
        self.partial = partial
        self.rest = rest

    def __str__(self):
        return self.message


class RefineryCriticalException(RuntimeError):
    """
    If this exception is thrown, processing of the entire input stream
    is aborted instead of just aborting the processing of the current
    chunk.
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


class arg(Argument):
    """
    This child class of `refinery.units.Argument` is specifically an argument for the
    `add_argument` method of an `ArgumentParser` from the `argparse` module. It can also
    be used as a decorator for the constructor of a refinery unit to better control
    the argument parser of that unit's command line interface. Example:
    ```
    class prefixer(Unit):
        @arg('prefix', help='this data will be prepended to the input.')
        def __init__(self, prefix): pass

        def process(self, data):
            return self.args.prefix + data
    ```
    Note that when the init of a unit has a return annotation that is a base class of
    itself, then all its parameters will automatically be forwarded to that base class.
    """

    class delete: pass
    class omit: pass

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
            guess    : bool                       = False # noqa
    ) -> None:
        kwargs = dict(action=action, choices=choices, const=const, default=default, dest=dest,
            help=help, metavar=metavar, nargs=nargs, required=required, type=type)
        kwargs = {key: value for key, value in kwargs.items() if value is not arg.omit}
        self.group = group
        self.guess = guess
        super().__init__(*args, **kwargs)

    def update_help(self):
        if 'help' not in self.kwargs:
            return

        class formatting(dict):
            arg = self

            def __missing__(self, key):
                if key == 'choices':
                    return ', '.join(self.arg.kwargs['choices'])
                if key == 'default':
                    default = self.arg.kwargs['default']
                    if not isbuffer(default):
                        return str(default)
                    if default.isalnum():
                        return default.decode('latin-1')
                    return F'H:{default.hex()}'
                if key == 'varname':
                    return self.arg.kwargs.get('metavar', self.arg.destination)

        try:
            self.kwargs.update(
                help=self.kwargs['help'].format_map(formatting()))
        except Exception:
            pass

    def __rmatmul__(self, method):
        self.update_help()
        return super().__rmatmul__(method)

    @staticmethod
    def as_option(value: Optional[Any], cls: Enum) -> Enum:
        if value is None or isinstance(value, cls):
            return value
        if isinstance(value, str):
            try: return cls[value]
            except KeyError: pass
            needle = value.upper()
            for item in cls:
                if item.name.upper() == needle:
                    return item
        try:
            return cls(value)
        except Exception as E:
            raise ValueError(F'Could not transform {value} into a {cls.__name__}.') from E

    @staticmethod
    def switch(
        *args: str, off=False,
        help : Union[omit, str] = omit,
        dest : Union[omit, str] = omit,
        group: Optional[str] = None,
    ) -> Argument:
        """
        A convenience method to add argparse arguments that change a boolean value from True to False or
        vice versa. By default, a switch will have a False default and change it to True when specified.
        """
        return arg(*args, group=group, help=help, dest=dest, action='store_false' if off else 'store_true')

    @staticmethod
    def binary(
        *args: str,
        help : Union[omit, str] = omit,
        dest : Union[omit, str] = omit,
        metavar : Optional[str] = None,
        group: Optional[str] = None,
    ) -> Argument:
        """
        Used to add argparse arguments that contain binary data.
        """
        return arg(*args, group=group, help=help, dest=dest, type=multibin, metavar=metavar or 'B')

    @staticmethod
    def number(
        *args: str,
        bound: Union[omit, Tuple[int, int]] = omit,
        help : Union[omit, str] = omit,
        dest : Union[omit, str] = omit,
        metavar : Optional[str] = None,
        group: Optional[str] = None,
    ) -> Argument:
        """
        Used to add argparse arguments that contain a number.
        """
        nt = number
        if bound is not arg.omit:
            lower, upper = bound
            nt = nt[lower:upper]
        return arg(*args, group=group, help=help, dest=dest, type=nt, metavar=metavar or 'N')

    @staticmethod
    def option(
        *args: str, choices: Enum,
        help : Union[omit, str] = omit,
        dest : Union[omit, str] = omit,
        metavar: Optional[str] = None,
        group: Optional[str] = None,
    ) -> Argument:
        """
        Used to add argparse arguments with a fixed set of options, based on an enumeration.
        """
        cnames = [c.name for c in choices]
        metavar = metavar or choices.__name__
        return arg(*args, group=group, help=help, metavar=metavar, dest=dest, choices=cnames, type=str)

    @staticmethod
    def choice(
        *args: str, choices : List[str],
        help    : Union[omit, str] = omit,
        metavar : Union[omit, str] = omit,
        dest    : Union[omit, str] = omit,
        nargs   : Union[omit, int, str] = omit,
        group   : Optional[str] = None,
    ):
        """
        Used to add argparse arguments with a fixed set of options, based on a list of strings.
        """
        return arg(*args, group=group, type=str, metavar=metavar, nargs=nargs,
            dest=dest, help=help, choices=choices)

    @property
    def positional(self) -> bool:
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
                    dest = a.lstrip('-').replace('-', '_')
                    if dest.isidentifier():
                        return dest
            raise AttributeError(F'The argument with these values has no destination: {self!r}')

    @classmethod
    def infer(cls, pt: inspect.Parameter) -> Argument:
        """
        This class method can be used to infer the argparse argument for a Python function
        parameter. This guess is based on the annotation, name, and default value.
        """

        def needs_type(item):
            return item.get('action', 'store') == 'store'

        def get_argp_type(annotation_type):
            if issubclass(annotation_type, (bytes, bytearray, memoryview)):
                return multibin
            if issubclass(annotation_type, int):
                return number
            if issubclass(annotation_type, slice):
                return sliceobj
            return annotation_type

        name = pt.name.replace('_', '-')
        default = pt.default
        guessed_pos_args = []
        guessed_kwd_args = dict(dest=pt.name, guess=True)
        annotation = pt.annotation

        if isinstance(annotation, str):
            try: annotation = eval(annotation)
            except Exception: pass

        if annotation is not pt.empty:
            if isinstance(annotation, Argument):
                if annotation.kwargs.get('dest', pt.name) != pt.name:
                    raise ValueError(
                        F'Incompatible argument destination specified; parameter {pt.name} '
                        F'was annotated with {annotation!r}.')
                guessed_pos_args = annotation.args
                guessed_kwd_args.update(annotation.kwargs)
                guessed_kwd_args['guess'] = False
                guessed_kwd_args['group'] = annotation.group
            elif isinstance(annotation, type):
                if not issubclass(annotation, bool) and needs_type(guessed_kwd_args):
                    guessed_kwd_args.update(type=get_argp_type(annotation))
                elif not isinstance(default, bool):
                    raise ValueError('Default value for boolean arguments must be provided.')

        if not guessed_pos_args:
            guessed_pos_args = guessed_pos_args or [F'--{name}' if pt.kind is pt.KEYWORD_ONLY else name]

        if pt.kind is pt.VAR_POSITIONAL:
            oldnargs = guessed_kwd_args.setdefault('nargs', ZERO_OR_MORE)
            if oldnargs not in (ONE_OR_MORE, ZERO_OR_MORE, REMAINDER):
                raise ValueError(F'Variadic positional arguments has nargs set to {oldnargs!r}')
            return cls(*guessed_pos_args, **guessed_kwd_args)

        if default is not pt.empty:
            if isinstance(default, Enum):
                default = default.name
            if isinstance(default, (list, tuple)):
                guessed_kwd_args.setdefault('nargs', ZERO_OR_MORE)
                if not pt.default:
                    default = pt.empty
                else:
                    guessed_kwd_args.setdefault('default', pt.default)
                    default = default[0]
            else:
                guessed_kwd_args.setdefault('default', default)
                if pt.kind is pt.POSITIONAL_ONLY:
                    guessed_kwd_args.setdefault('nargs', OPTIONAL)

        if default is not pt.empty:
            if isinstance(default, bool):
                guessed_kwd_args['action'] = 'store_false' if default else 'store_true'
            elif needs_type(guessed_kwd_args) and 'type' not in guessed_kwd_args:
                guessed_kwd_args['type'] = get_argp_type(type(default))

        return cls(*guessed_pos_args, **guessed_kwd_args)

    def merge_args(self, them: Argument) -> None:
        def iterboth():
            yield from them.args
            yield from self.args
        if not self.args:
            self.args = list(them.args)
            return
        sflag = None
        lflag = None
        for a in iterboth():
            if a[:2] == '--': lflag = lflag or a
            elif a[0] == '-': sflag = sflag or a
        self.args = []
        if sflag: self.args.append(sflag)
        if lflag: self.args.append(lflag)
        if not self.args:
            self.args = list(them.args)

    def merge_all(self, them: Argument) -> None:
        for key, value in them.kwargs.items():
            if value is arg.delete:
                self.kwargs.pop(key, None)
                continue
            self.kwargs[key] = value
        self.merge_args(them)
        self.guess = self.guess and them.guess
        self.group = self.group or them.group

    def __copy__(self) -> Argument:
        cls = self.__class__
        clone = cls.__new__(cls)
        clone.kwargs = dict(self.kwargs)
        clone.args = list(self.args)
        clone.group = self.group
        clone.guess = self.guess
        return clone

    def __repr__(self) -> str:
        return F'arg({super().__repr__()})'

    def __call__(self, init: Callable) -> Callable:
        parameters = inspect.signature(init).parameters
        try:
            inferred = arg.infer(parameters[self.destination])
            inferred.merge_all(self)
            init.__annotations__[self.destination] = inferred
        except KeyError:
            raise ValueError(F'Unable to decorate because no parameter with name {self.destination} exists.')
        return init


class ArgumentSpecification(OrderedDict):
    """
    A container object that stores `refinery.units.arg` specifications.
    """

    def merge(self, argument: arg):
        """
        Insert or update the specification with the given argument.
        """
        dest = argument.destination
        if dest in self:
            self[dest].merge_all(argument)
            return
        self[dest] = argument


DataType = TypeVar('DataType', bound=ByteString)
ProcType = Callable[['Unit', ByteString], Optional[Union[DataType, Iterable[DataType]]]]


def UnitProcessorBoilerplate(operation: ProcType[ByteString]) -> ProcType[Chunk]:
    @wraps(operation)
    def wrapped(self, data: ByteString) -> Optional[Union[Chunk, Iterable[Chunk]]]:
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
        if not inspect.isgenerator(result):
            return self.labelled(result)
        return (self.labelled(r) for r in result)
    return wrapped


def UnitFilterBoilerplate(
    operation : Callable[[Any, Iterable[Chunk]], Iterable[Chunk]]
) -> Callable[[Any, Iterable[Chunk]], Iterable[Chunk]]:
    @wraps(operation)
    def peekfilter(self, chunks: Iterable[Chunk]) -> Iterable[Chunk]:
        def rewind(*head):
            yield from head
            yield from it
        it = iter(chunks)
        for head in it:
            yield from operation(self, rewind(self.args @ head))
            break
    return peekfilter


def _singleton(cls): return cls()
@_singleton # noqa
class _NoReverseImplemented:
    def __call__(*_): raise NotImplementedError


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

    def _infer_argspec(cls, parameters, args: Optional[ArgumentSpecification] = None):

        args = ArgumentSpecification() if args is None else args
        temp = ArgumentSpecification()

        exposed = [pt.name for pt in skipfirst(parameters.values()) if pt.kind != pt.VAR_KEYWORD]
        # The arguments are added in reverse order to the argument parser later.
        # This is done to have a more intuitive use of decorator based argument configuration.
        exposed.reverse()

        for name in exposed:
            try:
                argument = arg.infer(parameters[name])
            except KeyError:
                continue
            if argument.guess:
                temp.merge(argument)
            else:
                args.merge(argument)

        for guess in temp.values():
            known = args.get(guess.destination, None)
            if known is None:
                args.merge(guess)
                continue
            if not known.positional:
                known.merge_args(guess)
            for k, v in guess.kwargs.items():
                if k == 'default':
                    known.kwargs[k] = v
                else:
                    known.kwargs.setdefault(k, v)

        for name in exposed:
            args.move_to_end(name)

        for known in args.values():
            if known.positional:
                known.kwargs.pop('dest', None)
                if 'default' in known.kwargs:
                    known.kwargs.setdefault('nargs', OPTIONAL)
            elif not any(a.startswith('--') for a in known.args):
                flagname = known.destination.replace('_', '-')
                known.args.append(F'--{flagname}')
            action = known.kwargs.get('action', 'store')
            if action.startswith('store_'):
                known.kwargs.pop('default', None)
                continue
            if action == 'store':
                known.kwargs.setdefault('type', multibin)
        return args

    def __new__(mcs, name, bases, nmspc, abstract=False):
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
            filter=UnitFilterBoilerplate,
            process=UnitProcessorBoilerplate,
            reverse=UnitProcessorBoilerplate,
            __init__=no_type_check,
        )
        if not abstract and Entry not in bases:
            bases = bases + (Entry,)
            if not bases[0].is_reversible:
                nmspc.setdefault('reverse', _NoReverseImplemented)
        nmspc.setdefault('__doc__', '')
        return super(Executable, mcs).__new__(mcs, name, bases, nmspc)

    def __init__(cls, name, bases, nmspc, abstract=False):
        super(Executable, cls).__init__(name, bases, nmspc)
        cls._argspec_ = ArgumentSpecification()

        cls_init = cls.__init__
        sig_init = inspect.signature(cls_init)
        parameters = sig_init.parameters

        for base in bases:
            for key, value in base._argspec_.items():
                if not value.guess and key in parameters:
                    cls._argspec_[key] = value.__copy__()
            cls._infer_argspec(parameters, cls._argspec_)

        if not abstract and any(p.kind == p.VAR_KEYWORD for p in parameters.values()):
            @wraps(cls.__init__)
            def init(self, *args, **kwargs): super(cls, self).__init__(*args, **kwargs)
            init.__signature__ = sig_init.replace(parameters=tuple(
                p for p in parameters.values() if p.kind != p.VAR_KEYWORD))
            cls.__init__ = init

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
            if Executable.Entry:
                cls._output(
                    F'not executing this unit because the following unit was '
                    F'already executed: {Executable.Entry}'
                )
            else:
                Executable.Entry = cls.name
                cls.run()

    def __getitem__(cls, other):
        return cls().__getitem__(other)

    def __or__(cls, other):
        return cls().__or__(other)

    def __neg__(cls):
        unit = cls()
        unit.args.reverse = True
        return unit

    def __ror__(cls, other):
        return cls().__ror__(other)

    @property
    def is_multiplex(cls) -> bool:
        """
        This proprety is `True` if and only if the unit's `process` or `reverse` method is a generator, i.e.
        when the unit can generate multiple outputs.
        """
        if inspect.isgeneratorfunction(inspect.unwrap(cls.process)):
            return True
        if not cls.is_reversible:
            return False
        return inspect.isgeneratorfunction(inspect.unwrap(cls.reverse))

    @property
    def is_reversible(cls) -> bool:
        """
        This property is `True` if and only if the unit has a member function named `reverse`. By convention,
        this member function implements the inverse of `refinery.units.Unit.process`.
        """
        if cls.reverse is _NoReverseImplemented:
            return False
        try:
            return not cls.reverse.__isabstractmethod__
        except AttributeError:
            return True

    @property
    def codec(cls) -> str:
        """
        The default codec for encoding textual information between units. The value of this property is
        hardcoded to `UTF8`.
        """
        return 'UTF8'

    @property
    def name(cls) -> str:
        return cls.__name__.replace('_', '-')


class LogLevel(IntEnum):
    """
    An enumeration representing the current log level:
    """
    DETACHED = -1
    """
    This unit is not attached to a terminal but has been instantiated in
    code. This means that the only way to communicate problems is to throw
    an exception.
    """
    NONE = 0
    """
    Do not log anything.
    """
    WARN = 1
    """
    Default log level: Log warnings.
    """
    INFO = 2
    """
    Increased logging.
    """
    DEBUG = 3
    """
    Maximum logging.
    """


class DelayedArgumentProxy:
    """
    This class implements a proxy for the `args` member variable of `refinery.units.Unit`.
    Its primary purpose is to proxy `refinery.lib.argformats.DelayedArgument` values which
    can be computed only as soon as input data becomes available and which also have to be
    recomputed for each input.
    """
    class PendingUpdate:
        pass

    def __copy__(self):
        cls = self.__class__
        clone = cls.__new__(cls)
        clone._store(
            _argv=self._argv,
            _argo=list(self._argo),
            _args=dict(self._args),
            _done=self._done,
            _guid=self._guid,
        )
        return clone

    def __iter__(self):
        yield from self._args

    def __getitem__(self, key):
        return self._args[key]

    def __init__(self, argv, argo):
        args = {}
        done = True
        for name, value in vars(argv).items():
            if not pending(value):
                args[name] = value
            else:
                done = False
        self._store(
            _argv=argv,
            _argo=list(argo),
            _args=args,
            _done=done,
            _guid=None,
        )

    def __matmul__(self, data: bytearray):
        """
        Lock the current arguments for the given input `data`.
        """
        if self._done: return data
        if not isinstance(data, bytearray):
            data = bytearray(data)
        identifier = id(data)
        if identifier == self._guid:
            return data
        for name in self._argo:
            value = getattr(self._argv, name, None)
            if value is self.PendingUpdate:
                raise RuntimeError(F'Attempting to resolve {name} while an update for this argument is in flight')
            if value and pending(value):
                self._args[name] = self.PendingUpdate
                self._args[name] = manifest(value, data)
        self._store(_guid=identifier)
        return data

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
    def process(self, data: ByteString) -> Union[Optional[ByteString], Iterable[ByteString]]:
        """
        This routine is overridden by children of `refinery.units.Unit` to define how
        the unit processes a given chunk of binary data.
        """

    @abc.abstractmethod
    def reverse(self, data: ByteString) -> Union[Optional[ByteString], Iterable[ByteString]]:
        """
        If this routine is overridden by children of `refinery.units.Unit`, then it must
        implement an operation that reverses the `refinery.units.Unit.process` operation.
        The absence of an overload for this function is ignored for non-abstract children of
        `refinery.units.UnitBase`.
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


class Unit(UnitBase, abstract=True):
    """
    The base class for all refinery units. It implements a small set of globally
    available options and the handling for multiple inputs and outputs. All units
    implement the _framing_ syntax for producing multiple outputs and ingesting
    multiple inputs in a common format. For more details, see `refinery.lib.frame`.
    """
    @property
    def is_reversible(self) -> bool:
        return self.__class__.is_reversible

    @property
    def codec(self) -> str:
        return self.__class__.codec

    @property
    def name(self) -> str:
        return self.__class__.name

    @property
    def log_level(self) -> LogLevel:
        """
        Returns the current log level as an element of `refinery.units.LogLevel`.
        """
        try:
            return LogLevel.NONE if self.args.quiet else LogLevel(min(len(LogLevel) - 2, self.args.verbose))
        except AttributeError:
            return LogLevel.DETACHED

    @log_level.setter
    def log_level(self, value: LogLevel) -> None:
        self.args.verbose = int(value)

    def log_detach(self) -> None:
        self.log_level = LogLevel.DETACHED
        self.args.quiet = False

    def __iter__(self):
        return self

    def _exception_handler(self, exception: BaseException):
        if self.log_level <= LogLevel.DETACHED:
            if isinstance(exception, RefineryPartialResult) and self.args.lenient:
                return None
            raise exception
        elif isinstance(exception, RefineryCriticalException):
            self.log_warn(F'critical error, terminating: {exception}')
            raise exception
        elif isinstance(exception, VariableMissing):
            self.log_warn('critical error:', exception)
            raise RefineryCriticalException
        elif isinstance(exception, GeneratorExit):
            raise exception
        elif isinstance(exception, RefineryPartialResult):
            self.log_warn(F'error, partial result returned: {exception}')
            if not self.args.lenient:
                return None
            return exception.partial
        else:
            self.log_warn(F'unexpected exception of type {exception.__class__.__name__}; {exception!s}')

        if self.log_debug():
            import traceback
            traceback.print_exc(file=sys.stderr)

    def __next__(self):
        if not self._chunks:
            self._chunks = iter(self._framehandler)
        while True:
            try:
                return next(self._chunks)
            except RefineryCriticalException as R:
                raise StopIteration from R

    @property
    def _framehandler(self) -> Framed:
        if self._framed:
            return self._framed

        def normalized_action(data: ByteString) -> Iterable[Chunk]:
            try:
                result = self.act(data)
                if inspect.isgenerator(result):
                    yield from (x for x in result if x is not None)
                elif result is not None:
                    yield result
            except BaseException as B:
                result = self._exception_handler(B)
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
        )
        return self._framed

    def finish(self) -> Iterable[Chunk]:
        yield from ()

    def filter(self, inputs: Iterable[Chunk]) -> Iterable[Chunk]:
        return inputs

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

    def __neg__(self):
        pipeline = []
        cursor = self
        while isinstance(cursor, UnitBase):
            reversed = copy.copy(cursor)
            reversed.args.reverse = True
            reversed._source = None
            reversed.reset()
            pipeline.append(reversed)
            cursor = cursor._source
        reversed = None
        while pipeline:
            reversed = reversed | pipeline.pop()
        return reversed

    def __ror__(self, stream: Union[BinaryIO, ByteString]):
        if stream is None:
            return self
        if not isstream(stream):
            stream = MemoryFile(stream) if stream else open(os.devnull, 'rb')
        self.reset()
        self.nozzle.source = stream
        return self

    def __str__(self):
        with MemoryFile() as stdout:
            return (self | stdout).getbuffer().decode(self.codec)

    def __bytes__(self):
        with MemoryFile() as stdout:
            result = bytes((self | stdout).getbuffer())
        return result

    def __or__(self, stream: Union[BinaryIO, Unit]):
        if isinstance(stream, type) and issubclass(stream, Entry):
            stream = stream()
        if isinstance(stream, Entry):
            return stream.__copy__().__ror__(self)
        elif isinstance(stream, list):
            stream.extend(self)
            return stream
        elif isinstance(stream, set):
            stream.update(self)
            return stream
        elif isinstance(stream, dict):
            if len(stream) == 1:
                key, check = next(iter(stream.items()))
                if check is ...:
                    return {item[key]: item for item in self}
            raise ValueError('dict consumption target must be of format {"key": ...}')
        elif isinstance(stream, (bytearray, memoryview)):
            with MemoryFile(stream) as stdout:
                return (self | stdout).getvalue()
        elif callable(stream):
            with MemoryFile() as stdout:
                return stream((self | stdout).getvalue())

        if not stream.writable():
            raise ValueError('target stream is not writable')

        self._target = stream

        def cname(x): return x.lower().replace('-', '')

        recode = self.isatty and cname(self.codec) != cname(sys.stdout.encoding)
        chunk = None

        for last, chunk in lookahead(self):
            if (
                not last
                and (self._framehandler.unframed or self._framehandler.framebreak)
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
                    self.log_info(F'cannot send to next unit: {E}')
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
            out = self._buffer or next(self)
            if bytecount and bytecount > 0:
                out, self._buffer = out[:bytecount], out[bytecount:]
            elif self._buffer:
                self._buffer = B''
            return out
        except StopIteration:
            return B''

    def act(self, data: Union[Chunk, ByteString]) -> Optional[Chunk]:
        op = self.reverse if self.args.reverse else self.process
        return op(self.args @ data)

    def __call__(self, data: Optional[Union[ByteString, Chunk]] = None) -> bytes:
        with MemoryFile(data) if data else open(os.devnull, 'rb') as stdin:
            with MemoryFile() as stdout:
                return (stdin | self | stdout).getvalue()

    @classmethod
    def labelled(cls, data: Union[Chunk, ByteString], **meta) -> Chunk:
        """
        This class method can be used to label a chunk of binary output with metadata. This
        metadata will be visible inside pipeline frames, see `refinery.lib.frame`.
        """
        if isinstance(data, Chunk):
            data.meta.update(meta)
            return data
        return Chunk(data, meta=meta)

    def process(self, data: ByteString) -> Union[Optional[ByteString], Iterable[ByteString]]:
        return data

    def log_warn(self, *messages, clip=False) -> bool:
        """
        Call `refinery.units.Unit.output` for each provided message if and only if the
        current log level is at least `refinery.units.LogLevel.WARN`.
        """
        rv = self.log_level >= LogLevel.WARN
        if rv and messages:
            self.output(*messages, clip=clip)
        return rv

    def log_info(self, *messages, clip=False) -> bool:
        """
        Call `refinery.units.Unit.output` for each provided message if and only if the
        current log level is at least `refinery.units.LogLevel.INFO`.
        """
        rv = self.log_level >= LogLevel.INFO
        if rv and messages:
            self.output(*messages, clip=clip)
        return rv

    def log_debug(self, *messages, clip=False) -> bool:
        """
        Call `refinery.units.Unit.output` for each provided message if and only if the
        current log level is at least `refinery.units.LogLevel.DEBUG`.
        """
        rv = self.log_level >= LogLevel.DEBUG
        if rv and messages:
            self.output(*messages, clip=clip)
        return rv

    def output(self, *messages, clip=False) -> None:
        """
        Logs the provided messages to stderr, prefixed with the current unit's name.
        The routine accepts both string and byte type arguments. Bytestrings are
        decoded with the default codec, using the 'backslashreplace' error handler.
        Does not produce any output if the quiet switch has been enabled via the
        command line arguments.
        """
        if not self.args.quiet:
            return self._output(*messages, clip=clip)

    @property
    def isatty(self) -> bool:
        try:
            return self._target.isatty()
        except AttributeError:
            return False

    @classmethod
    def _output(cls, *messages, clip=False) -> None:
        def transform(message):
            if callable(message):
                message = message()
            if isinstance(message, str):
                return message
            if isbuffer(message):
                import codecs
                pmsg: str = codecs.decode(message, cls.codec, errors='backslashreplace')
                if not pmsg.isprintable():
                    pmsg = message.hex()
                return pmsg
            else:
                import pprint
                return pprint.pformat(message)
        message = ' '.join(transform(msg) for msg in messages)
        if clip:
            from textwrap import shorten
            from ..lib.tools import get_terminal_size
            message = shorten(
                message,
                get_terminal_size() - len(cls.name) - 2,
            )
        print(F'{cls.name}: {message}', file=sys.stderr)

    @classmethod
    def _interface(cls, argp: ArgumentParserWithKeywordHooks) -> ArgumentParserWithKeywordHooks:
        """
        Receives a reference to an argument parser. This parser will be used to parse
        the command line for this unit into the member variable called `args`.
        """
        base = argp.add_argument_group('generic options')

        base.set_defaults(reverse=False, squeeze=False)
        base.add_argument('-h', '--help', action='help', help='Show this help message and exit.')
        base.add_argument('-L', '--lenient', action='store_true', help='Allow partial results as output.')
        base.add_argument('-Q', '--quiet', action='store_true', help='Disables all log output.')
        base.add_argument('-0', '--devnull', action='store_true', help='Do not produce any output.')
        base.add_argument('-v', '--verbose', action='count', default=LogLevel.WARN,
            help='Specify up to two times to increase log level.')
        argp.add_argument('--debug-timing', dest='dtiming', action='store_true', help=SUPPRESS)

        if cls.is_reversible:
            base.add_argument('-R', '--reverse', action='store_true', help='Use the reverse operation.')

        groups = {None: argp}

        for argument in reversed(cls._argspec_.values()):
            gp = argument.group
            if gp not in groups:
                groups[gp] = argp.add_mutually_exclusive_group()
            groups[gp].add_argument @ argument

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
        args = argp.parse_args(args)

        try:
            unit = autoinvoke(cls, args.__dict__)
        except ValueError as E:
            argp.error(str(E))
        else:
            unit.args._store(_argo=argp.order)
            unit.args.quiet = args.quiet
            unit.args.lenient = args.lenient

            unit.args.squeeze = args.squeeze
            unit.args.dtiming = args.dtiming
            unit.args.nesting = args.nesting
            unit.args.reverse = args.reverse
            unit.args.devnull = args.devnull
            unit.args.verbose = args.verbose
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

        keywords.update(dict(
            dtiming=False,
            nesting=0,
            reverse=False,
            squeeze=False,
            devnull=False,
            verbose=LogLevel.DETACHED,
            quiet=False,
        ))
        # Since Python 3.6, functions always preserve the order of the keyword
        # arguments passed to them (see PEP 468).
        self.args = DelayedArgumentProxy(Namespace(**keywords), list(keywords))

    def detach(self):
        """
        When a unit is created using the `refinery.units.Unit.assemble` method, it is attached to a
        logger by default (in less abstract terms, the `refinery.units.Unit.log_level` property is
        set to a positive value). This method detaches the unit from its logger, which also means that
        any exceptions that occur during runtime will be raised to the caller.
        """
        self.log_level = LogLevel.DETACHED
        return self

    @classmethod
    def run(cls, argv=None, stream=None) -> None:
        """
        Implements command line execution. As `refinery.units.Unit` is an `refinery.units.Executable`,
        this method will be executed when a class inheriting from `refinery.units.Unit` is defined in
        the current `__main__` module.
        """
        argv = argv if argv is not None else sys.argv[1:]

        if stream is None:
            stream = open(os.devnull, 'rb') if sys.stdin.isatty() else sys.stdin.buffer

        with stream as source:
            try:
                unit = cls.assemble(*argv)
            except ArgparseError as ap:
                ap.parser.error_commandline(str(ap))
                return
            except Exception as msg:
                import traceback
                cls._output('initialization failed:', msg)
                for line in traceback.format_exc().splitlines(keepends=False):
                    cls._output(line)
                return

            try:
                loglevel = os.environ['REFINERY_VERBOSITY']
            except KeyError:
                pass
            else:
                try:
                    loglevel = LogLevel[loglevel]
                except KeyError:
                    loglevels = ', '.join(ll.name for ll in LogLevel)
                    unit.log_warn(F'unknown verbosity {loglevel!r}, pick from {loglevels}')
                else:
                    unit.log_level = loglevel

            if unit.args.dtiming:
                from time import process_time
                start_clock = process_time()
                unit.output('starting clock: {:.4f}'.format(start_clock))

            try:
                with open(os.devnull, 'wb') if unit.args.devnull else sys.stdout.buffer as output:
                    source | unit | output
            except ArgumentTypeError as E:
                unit.output('delayed argument initialization failed:', str(E))
            except KeyboardInterrupt:
                unit.output('aborting due to keyboard interrupt')
            except OSError:
                pass

            if unit.args.dtiming:
                stop_clock = process_time()
                unit.output('stopping clock: {:.4f}'.format(stop_clock))
                unit.output('time delta was: {:.4f}'.format(stop_clock - start_clock))


__pdoc__ = {
    'Unit.is_reversible': Executable.is_reversible.__doc__,
    'Unit.codec': Executable.codec.__doc__
}
