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
        def process(self, data):
            return bytes.fromhex(data.decode('ascii'))

        def reverse(self, data):
            return data.hex().encode(self.codec)

The above script can be run from the command line. Since `hex` is not marked as
abstract, its inherited `refinery.units.Unit.run` method will be invoked when
the script is executed.
"""
import sys
import os
import io
import inspect

from enum import IntEnum, Enum
from functools import wraps
from collections import OrderedDict
from typing import Iterable, BinaryIO, Union, List, Optional, Callable, Tuple, Any, ByteString
from argparse import (
    ArgumentParser,
    ArgumentError,
    Namespace,
    RawDescriptionHelpFormatter,
    ONE_OR_MORE,
    OPTIONAL,
    REMAINDER,
    SUPPRESS,
    ZERO_OR_MORE
)

from ..lib.argformats import pending, manifest, multibin, number, sliceobj
from ..lib.tools import terminalfit, get_terminal_size, documentation, lookahead, autoinvoke, skipfirst, isbuffer
from ..lib.frame import Framed, Chunk


def _retrofitted(cls: Union[type, Any]) -> bool:
    if not isinstance(cls, type):
        cls = cls.__class__
    bases = cls.__mro__[1:]
    if len(bases) == 1:
        return False
    for base in bases:
        try:
            if cls.interface.__func__ is not base.interface.__func__:
                return False
        except AttributeError:
            pass
    return True


class ArgparseError(ValueError):
    """
    This custom exception type is thrown from the custom argument parser of
    `refinery.units.Unit` rather than terminating program execution immediately.
    The `parser` parameter is a reference to the argument parser that threw
    the original argument parsing exception with the given `message`.
    """
    def __init__(self, parser, message):
        self.parser = parser
        super().__init__(message)


class RefineryPartialResult(ValueError):
    """
    This exception indicates that a partial result is available.
    """
    def __init__(self, msg, partial):
        super().__init__(msg)
        self.partial = partial


class RefineryCriticalException(RuntimeError):
    """
    If this exception is thrown, processing of the entire input stream
    is aborted instead of just aborting the processing of the current
    chunk.
    """
    pass


class Entry:
    """
    An empty class maker. Any entry point unit (i.e. any unit that can be executed
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
        def __init__(self, prefix) -> Unit: pass

        def process(self, data):
            return self.args.prefix + data
    ```
    Note that when the init of a unit has a return annotation that is a base class of
    itself, then all its parameters will automatically be forwarded to that base class.
    """

    class delete: pass

    def __init__(
        self, *args: str,
            group    : Optional[str]              = None, # noqa
            action   : Optional[str]              = None, # noqa
            choices  : Optional[Iterable[Any]]    = None, # noqa
            const    : Optional[Any]              = None, # noqa
            default  : Optional[Any]              = None, # noqa
            dest     : Optional[str]              = None, # noqa
            help     : Optional[str]              = None, # noqa
            metavar  : Optional[str]              = None, # noqa
            nargs    : Optional[Union[int, str]]  = None, # noqa
            required : Optional[bool]             = None, # noqa
            type     : Optional[type]             = None, # noqa
            guess    : bool                       = False # noqa
    ) -> None:
        kwargs = dict(action=action, choices=choices, const=const, default=default, dest=dest,
            help=help, metavar=metavar, nargs=nargs, required=required, type=type)
        kwargs = {key: value for key, value in kwargs.items() if value is not None}
        self.group = group
        self.guess = guess
        super().__init__(*args, **kwargs)

    @staticmethod
    def switch(*args: str, group: Optional[str] = None, help: Optional[str] = None, dest: Optional[str] = None, off=False) -> Argument:
        """
        A convenience method to add argparse arguments that change a boolean value from True to False or
        vice versa. By default, a switch will have a False default and change it to True when specified.
        """
        return arg(*args, group=group, help=help, dest=dest, action='store_false' if off else 'store_true')

    @staticmethod
    def number(
        *args: str,
        group : Optional[str] = None,
        bound : Optional[Tuple[int, int]] = None,
        help  : Optional[str] = None,
        dest  : Optional[str] = None,
    ) -> Argument:
        """
        Used to add argparse arguments that contain a number.
        """
        nt = number
        if bound is not None:
            lower, upper = bound
            nt = nt[lower:upper]
        return arg(*args, group=group, help=help, dest=dest, type=nt, metavar='N')

    @staticmethod
    def option(*args: str, choices: Enum, group: Optional[str] = None, help: Optional[str] = None, dest: Optional[str] = None) -> Argument:
        """
        Used to add argparse arguments with a fixed set of options, based on an enumeration.
        """
        cnames = [c.name for c in choices]
        return arg(*args, group=group, help=help.format(choices=', '.join(cnames)),
            metavar=choices.__name__, dest=dest, choices=cnames, type=choices.__getitem__)

    @staticmethod
    def help(msg: str) -> Argument:
        return arg(help=msg)

    @staticmethod
    def choice(
        *args: str, choices : List[str],
        group   : Optional[str] = None,
        help    : Optional[str] = None,
        metavar : Optional[str] = None,
        dest    : Optional[str] = None,
        nargs   : Optional[Union[int, str]] = None,
    ):
        """
        Used to add argparse arguments with a fixed set of options, based on a list of strings.
        """
        return arg(*args, group=group, type=str, metavar=metavar, nargs=nargs,
            dest=dest, help=help.format(choices=', '.join(choices)), choices=choices)

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

        def get_argp_type(annotation_type):
            if issubclass(annotation_type, (bytes, bytearray)):
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

        if pt.annotation is not pt.empty:
            if isinstance(pt.annotation, Argument):
                if pt.annotation.kwargs.get('dest', pt.name) != pt.name:
                    raise ValueError(
                        F'Incompatible argument destination specified; parameter {pt.name} '
                        F'was annotated with {pt.annotation!r}.')
                guessed_pos_args = pt.annotation.args
                guessed_kwd_args.update(pt.annotation.kwargs)
                guessed_kwd_args['guess'] = False
                guessed_kwd_args['group'] = pt.annotation.group
            elif isinstance(pt.annotation, type):
                if not issubclass(pt.annotation, bool):
                    guessed_kwd_args.update(type=get_argp_type(pt.annotation))
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
            if isinstance(default, (list, tuple)):
                if not pt.default:
                    guessed_kwd_args.setdefault('nargs', ZERO_OR_MORE)
                    default = pt.empty
                else:
                    guessed_kwd_args.setdefault('nargs', ONE_OR_MORE)
                    guessed_kwd_args.setdefault('default', pt.default)
                    default = default[0]
            else:
                guessed_kwd_args.setdefault('default', default)
                if pt.kind is pt.POSITIONAL_ONLY:
                    guessed_kwd_args.setdefault('nargs', OPTIONAL)

        if default is not pt.empty:
            if isinstance(default, bool):
                guessed_kwd_args['action'] = 'store_false' if default else 'store_true'
            elif 'type' not in guessed_kwd_args:
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

    def __or__(self, them: Argument) -> Argument:
        clone = self.__copy__()
        clone.kwargs.update(self.kwargs)
        clone.merge_args(them)
        return clone

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


class Executable(type):
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

        exposed = [pt.name for pt in skipfirst(parameters.values())]
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
            for k in guess.kwargs:
                known.kwargs.setdefault(k, guess.kwargs[k])

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
            if known.kwargs.get('action', '').startswith('store_'):
                known.kwargs.pop('default', None)
                continue
            known.kwargs.setdefault('type', multibin)
        return args

    def __new__(mcs, name, bases, nmspc, abstract=False):
        def normalize(operation: Callable[[Any, ByteString], Any]) -> Callable[[ByteString], Any]:
            @wraps(operation)
            def wrapped(self, data: ByteString) -> bytes:
                if -self.args:
                    if not isinstance(data, bytearray):
                        data = bytearray(data)
                    self.args @= data
                return operation(self, data)
            return wrapped

        nmspc.setdefault('__doc__', '')

        for op in ('process', 'reverse'):
            if op in nmspc:
                nmspc[op] = normalize(nmspc[op])

        if not abstract and Entry not in bases:
            bases = bases + (Entry,)

        return super(Executable, mcs).__new__(mcs, name, bases, nmspc)

    def __init__(cls, name, bases, nmspc, abstract=False):
        super(Executable, cls).__init__(name, bases, nmspc)
        parameters = inspect.signature(cls.__init__).parameters
        cls.argspec = ArgumentSpecification()

        if _retrofitted(cls):
            if not bases:
                raise TypeError(
                    F'Unexpected empty MRO for {cls.__name__}: You should not use the Executable '
                    F'metaclass directly, instead you should inherit from Unit.'
                )
            parent = bases[0]
            if not _retrofitted(parent) and cls.__init__ is parent.__init__:
                @wraps(cls.__init__)
                def __init__stub_(self): parent.__init__(self)
                cls.__init__ = __init__stub_
                parameters = dict(self=None)
            for key, value in parent.argspec.items():
                if not value.guess and key in parameters:
                    cls.argspec[key] = value.__copy__()
            cls._infer_argspec(parameters, cls.argspec)

        fwd = cls.__init__.__annotations__.get('return', None)

        if fwd is not None and not issubclass(cls, fwd):
            fwd = None
        elif cls.__init__.__code__.co_code == (lambda: None).__code__.co_code:
            fwd = bases[0]

        if fwd is not None:
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
                fwd.__init__(self, **kw)

            cls.__init__ = cls__init__

        if not abstract and sys.modules[cls.__module__].__name__ == '__main__':
            if Executable.Entry:
                cls._output(
                    F'not executing this unit because the following unit was '
                    F'already executed: {Executable.Entry}'
                )
            else:
                Executable.Entry = cls.__name__
                cls.run()

    def __getitem__(cls, other):
        return cls().__getitem__(other)

    def __or__(cls, other):
        return cls().__or__(other)

    def __ror__(cls, other):
        return cls().__ror__(other)

    @property
    def is_reversible(cls) -> bool:
        """
        This property is `True` if and only if the unit has a member function
        named `reverse`. By convention, this member function implements the
        inverse of `refinery.units.Unit.process`.
        """
        return hasattr(cls, 'reverse')

    @property
    def codec(self) -> str:
        """
        The default codec for encoding textual information between units.
        The value of this property is hardcoded to `UTF8`.
        """
        return 'UTF8'


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

    def __neg__(self):
        return not self._done

    def __imatmul__(self, data: bytearray):
        """
        Lock the current arguments for the given input `data`.
        """
        identifier = id(data)
        if not self._done and identifier != self._guid:
            self._store(_guid=identifier)
            for name in self._argo:
                value = getattr(self._argv, name, None)
                if value and pending(value):
                    self._args[name] = manifest(value, data)
        return self

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


class Unit(metaclass=Executable, abstract=True):
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
            raise exception
        elif isinstance(exception, RefineryCriticalException):
            self.log_warn(F'critical error, terminating: {exception}')
        elif isinstance(exception, GeneratorExit):
            raise
        elif isinstance(exception, RefineryPartialResult):
            if not self.log_level:
                return None
            elif not self.log_warn(F'error, partial result returned: {exception}'):
                raise exception
            return exception.partial

        self.log_warn(F'unexpected exception of type {exception.__class__.__name__}; {exception!s}')

        if self.log_debug():
            import traceback
            traceback.print_exc(file=sys.stderr)

    def __next__(self):
        if not self._chunks:
            self._chunks = iter(self._framehandler)
        while True:
            try:
                result = next(self._chunks)
            except Exception as E:
                if isinstance(E, StopIteration):
                    raise
                result = self._exception_handler(E)
                if result is None:
                    raise StopIteration from E
            if not isinstance(result, BaseException):
                return result

    @property
    def _framehandler(self) -> Framed:
        if self._framed:
            return self._framed

        op = self.reverse if self.args.reverse else self.process

        def normalized_action(data: bytearray) -> Iterable[bytes]:
            try:
                result = op(data)
                if inspect.isgenerator(result):
                    yield from filter(lambda x: x is not None, result)
                elif result is not None:
                    yield result
            except BaseException as B:
                result = self._exception_handler(B)
                if result is not None:
                    yield result

        self._framed = Framed(
            normalized_action,
            self.source,
            self.args.nesting,
            self.filter
        )
        return self._framed

    def filter(self, inputs: Iterable[Chunk]) -> Iterable[Chunk]:
        """
        Receives an iterable of `refinery.lib.frame.Chunk`s and yields only those that
        should be processed. The default implementation returns the iterator without
        change; this member function is designed to be overloaded by child classes of
        `refinery.units.Unit` to allow inspection of an entire frame layer and altering
        it before `refinery.units.Unit.process` is called on the individual chunks.
        """
        return inputs

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
            self._framed = None
            self._chunks = None
        self._source = stream

    @property
    def nozzle(self) -> 'Unit':
        """
        The nozzle is defined recursively as the nozzle of `refinery.units.Unit.source`
        and `self` if no such thing exists. In other words, it is the leftmost unit in
        a pipeline, where data should be inserted for processing.
        """
        try:
            return self.source.nozzle
        except AttributeError:
            return self

    def __getitem__(self, unit: 'Unit'):
        if isinstance(unit, type):
            unit = unit()
        alpha = self.__copy__()
        omega = unit.__copy__()
        alpha.args.nesting += 1
        omega.args.nesting -= 1
        omega.nozzle.source = alpha
        return omega

    def __ror__(self, stream: Union[BinaryIO, ByteString]):
        if not isbuffer(stream):
            self.nozzle.source = stream
            return self
        return self(stream)

    def __or__(self, stream: Union[BinaryIO, 'Unit']):
        try:
            if isinstance(stream, type):
                stream = stream()
            return stream.__copy__().__ror__(self)
        except AttributeError:
            self._target = stream

        if not self._target.writable():
            return

        def cname(x): return x.lower().replace('-', '')

        if self.isatty and cname(self.codec) != cname(sys.stdout.encoding):
            def recode(chunk):
                import codecs
                return codecs.encode(
                    codecs.decode(chunk, self.codec, errors='backslashreplace'),
                    sys.stdout.encoding
                )
        else:
            def recode(chunk): return chunk

        for last, chunk in lookahead(self):
            if (
                self._framehandler.framebreak
                or self._framehandler.unframed
                and not last
                and not chunk.endswith(B'\n')
            ):
                chunk += B'\n'
            try:
                self._target.write(recode(chunk))
                self._target.flush()
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
            if self.isatty and not chunk.endswith(B'\n'):
                self._target.write(B'\n')
                self._target.flush()
        except (NameError, AttributeError):
            pass

        return self._target

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

    def __call__(self, data: Optional[ByteString] = None) -> bytes:
        with io.BytesIO(data) if data else open(os.devnull, 'rb') as stdin:
            with io.BytesIO() as stdout:
                return (stdin | self | stdout).getvalue()

    def process(self, data: bytes) -> Union[Optional[bytes], Iterable[bytes]]:
        """
        This routine is overridden by children of `refinery.units.Unit` to define how
        the unit processes a given chunk of binary data.
        """
        return data

    def log_warn(self, *messages) -> bool:
        """
        Call `refinery.units.Unit.output` for each provided message if and only if the
        current log level is at least `refinery.units.LogLevel.WARN`.
        """
        rv = self.log_level >= LogLevel.WARN
        if rv and messages:
            self.output(*messages)
        return rv

    def log_info(self, *messages) -> bool:
        """
        Call `refinery.units.Unit.output` for each provided message if and only if the
        current log level is at least `refinery.units.LogLevel.INFO`.
        """
        rv = self.log_level >= LogLevel.INFO
        if rv and messages:
            self.output(*messages)
        return rv

    def log_debug(self, *messages) -> bool:
        """
        Call `refinery.units.Unit.output` for each provided message if and only if the
        current log level is at least `refinery.units.LogLevel.DEBUG`.
        """
        rv = self.log_level >= LogLevel.DEBUG
        if rv and messages:
            self.output(*messages)
        return rv

    def output(self, *messages) -> None:
        """
        Logs the provided messages to stderr, prefixed with the current unit's name.
        The routine accepts both string and byte type arguments. Bytestrings are
        decoded with the default codec, using the 'backslashreplace' error handler.
        Does not produce any output if the quiet switch has been enabled via the
        command line arguments.
        """
        if not self.args.quiet:
            return self._output(*messages)

    @property
    def isatty(self) -> bool:
        try:
            return self._target.isatty()
        except AttributeError:
            return False

    @classmethod
    def _output(cls, *messages) -> None:
        def transform(x):
            try: x = x()
            except TypeError: pass
            if isinstance(x, str):
                return x
            if isinstance(x, (bytes, bytearray)):
                import codecs
                return codecs.decode(x, cls.codec, errors='backslashreplace')
            return str(x)
        message = ' '.join(transform(msg) for msg in messages)
        sys.stderr.write(F'{cls.__name__}: {message}\n')

    @classmethod
    def interface(cls, argp: ArgumentParser) -> ArgumentParser:
        """
        Receives a reference to an `ArgumentParser` object. This parser will be used to parse
        the command line for this unit into the member variable called `args`. Previously, it
        was requested that children of `refinery.units.Unit` override this method to customize
        their command line interface. This is now deprecated in favor of using initialization
        methods and `refinery.units.arg` decorators to customize the parser. The current goal
        is to remove `refinery.units.Unit.interface` in a future version when retrofitting the
        old units to the new `refinery.units.arg` based interface is complete.
        """
        base = argp.add_argument_group('generic options')

        base.add_argument('-h', '--help', action='help', help='Show this help message and exit.')
        base.set_defaults(reverse=False)

        if cls.is_reversible:
            base.add_argument('-R', '--reverse', action='store_true', help='Use the reverse operation.')

        base.add_argument('-Q', '--quiet', action='store_true', help='Disables all log output.')
        base.add_argument('-0', '--devnull', action='store_true', help='Do not produce any output.')
        base.add_argument('-v', '--verbose', action='count', default=LogLevel.WARN,
            help='Specify up to two times to increase log level.')
        argp.add_argument('--debug-timing', dest='dtiming', action='store_true', help=SUPPRESS)

        groups = {None: argp}

        for argument in reversed(cls.argspec.values()):
            gp = argument.group
            if gp not in groups:
                groups[gp] = argp.add_mutually_exclusive_group()
            groups[gp].add_argument @ argument

        return argp

    @classmethod
    def argparser(cls, *args, **keywords):
        cols = get_terminal_size()
        args = list(args)

        class ArgumentParserWithKeywordHooks(ArgumentParser):
            def _add_action(self, action):

                class RememberOrder:
                    def __getattr__(self, name): return getattr(action, name)
                    def __setattr__(self, name, value): return setattr(action, name, value)

                    def __call__(self, parser, ns, values, opt=None):
                        if self.dest not in parser.order:
                            parser.order.append(self.dest)
                        return action(parser, ns, values, opt)

                action.required = action.required and action.dest not in keywords
                return super()._add_action(RememberOrder())

            def _parse_optional(self, arg_string):
                if isinstance(arg_string, str):
                    return super()._parse_optional(arg_string)

            def error_commandline(self, message):
                super().error(message)

            def error(self, message):
                parser_instance = self
                raise ArgparseError(parser_instance, message)

            def parse_args(self):
                self.order = []
                args_for_parser = args
                if args and args[~0] and isinstance(args[~0], str):
                    nestarg = args[~0]
                    nesting = len(nestarg)
                    if nestarg == ']' * nesting:
                        self.set_defaults(nesting=-nesting)
                        args_for_parser = args[:~0]
                    elif nestarg == '[' * nesting:
                        self.set_defaults(nesting=nesting)
                        args_for_parser = args[:~0]
                self.set_defaults(**keywords)
                try:
                    parsed = super().parse_args(args=args_for_parser)
                except ArgumentError as e:
                    self.error(str(e))
                for name in keywords:
                    param = getattr(parsed, name, None)
                    if param != keywords[name]:
                        self.error(
                            F'parameter "{name}" duplicated with conflicting '
                            F'values {param} and {keywords[name]}'
                        )
                for name in vars(parsed):
                    if name not in self.order:
                        self.order.append(name)
                return parsed

        class LineWrapRawTextHelpFormatter(RawDescriptionHelpFormatter):
            def __init__(self, prog, indent_increment=2, max_help_position=30, width=None):
                super().__init__(prog, indent_increment, max_help_position, width=cols)

            def add_text(self, text):
                if isinstance(text, str):
                    text = terminalfit(text, width=cols)
                return super().add_text(text)

            def _format_action_invocation(self, action):
                if not action.option_strings:
                    metavar, = self._metavar_formatter(action, action.dest)(1)
                    return metavar
                else:
                    parts = []
                    if action.nargs == 0:
                        parts.extend(action.option_strings)
                    else:
                        default = action.dest.upper()
                        args_string = self._format_args(action, default)
                        for option_string in action.option_strings:
                            parts.append(str(option_string))
                        parts[-1] += F' {args_string}'
                    return ', '.join(parts)

        argp = ArgumentParserWithKeywordHooks(
            prog=cls.__name__.replace('_', '-'),
            description=documentation(cls),
            formatter_class=LineWrapRawTextHelpFormatter,
            add_help=False
        )

        argp.set_defaults(nesting=0)
        return cls.interface(argp)

    @staticmethod
    def superinit(super, **keywords):
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
        return autoinvoke(super.__init__, keywords)

    @classmethod
    def assemble(cls, *args, **keywords):
        """
        Creates a unit from the given arguments and keywords. The given keywords are used to overwrite any
        previously specified defaults for the argument parser of the unit, then this modified parser is
        used to parse the given list of arguments as though they were given on the command line. The parser
        results are used to construct an instance of the unit, this object is consequently returned.
        """
        argp = cls.argparser(*args, **keywords)
        args = argp.parse_args()

        try:
            if _retrofitted(cls): unit = autoinvoke(cls, args.__dict__)
            else: unit = cls(DelayedArgumentProxy(args, argp.order))
        except ValueError as E:
            argp.error(str(E))

        unit.args._store(_argo=argp.order)
        unit.args.quiet = args.quiet

        unit.args.dtiming = args.dtiming
        unit.args.nesting = args.nesting
        unit.args.reverse = args.reverse
        unit.args.devnull = args.devnull
        unit.args.verbose = args.verbose

        return unit

    def __copy__(self):
        cls = self.__class__
        clone = cls.__new__(cls)
        clone.__dict__.update(self.__dict__)
    #   TODO: Preferably, units should keep all their information in args, making
    #         the above __dict__ update unnecessary.
    #   clone._buffer = self._buffer
    #   clone._source = self._source
        clone._target = None
        clone._framed = None
        clone._chunks = None
        clone.args = self.args.__copy__()
        return clone

    def __init__(self, *args, **keywords):
        self._buffer = B''
        self._source = None
        self._target = None
        self._framed = None
        self._chunks = None

        if _retrofitted(self):
            assert not args, (
                'Retrofitted units may not call the Unit base constructor with positional arguments.'
            )
            keywords.update(dict(
                dtiming=False,
                nesting=0,
                reverse=False,
                devnull=False,
                verbose=LogLevel.DETACHED,
                quiet=False,
            ))
            # Since Python 3.6, functions always preserve the order of the keyword
            # arguments passed to them (see PEP 468).
            self.args = DelayedArgumentProxy(
                Namespace(**keywords), list(keywords))
        elif not keywords and len(args) == 1 and isinstance(args[0], DelayedArgumentProxy):
            self.args = args[0]
        else:
            keywords.setdefault('verbose', -1)
            argp = self.argparser(*args, **keywords)
            self.args = DelayedArgumentProxy(argp.parse_args(), argp.order)

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
            except Exception as msg:
                raise
                cls._output(F'initialization failed:', msg)
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
