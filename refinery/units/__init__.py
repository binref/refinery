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

from enum import IntEnum
from functools import wraps
from inspect import isgeneratorfunction
from typing import Iterable, BinaryIO, Union, Optional, Callable, Any, ByteString
from argparse import (
    ArgumentParser,
    ArgumentError,
    RawDescriptionHelpFormatter,
    SUPPRESS,
)

from ..lib.argformats import pending, manifest
from ..lib.tools import terminalfit, get_terminal_size, documentation, lookahead
from ..lib.frame import Framed, Chunk


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

    def __new__(mcs, name, bases, nmspc, abstract=False, helpdoc=False):
        def normalize(operation: Callable[[Any, ByteString], Any]) -> Callable[[ByteString], Any]:

            @wraps(operation)
            def wrapped(self, data: ByteString) -> bytes:
                if not isinstance(data, bytearray):
                    data = bytearray(data)
                self.args._lock(data)
                try:
                    return operation(self, bytes(data))
                except BaseException as B:
                    return self._exception_handler(B)

            wrapped.demux = isgeneratorfunction(operation)
            return wrapped

        for op in ('process', 'reverse'):
            if op in nmspc:
                nmspc[op] = normalize(nmspc[op])

        nmspc['__br_helpdoc__'] = helpdoc
        nmspc['__doc__'] = '\n\n'.join(filter(None, [nmspc.get('__doc__')] + [
            b.__doc__ for b in bases if getattr(b, '__br_helpdoc__', False)
        ]))

        if not abstract and Entry not in bases:
            bases = bases + (Entry,)
        return super(Executable, mcs).__new__(mcs, name, bases, nmspc)

    def __init__(cls, name, bases, nmspc, abstract=False, helpdoc=False):
        super(Executable, cls).__init__(name, bases, nmspc)
        if not abstract and sys.modules[cls.__module__].__name__ == '__main__':
            if Executable.Entry:
                cls._output(
                    F'not executing this unit because the following unit was '
                    F'already executed: {Executable.Entry}'
                )
            else:
                Executable.Entry = cls.__name__
                cls.run()

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

    def __init__(self, argv, argo):
        args = {}
        same = True
        for name, value in vars(argv).items():
            if not pending(value):
                args[name] = value
            else:
                same = False
        self._store(
            _argv=argv,
            _argo=argo,
            _args=args,
            _same=same
        )

    def _lock(self, data: bytearray):
        """
        Lock the current arguments for the given input `data`.
        """
        if self._same:
            return
        for name in self._argo:
            value = getattr(self._argv, name, None)
            if value and pending(value):
                self._args[name] = manifest(value, data)

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
        value = getattr(self._argv, name)
        if not value or not pending(value):
            return value
        raise AttributeError(F'the value {name} cannot be accessed until data is available.')

    def __setattr__(self, name, value):
        if pending(value):
            self._store(_same=False)
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
        if self.args.quiet:
            return LogLevel.NONE
        return LogLevel(min(len(LogLevel) - 2, self.args.verbose))

    @log_level.setter
    def log_level(self, value: LogLevel) -> None:
        self.args.verbose = int(value)

    def interface(self, argp: ArgumentParser) -> ArgumentParser:
        """
        Receives a reference to an `ArgumentParser` object. This parser will be used to parse
        the command line for this unit into the member variable called `args`.
        Children of `refinery.units.Unit` should override this method to customize their command
        line interface.
        """
        base = argp.add_argument_group(
            'Global Options',
            'The following options are available in every refinery unit.'
        )

        base.add_argument('-h', '--help', action='help',
            help='Show this help message and exit.')
        if self.is_reversible:
            base.add_argument('-R', '--reverse', action='store_true', help='Use the reverse operation.')
        else:
            base.set_defaults(reverse=False)
        base.add_argument('-0', '--null',
            action='store_true', help='Do not produce any output.')

        base.add_argument('-Q', '--quiet', action='store_true', help='Disables all log output.')
        base.add_argument('-L', '--lenient', dest='partial', action='store_true',
            help='Allow this unit to return incomplete results.')
        base.add_argument('-v', '--verbose', action='count', help=(
            'Verbosity: Specify up to two times to enable levels INFO and '
            'DEBUG, respectively. The default level is WARN. Can also be '
            'specified in the environment variable REFINERY_VERBOSITY as '
            'one of these strings or a number from 1 to 3.'
        ))
        base.set_defaults(verbose=1)

        argp.add_argument('--debug-timing', action='store_true', help=SUPPRESS)
        return argp

    def __iter__(self):
        return self

    def _exception_handler(self, exception: BaseException):
        if self.log_level <= LogLevel.DETACHED:
            raise exception
        try:
            raise exception
        except KeyboardInterrupt as K:
            self.output('aborting due to keyboard interrupt')
            self._source = None
            return None
        except RefineryCriticalException as E:
            self.log_warn(F'critical error, terminating: {E}')
        except RefineryPartialResult as E:
            self.log_warn(F'error, partial result returned: {E}')
            if self.args.partial:
                return E.partial
        except Exception as E:
            self.log_warn(F'unexpected error: {E}')
        finally:
            if self.log_level >= LogLevel.DEBUG:
                import traceback
                traceback.print_exc(file=sys.stderr)            

    def __next__(self):
        if not self._chunks:
            self._chunks = iter(self._framehandler)
        while True:
            result = next(self._chunks)
            if not isinstance(result, BaseException):
                return result


    @property
    def _framehandler(self) -> Framed:
        if self._framed:
            return self._framed

        op = self.reverse if self.args.reverse else self.process

        if op.demux:
            def normalized_action(data: bytearray) -> Iterable[bytes]:
                yield from filter(lambda x: x is not None, op(data))
        else:
            def normalized_action(data: bytearray) -> Iterable[bytes]:
                result = op(data)
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

    def __class_getitem__(cls, unit: 'Unit'):
        return cls().__getitem__(unit)

    def __getitem__(self, unit: 'Unit'):
        if isinstance(unit, type):
            unit = unit()
        alpha = self.clone()
        omega = unit.clone()
        alpha.args.nesting += 1
        omega.args.nesting -= 1
        omega.nozzle.source = alpha
        return omega

    def __ror__(self, stream: Union[BinaryIO, bytes, bytearray, 'Unit']):
        self.nozzle.source = stream
        return self

    def __or__(self, stream: Union[BinaryIO, 'Unit']):
        try:
            if isinstance(stream, type):
                stream = stream()
            return stream.clone().__ror__(self)
        except AttributeError:
            pass

        if not stream.writable():
            return

        def cname(x): return x.lower().replace('-', '')
        terminal = getattr(stream, 'isatty', lambda: False)()

        if terminal and cname(self.codec) != cname(sys.stdout.encoding):
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
                stream.write(recode(chunk))
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
            except KeyboardInterrupt:
                break

        try:
            if terminal and not chunk.endswith(B'\n'):
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

    def __call__(self, data: bytes) -> bytes:
        with io.BytesIO(data) as stdin:
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

    @classmethod
    def _output(cls, *messages) -> None:
        def transform(x):
            if isinstance(x, str):
                return x
            if isinstance(x, (bytes, bytearray)):
                import codecs
                return codecs.decode(x, cls.codec, errors='backslashreplace')
            return str(x)
        message = ' '.join(transform(msg) for msg in messages)
        sys.stderr.write(F'{cls.__name__}: {message}\n')

    def clone(self):
        """
        Return a clone of this unit. This routine is used internally to avoid
        mutability issues when using pipe-like syntax for `refinery.units.Unit`
        objects in a Python script.
        """
        other = self.__class__(**vars(self.argv))
        other._source = self._source
        other._buffer = self._buffer
        return other

    def __init__(self, *args, **keywords):
        args = [str(a) for a in args]
        cols = keywords.pop('_terminal_width', 0)

        class ArgumentParserWithKeywordHooks(ArgumentParser):
            def _add_action(self, action):
                class RememberOrder:
                    _a = action
                    def __getattr__(self, name): return getattr(self._a, name)
                    def __setattr__(self, name, value): return setattr(self._a, name, value)

                    def __call__(self, parser, ns, values, opt=None):
                        if self.dest not in parser.order:
                            parser.order.append(self.dest)
                        return self._a(parser, ns, values, opt)

                action.required = action.required and action.dest not in keywords
                super()._add_action(RememberOrder())

            def error_commandline(self, message):
                super().error(message)

            def error(self, message):
                parser_instance = self
                raise ArgparseError(parser_instance, message)

            def parse_args(self):
                self.order = []
                args_for_parser = args
                if args and args[~0]:
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
                super().__init__(prog, indent_increment, max_help_position, width=cols or get_terminal_size())

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
            prog=self.__class__.__name__.replace('_', '-'),
            description=documentation(self.__class__),
            formatter_class=LineWrapRawTextHelpFormatter,
            add_help=False
        )

        argp.set_defaults(nesting=0)

        self.argp = self.interface(argp)
        self.argv = argp.parse_args()
        self.args = DelayedArgumentProxy(self.argv, self.argp.order)

        self._buffer = B''
        self._source = None
        self._framed = None
        self._chunks = None

        if self.log_level == LogLevel.WARN:
            level = os.environ.get('REFINERY_VERBOSITY', LogLevel.DETACHED)
            try:
                level = int(level)
            except ValueError:
                level = getattr(LogLevel, level, LogLevel.DETACHED)
            self.log_level = level

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
                unit = cls(*argv)
                unit.log_level = max(unit.log_level, LogLevel.WARN)
            except ArgparseError as ap:
                ap.parser.error_commandline(str(ap))
            except Exception as msg:
                cls._output(F'initialization failed:', msg)
            else:
                if unit.args.debug_timing:
                    from time import process_time
                    start_clock = process_time()
                    unit.output('starting clock: {:.4f}'.format(start_clock))

                try:
                    with open(os.devnull, 'wb') if unit.args.null else sys.stdout.buffer as output:
                        source | unit | output
                except OSError:
                    pass

                if unit.args.debug_timing:
                    stop_clock = process_time()
                    unit.output('stopping clock: {:.4f}'.format(stop_clock))
                    unit.output('time delta was: {:.4f}'.format(stop_clock - start_clock))


__pdoc__ = {
    'Unit.is_reversible': Executable.is_reversible.__doc__,
    'Unit.codec': Executable.codec.__doc__
}
