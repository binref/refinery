"""
Miscellaneous helper functions.
"""
from __future__ import annotations

import copy
import functools
import inspect
import io
import itertools
import logging
import os
import re
import sys
import warnings

from enum import Enum, IntFlag
from math import log
from types import WrapperDescriptorType
from typing import Generator, Iterable, Iterator, TypeVar, cast

from refinery.lib.types import buf

_T = TypeVar('_T')


def lookahead(iterator: Iterable[_T]) -> Generator[tuple[bool, _T]]:
    """
    Implements a new iterator from a given one which returns elements `(last, item)` where each
    `item` is taken from the original iterator and `last` is a boolean indicating whether this is
    the last item.
    """
    last = False
    it = iter(iterator)
    try:
        peek = next(it)
    except StopIteration:
        return
    while not last:
        item = peek
        try:
            peek = next(it)
        except StopIteration:
            last = True
        yield last, item


class HandOver(Iterator[_T]):
    """
    An iterator over a single item, or over nothing if the item is `None`. Unlike a generator that
    yields the item, it keeps no reference to the item once it has returned it, so the item can be
    freed as soon as its receiver lets go of it.
    """
    __slots__ = '_item',

    def __init__(self, item: _T | None):
        self._item = item

    def __iter__(self):
        return self

    def __next__(self) -> _T:
        if (item := self._item) is None:
            raise StopIteration
        self._item = None
        return item


if sys.platform == 'win32':
    import ctypes
    import msvcrt

    _FILE_FS_DEVICE_INFORMATION = 4
    _FILE_DEVICE_NULL = 0x15

    class _IoStatusBlock(ctypes.Structure):
        """
        The structure `IO_STATUS_BLOCK` of the Windows API.
        """
        _fields_ = [('Status', ctypes.c_void_p), ('Information', ctypes.c_size_t)]

    class _FileFsDeviceInformation(ctypes.Structure):
        """
        The structure of the Windows API that receives the type of the device behind a handle.
        """
        _fields_ = [('DeviceType', ctypes.c_uint32), ('Characteristics', ctypes.c_uint32)]

    @functools.cache
    def _volume_information_query():
        """
        Returns the function of the Windows API that queries information about the volume or the
        device behind a handle.
        """
        query = ctypes.WinDLL('ntdll').NtQueryVolumeInformationFile
        query.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(_IoStatusBlock),
            ctypes.POINTER(_FileFsDeviceInformation),
            ctypes.c_ulong,
            ctypes.c_int,
        ]
        query.restype = ctypes.c_long
        return query

    def _is_windows_null_device(stream) -> bool:
        """
        Returns whether the descriptor of the given stream refers to the Windows null device. A
        stream whose descriptor cannot be determined, for any reason, is not the null device.
        """
        try:
            handle = msvcrt.get_osfhandle(stream.fileno())
        except Exception:
            return False
        status = _IoStatusBlock()
        info = _FileFsDeviceInformation()
        failure = _volume_information_query()(
            handle,
            ctypes.byref(status),
            ctypes.byref(info),
            ctypes.sizeof(info),
            _FILE_FS_DEVICE_INFORMATION,
        )
        return not failure and info.DeviceType == _FILE_DEVICE_NULL

else:
    def _is_windows_null_device(stream) -> bool:
        return False


def is_terminal(stream) -> bool:
    """
    Returns whether the given stream is connected to a terminal. On Windows, a stream reports itself
    as a terminal when it is connected to any character device, including the null device; this
    function returns false for the null device. A stream that reports itself as a terminal but has
    no usable descriptor is believed.
    """
    try:
        if not stream.isatty():
            return False
    except AttributeError:
        return False
    return not _is_windows_null_device(stream)


def get_terminal_size(default=100):
    """
    Returns the size of the currently attached terminal. If the environment variable
    `REFINERY_TERM_SIZE` is set to an integer value, it takes prescedence. If the width of the
    terminal cannot be determined or if the width is less than 8 characters, the function
    returns zero.
    """
    from refinery.lib.environment import environment
    ev_terminal_size = environment.term_size.value
    if ev_terminal_size and ev_terminal_size > 0:
        return ev_terminal_size
    width = default
    for stream in (sys.stderr, sys.stdout):
        if is_terminal(stream):
            try:
                width = os.get_terminal_size(stream.fileno()).columns
            except Exception:
                width = default
            else:
                break
    return default if width < 5 else width - 1


def terminalfit(text: str, delta: int = 0, width: int = 0, parsep: str = '\n\n', **kw) -> str:
    """
    Reformats text to fit the given width while not mangling bullet point lists.
    """
    import re
    import textwrap

    width = width or get_terminal_size()
    width = width - delta

    def isol(t):
        return re.match(R'^\(\d+\)|\d+[.:;]', t)

    def isul(t):
        return t.startswith('-') or t.startswith('*')

    def issp(t):
        return t.startswith('  ')

    text = text.replace('\r', '')

    def bulletpoint(line):
        wrapped = textwrap.wrap(line, width - 2, **kw)
        indent = '  ' if isul(line) else '   '
        wrapped[1:] = [f'{indent}{line}' for line in wrapped[1:]]
        return '\n'.join(wrapped)

    def fitted(paragraphs):
        for k, p in enumerate(paragraphs):
            if p.startswith(' '):
                yield p
                continue
            ol, ul = isol(p), isul(p)
            if ol or ul:
                input_lines = p.splitlines(keepends=False)
                unwrapped_line = input_lines[0].rstrip()
                lines = []
                if (ol and all(isol(t) or issp(t) for t in input_lines) or ul and all(isul(t) or issp(t) for t in input_lines)):
                    for line in input_lines[1:]:
                        if not (ol and isol(line) or ul and isul(line)):
                            unwrapped_line += ' ' + line.strip()
                            continue
                        lines.append(bulletpoint(unwrapped_line))
                        unwrapped_line = line.rstrip()
                    lines.append(bulletpoint(unwrapped_line))
                    yield '\n'.join(lines)
                    continue
            yield '\n'.join(textwrap.wrap(p, width, **kw))

    return parsep.join(fitted(text.split('\n\n')))


def documentation(unit):
    """
    Return the documentation string of a given unit as it should be displayed on the command line.
    Certain pdoc3-specific reference strings are removed.
    """
    import re
    docs = inspect.getdoc(unit) or ''
    docs = re.sub(R'`refinery\.(?:\w+\.)*(\w+)`', R'\1', docs)
    return docs.replace('`', '')


def begin(iterable: Iterable[_T]) -> tuple[_T, Iterable[_T]] | None:
    """
    Iterates the first element of an iterator and returns None if this fails. Otherwise, it returns
    both the first element and a new iterable which will return the same elements as the input.
    """
    try:
        body = iter(iterable)
        head = next(body)
    except StopIteration:
        return None
    else:
        def _fused():
            yield head
            yield from body
        return head, _fused()


def skipfirst(iterable: Iterable[_T]) -> Generator[_T]:
    """
    Returns an interable where the first element of the input iterable was skipped.
    """
    it = iter(iterable)
    next(it)
    yield from it


def entropy_fallback(data: buf) -> float:
    """
    This method is called by `refinery.lib.tools.entropy` when the `numpy` module is not available.
    It computes the shannon entropy of the input byte string and is written in pure Python.
    """
    if isinstance(data, memoryview):
        # this copy is better than re-implementing count in Python for memory views
        data = bytes(data)
    histogram = {b: data.count(b) for b in range(0x100)}
    S = [histogram[b] / len(data) for b in histogram]
    return 0.0 + -sum(p * log(p, 2) for p in S if p) / 8.0


def entropy(data: buf) -> float:
    """
    Computes the entropy of `data` over the alphabet of all bytes.
    """
    if not data:
        return 0.0
    try:
        import numpy
    except ImportError:
        return entropy_fallback(data)
    hist = numpy.unique(memoryview(data), return_counts=True)[1]
    prob = hist / len(data)
    # 8 bits are the maximum number of bits of information in a byte
    return 0.0 - (numpy.log2(prob) * prob).sum() / 8.0


def index_of_coincidence(data: buf) -> float:
    """
    Computes the index of coincidence of `data` over the alphabet of all bytes.
    """
    if not data:
        return 0.0
    N = len(data)
    if N < 2:
        return 0.0
    try:
        import numpy
    except ImportError:
        C = [0] * 0x100
        for b in data:
            C[b] += 1
    else:
        C = numpy.histogram(
            numpy.frombuffer(data, dtype=numpy.uint8),
            numpy.arange(0x100))[0]
    d = 1 / N / (N - 1)
    return float(sum(x * (x - 1) * d for x in C))


def splitchunks(
    data: buf,
    size: int,
    step: int | None = None,
    truncate: bool = False
) -> Iterable[buf]:
    """
    Split `data` into chunks of size `size`. The cursor advances by `step` bytes after extracting a
    block, the default value for `step` is equal to `size`. The boolean parameter `truncate`
    specifies whether any chunks of size smaller than `size` are generated or whether to abort as
    soon as the last complete chunk of the given size is extracted.
    """
    if step is None:
        step = size
    if len(data) <= size:
        if not truncate or len(data) == size:
            yield data
        return
    for k in range(0, len(data), step):
        chunk = data[k:k + size]
        if not chunk:
            break
        if len(chunk) < size and truncate:
            break
        yield chunk


def infinitize(it: _T | Iterable[_T]) -> Iterable[_T]:
    """
    Creates an infinite iterable from the input.
    """
    if isinstance(it, (
        itertools.cycle,
        itertools.repeat,
        itertools.count,
    )):
        return it
    elif isinstance(it, Iterable):
        return itertools.cycle(it)
    else:
        return itertools.repeat(it)


class RecursionDepth:
    """
    A context manager that raises the interpreter's recursion limit for a recursive operation
    that needs more of it than the ambient limit provides, and restores the prior limit on exit.
    A limit lower than the ambient one is left untouched. Some third-party packages raise the
    process-wide limit as a side effect of being imported and never restore it, so a caller that
    needs a deep limit only for the duration of one call should ask for it here rather than trust
    that the import already did it.
    """
    def __init__(self, depth: int):
        self.depth = depth
        self.default = sys.getrecursionlimit()

    def __enter__(self):
        if self.depth > self.default:
            sys.setrecursionlimit(self.depth)
        return self

    def __exit__(self, *_):
        sys.setrecursionlimit(self.default)
        return False


class NoLogging:
    """
    A context manager to prevent various unwanted kinds of logging messages to appear.
    The class is initialized with a given mode that encodes the logging channels to be
    suppressed. After the context is exited, the original logging behavior is restored.
    """

    class Mode(IntFlag):
        """
        A set of flags for different logging mechanisms to be suppressed.
        """
        STD_OUT = 0b0001
        """Silence the standard output channel."""
        STD_ERR = 0b0010
        """Silence the standard error channel."""
        WARNING = 0b0100
        """Silence the Python warning module."""
        LOGGING = 0b1000
        """Silence the Python logging module."""
        ALL     = 0b1111 # noqa
        """Silence all known logging mechanisms."""

    def __init__(self, mode: Mode = Mode.WARNING | Mode.LOGGING):
        self.mode = mode

    def __enter__(self):
        if self.mode & NoLogging.Mode.LOGGING:
            self._logging_disabled = logging.root.manager.disable
            logging.disable(logging.CRITICAL)
        if self.mode & NoLogging.Mode.WARNING:
            self._warning_filters = list(warnings.filters)
            warnings.filterwarnings('ignore')
        if self.mode & NoLogging.Mode.STD_ERR:
            self._stderr = sys.stderr
            sys.stderr = io.TextIOWrapper(open(os.devnull, 'wb'), encoding='latin1')
        if self.mode & NoLogging.Mode.STD_OUT:
            self._stdout = sys.stdout
            sys.stdout = io.TextIOWrapper(open(os.devnull, 'wb'), encoding='latin1')
        return self

    def __exit__(self, *_):
        if self.mode & NoLogging.Mode.LOGGING:
            logging.disable(self._logging_disabled)
        if self.mode & NoLogging.Mode.WARNING:
            warnings.resetwarnings()
            assert isinstance(warnings.filters, list)
            warnings.filters[:] = self._warning_filters
        if self.mode & NoLogging.Mode.STD_ERR:
            sys.stderr.close()
            sys.stderr = self._stderr
        if self.mode & NoLogging.Mode.STD_OUT:
            sys.stdout.close()
            sys.stdout = self._stdout


class NoLoggingProxy:
    """
    This class can be used to wrap any object. It acts as a proxy for this object, passing through
    attribute access, item access, iteration, and calls to its base. However, any such action is
    wrapped in a `refinery.lib.tools.NoLogging` context to ensure that it produces no logging
    output. Notably, any returned values that are not considered primitive are wrapped as a proxy
    as well. The main downside of this is that instance checks no longer work as expected.
    """

    __slots__ = (
        '__wrapped__',
        '__nl_mode__',
    )

    def __new__(cls, wrap, mode: NoLogging.Mode = NoLogging.Mode.ALL):
        if isinstance(wrap, (int, float, str, bytes, bytearray, memoryview, Enum)):
            return wrap
        return super().__new__(cls)

    def __init__(self, wrap, mode: NoLogging.Mode = NoLogging.Mode.ALL):
        self.__wrapped__ = wrap
        self.__nl_mode__ = mode

    def __setattr__(self, name, value):
        if name in NoLoggingProxy.__slots__:
            return super().__setattr__(name, value)
        mode = self.__nl_mode__
        wrap = self.__wrapped__
        with NoLogging(mode):
            setattr(wrap, name, value)

    def __repr__(self):
        with NoLogging(self.__nl_mode__):
            return repr(self.__wrapped__)

    def __getattribute__(self, name):
        wrap = super().__getattribute__('__wrapped__')
        mode = super().__getattribute__('__nl_mode__')
        if name == '__wrapped__':
            return wrap
        if name == '__nl_mode__':
            return mode
        with NoLogging(mode):
            attr = getattr(wrap, name)
        return NoLoggingProxy(attr, mode)

    def __getitem__(self, k):
        mode = self.__nl_mode__
        with NoLogging(mode):
            item = self.__wrapped__[k]
        return NoLoggingProxy(item, mode)

    def __iter__(self):
        mode = self.__nl_mode__
        with NoLogging(mode):
            it = iter(self.__wrapped__)
        while True:
            try:
                with NoLogging(mode):
                    item = next(it)
            except StopIteration:
                return
            else:
                yield NoLoggingProxy(item, mode)

    def __call__(self, *args, **kwargs):
        mode = self.__nl_mode__
        with NoLogging(mode):
            rv = self.__wrapped__(*args, **kwargs)
        return NoLoggingProxy(rv, mode)


@functools.cache
def mixed_class(mixin: type[_T], base: type, name: str) -> type[_T]:
    """
    The class of the given name that adds the given mixin to a base class chosen at run time; one
    class for each combination. It belongs to the module of the mixin.
    """
    return cast('type[_T]', type(name, (mixin, base), {'__module__': mixin.__module__}))


def proxy(t: _T) -> _T:
    """
    Proxy an object using `refinery.lib.tools.NoLoggingProxy` but cheat the type checker into
    thinking that it has retained its type.
    """
    return cast(_T, NoLoggingProxy(t))


def unwrap(t: _T) -> _T:
    """
    Unwrap an object that is potentially wrapped, say, as a `refinery.lib.tools.NoLoggingProxy`.
    """
    return getattr(t, '__wrapped__', t)


class NotOne(LookupError):
    """
    A custom exception raised by `refinery.lib.tools.one` if the input iterator does not yield
    exactly one element. The property `empty` indicates whether the iterator was empty; if it is
    false, then the exception was raised because the iterator contained more than one element.
    """
    def __init__(self, empty: bool):
        how = 'none' if empty else 'more'
        super().__init__(F'Expected a single item, but the iterator was {how}')
        self.empty = empty


def one(iterable: Iterable[_T]) -> _T:
    """
    The function expects the input `iterable` to be an iterable that yields exactly one element
    and returns that element. Raises `refinery.lib.tools.NotOne` for invalid inputs.
    """
    it = iter(iterable)
    try:
        top = next(it)
    except StopIteration:
        raise NotOne(True)
    try:
        next(it)
    except StopIteration:
        return top
    else:
        raise NotOne(False)


def integers_of_slice(s: slice) -> Iterable[int]:
    """
    Returns an iterable that iterates the integers in the range given by the input slice.
    """
    if s.stop is None:
        return itertools.count(s.start or 0, s.step or 1)
    else:
        return range(s.start or 0, s.stop, s.step or 1)


def normalize_word_separators(words: str, unified_separator: str, strip: bool = True):
    """
    For a sequence of words separated by whitespace, punctuation, slashes, dashes or underscores,
    normalize all occurrences of one or more of these separators to one given symbol. Leading and
    trailing occurrences of separators are removed.
    """
    normalized = re.sub('[-\\s_.,;:/\\\\]+', unified_separator, words)
    if strip:
        normalized = normalized.strip(unified_separator)
    return normalized


def normalize_to_display(words: str, strip: bool = True):
    """
    Normalizes all separators to dashes.
    """
    return normalize_word_separators(words, '-', strip)


def normalize_to_identifier(words: str, strip: bool = True):
    """
    Normalizes all separators to underscores.
    """
    return normalize_word_separators(words, '_', strip)


_E = TypeVar('_E', bound=BaseException)


def copy_exception(error: _E) -> _E:
    """
    A copy of the given exception without traceback, cause and context. An exception that is kept
    to be raised again later must not keep the frames of an earlier raise, which refer to whatever
    keeps it; a fresh copy is raised each time. Builtin exception classes are copied through their
    own copy protocol, which keeps the fields that their `__init__` sets from its arguments. A class
    that defines `__init__` in Python keeps its state in `args` and in its attributes, and its
    `__init__` may expect other arguments, so these are copied.
    """
    cls = error.__class__
    if isinstance(cls.__init__, WrapperDescriptorType):
        return copy.copy(error)
    replica = cls.__new__(cls, *error.args)
    replica.__dict__.update(error.__dict__)
    return replica


def exception_to_string(exception: BaseException, default=None) -> str:
    """
    Attempts to convert a given exception to a good description that can be exposed to the user.
    """
    if not exception.args:
        return exception.__class__.__name__
    it = (a for a in exception.args if isinstance(a, str))
    if default is None:
        default = str(exception)
    return max(it, key=len, default=default).strip()
