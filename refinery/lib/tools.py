"""
Miscellaneous helper functions.
"""
from __future__ import annotations

import datetime
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
from typing import Any, Callable, Generator, Iterable, TypeVar

from refinery.lib.types import INF, buf

_T = TypeVar('_T')


try:
    import ctypes
except ImportError:
    def _meminfo_d(v: memoryview) -> slice | None:
        return None
    meminfo = _meminfo_d
else:
    def _meminfo_c(v: memoryview):
        if not (n := len(v)):
            return None
        if v.readonly or not v.contiguous:
            return None
        base = memoryview(v.obj)
        offset, base_addr = (
            ctypes.addressof(ctypes.c_char.from_buffer(t)) for t in (v, base))
        start = offset - base_addr
        return slice(start, min(start + n, len(base)), 1)
    meminfo = _meminfo_c


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


def get_terminal_size(default=0):
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
        if stream.isatty():
            try:
                width = os.get_terminal_size(stream.fileno()).columns
            except Exception:
                width = default
            else:
                break
    return default if width < 2 else width - 1


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


def autoinvoke(method: Callable[..., _T], keywords: dict) -> _T:
    """
    For each parameter that `method` expects, this function looks for an entry in `keywords` which
    has the same name as that parameter. `autoinvoke` then calls `method` with all matching
    parameters forwarded in the appropriate manner.
    """

    kwdargs = {}
    posargs = []
    varargs = []
    kwdjoin = False

    for p in inspect.signature(method).parameters.values():
        if p.kind is p.VAR_KEYWORD:
            kwdjoin = True
        try:
            value = keywords.pop(p.name)
        except KeyError:
            if p.kind is p.VAR_KEYWORD:
                continue
            value = p.default
            if value is p.empty:
                raise ValueError(F'missing required parameter {p.name}')
        if p.kind is p.POSITIONAL_OR_KEYWORD or p.kind is p.POSITIONAL_ONLY:
            if value == p.default:
                # when equality holds, we force identity
                value = p.default
            posargs.append(value)
        elif p.kind is p.VAR_POSITIONAL:
            varargs = value
        elif p.kind is p.KEYWORD_ONLY:
            kwdargs[p.name] = value

    if kwdjoin:
        kwdargs.update(keywords)

    return method(*posargs, *varargs, **kwdargs)


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


def isstream(obj) -> bool:
    """
    Tests whether `obj` is a stream. This is currently done by simply testing whether the object
    has an attribute called `read`.
    """
    return hasattr(obj, 'read')


def isbuffer(obj) -> bool:
    """
    Test whether `obj` is an object that supports the buffer API, like a bytes or bytearray object.
    """
    try:
        with memoryview(obj):
            return True
    except TypeError:
        return False


def asbuffer(obj) -> memoryview | None:
    """
    Attempts to acquire a memoryview of the given object. This works for bytes and bytearrays, or
    memoryview objects themselves. The return value is `None` for objects that do not support the
    buffer protocol.
    """
    try:
        return memoryview(obj)
    except TypeError:
        return None


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


def make_buffer_mutable(data: buf):
    """
    Returns a mutable version of the input data. Already mutable inputs are returned
    as themselves, i.e. no copy operation occurs in these cases.
    """
    if isinstance(data, bytearray):
        return data
    if isinstance(data, memoryview) and not data.readonly:
        return data
    return bytearray(data)


def infinitize(it: _T | Iterable[_T]) -> Iterable[_T]:
    if isinstance(it, (
        itertools.cycle,
        itertools.repeat,
        itertools.count,
    )):
        return it
    try:
        it = iter(it)           # type:ignore
    except TypeError:
        it = (it,)              # type:ignore
    return itertools.cycle(it)  # type:ignore


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
            logging.disable(logging.NOTSET)
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
    This class can be used to wrap any object. It acts as a proxy for this object, passing though
    and attribute access, operator use, and method calls to its base. However, any such action
    is wrapped in a `refinery.lib.tools.NoLogging` context to ensure that it procudes no logging
    output. Notably, any returned values that are not considered primitive are wrapped as a proxy
    as well. The main downside of this is that instance checks no longer work as expected.
    """

    __slots__ = (
        '__wrapped__',
        '__nl_mode__',
    )

    __proxy_cache__ = {}

    def __new__(cls, wrap, mode: NoLogging.Mode = NoLogging.Mode.ALL):
        wrap_type = type(wrap)
        if isinstance(wrap, (int, float, str, bytes, bytearray, memoryview, Enum)):
            return wrap
        if (proxy_class := cls.__proxy_cache__.get(wrap_type)) is None:
            dunder_names = [
                name for name in dir(wrap_type) if name.startswith('__') and name.endswith('__')]
            proxied_dunder_methods = {}
            for name in dunder_names:
                if name == '__new__':
                    continue
                class_method = getattr(wrap_type, name)
                if class_method and class_method is getattr(wrap, name):
                    def proxied_method(
                        _, *args,
                        _proxy___call=class_method,
                        _proxy___wrap=wrap,
                        _proxy___mode=mode,
                        **kwargs
                    ):
                        with NoLogging(_proxy___mode):
                            result = _proxy___call(_proxy___wrap, *args, **kwargs)
                        return NoLoggingProxy(result, _proxy___mode)
                    if not callable(class_method):
                        continue
                    proxied_dunder_methods[name] = proxied_method
            if proxied_dunder_methods:
                proxy_class = type(
                    F'_proxy_{wrap_type.__name__}', (NoLoggingProxy,), proxied_dunder_methods)
            else:
                proxy_class = cls
            cls.__proxy_cache__[wrap_type] = proxy_class
        return super().__new__(proxy_class) # type:ignore

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


def isodate(iso: str) -> datetime.datetime | None:
    """
    Convert an input date string in ISO format to a `datetime` object. Contains fallbacks for early
    Python versions.
    """
    if len(iso) not in range(16, 25):
        return None
    iso = iso[:19].replace(' ', 'T', 1)
    try:
        try:
            return datetime.datetime.fromisoformat(iso)
        except AttributeError:
            return datetime.datetime.strptime(iso, "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return None


def date_from_timestamp(ts: int | float):
    """
    Convert a UTC timestamp to a datetime object.
    """
    if sys.version_info >= (3, 12):
        dt = datetime.datetime.fromtimestamp(ts, datetime.UTC)
    else:
        dt = datetime.datetime.utcfromtimestamp(ts)
    return dt.replace(tzinfo=None)


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


def typename(thing):
    """
    Determines the name of the type of an object.
    """
    if not isinstance(thing, type):
        thing = type(thing)
    mro = [c for c in thing.__mro__ if c is not object]
    if mro:
        thing = mro[~0]
    try:
        return thing.__name__
    except AttributeError:
        return repr(thing)


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


def nopdoc(obj: object):
    """
    This decorator can be applied to any object to exclude it from the automatically generated
    documentation.
    """
    pdoc: dict = sys.modules[obj.__module__].__dict__.setdefault('__pdoc__', {})
    pdoc[obj.__qualname__] = False
    return obj


def convert(x: _T | Any, t: type[_T]) -> _T:
    """
    Convert the given object `x` to the type `t`.
    """
    return x if isinstance(x, t) else t(x) # type:ignore


class BoundsType:
    """
    Can be used to specify certain upper and lower bounds. For example, the following is `True`:

        5 in bounds[3:5]

    This is notably different from how a `range` object functions since the upper bound is included
    in the valid range, and it is also permitted to be `None` for an unbounded range.
    """
    __name__ = 'bounds'

    min: int
    max: int | INF
    inc: int

    def __getitem__(self, k: slice):
        return BoundsType(k)

    def __init__(self, bounds: int | slice[int, int | None | INF, int | None] | None):
        if bounds is None:
            self.min = 0
            self.max = INF
            self.inc = 1
        elif isinstance(bounds, int):
            self.min = self.max = bounds
            self.inc = 1
        else:
            _min, _max, _inc = bounds.start, bounds.stop, bounds.step
            self.min = _min or 0
            self.max = _max or INF
            self.inc = _inc or 1
            if _max and _max < self.min:
                raise ValueError(F'The maximum {self.max} is lesser than the minimum {self.min}.')
            if self.inc < 0:
                raise ValueError('Negative step size not supported for range expressions.')

    def __iter__(self):
        k = self.min
        i = self.inc
        if (m := self.max) is INF:
            yield from itertools.count(k, i)
        else:
            while k <= m:
                yield k
                k += i

    def __repr__(self):
        return F'[{self.min}:{self.max}:{self.inc}]'

    def __contains__(self, value: int):
        if value < self.min:
            return False
        if (m := self.max) and value > m:
            return False
        return (value - self.min) % self.inc == 0


bounds = BoundsType(slice(None, None))
