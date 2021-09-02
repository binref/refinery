#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Interfaces and classes to read structured data.
"""
from __future__ import annotations

import contextlib
import enum
import functools
import io
import re
import struct
import weakref

from refinery.lib.tools import cached_property
from typing import List, Union, Tuple, Optional, Iterable, ByteString, TypeVar, Generic, Any, Dict


T = TypeVar('T', bound=Union[bytearray, bytes, memoryview])
UnpackType = Union[int, bool, float, bytes]


class EOF(ValueError):
    def __init__(self, rest: ByteString = B''):
        super().__init__('Unexpected end of buffer.')
        self.rest = rest

    def __bytes__(self):
        return bytes(self.rest)


class StreamDetour:
    def __init__(self, stream: io.IOBase, offset=None, whence=io.SEEK_SET):
        self.stream = stream
        self.offset = offset
        self.whence = whence

    def __enter__(self):
        self.cursor = self.stream.tell()
        if self.offset is not None:
            self.stream.seek(self.offset, self.whence)
        return self

    def __exit__(self, *args):
        self.stream.seek(self.cursor, io.SEEK_SET)


class MemoryFile(Generic[T], io.IOBase):
    """
    A thin wrapper around (potentially mutable) byte sequences which gives it the
    features of a file-like object.
    """
    closed: bool
    read_as_bytes: bool

    _data: T
    _cursor: int
    _closed: bool

    class SEEK(int, enum.Enum):
        CUR = io.SEEK_CUR
        END = io.SEEK_END
        SET = io.SEEK_SET

    def __init__(self, data: Optional[T] = None, read_as_bytes=False, fileno: Optional[int] = None) -> None:
        if data is None:
            data = bytearray()
        self._data = data
        self._cursor = 0
        self._closed = False
        self._fileno = fileno
        self.read_as_bytes = read_as_bytes

    def close(self) -> None:
        self._closed = True

    @property
    def closed(self) -> bool:
        return self._closed

    def __enter__(self) -> MemoryFile:
        return self

    def __exit__(self, ex_type, ex_value, trace) -> bool:
        return False

    def flush(self) -> None:
        pass

    def isatty(self) -> bool:
        return False

    def __iter__(self):
        return self

    def __len__(self):
        return len(self._data)

    def __next__(self):
        line = self.readline()
        if not line:
            raise StopIteration
        return line

    def fileno(self) -> int:
        if self._fileno is None:
            raise OSError
        return self._fileno

    def readable(self) -> bool:
        return not self._closed

    def seekable(self) -> bool:
        return not self._closed

    @property
    def eof(self) -> bool:
        return self._closed or self._cursor >= len(self._data)

    def writable(self) -> bool:
        if self._closed:
            return False
        if isinstance(self._data, memoryview):
            return not self._data.readonly
        return isinstance(self._data, bytearray)

    def read(self, size: int = -1) -> T:
        return self.read1(size)

    def peek(self, size: int = -1) -> memoryview:
        cursor = self._cursor
        mv = memoryview(self._data)
        if size is None or size < 0:
            return mv[cursor:]
        return mv[cursor:cursor + size]

    def read1(self, size: int = -1) -> T:
        beginning = self._cursor
        if size is None or size < 0:
            self._cursor = len(self._data)
        else:
            self._cursor = min(self._cursor + size, len(self._data))
        result = self._data[beginning:self._cursor]
        if self.read_as_bytes and not isinstance(result, bytes):
            result = bytes(result)
        return result

    def _find_linebreak(self, beginning: int, end: int) -> int:
        if not isinstance(self._data, memoryview):
            return self._data.find(B'\n', beginning, end)
        for k in range(beginning, end):
            if self._data[k] == 0xA: return k
        return -1

    def readline(self, size: int = -1) -> T:
        beginning, end = self._cursor, len(self._data)
        if size is not None and size >= 0:
            end = beginning + size
        p = self._find_linebreak(beginning, end)
        self._cursor = end if p < 0 else p + 1
        result = self._data[beginning:self._cursor]
        if self.read_as_bytes and not isinstance(result, bytes):
            result = bytes(result)
        return result

    def readlines(self, hint: int = -1) -> Iterable[T]:
        if hint is None or hint < 0:
            yield from self
        else:
            total = 0
            while total < hint:
                line = next(self)
                total += len(line)
                yield line

    def readinto1(self, b) -> int:
        data = self.read(len(b))
        size = len(data)
        b[:size] = data
        return size

    def readinto(self, b) -> int:
        return self.readinto1(b)

    def tell(self) -> int:
        return self._cursor

    def seekrel(self, offset: int) -> int:
        return self.seek(offset, io.SEEK_CUR)

    def seekset(self, offset: int) -> int:
        if offset < 0:
            return self.seek(offset, io.SEEK_END)
        else:
            return self.seek(offset, io.SEEK_SET)

    def getbuffer(self) -> T:
        return self._data

    def getvalue(self) -> T:
        return self._data

    def seek(self, offset: int, whence=io.SEEK_SET) -> int:
        if whence == io.SEEK_SET:
            if offset < 0:
                raise ValueError('no negative offsets allowed for SEEK_SET.')
            self._cursor = offset
        elif whence == io.SEEK_CUR:
            self._cursor += offset
        elif whence == io.SEEK_END:
            self._cursor = len(self._data) + offset
        self._cursor = max(self._cursor, 0)
        self._cursor = min(self._cursor, len(self._data))
        return self._cursor

    def writelines(self, lines: Iterable[ByteString]) -> None:
        for line in lines:
            self.write(line)

    def truncate(self, size=None) -> None:
        if size is not None:
            if not (0 <= size < len(self._data)):
                raise ValueError('invalid size value')
            self._cursor = size
        del self._data[self._cursor:]

    def write(self, data: ByteString) -> int:
        beginning = self._cursor
        self._cursor += len(data)
        try:
            self._data[beginning:self._cursor] = data
        except Exception as T:
            self._cursor = beginning
            raise OSError(str(T)) from T
        return len(data)


class order(str, enum.Enum):
    big = '>'
    little = '<'


class StructReader(MemoryFile[T]):
    """
    An extension of a `refinery.lib.structures.MemoryFile` which provides methods to
    read structured data.
    """

    class Unaligned(RuntimeError):
        pass

    def __init__(self, data: T, bigendian: bool = False):
        super().__init__(data)
        self._bbits = 0
        self._nbits = 0
        self.bigendian = bigendian

    def __enter__(self) -> StructReader:
        return super().__enter__()

    @property
    @contextlib.contextmanager
    def be(self):
        self.bigendian = True
        try:
            yield self
        finally:
            self.bigendian = False

    def readinto(self, b) -> int:
        size = super().readinto(b)
        if size != len(b):
            raise EOF
        return size

    @cached_property
    def byteorder_format(self) -> str:
        return '>' if self.bigendian else '<'

    @cached_property
    def byteorder_name(self) -> str:
        return 'big' if self.bigendian else 'little'

    def seek(self, offset, whence=io.SEEK_SET) -> int:
        self._bbits = 0
        self._nbits = 0
        return super().seek(offset, whence)

    def read1(self, size: Optional[int] = None) -> T:
        """
        Read bytes from the underlying stream. Raises a `RuntimeError` when the stream is not currently
        byte-aligned, i.e. when `refinery.lib.structures.StructReader.byte_aligned` is `False`. Raises
        an exception of type `refinery.lib.structures.EOF` when less data is available in the stream than
        requested via the `size` parameter. The remaining data can be extracted from the exception.
        Use `refinery.lib.structures.StructReader.read_bytes` to read bytes from the stream when it is
        not byte-aligned.
        """
        if not self.byte_aligned:
            raise StructReader.Unaligned('buffer is not byte-aligned')
        data = super().read1(size)
        if size and len(data) < size:
            raise EOF(data)
        return data

    @property
    def byte_aligned(self) -> bool:
        """
        This property is `True` if and only if there are currently no bits still waiting in the internal
        bit buffer.
        """
        return not self._nbits

    def byte_align(self, blocksize: int = 1) -> Tuple[int, int]:
        """
        This method clears the internal bit buffer and moves the cursor to the next byte. It returns a
        tuple containing the size and contents of the bit buffer.
        """
        nbits = self._nbits
        bbits = self._bbits
        self._nbits = 0
        self._bbits = 0
        mod = self._cursor % blocksize
        self.seekrel(mod and blocksize - mod)
        return nbits, bbits

    def read_integer(self, length: int) -> int:
        """
        Read `length` many bits from the underlying stream as an integer.
        """
        if length < self._nbits:
            self._nbits -= length
            if self.bigendian:
                result = self._bbits >> self._nbits
                self._bbits ^= result << self._nbits
            else:
                result = self._bbits & 2 ** length - 1
                self._bbits >>= length
            return result
        nbits, bbits = self.byte_align()
        required = length - nbits
        bytecount, rest = divmod(required, 8)
        if rest:
            bytecount += 1
            rest = 8 - rest
        result = int.from_bytes(self.read(bytecount), self.byteorder_name)
        if not nbits and not rest:
            return result
        if self.bigendian:
            rbmask   = 2 ** rest - 1       # noqa
            excess   = result & rbmask     # noqa
            result >>= rest                # noqa
            result  ^= bbits << required   # noqa
        else:
            excess   = result >> required  # noqa
            result  ^= excess << required  # noqa
            result <<= nbits               # noqa
            result  |= bbits               # noqa
        assert excess.bit_length() <= rest
        self._nbits = rest
        self._bbits = excess
        return result

    def read_bytes(self, size: int) -> bytes:
        """
        The method reads `size` many bytes from the underlying stream starting at the current bit.
        """
        if self.byte_aligned:
            data = self.read(size)
            if not isinstance(data, bytes):
                data = bytes(data)
            return data
        return self.read_integer(size * 8).to_bytes(size, self.byteorder_name)

    def read_bit(self) -> int:
        """
        This function is a shortcut for calling `refinery.lib.structures.StructReader.read_integer` with
        an argument of `1`, i.e. this reads the next bit from the stream. The bits of any byte in the stream
        are read from least significant to most significant.
        """
        return self.read_integer(1)

    def read_bits(self, nbits: int) -> Iterable[int]:
        """
        This method returns the bits of `refinery.lib.structures.StructReader.read_integer` as an iterable
        from least to most significant.
        """
        chunk = self.read_integer(nbits)
        for k in range(nbits - 1, -1, -1):
            yield chunk >> k & 1

    def read_flags(self, nbits: int, reverse=False) -> Iterable[bool]:
        """
        Identical to `refinery.lib.structures.StructReader.read_bits` with every bit value cast to a boolean.
        """
        bits = list(self.read_bits(nbits))
        if reverse:
            bits.reverse()
        for bit in bits:
            yield bool(bit)

    def read_struct(self, spec: str, unwrap=False) -> Union[List[UnpackType], UnpackType]:
        """
        Read structured data from the stream in any format supported by the `struct` module. The `format`
        argument can be used to override the current byte ordering. If the `unwrap` parameter is `True`, a
        single unpacked value will be returned as a scalar, not as a tuple with one element.
        """
        if not spec:
            raise ValueError('no format specified')
        byteorder = spec[:1]
        if byteorder in '<!=@>':
            spec = spec[1:]
        else:
            byteorder = self.byteorder_format
        data = []
        for part in re.split('(a|u)', spec):
            if part == 'a':
                data.append(self.read_c_string())
                continue
            if part == 'u':
                data.append(self.read_w_string())
                continue
            part = F'{byteorder}{part}'
            data.extend(struct.unpack(part, self.read_bytes(struct.calcsize(part))))
        if unwrap and len(data) == 1:
            return data[0]
        return data

    def read_nibble(self) -> int:
        """
        Calls `refinery.lib.structures.StructReader.read_integer` with an argument of `4`.
        """
        return self.read_integer(4)

    def u16(self) -> int: return self.read_integer(16)
    def u32(self) -> int: return self.read_integer(32)
    def u64(self) -> int: return self.read_integer(64)
    def i16(self) -> int: return self.read_struct('h', True)
    def i32(self) -> int: return self.read_struct('l', True)
    def i64(self) -> int: return self.read_struct('q', True)

    def read_byte(self) -> int: return self.read_integer(8)
    def read_char(self) -> int: return self.read_struct('b', True)

    def read_terminated_array(self, alignment: int, terminator: bytes):
        pos = self.tell()
        buf = self.getbuffer()
        try:
            end = pos - 1
            while True:
                end = buf.find(terminator, end + 1)
                if end < 0 or not (end - pos) % alignment:
                    break
        except AttributeError:
            result = bytearray()
            while not self.eof:
                result.append(self.read_byte())
                if result.endswith(terminator):
                    t = len(result) - len(terminator)
                    if not t % alignment:
                        result[t:] = []
                        return result
            self.seek(pos)
            raise EOF
        else:
            data = self.read(end - pos)
            self.seekrel(len(terminator))
            return data

    def read_c_string(self, encoding=None) -> Union[str, bytes]:
        data = self.read_terminated_array(1, B'\0')
        if encoding is not None:
            data = data.decode(encoding)
        return data

    def read_w_string(self, encoding=None) -> Union[str, bytes]:
        data = self.read_terminated_array(2, B'\0\0')
        if encoding is not None:
            data = data.decode(encoding)
        return data


class StructMeta(type):
    """
    A metaclass to facilitate the behavior outlined for `refinery.lib.structures.Struct`.
    """
    def __new__(mcls, name, bases, nmspc, **kwargs):
        nmspc.update(kwargs)
        return type.__new__(mcls, name, bases, nmspc)

    def __init__(cls, name, bases, nmspc, **kwargs):
        super(StructMeta, cls).__init__(name, bases, nmspc)
        original__init__ = cls.__init__

        @functools.wraps(original__init__)
        def wrapped__init__(self, data, *args, **kwargs):
            if not isinstance(data, StructReader):
                data = StructReader(data)
            for key, value in kwargs.items():
                setattr(self, key, value)
            original__init__(self, data, *args)

        cls.__init__ = wrapped__init__


class Struct(metaclass=StructMeta):
    """
    A class to parse structured data. A `refinery.lib.structures.Struct` class can be instantiated
    as follows:

        foo = Struct(data, bar=29)

    The initialization routine of the structure will be called with a single argument `reader`. If
    the object `data` is already a `refinery.lib.structures.StructReader`, then it will be passed
    as `reader`. Otherwise, the argument will be wrapped in a `refinery.lib.structures.StructReader`.
    Before initialization of the struct, the member `bar` of the newly created structure will be
    set to the value `29`.
    """
    def __init__(self, data): pass


AttrType = TypeVar('AttrType')


class PerInstanceAttribute(Generic[AttrType]):
    def resolve(self, parent, value: Any) -> AttrType:
        return value

    def __init__(self):
        self.__set: Dict[int, Any] = {}
        self.__get: Dict[int, AttrType] = {}

    def __set__(self, parent: Any, value: Any) -> None:
        pid = id(parent)
        if pid not in self.__set:
            def cleanup(self, pid):
                self.__set.pop(pid, None)
                self.__get.pop(pid, None)
            self.__set[pid] = value
            weakref.finalize(parent, cleanup, self, id(parent))

    def __get__(self, parent, tp=None) -> AttrType:
        pid = id(parent)
        if pid not in self.__get:
            try:
                seed = self.__set[pid]
            except KeyError as K:
                raise AttributeError from K
            self.__get[pid] = self.resolve(parent, seed)
        return self.__get[pid]
