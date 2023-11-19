#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Interfaces and classes to read structured data.
"""
from __future__ import annotations

import contextlib
import itertools
import enum
import functools
import io
import re
import struct
import weakref

from typing import List, Union, Tuple, Optional, Iterable, ByteString, TypeVar, Generic, Any, Dict


T = TypeVar('T', bound=Union[bytearray, bytes, memoryview])
UnpackType = Union[int, bool, float, bytes]


def signed(k: int, bits: int):
    M = 1 << bits
    k = k & (M - 1)
    return k - M if k >> (bits - 1) else k


class EOF(EOFError):
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

    def __init__(
        self,
        data: Optional[T] = None,
        read_as_bytes=False,
        fileno: Optional[int] = None,
        size_limit: Optional[int] = None,
    ) -> None:
        if data is None:
            data = bytearray()
        elif size_limit is not None and len(data) > size_limit:
            raise ValueError('Initial data exceeds size limit')
        self._data = data
        self._cursor = 0
        self._closed = False
        self._fileno = fileno
        self.read_as_bytes = read_as_bytes
        self._size_limit = size_limit

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

    @property
    def remaining_bytes(self) -> int:
        return len(self._data) - self.tell()

    def writable(self) -> bool:
        if self._closed:
            return False
        if isinstance(self._data, memoryview):
            return not self._data.readonly
        return isinstance(self._data, bytearray)

    def read(self, size: int = -1, peek: bool = False) -> T:
        beginning = self._cursor
        if size is None or size < 0:
            end = len(self._data)
        else:
            end = min(self._cursor + size, len(self._data))
        result = self._data[beginning:end]
        if self.read_as_bytes and not isinstance(result, bytes):
            result = bytes(result)
        if not peek:
            self._cursor = end
        return result

    def peek(self, size: int = -1) -> memoryview:
        cursor = self._cursor
        mv = memoryview(self._data)
        if size is None or size < 0:
            return mv[cursor:]
        return mv[cursor:cursor + size]

    def read1(self, size: int = -1, peek: bool = False) -> T:
        return self.read(size, peek)

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
            if not (0 <= size <= len(self._data)):
                raise ValueError('invalid size value')
            self._cursor = size
        del self._data[self._cursor:]

    def write_byte(self, byte: int) -> None:
        limit = self._size_limit
        cc = self._cursor
        nc = cc + 1
        if limit and nc > limit:
            raise EOF(bytes((byte,)))
        try:
            if cc < len(self._data):
                self._data[cc] = byte
            else:
                self._data.append(byte)
        except Exception as T:
            raise OSError(str(T)) from T
        else:
            self._cursor = nc

    def write(self, data: Iterable[int]) -> int:
        out = self._data
        end = len(out)
        beginning = self._cursor
        limit = self._size_limit

        if limit is None and beginning == end:
            out[end:] = data
            self._cursor = end = len(out)
            return end - beginning
        try:
            size = len(data)
        except Exception:
            it = iter(data)
            for cursor, b in enumerate(it, beginning):
                out[cursor] = b
                if cursor >= end - 1:
                    break
            else:
                cursor += 1
                self._cursor = cursor
                return cursor - beginning
            if limit is None:
                out[end:] = it
            else:
                out[end:limit] = itertools.islice(it, 0, limit - end)
                try:
                    b = next(it)
                except StopIteration:
                    self._cursor = limit
                    return limit - beginning
                else:
                    rest = bytearray((b,))
                    rest[1:] = it
                    raise EOF(rest)
        else:
            if limit and size + beginning > limit:
                raise EOF(data)
            self._cursor += size
            try:
                self._data[beginning:self._cursor] = data
            except Exception as T:
                self._cursor = beginning
                raise OSError(str(T)) from T
            return size
        self._cursor = end = len(out)
        return end - beginning

    def __getitem__(self, slice):
        result = self._data[slice]
        if self.read_as_bytes and not isinstance(result, bytes):
            result = bytes(result)
        return result

    def replay(self, offset: int, length: int):
        if offset not in range(self._cursor + 1):
            raise ValueError(F'The supplied delta {offset} is not in the valid range [0,{self._cursor}].')
        rep, r = divmod(length, offset)
        offset = -offset - len(self) + self._cursor
        replay = self._data[offset:offset + r]
        if rep > 0:
            replay = bytes(self._data[offset:self._cursor]) * rep + replay
        self.write(replay)


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

    @property
    def byteorder_format(self) -> str:
        return '>' if self.bigendian else '<'

    @property
    def byteorder_name(self) -> str:
        return 'big' if self.bigendian else 'little'

    def seek(self, offset, whence=io.SEEK_SET) -> int:
        self._bbits = 0
        self._nbits = 0
        return super().seek(offset, whence)

    def read_exactly(self, size: Optional[int] = None, peek: bool = False) -> T:
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
        data = self.read1(size, peek)
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

    def read_integer(self, length: int, peek: bool = False) -> int:
        """
        Read `length` many bits from the underlying stream as an integer.
        """
        if length < self._nbits:
            new_count = self._nbits - length
            if self.bigendian:
                result = self._bbits >> new_count
                if not peek:
                    self._bbits ^= result << new_count
            else:
                result = self._bbits & 2 ** length - 1
                if not peek:
                    self._bbits >>= length
            if not peek:
                self._nbits = new_count
            return result

        nbits, bbits = self.byte_align()
        number_of_missing_bits = length - nbits
        bytecount, rest = divmod(number_of_missing_bits, 8)
        if rest:
            bytecount += 1
            rest = 8 - rest
        if bytecount == 1:
            result, = self.read_exactly(1, peek)
        else:
            result = int.from_bytes(self.read_exactly(bytecount, peek), self.byteorder_name)
        if not nbits and not rest:
            return result
        if self.bigendian:
            rbmask   = 2 ** rest - 1       # noqa
            excess   = result & rbmask     # noqa
            result >>= rest                # noqa
            result  ^= bbits << number_of_missing_bits   # noqa
        else:
            excess   = result >> number_of_missing_bits  # noqa
            result  ^= excess << number_of_missing_bits  # noqa
            result <<= nbits               # noqa
            result  |= bbits               # noqa
        assert excess.bit_length() <= rest
        if not peek:
            self._nbits = rest
            self._bbits = excess
        return result

    def read_bytes(self, size: int, peek: bool = False) -> bytes:
        """
        The method reads `size` many bytes from the underlying stream starting at the current bit.
        """
        if self.byte_aligned:
            data = self.read_exactly(size, peek)
            if not isinstance(data, bytes):
                data = bytes(data)
            return data
        else:
            return self.read_integer(size * 8, peek).to_bytes(size, self.byteorder_name)

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

    def read_struct(self, spec: str, unwrap=False, peek=False) -> Union[List[UnpackType], UnpackType]:
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
        current_cursor = self.tell()

        # reserved struct characters: xcbB?hHiIlLqQnNefdspP
        for k, part in enumerate(re.split('(\\d*[auwE])', spec)):
            if k % 2 == 1:
                count = 1 if len(part) == 1 else int(part[:~0])
                part = part[~0]
                for _ in range(count):
                    if part == 'a':
                        data.append(self.read_c_string())
                    elif part == 'u':
                        data.append(self.read_w_string())
                    elif part == 'w':
                        data.append(self.read_w_string().decode('utf-16le'))
                    elif part == 'E':
                        data.append(self.read_7bit_encoded_int())
                continue
            else:
                part = F'{byteorder}{part}'
                data.extend(struct.unpack(part, self.read_bytes(struct.calcsize(part))))
        if unwrap and len(data) == 1:
            return data[0]
        if peek:
            self.seekset(current_cursor)
        return data

    def read_nibble(self, peek: bool = False) -> int:
        """
        Calls `refinery.lib.structures.StructReader.read_integer` with an argument of `4`.
        """
        return self.read_integer(4, peek)

    def u8(self, peek: bool = False) -> int: return self.read_integer(8, peek)
    def i8(self, peek: bool = False) -> int: return signed(self.read_integer(8, peek), 8)

    def u16(self, peek: bool = False) -> int: return self.read_integer(16, peek)
    def u32(self, peek: bool = False) -> int: return self.read_integer(32, peek)
    def u64(self, peek: bool = False) -> int: return self.read_integer(64, peek)
    def i16(self, peek: bool = False) -> int: return signed(self.read_integer(16, peek), 16)
    def i32(self, peek: bool = False) -> int: return signed(self.read_integer(32, peek), 32)
    def i64(self, peek: bool = False) -> int: return signed(self.read_integer(64, peek), 64)

    def f32(self, peek: bool = False) -> float: return self.read_struct('f', unwrap=True, peek=peek)
    def f64(self, peek: bool = False) -> float: return self.read_struct('d', unwrap=True, peek=peek)

    def read_byte(self, peek: bool = False) -> int: return self.read_integer(8, peek)
    def read_char(self, peek: bool = False) -> int: return signed(self.read_integer(8, peek), 8)

    def read_terminated_array(self, terminator: bytes, alignment: int = 1) -> bytearray:
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
                result.extend(self.read_bytes(alignment))
                if result.endswith(terminator):
                    return result[:-len(terminator)]
            self.seek(pos)
            raise EOF
        else:
            data = self.read_exactly(end - pos)
            self.seekrel(len(terminator))
            return bytearray(data)

    def read_c_string(self, encoding=None) -> Union[str, bytearray]:
        data = self.read_terminated_array(B'\0')
        if encoding is not None:
            data = data.decode(encoding)
        return data

    def read_w_string(self, encoding=None) -> Union[str, bytearray]:
        data = self.read_terminated_array(B'\0\0', 2)
        if encoding is not None:
            data = data.decode(encoding)
        return data

    def read_length_prefixed_ascii(self, prefix_size: int = 32):
        return self.read_length_prefixed(prefix_size, 'latin1')

    def read_length_prefixed_utf8(self, prefix_size: int = 32):
        return self.read_length_prefixed(prefix_size, 'utf8')

    def read_length_prefixed_utf16(self, prefix_size: int = 32, bytecount: bool = False):
        block_size = 1 if bytecount else 2
        return self.read_length_prefixed(prefix_size, 'utf-16le', block_size)

    def read_length_prefixed(self, prefix_size: int = 32, encoding: Optional[str] = None, block_size: int = 1) -> Union[T, str]:
        prefix = self.read_integer(prefix_size) * block_size
        data = self.read(prefix)
        if encoding is not None:
            data = data.decode(encoding)
        return data

    def read_7bit_encoded_int(self, max_bits: int = 0) -> int:
        value = 0
        for shift in itertools.count(0, step=7):
            b = self.read_byte()
            value |= (b & 0x7F) << shift
            if not b & 0x80:
                return value
            if shift > max_bits > 0:
                raise RuntimeError('Maximum bits were exceeded by encoded integer.')


class StructMeta(type):
    """
    A metaclass to facilitate the behavior outlined for `refinery.lib.structures.Struct`.
    """
    def __new__(mcls, name, bases, nmspc, parser=StructReader):
        return type.__new__(mcls, name, bases, nmspc)

    def __init__(cls, name, bases, nmspc, parser=StructReader):
        super(StructMeta, cls).__init__(name, bases, nmspc)
        original__init__ = cls.__init__

        @functools.wraps(original__init__)
        def wrapped__init__(self: Struct, reader, *args, **kwargs):
            if not isinstance(reader, parser):
                if issubclass(parser, reader.__class__):
                    raise ValueError(
                        F'A reader of type {reader.__class__.__name__} was passed to {cls.__name__}, '
                        F'but a {parser.__name__} is required.')
                reader = parser(reader)
            start = reader.tell()
            view = memoryview(reader.getbuffer())
            original__init__(self, reader, *args, **kwargs)
            self._data = view[start:reader.tell()]

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
    _data: Union[memoryview, bytearray]

    def __len__(self):
        return len(self._data)

    def __bytes__(self):
        return bytes(self._data)

    def get_data(self, decouple=False):
        if decouple and isinstance(self._data, memoryview):
            self._data = bytearray(self._data)
        return self._data

    def __init__(self, reader: StructReader):
        pass


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
