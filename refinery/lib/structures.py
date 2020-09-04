#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Interfaces and classes to read structured data.
"""
import struct
import functools
import io
import enum
import weakref

from typing import Union, Tuple, Optional, Iterable, ByteString, TypeVar, Generic, Any, Dict


class EOF(ValueError):
    def __init__(self, rest: ByteString = B''):
        super().__init__('Unexpected end of buffer.')
        self.rest = rest

    def __bytes__(self):
        return bytes(self.rest)


class StreamDetour:
    def __init__(self, stream, offset=None, whence=io.SEEK_SET):
        self._stream = stream
        self._offset = offset
        self._whence = whence

    def __enter__(self):
        self._cursor = self._stream.tell()
        if self._offset is not None:
            self._stream.seek(self._offset, self._whence)
        return self

    def __exit__(self, *args):
        self._stream.seek(self._cursor, io.SEEK_SET)


class MemoryFile(io.RawIOBase):
    """
    A thin wrapper around (potentially mutable) byte sequences which gives it the
    features of a file-like object.
    """

    __slots__ = ['_data', '_cursor']

    def __init__(self, data: Optional[ByteString] = None):
        if data is None:
            data = bytearray()
        self._data = data
        self._cursor = 0

    def close(self):
        self._data = None

    def closed(self):
        return self._data is None

    def __enter__(self):
        return self

    def __exit__(self, ex_type, ex_value, trace):
        return False

    def flush(self):
        pass

    def isatty(self):
        return False

    def __iter__(self):
        return self

    def __next__(self):
        line = self.readline()
        if not line:
            raise StopIteration
        return line

    def fileno(self) -> int:
        raise OSError

    def readable(self):
        return not self.closed()

    def seekable(self):
        return not self.closed()

    @property
    def eof(self) -> bool:
        return self.closed() or self._cursor >= len(self._data)

    def writable(self):
        if self.closed():
            return False
        if isinstance(self._data, memoryview):
            return not self._data.readonly
        return isinstance(self._data, bytearray)

    def read(self, size=-1) -> ByteString:
        return self.read1(size)

    def read1(self, size=-1) -> ByteString:
        beginning = self._cursor
        if size is None or size < 0:
            self._cursor = len(self._data)
        else:
            self._cursor = min(self._cursor + size, len(self._data))
        return self._data[beginning:self._cursor]

    def _find_linebreak(self, beginning: int, end: int) -> int:
        if not isinstance(self._data, memoryview):
            return self._data.find(B'\n', beginning, end)
        for k in range(beginning, end):
            if self._data[k] == 0xA: return k
        return -1

    def readline(self, size=-1) -> ByteString:
        beginning, end = self._cursor, len(self._data)
        if size is not None and size >= 0:
            end = beginning + size
        p = self._find_linebreak(beginning, end)
        self._cursor = end if p < 0 else p + 1
        return self._data[beginning:self._cursor]

    def readlines(self, hint=-1) -> Iterable[ByteString]:
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

    def seekrel(self, offset) -> int:
        return self.seek(offset, io.SEEK_CUR)

    def getbuffer(self) -> ByteString:
        return self._data

    def getvalue(self) -> ByteString:
        return self._data

    def seek(self, offset, whence=io.SEEK_SET) -> int:
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

    def writelines(self, lines) -> None:
        for line in lines:
            self.write(line)

    def truncate(self, size=None) -> None:
        if size is not None:
            if not (0 <= size < len(self._data)):
                raise ValueError('invalid size value')
            self._cursor = size
        del self._data[self._cursor:]

    def write(self, data) -> int:
        beginning = self._cursor
        self._cursor += len(data)
        try:
            self._data[beginning:self._cursor] = data
        except Exception as T:
            self._cursor = beginning
            raise OSError(str(T)) from T
        return len(data)


class bitorder(str, enum.Enum):
    big = 'big'
    little = 'little'


class StructReader(MemoryFile):
    """
    An extension of a `refinery.lib.structures.MemoryFile` which provides methods to
    read structured data.
    """

    class Unaligned(RuntimeError):
        pass

    def __init__(self, data: Union[bytearray, bytes, memoryview], bo='little'):
        super().__init__(data)
        self._bbits = 0
        self._nbits = 0
        self.bitorder = bitorder(bo)

    def set_bitorder_big(self):
        self.bitorder = bitorder.big

    def set_bitorder_little(self):
        self.bitorder = bitorder.little

    def readinto(self, b):
        size = super().readinto(b)
        if size != len(b):
            raise EOF
        return size

    @property
    def byteorder_format(self) -> str:
        return '<>'[int(self.bitorder is bitorder.big)]

    def seek(self, offset, whence=io.SEEK_SET):
        self._bbits = 0
        self._nbits = 0
        return super().seek(offset, whence)

    def read1(self, size: Optional[int] = None):
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

    def byte_align(self, blocksize=1) -> Tuple[int, int]:
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

    def read_integer(self, length) -> int:
        """
        Read `length` many bits from the underlying stream as an integer.
        """
        if length < self._nbits:
            self._nbits -= length
            if self.bitorder is bitorder.little:
                result = self._bbits & 2 ** length - 1
                self._bbits >>= length
            else:
                result = self._bbits >> self._nbits
                self._bbits ^= result << self._nbits
            return result
        nbits, bbits = self.byte_align()
        required = length - nbits
        bytecount, rest = divmod(required, 8)
        if rest:
            bytecount += 1
            rest = 8 - rest
        result = int.from_bytes(self.read(bytecount), self.bitorder)
        if not nbits and not rest:
            return result
        if self.bitorder is bitorder.little:
            excess   = result >> required  # noqa
            result  ^= excess << required  # noqa
            result <<= nbits               # noqa
            result  |= bbits               # noqa
        else:
            rbmask   = 2 ** rest - 1       # noqa
            excess   = result & rbmask     # noqa
            result >>= rest                # noqa
            result  ^= bbits << required   # noqa
        assert excess.bit_length() <= rest
        self._nbits = rest
        self._bbits = excess
        return result

    def read_bytes(self, size) -> bytes:
        """
        The method reads `size` many bytes from the underlying stream starting at the current bit.
        """
        if self.byte_aligned:
            return self.read(size)
        return self.read_integer(size * 8).to_bytes(size, self.bitorder)

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

    def read_struct(self, format: str, unwrap=False) -> Union[Tuple, int, bool, float, bytes]:
        """
        Read structured data from the stream in any format supported by the `struct` module. If the `format`
        argument does not specify a byte order, then `refinery.lib.structures.StructReader.bitorder` will be
        used to determine a format. If the `unwrap` parameter is `True`, a single unpacked value will be
        returned as a scalar, not as a tuple with one element.
        """
        if not format:
            raise ValueError('no format specified')
        if format[:1] not in '<!=@>':
            format = F'{self.byteorder_format}{format}'
        data = struct.unpack(format, self.read_bytes(struct.calcsize(format)))
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
