#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Interfaces and classes to read structured data.
"""
import struct
import functools
import io

from typing import Union, Tuple, Optional, Iterable


class EOF(ValueError):
    def __init__(self):
        super().__init__('Unexpected end of buffer.')


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


class ByteFile(io.RawIOBase):
    """
    A thin wrapper around (potentially mutable) byte sequences which gives it the
    features of a file-like object.
    """

    __slots__ = ['_data', '_cursor']

    def __init__(self, data: Union[bytearray, bytes, memoryview]):
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
        return self._cursor >= len(self._data)

    def writable(self):
        if self.closed():
            return False
        if isinstance(self._data, memoryview):
            return not self._data.readonly
        return isinstance(self._data, bytearray)

    def read(self, size=-1) -> memoryview:
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

    def readline(self, size=-1):
        beginning, end = self._cursor, len(self._data)
        if size is not None and size >= 0:
            end = beginning + size
        self._cursor = max(self._find_linebreak(beginning, end) + 1, end)
        return self._data[beginning:self._cursor]

    def readlines(self, hint=-1):
        if hint is None or hint < 0:
            yield from self
        else:
            total = 0
            while total < hint:
                line = next(self)
                total += len(line)
                yield line

    def readinto1(self, b) -> int:
        rest = self.read()
        size = len(rest)
        b[:] = rest
        return size

    def readinto(self, b) -> int:
        return self.readinto1(b)

    def tell(self):
        return self._cursor

    def seekrel(self, offset):
        return self.seek(offset, io.SEEK_CUR)

    def getbuffer(self):
        return self._data

    def seek(self, offset, whence=io.SEEK_SET):
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

    def writelines(self, lines):
        for line in lines:
            self.write(line)

    def truncate(self, size=None):
        if size is not None:
            if not (0 <= size < len(self._data)):
                raise ValueError('invalid  size value')
            self._cursor = size
        del self._data[self._cursor:]

    def write(self, data):
        beginning = self._cursor
        self._cursor += len(data)
        self._data[beginning:self._cursor] = data
        return len(data)


class StructReader(ByteFile):

    def __init__(self, *args):
        super().__init__(*args)
        self._bbits = 0
        self._nbits = 0

    def seek(self, offset, whence=io.SEEK_SET):
        self._bbits = 0
        self._nbits = 0
        return super().seek(offset, whence)

    def read(self, size: Optional[int] = None, stash_bits=False):
        if self._nbits > 0 and not stash_bits:
            raise RuntimeError(F'Attempt to perform bytewise read with {self._nbits} bits left in buffer.')
        return super().read(size)

    def read_bit(self) -> int:
        bit, = self.read_bits(1)
        return bit

    def byte_aligned(self) -> bool:
        return not self._nbits

    def byte_align(self) -> None:
        self._nbits = 0
        self._bbits = 0

    def _bitstash(self, nbits) -> None:
        if self._nbits < nbits:
            required = nbits - self._nbits
            bytecount, r = divmod(required, 8)
            if r: bytecount += 1
            self._bbits |= (self.read_bigint(bytecount) << self._nbits)
            self._nbits += bytecount * 8

    def read_fixed_int(self, nbits) -> int:
        self._bitstash(nbits)
        chunk = self._bbits & ((1 << nbits) - 1)
        self._bbits >>= nbits
        self._nbits -= nbits
        return chunk

    def read_bits(self, nbits) -> Iterable[int]:
        self._bitstash(nbits)
        for k in range(nbits):
            yield (self._bbits >> k) & 1
        self._bbits >>= nbits
        self._nbits -= nbits

    def read_struct(self, format) -> Union[Tuple, int, bytes]:
        data = struct.unpack(format, self.read_exactly(struct.calcsize(format)))
        if len(data) == 1:
            return data[0]
        return data

    def read_nibble(self) -> int:
        return self.read_fixed_int(4)

    def read_byte(self) -> int:
        if not self._nbits:
            onebyte = self.read_exactly(1)
            return onebyte[0]
        return self.read_fixed_int(8)

    def read_word(self) -> int:
        if not self._nbits:
            return self.read_struct('<H')
        return self.read_fixed_int(16)

    def read_dword(self) -> int:
        if not self._nbits:
            return self.read_struct('<I')
        return self.read_fixed_int(32)

    def read_qword(self) -> int:
        if not self._nbits:
            return self.read_struct('<Q')
        return self.read_fixed_int(64)

    def read_bigint(self, length, byteorder='little') -> int:
        return int.from_bytes(self.read_exactly(length), byteorder)

    def read_exactly(self, size) -> bytes:
        result = super().read(size)
        if len(result) != size:
            raise EOF
        return result


class StructMeta(type):
    def __init__(cls, name, bases, nmspc):
        super(StructMeta, cls).__init__(name, bases, nmspc)
        original__init__ = cls.__init__

        @functools.wraps(original__init__)
        def wrapped__init__(self, data):
            if not isinstance(data, StructReader):
                data = StructReader(data)
            return original__init__(self, data)

        cls.__init__ = wrapped__init__


class Struct(metaclass=StructMeta):
    def __init__(self, data):
        pass
