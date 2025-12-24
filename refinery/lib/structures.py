"""
Interfaces and classes to read structured data.
"""
from __future__ import annotations

import abc
import codecs
import contextlib
import enum
import functools
import inspect
import io
import itertools
import re
import struct
import sys
import weakref

from typing import (
    TYPE_CHECKING,
    Any,
    Generic,
    Iterable,
    NamedTuple,
    Sized,
    TypeVar,
    Union,
    cast,
    get_origin,
    overload,
)
from uuid import UUID

from refinery.lib.id import buffer_offset

if TYPE_CHECKING:
    from typing import Generator, Protocol, Self

    from refinery.lib.types import JSON, buf

    T = TypeVar('T', bound=Union[bytearray, bytes, memoryview])
    B = TypeVar('B', bound=Union[bytearray, bytes, memoryview], default=T)
    C = TypeVar('C', bound=Union[bytearray, bytes, memoryview])
    R = TypeVar('R', bound=io.IOBase)
else:
    Protocol = abc.ABC
    T = TypeVar('T')
    B = TypeVar('B')
    C = TypeVar('C')
    R = TypeVar('R')

if sys.version_info >= (3, 12):
    from collections.abc import Buffer
else:
    Buffer = object


class ToJSON(Protocol):
    @abc.abstractmethod
    def __json__(self) -> JSON:
        raise NotImplementedError


UnpackType = Union[int, bool, float, bytes]


def signed(k: int, bitsize: int):
    """
    If `k` is an integer of the given bit size, cast it to a signed one.
    """
    M = 1 << bitsize
    k = k & (M - 1)
    return k - M if k >> (bitsize - 1) else k


class EOF(EOFError):
    """
    While reading from a `refinery.lib.structures.MemoryFile`, less bytes were available than
    requested. The exception contains the data from the incomplete read.
    """
    def __init__(self, size: int, rest: buf = B''):
        super().__init__(F'Unexpected end of buffer; attempted to read {size} bytes, but got only {len(rest)}.')
        self.rest = rest
        self.size = size

    def __bytes__(self):
        return bytes(self.rest)


class LimitExceeded(EOFError):
    """
    While writing to a `refinery.lib.structures.MemoryFile`, the buffer limit was exceeded.
    """
    def __init__(self, rest: buf = B''):
        super().__init__(F'Unable to write {len(rest)} data to stream due to limit.')
        self.rest = rest

    def __bytes__(self):
        return bytes(self.rest)


class StreamDetour(Generic[R]):
    """
    A stream detour is used as a context manager to temporarily read from a different location
    in the stream and then return to the original offset when the context ends.
    """
    def __init__(self, stream: R, offset: int | None = None, whence: int = io.SEEK_SET):
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


class MemoryFileMethods(Generic[T, B]):
    """
    A thin wrapper around (potentially mutable) byte sequences which gives it the features of a
    file-like object.
    """
    # TODO: This sadly breaks everything. It would provide minor performance gains for e.g.
    #       decompression routines where tight loops with access to a binary reader dominate
    #       the runtime; so it is a nice to have, not a must.
    # __slots__ = (
    #     '_data',
    #     '_name',
    #     '_output',
    #     '_cursor',
    #     '_closed',
    #     '_maxlen',
    #     '_fileno',
    # )

    _data: T
    _name: str

    _output: type[B]
    _cursor: int
    _closed: bool
    _fileno: int | None
    _maxlen: int | None

    class SEEK(int, enum.Enum):
        CUR = io.SEEK_CUR
        END = io.SEEK_END
        SET = io.SEEK_SET

    def __bytes__(self):
        return bytes(self._data)

    def __init__(
        self,
        data: T | MemoryFileMethods[T, B] | type[T] = bytearray,
        output: type[B] | None = None,
        fileno: int | None = None,
        maxlen: int | None = None,
        name: str = '',
    ) -> None:
        if isinstance(data, type):
            if not issubclass(data, bytearray):
                raise TypeError(data.__name__)
            _data = data()
        else:
            _data = data
        if isinstance(_data, (bytearray, bytes, memoryview)):
            if output is None:
                if TYPE_CHECKING:
                    output = cast(type[B], type(_data))
                else:
                    output = type(_data)
            if maxlen is not None and len(_data) > maxlen:
                raise ValueError('Initial data exceeds size limit')
            self._output = output
            self._cursor = 0
            self._closed = False
            self._fileno = fileno
            self._maxlen = maxlen
            self._data = _data
            self._name = name
        elif isinstance(_data, MemoryFileMethods):
            self._output = output or _data._output
            self._cursor = _data._cursor
            self._closed = _data._closed
            self._fileno = fileno or _data._fileno
            self._maxlen = maxlen or _data._maxlen
            self._data = _data._data
            self._name = _data._name
        else:
            raise TypeError(F'Invalid input: {data!r}.')

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, name: str):
        self._name = name

    @property
    def mode(self):
        return 'r+b'

    def close(self) -> None:
        self._closed = True

    @property
    def closed(self) -> bool:
        return self._closed

    def __enter__(self):
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

    def detour(self, offset: int | None = None, whence: int = io.SEEK_SET):
        return StreamDetour(cast(io.IOBase, self), offset, whence=whence)

    def detour_absolute(self, offset: int | None = None):
        return self.detour(offset, io.SEEK_SET)

    def detour_relative(self, offset: int | None = None):
        return self.detour(offset, io.SEEK_CUR)

    def detour_from_end(self, offset: int | None = None):
        return self.detour(offset, io.SEEK_END)

    def writable(self) -> bool:
        if self._closed:
            return False
        if isinstance(self._data, memoryview):
            return not self._data.readonly
        return isinstance(self._data, bytearray)

    def read_as(self, cast: type[C], size: int = -1, peek: bool = False) -> C:
        out = self.read(size, peek)
        if not isinstance(out, cast):
            out = cast(out)
        return out

    def read(self, size: int | None = None, peek: bool = False) -> B:
        beginning = self._cursor
        if size is None or size < 0:
            end = len(self._data)
        else:
            end = min(self._cursor + size, len(self._data))
        result = self._data[beginning:end]
        if not isinstance(result, t := self._output):
            result = t(result)
        if not peek:
            self._cursor = end
        return result

    def readif(self, value: bytes) -> bool:
        size = len(value)
        stop = self._cursor + size
        mv = memoryview(self._data)
        if match := mv[self._cursor:stop] == value:
            self._cursor = stop
        return match

    def peek(self, size: int | None = None) -> memoryview:
        cursor = self._cursor
        mv = memoryview(self._data)
        if size is None or size < 0:
            return mv[cursor:]
        return mv[cursor:cursor + size]

    def read1(self, size: int | None = None, peek: bool = False) -> B:
        return self.read(size, peek)

    def readline(self, size: int | None = None) -> B:
        beginning, end = self._cursor, len(self._data)
        if size is not None and size >= 0:
            end = beginning + size
        p = buffer_offset(self._data, B'\n', beginning, end)
        self._cursor = end if p < 0 else p + 1
        result = self._data[beginning:self._cursor]
        if not isinstance(result, t := self._output):
            result = t(result)
        return result

    def readlines_iter(self, hint: int | None = None) -> Iterable[B]:
        if hint is None or hint < 0:
            yield from self
        else:
            total = 0
            while total < hint:
                line = next(self)
                total += len(line)
                yield line

    def readlines(self, hint: int | None = None) -> list[bytes]:
        it = self.readlines_iter(hint)
        if issubclass(self._output, bytes):
            return list(it)
        return [bytes(t) for t in it]

    def readinto1(self, b) -> int:
        data = self.read(len(b))
        size = len(data)
        b[:size] = data
        return size

    def readinto(self, b) -> int:
        return self.readinto1(b)

    def tell(self) -> int:
        return self._cursor

    def skip(self, n: int):
        self._cursor += n

    def seekrel(self, offset: int) -> int:
        return self.seek(offset, io.SEEK_CUR)

    def seekend(self, offset: int) -> int:
        return self.seek(offset, io.SEEK_END)

    def seekset(self, offset: int) -> int:
        if offset < 0:
            return self.seek(offset, io.SEEK_END)
        else:
            return self.seek(offset, io.SEEK_SET)

    def getbuffer(self) -> memoryview:
        return memoryview(self._data)

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

    def writelines(self, lines: Iterable[Iterable[int]] | Iterable[Buffer]) -> None:
        for line in lines:
            self.write(line)

    def truncate(self, size: int | None = None) -> int:
        if not isinstance(self._data, bytearray):
            raise TypeError
        if size is not None:
            if not (0 <= size <= len(self._data)):
                raise ValueError('invalid size value')
            self._cursor = size
        del self._data[self._cursor:]
        return self.tell()

    def write_byte(self, byte: int) -> None:
        if isinstance(self._data, bytes):
            raise TypeError
        if isinstance(self._data, memoryview):
            raise NotImplementedError
        limit = self._maxlen
        cc = self._cursor
        nc = cc + 1
        if limit and nc > limit:
            raise LimitExceeded(bytes((byte,)))
        try:
            if cc < len(self._data):
                self._data[cc] = byte
            else:
                self._data.append(byte)
        except Exception as T:
            raise OSError(str(T)) from T
        else:
            self._cursor = nc

    def write(self, _data: Buffer | Iterable[int]) -> int:
        out = self._data
        end = len(out)

        if isinstance(out, memoryview):
            if out.readonly:
                raise PermissionError
            out = out.obj
        if not isinstance(out, bytearray):
            raise PermissionError

        try:
            getbuf = cast('Buffer', _data).__buffer__
        except AttributeError:
            data = cast('Iterable[int]', _data)
        else:
            data = getbuf(0)

        beginning = self._cursor
        limit = self._maxlen

        if limit is None and beginning == end:
            out[end:] = data
            self._cursor = end = len(out)
            return end - beginning
        try:
            size = len(cast(Sized, data))
        except Exception:
            it = iter(data)
            cursor = 0
            for cursor, b in enumerate(it, beginning):
                out[cursor] = b
                if cursor >= end - 1:
                    break
            else:
                cursor += 1
                self._cursor = cursor
                return cursor - beginning
            if limit is None:
                out[end:] = bytes(it)
            else:
                out[end:limit] = bytes(itertools.islice(it, 0, limit - end))
                try:
                    b = next(it)
                except StopIteration:
                    self._cursor = limit
                    return limit - beginning
                else:
                    rest = bytearray((b,))
                    rest[1:] = it
                    raise LimitExceeded(rest)
        else:
            if limit and size + beginning > limit:
                raise LimitExceeded(bytes(data))
            self._cursor += size
            try:
                out[beginning:self._cursor] = data
            except Exception as T:
                self._cursor = beginning
                raise OSError(str(T)) from T
            return size
        self._cursor = end = len(out)
        return end - beginning

    def __getitem__(self, slice):
        result = self._data[slice]
        if not isinstance(result, t := self._output):
            result = t(result)
        return result

    def replay(self, offset: int, length: int):
        cursor = self._cursor
        if offset not in range(cursor + 1):
            raise ValueError(F'The supplied delta {offset} is not in the valid range [0,{self._cursor}].')
        rep, r = divmod(length, offset)
        offset = cursor - offset
        replay = self._data[offset:offset + r]
        if rep > 0:
            # While this is technically a copy, it is faster than repeated calls to write.
            replay = bytes(self._data[offset:cursor]) * rep + replay
        self.write(replay)


class MemoryFile(MemoryFileMethods[T, B], io.BytesIO):
    pass


class order(str, enum.Enum):
    big = '>'
    little = '<'


class StructReader(MemoryFile[T, T]):
    """
    An extension of a `refinery.lib.structures.MemoryFile` which provides methods to read
    structured data.
    """
    __slots__ = 'bigendian',

    class Unaligned(RuntimeError):
        pass

    def __init__(self, data: T | StructReader[T], bigendian: bool | None = None):
        super().__init__(data)
        if bigendian is None:
            if isinstance(data, StructReader):
                bigendian = data.bigendian
            else:
                bigendian = False
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
    def byteorder_name(self):
        return 'big' if self.bigendian else 'little'

    def read_exactly(self, size: int | None = None, peek: bool = False) -> T:
        """
        Read bytes from the underlying stream. Raises a `RuntimeError` when the stream is not currently
        byte-aligned, i.e. when `refinery.lib.structures.StructReader.bits_in_buffer` is positive. Raises
        an exception of type `refinery.lib.structures.EOF` when fewer data is available in the stream than
        requested via the `size` parameter. The remaining data can be extracted from the exception.
        Use `refinery.lib.structures.StructReader.read_bytes` to read bytes from the stream when it is
        not byte-aligned.
        """
        data = self.read(size, peek)
        if size and len(data) < size:
            raise EOF(size, data)
        return data

    def read_bit_field(self, *sizes: int, peek: bool = False):
        """
        Read multiple integers that form a bit field. This method can be used to read bit fields without
        having to use a `refinery.lib.structures.StructReaderBits` when the bit count sums to a multiple
        of 8.
        """
        data = self.read_integer(sum(sizes))
        if self.bigendian:
            sizes = sizes[::-1]
        fields = []
        for size in sizes:
            fields.append(data & ~(-1 << size))
            data >>= size
        if self.bigendian:
            fields.reverse()
        return fields

    def read_integer(
        self,
        size: int,
        peek: bool = False,
        signed: bool = False
    ) -> int:
        """
        Read an integer of the given size (in bytes) from the stream.
        """
        nbytes, rest = divmod(size, 8)
        if rest > 0:
            raise ValueError(
                F'A {self.__class__.__name__} cannot read {size} bit{"s" * (size > 1)}, only multiples of 8 are possible.')
        data = self.read(nbytes, peek)
        if len(data) < nbytes:
            raise EOF(nbytes, data)
        return int.from_bytes(data, self.byteorder_name, signed=signed)

    def byte_align(self, blocksize: int = 1):
        """
        Align the cursor at the given block size boundary.
        """
        if mod := -self._cursor % blocksize:
            self.seekrel(mod)

    def read_bytes(self, size: int, peek: bool = False) -> bytes:
        """
        The method reads `size` many bytes from the underlying stream starting at the current bit.
        """
        data = self.read_exactly(size, peek)
        if not isinstance(data, bytes):
            data = bytes(data)
        return data

    def read_one_struct(self, spec: str, peek=False) -> UnpackType:
        item, = self.read_struct(spec, peek=peek)
        return item

    def read_struct(self, spec: str, peek=False) -> list[UnpackType]:
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
        for k, part in enumerate(re.split('(\\d*[auwgk])', spec)):
            if k % 2 == 1:
                count = 1 if len(part) == 1 else int(part[:~0])
                part = part[~0]
                for _ in range(count):
                    if part == 'a':
                        data.append(self.read_c_string())
                    elif part == 'g':
                        data.append(str(self.read_guid()))
                    elif part == 'u':
                        data.append(self.read_w_string())
                    elif part == 'w':
                        data.append(codecs.decode(self.read_w_string(), 'utf-16le'))
                    elif part == 'k':
                        data.append(self.read_7bit_encoded_int())
                continue
            else:
                part = F'{byteorder}{part}'
                data.extend(struct.unpack(part, self.read_bytes(struct.calcsize(part))))
        if peek:
            self.seekset(current_cursor)
        return data

    def read_bool_byte(self, strict=False):
        value = self.u8()
        if strict and value not in (0, 1):
            raise ValueError(F'Invalid boolean byte value {value:#02x}.')
        return bool(value)

    def read_regex(
        self,
        pattern: bytes | bytearray | memoryview | re.Pattern[bytes],
        dotall: bool = True
    ):
        if isinstance(pattern, (bytes, bytearray, memoryview)):
            flags = re.DOTALL if dotall else re.NOFLAG
            pattern = re.compile(bytes(pattern), flags=flags)
        elif dotall and not re.DOTALL | pattern.flags:
            pattern = re.compile(pattern.pattern, flags=re.DOTALL)
        data = self._data
        if isinstance(data, memoryview) and not data.contiguous:
            raise NotImplementedError('Cannot perform regex-based read on non-contiguous buffer.')
        if result := pattern.match(data, self._cursor):
            self._cursor = result.end()
            return result

    def read_byte(self, peek: bool = False) -> int:
        try:
            b = self._data[self._cursor]
        except IndexError:
            raise EOF(1)
        if not peek:
            self._cursor += 1
        return b

    def read_char(self, peek: bool = False) -> str:
        try:
            b = self._data[self._cursor]
        except IndexError:
            raise EOF(1)
        if not peek:
            self._cursor += 1
        return chr(b)

    def u8fast(self):
        c = self._cursor
        b = self._data[c]
        self._cursor = c + 1
        return b

    u8 = read_byte

    def i8(self, peek: bool = False) -> int:
        return signed(self.u8(peek), 8)

    def u16(self, peek: bool = False) -> int:
        return self.read_integer(16, peek, signed=False)

    def u32(self, peek: bool = False) -> int:
        return self.read_integer(32, peek, signed=False)

    def u64(self, peek: bool = False) -> int:
        return self.read_integer(64, peek, signed=False)

    def i16(self, peek: bool = False) -> int:
        return self.read_integer(16, peek, signed=True)

    def i32(self, peek: bool = False) -> int:
        return self.read_integer(32, peek, signed=True)

    def i64(self, peek: bool = False) -> int:
        return self.read_integer(64, peek, signed=True)

    def f32(self, peek: bool = False) -> float:
        return cast(float, self.read_one_struct('f', peek=peek))

    def f64(self, peek: bool = False) -> float:
        return cast(float, self.read_one_struct('d', peek=peek))

    def read_terminated_array(self, terminator: bytes, alignment: int = 1) -> T:
        buf = self.getvalue()
        pos = self.tell()
        end = pos - 1
        n = len(terminator)
        while True:
            end = buffer_offset(buf, terminator, end + 1)
            if end < 0 or not (end - pos) % alignment:
                break
        if end >= pos:
            result = self.read_exactly(end - pos)
            self.skip(n)
            return result
        raise EOF(len(buf) - pos + n)

    def read_guid(self) -> UUID:
        return UUID(bytes_le=self.read_bytes(16))

    def read_uuid(self) -> UUID:
        return UUID(bytes=self.read_bytes(16))

    @overload
    def read_c_string(self) -> T:
        ...

    @overload
    def read_c_string(self, encoding: str) -> str:
        ...

    def read_c_string(self, encoding=None) -> str | T:
        data = self.read_terminated_array(B'\0')
        if encoding is not None:
            data = codecs.decode(data, encoding)
        return data

    @overload
    def read_w_string(self) -> T:
        ...

    @overload
    def read_w_string(self, encoding: str) -> str:
        ...

    def read_w_string(self, encoding=None) -> str | T:
        data = self.read_terminated_array(B'\0\0', 2)
        if encoding is not None:
            data = codecs.decode(data, encoding)
        return data

    def read_length_prefixed_ascii(self, prefix_size: int = 32):
        return self.read_length_prefixed(prefix_size, 'latin1')

    def read_length_prefixed_utf8(self, prefix_size: int = 32):
        return self.read_length_prefixed(prefix_size, 'utf8')

    def read_length_prefixed_utf16(self, prefix_size: int = 32, bytecount: bool = False):
        block_size = 1 if bytecount else 2
        return self.read_length_prefixed(prefix_size, 'utf-16le', block_size)

    @overload
    def read_length_prefixed(self, *, encoding: str, prefix_size: int = 32, block_size: int = 1) -> str:
        ...

    @overload
    def read_length_prefixed(self, prefix_size: int, encoding: str, block_size: int = 1) -> str:
        ...

    @overload
    def read_length_prefixed(self, *, prefix_size: int = 32, block_size: int = 1) -> T:
        ...

    @overload
    def read_length_prefixed(self, prefix_size: int, *, block_size: int = 1) -> T:
        ...

    def read_length_prefixed(self, prefix_size: int = 32, encoding: str | None = None, block_size: int = 1) -> T | str:
        prefix = self.read_integer(prefix_size) * block_size
        data = self.read(prefix)
        if encoding is not None:
            data = codecs.decode(data, encoding)
        return data

    def read_7bit_encoded_int(self, max_bits: int = 0, bigendian: bool | None = None) -> int:
        value = 0
        shift = 0
        if bigendian is None:
            bigendian = self.bigendian
        while True:
            b = self.u8()
            if bigendian:
                value <<= 7
                value |= (b & 0x7F)
            else:
                value |= (b & 0x7F) << shift
            if not b & 0x80:
                return value
            if (shift := shift + 7) > max_bits > 0:
                raise OverflowError('Maximum bits were exceeded by encoded integer.')

    def read_bits(self, nbits: int) -> Iterable[int]:
        """
        This method returns the bits of `refinery.lib.structures.StructReader.read_integer` one by one.
        """
        chunk = self.read_integer(nbits)
        it = range(nbits - 1, -1, -1) if self.bigendian else range(nbits)
        for k in it:
            yield chunk >> k & 1

    def read_flags(self, nbits: int, reverse=False) -> Iterable[bool]:
        """
        Identical to `refinery.lib.structures.StructReader.read_bits` with every bit value cast to a boolean.
        """
        bits = self.read_bits(nbits)
        if reverse:
            bits = list(bits)
            bits.reverse()
        for bit in bits:
            yield bool(bit)


class StructReaderBits(StructReader[T]):
    __slots__ = '_bbits', '_nbits'

    def __init__(self, data: T | StructReader[T], bigendian: bool | None = None):
        super().__init__(data, bigendian)
        if isinstance(data, StructReaderBits):
            self._bbits = data._bbits
            self._nbits = data._nbits
        else:
            self._bbits = 0
            self._nbits = 0

    @property
    def remaining_bits(self) -> int:
        return 8 * self.remaining_bytes + self._nbits

    @property
    def bits_in_buffer(self) -> int:
        """
        This property is `True` if and only if there are currently no bits still waiting in the internal
        bit buffer.
        """
        return self._nbits

    def read_bytes(self, size: int, peek: bool = False) -> bytes:
        """
        The method reads `size` many bytes from the underlying stream starting at the current bit.
        """
        if self.bits_in_buffer:
            return self.read_integer(size * 8, peek).to_bytes(size, self.byteorder_name)
        return super().read_bytes(size, peek)

    def byte_align(self, blocksize: int = 1):
        """
        This method clears the internal bit buffer and moves the cursor to the next byte. It returns a
        tuple containing the size and contents of the bit buffer.
        """
        self._nbits = 0
        self._bbits = 0
        super().byte_align(blocksize)

    def read_exactly(self, size: int | None = None, peek: bool = False) -> T:
        if self.bits_in_buffer:
            raise StructReader.Unaligned('The bit buffer is not empty.')
        return super().read_exactly(size, peek)

    def seek(self, offset, whence=io.SEEK_SET) -> int:
        self._bbits = 0
        self._nbits = 0
        return super().seek(offset, whence)

    def read_integer(
        self,
        size: int | None = None,
        peek: bool = False,
        signed: bool = False,
    ) -> int:
        """
        Read `size` many bits from the underlying stream as an integer.
        """
        if size is None:
            size = self.remaining_bits
        if size < self._nbits:
            new_count = self._nbits - size
            if self.bigendian:
                result = self._bbits >> new_count
                if not peek:
                    self._bbits ^= result << new_count
            else:
                result = self._bbits & 2 ** size - 1
                if not peek:
                    self._bbits >>= size
            if not peek:
                self._nbits = new_count
        else:
            nbits, bbits = self._nbits, self._bbits
            needed = size - nbits
            bytecount, rest = divmod(needed, 8)
            if rest:
                bytecount += 1
                rest = 8 - rest
            bb = self.read(bytecount, True)
            if len(bb) != bytecount:
                raise EOF(bytecount, bb)
            if not peek:
                self._cursor += bytecount
            if bytecount == 1:
                result, = bb
            else:
                result = int.from_bytes(bb, self.byteorder_name)
            if nbits or rest:
                if self.bigendian:
                    rbmask   = 2 ** rest - 1        # noqa
                    excess   = result & rbmask      # noqa
                    result >>= rest                 # noqa
                    result  ^= bbits << needed      # noqa
                else:
                    excess   = result >> needed     # noqa
                    result  ^= excess << needed     # noqa
                    result <<= nbits                # noqa
                    result  |= bbits                # noqa
                assert excess.bit_length() <= rest
                if not peek:
                    self._nbits = rest
                    self._bbits = excess
        if signed and (result & (msb := 1 << (size - 1))):
            result &= msb - 1
            result -= msb
        return result

    def read_bit(self) -> int:
        """
        This function is a shortcut for calling `refinery.lib.structures.StructReader.read_integer` with
        an argument of `1`, i.e. this reads the next bit from the stream. The bits of any byte in the stream
        are read from least significant to most significant.
        """
        return self.read_integer(1)

    def read_nibble(self, peek: bool = False) -> int:
        """
        Calls `refinery.lib.structures.StructReader.read_integer` with an argument of `4`.
        """
        return self.read_integer(4, peek)

    def read_byte(self, peek: bool = False) -> int:
        return self.read_integer(8, peek)

    def read_char(self, peek: bool = False) -> str:
        return chr(self.read_integer(8, peek))


class StructMeta(abc.ABCMeta):
    """
    A metaclass to facilitate the behavior outlined for `refinery.lib.structures.Struct`.
    """
    def __new__(mcls, name, bases, namespace: dict, interface: type[StructReader] | None = None):
        if interface is None:
            if init := namespace.get('__init__'):
                args = iter(inspect.signature(init).parameters.values())
                next(args)
                interface = next(args).annotation
                if isinstance(interface, str):
                    try:
                        module = sys.modules[namespace['__module__']]
                        interface = eval(interface, module.__dict__)
                    except Exception:
                        interface = None
                if not isinstance(interface, type):
                    interface = get_origin(interface)
                if not isinstance(interface, type) or not issubclass(interface, StructReader):
                    raise RuntimeError
            else:
                interface = StructReader

        def parse(cls, reader: T | StructReader[T], *args, **kwargs):
            if not isinstance(reader, interface):
                reader = interface(reader)
            return cls(reader, *args, **kwargs)

        namespace.update(Parse=classmethod(parse))
        return super().__new__(mcls, name, bases, namespace)

    def __init__(cls, name, bases, nmspc, **_):
        super().__init__(name, bases, nmspc)
        original__init__ = cls.__init__

        @functools.wraps(original__init__)
        def wrapped__init__(self: Struct, reader: StructReader, *args, **kwargs):
            start = reader.tell()
            view = reader.getbuffer()
            original__init__(self, reader, *args, **kwargs)
            self._data = view[start:reader.tell()]
            del view

        setattr(cls, '__init__', wrapped__init__)


class Struct(Generic[T], Buffer, metaclass=StructMeta):
    """
    A class to parse structured data. A `refinery.lib.structures.Struct` class can be instantiated
    as follows:

        foo = Struct(data, bar=29)

    The initialization routine of the structure will be called with a single argument `reader`. If
    the object `data` is already a `refinery.lib.structures.StructReader`, then it will be passed
    as `reader`. Otherwise, the argument will be wrapped in a `refinery.lib.structures.StructReader`.
    Additional arguments to the struct are passed through.
    """
    _data: memoryview | bytearray

    @classmethod
    def Parse(cls, reader: T | StructReader[T], *args, **kwargs) -> Self:
        ...

    def __len__(self):
        return len(self._data)

    def __bytes__(self):
        return bytes(self._data)

    def __buffer__(self, flags: int, /):
        return memoryview(self._data)

    def __init__(self, reader: StructReader[T], *args, **kwargs):
        pass


AttrType = TypeVar('AttrType')


class PerInstanceAttribute(Generic[AttrType]):
    def resolve(self, parent, value: Any) -> AttrType:
        return value

    def __init__(self):
        self.__set: dict[int, Any] = {}
        self.__get: dict[int, AttrType] = {}

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


def struct_to_json(o: dict | list | enum.IntFlag | enum.IntEnum | Struct | ToJSON | NamedTuple | None, codec: str | None = None) -> JSON:
    """
    Attempt to convert a `refinery.lib.structures.Struct` to a JSON representation.
    """
    if o is None:
        return o
    if isinstance(o, Struct):
        return {k: struct_to_json(v) for k, v in o.__dict__.items() if not k.startswith('_')}
    if isinstance(o, tuple):
        o = o._asdict()
    if isinstance(o, dict):
        for k, v in o.items():
            o[k] = struct_to_json(v, codec)
    elif isinstance(o, list):
        for k, v in enumerate(o):
            o[k] = struct_to_json(v, codec)
    elif isinstance(o, enum.IntFlag):
        return [option.name for option in o.__class__ if o & option == option]
    elif isinstance(o, enum.IntEnum):
        return o.name
    elif isinstance(o, int) and o.bit_length() > 64:
        return hex(o)
    elif codec is not None and isinstance(o, (memoryview, bytes, bytearray)):
        return codecs.decode(o, codec)
    else:
        try:
            return o.__json__()
        except AttributeError:
            pass
    return cast('JSON', o)


class FlagAccessMixin:
    """
    This class can be mixed into an `enum.IntFlag` for some quality of life improvements. Firstly,
    you can now access flags as follows:

        class Flags(FlagAccessMixin, enum.IntFlag):
            IsBinary = 1
            IsCompressed = 2

        flag = Flags(3)

        if flag.IsCompressed:
            decompress()

    Furthermore, flag values can be enumerated:

        >>> list(flag)
        [IsBinary, IsCompressed]
        >>> flag
        IsBinary|IsCompressed

    And finally, as visible from the above output, flag values are represented by their name by
    default.
    """
    def __getattribute__(self, name: str):
        if not isinstance(self, enum.IntFlag):
            raise RuntimeError
        if not name.startswith('_'):
            try:
                flag = self.__class__[name]
            except KeyError:
                pass
            else:
                return flag in self
        return super().__getattribute__(name)

    def __iter__(self) -> Generator[Self]:
        if not isinstance(self, enum.IntFlag):
            raise RuntimeError
        for flag in self.__class__:
            if flag in self:
                yield flag

    def __repr__(self):
        if not isinstance(self, enum.IntFlag):
            raise RuntimeError
        if name := self.name:
            return name
        return super().__repr__()
