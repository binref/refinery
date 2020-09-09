# -*- coding: utf-8 -*-
"""
These definitions in this module are used across the other modules in the .NET
parsing library.
"""
import struct
import datetime
import time
import base64

from io import BytesIO
from typing import Type, TypeVar

T = TypeVar('T')


class RepresentedByNameOnly(type):
    def __repr__(self):
        return self.__name__

    def __init__(cls, name, bases, nmspc):
        def representation(self):
            return repr(self.__class__)
        setattr(cls, '__repr__', representation)


class TimeZone_UTC(datetime.tzinfo):
    def utcoffset(self, dt):
        return datetime.timedelta(0)

    def tzname(self, dt):
        return "UTC"

    def dst(self, dt):
        return datetime.timedelta(0)


class TimeZone_Local(datetime.tzinfo):
    def __init__(self):
        self._stdoffset = datetime.timedelta(seconds=-time.timezone)
        self._altoffset = datetime.timedelta(seconds=-time.altzone)
        self._dstoffset = self._altoffset if time.daylight else self._stdoffset

    def _is_dst(self, dt):
        tt = (dt.year, dt.month, dt.day, dt.hour,
              dt.minute, dt.second, dt.weekday(), 0, 0)
        tt = time.localtime(time.mktime(tt))
        return tt.tm_isdst > 0

    def utcoffset(self, dt):
        return self._dstoffset if self._is_dst(dt) else self._stdoffset

    def dst(self, dt):
        return self.utcoffset(dt) - self._stdoffset

    def tzname(self, dt):
        return time.tzname[self._is_dst(dt)]


class MetaBox(metaclass=RepresentedByNameOnly):
    pass


class Box(dict, MetaBox):
    def __init__(self, **kw):
        super(Box, self).__init__()
        for key, value in kw.items():
            setattr(self, key, value)

    def __getattr__(self, key):
        try:
            return super(Box, self).__getattribute__(key)
        except AttributeError:
            if key in self:
                return self[key]
            else:
                raise

    def __setattr__(self, name, value):
        if name.startswith('_') or hasattr(self.__class__, name):
            return super(Box, self).__setattr__(name, value)
        return self.__setitem__(name, value)


class ParserException(Exception):
    pass


class ParserEOF(ParserException):
    def __init__(self, size, data):
        ParserException.__init__(
            self,
            'attempted to read {} bytes from reader and '
            'got only {}.'.format(size, len(data))
        )
        self.data = data
        self.size = size


def unpack(item):
    while True:
        try:
            value = item.Value
        except AttributeError:
            break
        if type(value) == property:
            break
        item = value
    return item


class StreamReader(BytesIO):

    def read(self, size=None):
        if size is None:
            start = self.tell()
            self.seek(0, 2)
            size = self.tell() - start
            self.seek(start)
        data = BytesIO.read(self, size)
        if len(data) != size:
            raise ParserEOF(size, data)
        return data

    def skip(self, count):
        self.seek(count, 1)

    def align(self, blocksize):
        skip = self.tell() % blocksize
        if skip:
            self.skip(blocksize - skip)

    def __len__(self):
        pos = self.tell()
        self.seek(0, 2)
        size = self.tell()
        self.seek(pos)
        return size

    def checkpoint(self):

        class streamframe:
            reader = self

            def __enter__(self):
                self.rewind = self.reader.tell()
                return self

            def __exit__(self, type, value, tb):
                self.reader.seek(self.rewind)
                return False

        return streamframe()

    def expect(self, parser: Type[T], **kw) -> T:
        return unpack(self.expect_with_meta(parser, **kw))

    def expect_with_meta(self, parser: Type[T], **kw) -> T:
        return parser(self, **kw)


class Blob(metaclass=RepresentedByNameOnly):
    def __init__(self, reader, size=None):
        self._size = 0
        if size is None:
            start = reader.tell()
            size = self._readLengthPrefix(reader)
            self._size = reader.tell() - start
        self._data = self._consume(reader, size)
        self._size += len(self._data)

    def _readLengthPrefix(self, reader):
        size = reader.expect(Byte)
        if not size & 0x80:
            return size
        elif not size & 0x40:
            size = size & 0x3f
            size = size << 8 | reader.expect(Byte)
            return size
        elif not size & 0x20:
            size = size & 0x1f
            size = size << 8 | reader.expect(Byte)
            size = size << 8 | reader.expect(Byte)
            size = size << 8 | reader.expect(Byte)
            return size
        else:
            self._raise('length prefix invalid')

    def _consume(self, reader, size):
        return reader.read(size)

    def _raise(self, msg):
        raise ParserException(
            'attempted to parse {}: {}.'.format(repr(self), msg))

    def __len__(self):
        return self._size

    def __bytes__(self):
        return self._data


class RawBytes(Blob):
    @property
    def Value(self):
        return self._data


class StringPrimitive(Blob):
    def __init__(self, reader, size=None, align=1, codec='latin-1'):
        Blob.__init__(self, reader, size)
        self._codec = codec
        if align > 1:
            excess = self._size % align
            if excess:
                self._size += len(reader.read(align - excess))

    @property
    def Value(self):
        try:
            return self._data.decode(self._codec).rstrip(u'\x00')
        except UnicodeDecodeError:
            codec = 'utf-16le' if self._data.count(B'\0') == len(self._data) // 2 else 'latin-1'
        try:
            return self._data.decode(codec)
        except UnicodeDecodeError:
            return self._data.decode('UNICODE_ESCAPE')


class UnicodeString(StringPrimitive):
    def __init__(self, reader):
        StringPrimitive.__init__(self, reader, align=1, codec='utf-16LE')
        if len(self._data) > 0:
            if not len(self._data) % 2:
                raise ParserException('unicode string has no terminator')
            self._data = self._data[:-1]


class EncodedInteger(Blob):
    def __init__(self, reader):
        Blob.__init__(self, reader, 0)
        self._size = 0
        data = bytearray()
        value = 0
        for position in range(5):
            byte = reader.expect(Byte)
            data.append(byte)
            self._size += 1
            value |= (byte & 0b01111111) << (position * 7)
            if byte & 0b10000000 == 0:
                break
        else:
            self._raise('length prefix overflow')
        self._data = bytes(data)
        self.Value = value


class LengthPrefixedString(StringPrimitive):
    def __init__(self, reader, codec='UTF8'):
        StringPrimitive.__init__(self, reader, size=None, align=1, codec=codec)

    def _readLengthPrefix(self, reader):
        return reader.expect(EncodedInteger)


class StringGUID(Blob):
    def __init__(self, reader):
        Blob.__init__(self, reader, 16)

    @property
    def Value(self):
        rest = base64.b16encode(self._data[10:]).decode('ascii')
        values = struct.unpack('<IHHBB', self._data[:10]) + (rest,)
        return '{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{}'.format(*values)

    def __str__(self):
        return self.Value


class NullTerminatedString(StringPrimitive):
    def __init__(self, reader, align=1, codec='latin-1'):
        StringPrimitive.__init__(self, reader, 0, align, codec=codec)

    def _consume(self, reader, size):
        data = b''
        assert size == 0
        while not data.endswith(b'\0'):
            data += reader.read(1)
        return data


class FixedSize(Blob):
    format = None

    def __init__(self, reader, fmt=None):
        fmt = fmt or self.format
        assert fmt is not None, 'not format specified for this FixedSize instance'
        Blob.__init__(self, reader, struct.calcsize(fmt))
        self.__value = struct.unpack('<' + fmt, self._data)
        if len(self.__value) == 0:
            self.__value = None
            return
        if len(self.__value) == 1:
            self.__value = self.__value[0]
        if hasattr(self, 'parser'):
            try:
                self.__value = self.parser(self.__value)
            except Exception as e:
                self._raise(str(e))

    @property
    def Value(self):
        return self.__value


class TypeCode(FixedSize):
    format = 'B'
    lookup = {}

    def parser(self, x):
        assert x in self.lookup, 'unknown {}({}) encountered'.format(repr(self), x)
        return self.lookup[x]


class BinaryArrayTypeEnumeration(TypeCode):
    lookup = {
        0: 'Single',
        1: 'Jagged',
        2: 'Rectangular',
        3: 'SingleOffset',
        4: 'JaggedOffset',
        5: 'RectangularOffset'
    }


class Boolean(FixedSize):
    format = 'B'
    parser = bool


class Byte(FixedSize):
    format = 'B'


class Char(FixedSize):
    format = 'b'
    parser = chr


class Int16(FixedSize):
    format = 'h'


class Int32(FixedSize):
    format = 'i'


class Int64(FixedSize):
    format = 'q'


class SByte(FixedSize):
    format = 'B'


class Single(FixedSize):
    format = 'f'


class Double(FixedSize):
    format = 'd'


class TimeSpan(FixedSize):
    format = 'Q'
    def parser(x): return datetime.timedelta(microseconds=0.1 * x)


class DateTime(FixedSize):
    format = 'Q'

    @classmethod
    def parser(x):
        hi_byte = x >> 56
        lo_part = x & 0xFFFFFFFFFFFFFFFF
        kind = hi_byte & 0b11
        time = (hi_byte >> 2) << 56 | lo_part
        assert kind < 3, 'invalid date kind'
        return datetime.datetime.fromtimestamp(time, {
            0: None,
            1: TimeZone_UTC(),
            2: TimeZone_Local()}[kind])


class UInt16(FixedSize):
    format = 'H'


class UInt32(FixedSize):
    format = 'I'


class UInt64(FixedSize):
    format = 'Q'


class Null(FixedSize):
    format = ''


class Struct(Box):

    def expect(self, parser, **kw):
        return unpack(self.expect_with_meta(parser, **kw))

    def expect_with_meta(self, parser, **kw):
        package = self._reader.expect_with_meta(parser, **kw)
        self._data += package._data
        return package

    def parse(self):
        pass

    def __init__(self, reader, cleanup=True, **kw):
        Box.__init__(self, **kw)
        self._reader = reader
        self._data = b''
        self.parse()
        if cleanup:
            self._cleanup(*kw)

    def _cleanup(self, *keywords):
        for key in keywords:
            delattr(self, key)
