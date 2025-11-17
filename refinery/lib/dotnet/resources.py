"""
Parsing of managed .NET resources, which are .NET resource directories which
begin with the magic sequence `0xBEEFCACE`. These resources can contain several
entries of serialized data. The main reference used for this parser was the
dnSpy source code.
"""
from __future__ import annotations

import datetime
import enum
import re

from refinery.lib.dotnet.deserialize import (
    BinaryFormatterParser,
    DotNetRsrcReader,
    DotNetStruct,
)
from refinery.lib.dotnet.header import DotNetStructReader
from refinery.lib.id import buffer_contains


class NoManagedResource(AssertionError):
    pass


def stream(reader: DotNetStructReader):
    return BinaryFormatterParser(reader.read_length_prefixed())


class RsrcPrimitive(enum.IntEnum):
    Null      = 0x00 # noqa
    String    = 0x01 # noqa
    Boolean   = 0x02 # noqa
    Char      = 0x03 # noqa
    Byte      = 0x04 # noqa
    SByte     = 0x05 # noqa
    Int16     = 0x06 # noqa
    UInt16    = 0x07 # noqa
    Int32     = 0x08 # noqa
    UInt32    = 0x09 # noqa
    Int64     = 0x0A # noqa
    UInt64    = 0x0B # noqa
    Single    = 0x0C # noqa
    Double    = 0x0D # noqa
    Decimal   = 0x0E # noqa
    DateTime  = 0x0F # noqa
    TimeSpan  = 0x10 # noqa
    ByteArray = 0x20 # noqa
    Stream    = 0x21 # noqa


RsrcUserTypeBase = 0x40


RsrcPrimitiveDispatch = {
    RsrcPrimitive.Null      : DotNetStructReader.read_dn_null,
    RsrcPrimitive.Boolean   : DotNetStructReader.read_bool_byte,
    RsrcPrimitive.Byte      : DotNetStructReader.read_byte,
    RsrcPrimitive.Char      : DotNetStructReader.read_char,
    RsrcPrimitive.Decimal   : DotNetStructReader.read_dn_decimal,
    RsrcPrimitive.Single    : DotNetStructReader.f32,
    RsrcPrimitive.Double    : DotNetStructReader.f64,
    RsrcPrimitive.Int16     : DotNetStructReader.i16,
    RsrcPrimitive.Int32     : DotNetStructReader.i32,
    RsrcPrimitive.Int64     : DotNetStructReader.i64,
    RsrcPrimitive.SByte     : DotNetStructReader.i8,
    RsrcPrimitive.TimeSpan  : DotNetStructReader.read_dn_time_span,
    RsrcPrimitive.DateTime  : DotNetStructReader.read_dn_date_time,
    RsrcPrimitive.UInt16    : DotNetStructReader.u16,
    RsrcPrimitive.UInt32    : DotNetStructReader.u32,
    RsrcPrimitive.UInt64    : DotNetStructReader.u64,
    RsrcPrimitive.String    : DotNetStructReader.read_dn_length_prefixed_string,
    RsrcPrimitive.ByteArray : DotNetStructReader.read_length_prefixed,
    RsrcPrimitive.Stream    : stream,
}


class NetResource(DotNetStruct):
    Value: int | str | bool | list | memoryview | datetime.datetime | datetime.timedelta | None
    Data: memoryview
    TypeName: str
    Error: str | None

    def __init__(self, reader: DotNetStructReader, base: int):
        self.Name = reader.read_dn_length_prefixed_string(codec='utf-16le')
        self.Offset = reader.u32() + base
        self.Size = 0
        self.Error = None


class NetManifestResource(DotNetStruct):

    def __init__(self, reader: DotNetStructReader):
        self.Signature = reader.u32()
        if self.Signature != 0xBEEFCACE:
            raise NoManagedResource
        self.ReaderCount = reader.u32()
        self.ReaderTypeLength = reader.u32()
        tr = DotNetRsrcReader(reader.read_exactly(self.ReaderTypeLength))
        self.ReaderType = rt = tr.read_dn_string_primitive()
        self.ResourceSetType = tr.read_dn_string_primitive()

        if not re.match(r"^System\.Resources\.ResourceReader,\s*mscorlib", rt):
            raise AssertionError('unknown resource reader')

        self.Version = reader.u32()
        ResourceCount = reader.u32()
        RsrcTypeCount = reader.u32()

        ResourceTypes = [reader.read_dn_length_prefixed_string()
            for _ in range(RsrcTypeCount)]

        reader.byte_align(8)
        self.ResourceHashes = [reader.u32() for _ in range(ResourceCount)]
        ResourceNameOffsets = [reader.u32() for _ in range(ResourceCount)]
        self.DataSectionOffset = base = reader.u32()
        rsrc: list[NetResource] = []
        self.Resources = rsrc

        for k in range(ResourceCount):
            with reader.detour():
                reader.skip(ResourceNameOffsets[k])
                rsrc.append(NetResource(reader, base))

        if rsrc:
            rsrc.sort(key=lambda r: r.Offset)
            it = iter(rsrc)
            next(it)
            ends = [r.Offset for r in it]
            ends.append(len(reader))
            for r, end in zip(rsrc, ends):
                r.Size = end - r.Offset - 1

        for Entry in rsrc:

            reader.seek(Entry.Offset)
            TypeCode = reader.read_dn_encoded_integer()
            Entry.Error = None
            Entry.Value = Entry.Data = reader.read_exactly(Entry.Size)

            if TypeCode >= RsrcUserTypeBase:
                Entry.TypeName = ResourceTypes[TypeCode - RsrcUserTypeBase]
                try:
                    Deserialized = BinaryFormatterParser(
                        Entry.Data,
                        ignore_errors=False,
                        dereference=False,
                        keep_meta=False
                    )
                except Exception as error:
                    Entry.Error = F'Failed to deserialize entry data: {error}'
                    continue
                try:
                    _, _, _, Data = Deserialized
                except ValueError:
                    Entry.Error = F'Deserialized entry has {len(Deserialized)} records, 4 were expected.'
                    continue
                if not buffer_contains(Entry.Data, Data):
                    Entry.Error = 'The computed entry value is not a substring of the entry data.'
                    Entry.Value = Entry.Data
                else:
                    Entry.Value = Data
            else:
                try:
                    Type = RsrcPrimitive(TypeCode)
                except ValueError:
                    Entry.TypeName = F'UnknownType[{TypeCode:#x}]'
                else:
                    Entry.TypeName = Type.name
                    package = DotNetStructReader(Entry.Value)
                    Entry.Value = RsrcPrimitiveDispatch[Type](package)


def NetStructuredResources(data):
    return NetManifestResource(DotNetStructReader(memoryview(data))).Resources
