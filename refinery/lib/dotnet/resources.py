# -*- coding: utf-8 -*-
"""
Parsing of managed .NET resources, which are .NET resource directories which
begin with the magic sequence `0xBEEFCACE`. These resources can contain several
entries of serialized data. The main reference used for this parser was the
dnSpy source code.
"""
import re

from .deserialize import BinaryFormatterParser
from .types import (
    Blob,
    Box,
    Byte,
    Char,
    LengthPrefixedString,
    StreamReader,
    StringPrimitive,
    EncodedInteger,
    Struct,
    UInt16,
    UInt32,
    Int16,
    Int32,
    Int64,
    SByte,
    Single,
    Double,
    Null,
    UInt64,
    unpack,
    DateTime,
    TimeSpan
)


class NoManagedResource(AssertionError):
    pass


class String(LengthPrefixedString):
    def __init__(self, reader):
        LengthPrefixedString.__init__(self, reader, codec='UTF-8')


class Boolean(Byte):
    @property
    def Value(self):
        return bool(super(Boolean, self).Value)


class Decimal(Blob):
    def __init__(self, reader):
        Blob.__init__(self, reader, 16)

    @property
    def Value(self):
        # TODO: Unknown whether this is correct
        return int.from_bytes(self._data, 'big')


class ByteArray(Struct):
    def parse(self):
        self.Size = self.expect(UInt32)
        self.Value = self._reader.read(self.Size)

    def __bytes__(self):
        return self.Value


class NetManifestResource(Struct):
    USERTYPES = 0x40
    PRIMITIVE = {
        0x00: Null,
        0x01: String,
        0x02: Boolean,
        0x03: Char,
        0x04: Byte,
        0x05: SByte,
        0x06: Int16,
        0x07: UInt16,
        0x08: Int32,
        0x09: UInt32,
        0x0A: Int64,
        0x0B: UInt64,
        0x0C: Single,
        0x0D: Double,
        0x0E: Decimal,
        0x0F: DateTime,
        0x10: TimeSpan,
        0x20: ByteArray,
        0x21: ByteArray,
    }

    def parse(self):
        self.Signature = self.expect(UInt32)
        if self.Signature != 0xBEEFCACE:
            raise NoManagedResource

        self.ReaderCount = self.expect(UInt32)
        self.ReaderTypeLength = self.expect(UInt32)

        tr = StreamReader(self._reader.read(self.ReaderTypeLength))
        self.ReaderType = tr.expect(StringPrimitive)
        self.ResourceSetType = tr.expect(StringPrimitive)

        if not re.match(r"^System\.Resources\.ResourceReader,\s*mscorlib", self.ReaderType):
            raise AssertionError('unknown resource reader')

        self.Version = self.expect(UInt32)
        ResourceCount = self.expect(UInt32)
        RsrcTypeCount = self.expect(UInt32)

        ResourceTypes = [
            self.expect(LengthPrefixedString)
            for _ in range(RsrcTypeCount)
        ]

        self._reader.align(8)
        self._reader.skip(4 * ResourceCount)

        # Since we do not require the resouce hashes, we skip over them.
        # The following would be the code to read in the hashes:
        #
        # ResourceHashes = [
        #     self.expect(UInt32)
        #     for _ in range(ResourceCount)
        # ]

        ResourceNameOffsets = [
            self.expect(UInt32)
            for _ in range(ResourceCount)
        ]

        self.DataSectionOffset = self.expect(UInt32)

        self.Resources = []

        for k in range(ResourceCount):
            with self._reader.checkpoint():
                self._reader.skip(ResourceNameOffsets[k])
                Name = self.expect(LengthPrefixedString, codec='UTF-16LE')
                Offset = self.expect(UInt32) + self.DataSectionOffset
                self.Resources.append(Box(Offset=Offset, Name=Name))

        self.Resources.sort(key=lambda r: r.Offset)
        self.Resources.append(Box(Offset=len(self._reader)))
        self.Resources = [
            Box(Size=b.Offset - a.Offset - 1, **a)
            for a, b in zip(self.Resources, self.Resources[1:])
        ]

        for Index, Entry in enumerate(self.Resources):

            self._reader.seek(Entry.Offset)
            TypeCode = self.expect(EncodedInteger)
            Entry.Error = None
            Entry.Value = Entry.Data = self._reader.read(Entry.Size)

            if TypeCode >= self.USERTYPES:
                Entry.TypeName = ResourceTypes[TypeCode - self.USERTYPES]
                try:
                    Deserialized = BinaryFormatterParser(
                        Entry.Data,
                        ignore_errors=False,
                        dereference=False,
                        keep_meta=False
                    )
                except Exception as error:
                    Entry.Error = 'failed to deserialize entry data: {}'.format(error)
                    continue
                try:
                    _, _, _, Data = Deserialized
                except ValueError:
                    Entry.Error = 'deserialized entry has {} records, 4 were expected.'.format(len(Deserialized))
                    continue
                if Data not in Entry.Data:
                    Entry.Error = 'the computed entry value is not a substring of the entry data.'
                    Entry.Value = Entry.Data
                else:
                    Entry.Value = Data

            elif TypeCode in self.PRIMITIVE:
                Type = self.PRIMITIVE[TypeCode]
                Entry.TypeName = repr(Type)
                package = StreamReader(Entry.Data).expect_with_meta(Type)
                Entry.Value = unpack(package)
            else:
                Entry.TypeName = 'UNKNOWN TYPE 0x{:X}'.format(TypeCode)


class NetStructuredResources(list):
    def __init__(self, data):
        list.__init__(self, NetManifestResource(StreamReader(data)).Resources)
