# -*- coding: utf-8 -*-
"""
Parsing of the .NET header. The code is based on the description in [1].

References:
  [1]: https://www.ntcore.com/files/dotnetformat.htm
"""
import pefile
from typing import List

from .types import (
    RawBytes,
    Box,
    Byte,
    NullTerminatedString,
    ParserException,
    StreamReader,
    StringGUID,
    StringPrimitive,
    Struct,
    UInt16,
    UInt32,
    UInt64,
    UnicodeString,
    unpack,
    ParserEOF
)


class InvalidDotNetHeader(ValueError):
    def __init__(self, msg=None):
        ValueError.__init__(self, msg or '.NET parsing failed: corrupt header.')


class InvalidSignature(InvalidDotNetHeader):
    def __init__(self):
        ValueError.__init__(self, '.NET parsing failed: Invalid signature.')


class BitMask:
    def __init__(self, bitmask):
        self._bitmask = bitmask

    def __contains__(self, pos):
        return self[pos] == 1

    def __len__(self):
        return self._bitmask.bit_length()

    def __getitem__(self, pos):
        return (self._bitmask >> pos) & 1

    def __iter__(self):
        for k in range(len(self)):
            if k in self:
                yield k

    def __repr__(self):
        return '{:b}'.format(self._bitmask)


def bits_required(n):
    return 0 if not n else (n - 1).bit_length()


class MultiTableIndex(Struct):
    _name_to_id = {
        'Assembly'               : 0x20,
        'AssemblyOS'             : 0x22,
        'AssemblyProcessor'      : 0x21,
        'AssemblyRef'            : 0x23,
        'AssemblyRefOS'          : 0x25,
        'AssemblyRefProcessor'   : 0x24,
        'ClassLayout'            : 0x0F,
        'Constant'               : 0x0B,
        'CustomAttribute'        : 0x0C,
        'ENCLog'                 : 0x1E,
        'ENCMap'                 : 0x1F,
        'Event'                  : 0x14,
        'EventMap'               : 0x12,
        'EventPtr'               : 0x13,
        'ExportedType'           : 0x27,
        'Field'                  : 0x04,
        'FieldLayout'            : 0x10,
        'FieldMarshal'           : 0x0D,
        'FieldPtr'               : 0x03,
        'FieldRVA'               : 0x1D,
        'File'                   : 0x26,
        'GenericParam'           : 0x2A,
        'GenericParamConstraint' : 0x2C,
        'ImplMap'                : 0x1C,
        'InterfaceImpl'          : 0x09,
        'ManifestResource'       : 0x28,
        'MemberRef'              : 0x0A,
        'MethodDef'              : 0x06,
        'MethodImpl'             : 0x19,
        'MethodPtr'              : 0x05,
        'MethodSemantics'        : 0x18,
        'MethodSpec'             : 0x2B,
        'Module'                 : 0x00,
        'ModuleRef'              : 0x1A,
        'NestedClass'            : 0x29,
        'Param'                  : 0x08,
        'ParamPtr'               : 0x07,
        'Permission'             : 0x0E,
        'Property'               : 0x17,
        'PropertyMap'            : 0x15,
        'PropertyPtr'            : 0x16,
        'StandAloneSig'          : 0x11,
        'TypeDef'                : 0x02,
        'TypeRef'                : 0x01,
        'TypeSpec'               : 0x1B,
    }
    refs = ()

    def __init__(self, reader, rows):
        if not self.refs:
            raise NotImplementedError
        row_max_len = max(
            rows.get(self._name_to_id[n], 0)
            for n in self.refs if n is not None
        )
        bits = self.bits + bits_required(row_max_len)
        Type = UInt32 if bits > 16 else UInt16
        Struct.__init__(self, reader, _type=Type)

    def __len__(self):
        return len(self.refs)

    @property
    def bits(self):
        return bits_required(len(self))

    @property
    def mask(self):
        return (1 << self.bits) - 1

    def parse(self):
        raw = self.expect(self._type)
        try:
            self.RowName = self.refs[raw & self.mask]
        except IndexError:
            self.Error = 'no ref at index {}'.format(raw & self.mask)
            self.RowName = None
        if self.RowName is not None:
            self.RowType = self._name_to_id[self.RowName]
        self.Index = raw >> self.bits


class TypeDefOrRefIndex(MultiTableIndex):
    refs = (
        'TypeDef',
        'TypeRef',
        'TypeSpec'
    )


class HasConstantIndex(MultiTableIndex):
    refs = (
        'Field',
        'Param',
        'Property'
    )


class HasCustomAttributeIndex(MultiTableIndex):
    refs = (
        'MethodDef',
        'Field',
        'TypeRef',
        'TypeDef',
        'Param',
        'InterfaceImpl',
        'MemberRef',
        'Module',
        'Permission',
        'Property',
        'Event',
        'StandAloneSig',
        'ModuleRef',
        'TypeSpec',
        'Assembly',
        'AssemblyRef',
        'File',
        'ExportedType',
        'ManifestResource',
    )


class HasFieldMarshallIndex(MultiTableIndex):
    refs = (
        'Field',
        'Param',
    )


class HasDeclSecurityIndex(MultiTableIndex):
    refs = (
        'TypeDef',
        'MethodDef',
        'Assembly',
    )


class MemberRefParentIndex(MultiTableIndex):
    refs = (
        'TypeDef',
        'TypeRef',
        'ModuleRef',
        'MethodDef',
        'TypeSpec',
    )


class HasSemanticsIndex(MultiTableIndex):
    refs = (
        'Event',
        'Property',
    )


class MethodDefOrRefIndex(MultiTableIndex):
    refs = (
        'MethodDef',
        'MemberRef',
    )


class MemberForwardedIndex(MultiTableIndex):
    refs = (
        'Field',
        'MethodDef',
    )


class ImplementationIndex(MultiTableIndex):
    refs = (
        'File',
        'AssemblyRef',
        'ExportedType',
    )


class CustomAttributeTypeIndex(MultiTableIndex):
    refs = (
        None,
        None,
        'MethodDef',
        'MemberRef',
        None
    )


class ResolutionScopeIndex(MultiTableIndex):
    refs = (
        'Module',
        'ModuleRef',
        'AssemblyRef',
        'TypeRef'
    )


class TypeOrMethodDefIndex(MultiTableIndex):
    refs = (
        'TypeDef',
        'MethodDef',
    )


class FieldIndex(MultiTableIndex):
    refs = ('Field',)


class MethodDefIndex(MultiTableIndex):
    refs = ('MethodDef',)


class ParamIndex(MultiTableIndex):
    refs = ('Param',)


class TypeDefIndex(MultiTableIndex):
    refs = ('TypeDef',)


class EventIndex(MultiTableIndex):
    refs = ('Event',)


class PropertyIndex(MultiTableIndex):
    refs = ('Property',)


class ModuleRefIndex(MultiTableIndex):
    refs = ('ModuleRef',)


class AssemblyRefIndex(MultiTableIndex):
    refs = ('AssemblyRef',)


class GenericParamIndex(MultiTableIndex):
    refs = ('GenericParam',)


class TableRow(Struct):
    def __init__(self, reader, streams, header, **kw):
        Struct.__init__(self, reader, _streams=streams, _header=header)

    def expect_strA(self):
        offset = self.expect(self._header.HeapOffsetTypes.String)
        return self._streams.Strings[offset]

    def expect_guid(self):
        index = self.expect(self._header.HeapOffsetTypes.GUID)
        offset = (index - 1) * 0x10
        return self._streams.GUID[offset]

    def expect_blob(self):
        offset = self.expect(self._header.HeapOffsetTypes.Blob)
        return self._streams.Blob[offset]

    def index(self, IndexParser):
        return self.expect(IndexParser, rows=self._header.RowCount)


class Module(TableRow):
    def parse(self):
        self.Generation = self.expect(UInt16)
        self.Name = self.expect_strA()
        self.MvId = self.expect_guid()
        self.EncId = self.expect_guid()
        self.EncBaseId = self.expect_guid()


class TypeRef(TableRow):
    def parse(self):
        self.ResolutionScope = self.index(ResolutionScopeIndex)
        self.TypeName = self.expect_strA()
        self.TypeNamespace = self.expect_strA()


class TypeDef(TableRow):
    def parse(self):
        self.Flags = self.expect(UInt32)
        self.TypeName = self.expect_strA()
        self.TypeNamespace = self.expect_strA()
        self.Extends = self.index(TypeDefOrRefIndex)
        self.FieldList = self.index(FieldIndex)
        self.MethodList = self.index(MethodDefIndex)


class FieldPtr(TableRow):
    def parse(self):
        self.Ref = self.expect(UInt16)


class Field(TableRow):
    def parse(self):
        class FieldFlags:
            def __init__(self, mask):
                self.Value = BitMask(mask)
                self.Static = bool(self.Value[4])
                self.InitOnly = bool(self.Value[5])
                self.Literal = bool(self.Value[6])
                self.NotSerialized = bool(self.Value[7])
                self.HasFieldRVA = bool(self.Value[8])
                self.SpecialName = bool(self.Value[9])
                self.RTSpecialName = bool(self.Value[10])
                self.HasFieldMarshal = bool(self.Value[11])
                self.PinvokeImpl = bool(self.Value[12])
                self.HasDefault = bool(self.Value[13])

            def __str__(self):
                return str(self.Value)

        self.Flags = FieldFlags(self.expect(UInt16))
        self.Name = self.expect_strA()
        self.Signature = self.expect_blob()


class MethodPtr(TableRow):
    def parse(self):
        self.Ref = self.expect(UInt16)


class MethodDef(TableRow):
    def parse(self):
        self.RVA = self.expect(UInt32)
        self.ImplFlags = self.expect(UInt16)
        self.Flags = self.expect(UInt16)
        self.Name = self.expect_strA()
        self.Signature = self.expect_blob()
        self.ParamList = self.index(ParamIndex)


class ParamPtr(TableRow):
    def parse(self):
        self.Ref = self.expect(UInt16)


class Param(TableRow):
    def parse(self):
        self.Flags = self.expect(UInt16)
        self.Sequence = self.expect(UInt16)
        self.Name = self.expect_strA()


class InterfaceImpl(TableRow):
    def parse(self):
        self.Class = self.index(TypeDefIndex)
        self.Interface = self.index(TypeDefOrRefIndex)


class MemberRef(TableRow):
    def parse(self):
        self.Class = self.index(MemberRefParentIndex)
        self.Name = self.expect_strA()
        self.Signature = self.expect_blob()


class Constant(TableRow):
    def parse(self):
        self.Type = self.expect(UInt16)
        self.Parent = self.index(HasConstantIndex)
        self.Value = self.expect_blob()


class CustomAttribute(TableRow):
    def parse(self):
        self.Parent = self.index(HasCustomAttributeIndex)
        self.Type = self.index(CustomAttributeTypeIndex)
        self.Value = self.expect_blob()


class FieldMarshal(TableRow):
    def parse(self):
        self.Parent = self.index(HasFieldMarshallIndex)
        self.NativeType = self.expect_blob()


class Permission(TableRow):
    def parse(self):
        self.Action = self.expect(UInt16)
        self.Parent = self.index(HasDeclSecurityIndex)
        self.PermissionSet = self.expect_blob()


class ClassLayout(TableRow):
    def parse(self):
        self.PackingSize = self.expect(UInt16)
        self.ClassSize = self.expect(UInt32)
        self.Parent = self.index(TypeDefIndex)


class FieldLayout(TableRow):
    def parse(self):
        self.Offset = self.expect(UInt32)
        self.Field = self.index(FieldIndex)


class StandAloneSig(TableRow):
    def parse(self):
        self.Signature = self.expect_blob()


class EventMap(TableRow):
    def parse(self):
        self.Parent = self.index(TypeDefIndex)
        self.EventList = self.index(EventIndex)


class EventPtr(TableRow):
    def parse(self):
        self.Ref = self.expect(UInt16)


class Event(TableRow):
    def parse(self):
        self.EventFlags = self.expect(UInt16)
        self.Name = self.expect_strA()
        self.EventType = self.index(TypeDefOrRefIndex)


class PropertyMap(TableRow):
    def parse(self):
        self.Parent = self.index(TypeDefIndex)
        self.PropertyList = self.index(PropertyIndex)


class PropertyPtr(TableRow):
    def parse(self):
        self.Ref = self.expect(UInt16)


class Property(TableRow):
    def parse(self):
        self.Flags = self.expect(UInt16)
        self.Name = self.expect_strA()
        self.Type = self.expect_blob()


class MethodSemantics(TableRow):
    def parse(self):
        self.Semantics = self.expect(UInt16)
        self.Method = self.index(MethodDefIndex)
        self.Association = self.index(HasSemanticsIndex)


class MethodImpl(TableRow):
    def parse(self):
        self.Class = self.index(TypeDefIndex)
        self.MethodBody = self.index(MethodDefOrRefIndex)
        self.MethodDeclaration = self.index(MethodDefOrRefIndex)


class ModuleRef(TableRow):
    def parse(self):
        self.Name = self.expect_strA()


class TypeSpec(TableRow):
    def parse(self):
        self.Signature = self.expect_blob()


class ImplMap(TableRow):
    def parse(self):
        self.MappingFlags = self.expect(UInt16)
        self.MemberForwarded = self.index(MemberForwardedIndex)
        self.ImportName = self.expect_strA()
        self.ImportScope = self.index(ModuleRefIndex)


class FieldRVA(TableRow):
    def parse(self):
        self.RVA = self.expect(UInt32)
        self.Field: MultiTableIndex = self.index(FieldIndex)


class Assembly(TableRow):
    def parse(self):
        self.HashAlgId = self.expect(UInt32)
        self.MajorVersion = self.expect(UInt16)
        self.MinorVersion = self.expect(UInt16)
        self.BuildNumber = self.expect(UInt16)
        self.RevisionNumber = self.expect(UInt16)
        self.Flags = self.expect(UInt32)
        self.PublicKey = self.expect_blob()
        self.Name = self.expect_strA()
        self.Culture = self.expect_strA()


class AssemblyProcessor(TableRow):
    def parse(self):
        self.Processor = self.expect(UInt32)


class AssemblyOS(TableRow):
    def parse(self):
        self.OsPlatformId = self.expect(UInt32)
        self.OsMajorVersion = self.expect(UInt32)
        self.OsMinorVersion = self.expect(UInt32)


class AssemblyRef(TableRow):
    def parse(self):
        self.MajorVersion = self.expect(UInt16)
        self.MinorVersion = self.expect(UInt16)
        self.BuildNumber = self.expect(UInt16)
        self.RevisionNumber = self.expect(UInt16)
        self.Flags = self.expect(UInt32)
        self.PublicKeyOrToken = self.expect_blob()
        self.Name = self.expect_strA()
        self.Culture = self.expect_strA()
        self.HashValue = self.expect_blob()


class AssemblyRefProcessor(TableRow):
    def parse(self):
        self.Processor = self.expect(UInt32)
        self.AssemblyRef = self.index(AssemblyRefIndex)


class AssemblyRefOS(TableRow):
    def parse(self):
        self.OsPlatformId = self.expect(UInt32)
        self.OsMajorVersion = self.expect(UInt32)
        self.OsMinorVersion = self.expect(UInt32)
        self.AssemblyRef = self.index(AssemblyRefIndex)


class File(TableRow):
    def parse(self):
        self.Flags = self.expect(UInt32)
        self.Name = self.expect_strA()
        self.HashValue = self.expect_blob()


class ExportedType(TableRow):
    def parse(self):
        self.Flags = self.expect(UInt32)
        self.TypeDefId = self.expect(UInt32)
        self.TypeName = self.expect_strA()
        self.TypeNamespace = self.expect_strA()
        self.Implementation = self.index(ImplementationIndex)


class ManifestResource(TableRow):
    def parse(self):
        self.Offset = self.expect(UInt32)
        self.Flags = self.expect(UInt32)
        self.Name = self.expect_strA()
        self.Implementation = self.index(ImplementationIndex)


class NestedClass(TableRow):
    def parse(self):
        self.NestedClass = self.index(TypeDefIndex)
        self.EnclosingClass = self.index(TypeDefIndex)


class GenericParam(TableRow):
    def parse(self):
        self.Number = self.expect(UInt16)
        self.Flags = self.expect(UInt16)
        self.Owner = self.index(TypeOrMethodDefIndex)
        self.Name = self.expect_strA()


class MethodSpec(TableRow):
    def parse(self):
        self.Method = self.index(MethodDefOrRefIndex)
        self.Instantiation = self.expect_blob()


class GenericParamConstraint(TableRow):
    def parse(self):
        self.Owner = self.index(GenericParamIndex)
        self.Constraint = self.index(TypeDefOrRefIndex)


class ENCLog(TableRow):
    def parse(self):
        self.Token = self.expect(UInt32)
        self.FuncCode = self.expect(UInt32)


class ENCMap(TableRow):
    def parse(self):
        self.Token = self.expect(UInt32)


class ImageDataDirectory(Struct):
    def parse(self):
        self.VirtualAddress = self.expect(UInt32)
        self.Size = self.expect(UInt32)


class NetDirectory(Struct):
    def parse(self):
        self.Size = self.expect(UInt32)
        self.MajorRuntimeVersion = self.expect(UInt16)
        self.MinorRuntimeVersion = self.expect(UInt16)
        self.MetaData = self.expect(ImageDataDirectory)
        self.Flags = self.expect(UInt32)
        self.EntryPointToken = self.expect(UInt32)
        self.Resources = self.expect(ImageDataDirectory)
        self.StringNameSignature = self.expect(ImageDataDirectory)
        self.CodeManagerTable = self.expect(ImageDataDirectory)
        self.VTableFixups = self.expect(ImageDataDirectory)
        self.ExportAddressTableJumps = self.expect(ImageDataDirectory)
        self.ManagedNativeHeader = self.expect(ImageDataDirectory)
        # Known Flags
        self.KnownFlags = dict(
            IL_ONLY=((self.Flags >> 0) & 1 == 1),
            REQUIRE_32BIT=((self.Flags >> 1) & 1 == 1),
            IL_LIBRARY=((self.Flags >> 2) & 1 == 1),
            STRONG_NAME_SIGNED=((self.Flags >> 3) & 1 == 1),
            NATIVE_ENTRYPOINT=((self.Flags >> 4) & 1 == 1),
            TRACK_DEBUG_DATA=((self.Flags >> 16) & 1 == 1)
        )


class NetMetaDataStreamEntry(Struct):
    def parse(self):
        self.VirtualAddress = self.expect(UInt32)
        self.Size = self.expect(UInt32)
        self.Name = self.expect(NullTerminatedString, align=4)


class NetMetaDataTablesHeader(Struct):
    def parse(self):
        Types = (UInt16, UInt32)
        self._Reserved1 = self.expect(UInt32)
        self.MajorVersion = self.expect(Byte)
        self.MinorVersion = self.expect(Byte)
        self.Flags = BitMask(self.expect(Byte))
        self.KnownFlags = dict(
            PADDING=bool(self.Flags[3]),
            DELTA_ONLY=bool(self.Flags[5]),
            LARGE_STRA=bool(self.Flags[0]),  # Strings require 4 byte offsets
            LARGE_GUID=bool(self.Flags[1]),  # GUIDs require 4 byte offsets
            LARGE_BLOB=bool(self.Flags[2]),  # Blobs require 4 byte offsets
            EXTRA_DATA=bool(self.Flags[6]),  # Extra data follows the row counts
            HAS_DELETE=bool(self.Flags[7])   # Certain tables can contain deleted rows.
        )
        self.HeapOffsetTypes = Box(
            String=Types[self.Flags[0]],
            GUID=Types[self.Flags[1]],
            Blob=Types[self.Flags[2]])
        self._Reserved2 = self.expect(Byte)
        self.ExistingRows = BitMask(self.expect(UInt64))
        self.SortedRows = BitMask(self.expect(UInt64))
        self.RowCount = {k: self.expect(UInt32) for k in self.ExistingRows}


class NetMetaDataTables(Struct):
    lookup = {
        0x00: Module,
        0x01: TypeRef,
        0x02: TypeDef,
        0x03: FieldPtr,
        0x04: Field,
        0x05: MethodPtr,
        0x06: MethodDef,
        0x07: ParamPtr,
        0x08: Param,
        0x09: InterfaceImpl,
        0x0A: MemberRef,
        0x0B: Constant,
        0x0C: CustomAttribute,
        0x0D: FieldMarshal,
        0x0E: Permission,
        0x0F: ClassLayout,
        0x10: FieldLayout,
        0x11: StandAloneSig,
        0x12: EventMap,
        0x13: EventPtr,
        0x14: Event,
        0x15: PropertyMap,
        0x16: PropertyPtr,
        0x17: Property,
        0x18: MethodSemantics,
        0x19: MethodImpl,
        0x1A: ModuleRef,
        0x1B: TypeSpec,
        0x1C: ImplMap,
        0x1D: FieldRVA,
        0x1E: ENCLog,
        0x1F: ENCMap,
        0x20: Assembly,
        0x21: AssemblyProcessor,
        0x22: AssemblyOS,
        0x23: AssemblyRef,
        0x24: AssemblyRefProcessor,
        0x25: AssemblyRefOS,
        0x26: File,
        0x27: ExportedType,
        0x28: ManifestResource,
        0x29: NestedClass,
        0x2A: GenericParam,
        0x2B: MethodSpec,
        0x2C: GenericParamConstraint,
    }

    def __init__(self, reader, streams):
        Struct.__init__(self, reader, _streams=streams)

    def parse(self):
        self.Header: NetMetaDataTablesHeader = self.expect(NetMetaDataTablesHeader)
        if self.Header.Flags[6]:
            self.ExtraData = self.expect(UInt32)

        self.Module: List[Module] = []
        self.TypeRef: List[TypeRef] = []
        self.TypeDef: List[TypeDef] = []
        self.FieldPtr: List[FieldPtr] = []
        self.Field: List[Field] = []
        self.MethodPtr: List[MethodPtr] = []
        self.MethodDef: List[MethodDef] = []
        self.ParamPtr: List[ParamPtr] = []
        self.Param: List[Param] = []
        self.InterfaceImpl: List[InterfaceImpl] = []
        self.MemberRef: List[MemberRef] = []
        self.Constant: List[Constant] = []
        self.CustomAttribute: List[CustomAttribute] = []
        self.FieldMarshal: List[FieldMarshal] = []
        self.Permission: List[Permission] = []
        self.ClassLayout: List[ClassLayout] = []
        self.FieldLayout: List[FieldLayout] = []
        self.StandAloneSig: List[StandAloneSig] = []
        self.EventMap: List[EventMap] = []
        self.EventPtr: List[EventPtr] = []
        self.Event: List[Event] = []
        self.PropertyMap: List[PropertyMap] = []
        self.PropertyPtr: List[PropertyPtr] = []
        self.Property: List[Property] = []
        self.MethodSemantics: List[MethodSemantics] = []
        self.MethodImpl: List[MethodImpl] = []
        self.ModuleRef: List[ModuleRef] = []
        self.TypeSpec: List[TypeSpec] = []
        self.ImplMap: List[ImplMap] = []
        self.FieldRVA: List[FieldRVA] = []
        self.ENCLog: List[ENCLog] = []
        self.ENCMap: List[ENCMap] = []
        self.Assembly: List[Assembly] = []
        self.AssemblyProcessor: List[AssemblyProcessor] = []
        self.AssemblyOS: List[AssemblyOS] = []
        self.AssemblyRef: List[AssemblyRef] = []
        self.AssemblyRefProcessor: List[AssemblyRefProcessor] = []
        self.AssemblyRefOS: List[AssemblyRefOS] = []
        self.File: List[File] = []
        self.ExportedType: List[ExportedType] = []
        self.ManifestResource: List[ManifestResource] = []
        self.NestedClass: List[NestedClass] = []
        self.GenericParam: List[GenericParam] = []
        self.MethodSpec: List[MethodSpec] = []
        self.GenericParamConstraint: List[GenericParamConstraint] = []

        for k in sorted(self.Header.RowCount):
            count = self.Header.RowCount[k]
            try:
                Type = self.lookup[k]
            except KeyError:
                raise RuntimeError('Cannot parse unknown table index 0x{:08X}; unable to continue parsing.')
            TypeEntries = getattr(self, repr(Type))
            for _ in range(count):
                Entry = self.expect(Type, streams=self._streams, header=self.Header)
                TypeEntries.append(Entry)

    def __getitem__(self, k):
        try:
            Type = self.lookup[k]
        except KeyError:
            return super(NetMetaDataTables, self).__getitem__(k)
        else:
            return getattr(self, repr(Type))


class ODict(dict):
    def in_sequence(self, k, default=None):
        for j, index in enumerate(sorted(self)):
            if j == k:
                return self[index]
        else:
            return default


class NetMetaDataStreamDummy(dict):
    def __init__(self, default=None):
        self._default = default
        dict.__init__(self)

    def __getitem__(self, offset):
        return self._default


class NetMetaDataStream(dict):
    def __init__(self, reader, type, default=None):
        dict.__init__(self)
        self._default = default
        self._reader = reader
        self._type = type
        self._cached = False
        self.read()

    def _next(self):
        return self._reader.expect(self._type)

    def __getitem__(self, offset):
        if offset < 0:
            return self._default
        try:
            return dict.__getitem__(self, offset)
        except KeyError:
            try:
                self._reader.seek(offset)
                item = self._next()
            except ParserException:
                pass
            else:
                self[offset] = item
                return item
        try:
            closest = max(key for key in self if key < offset)
        except ValueError:
            return None
        container = unpack(self[closest])
        return container[offset - closest:] or self._default

    def read(self):
        if self._cached:
            return
        self._reader.seek(0)
        while True:
            offset = self._reader.tell()
            try:
                self[offset] = self._next()
            except ParserException:
                break
        self._cached = True

    def __iter__(self):
        self.read()
        return dict.__iter__(self)


class NetMetaDataStreams(Struct):
    def __init__(self, reader, meta):
        Struct.__init__(self, reader, _meta=meta)

    def _read_all(self, reader, Type):
        while True:
            offset = reader.tell()
            try:
                yield offset, reader.expect(Type)
            except ParserException:
                break

    def parse(self):
        self.Tables: NetMetaDataTables = None
        self.Strings = NetMetaDataStreamDummy('')
        self.US = NetMetaDataStreamDummy('')
        self.GUID = NetMetaDataStreamDummy()
        self.Blob = NetMetaDataStreamDummy(B'')
        with self._reader.checkpoint():
            TableName = '#~'
            for se in self._meta.StreamInfo:
                if se.Name == TableName:
                    break
                if se.Name == '#-':
                    TableName = se.Name
                    break
            for k, name in reversed(tuple(enumerate((TableName, '#Strings', '#US', '#GUID', '#Blob')))):
                for _, Entry in enumerate(self._meta.StreamInfo):
                    if Entry.Name.upper() == name.upper():
                        break
                else:
                    continue
                self._reader.seek(Entry.VirtualAddress)
                try:
                    reader = StreamReader(self._reader.read(Entry.Size))
                except ParserEOF:
                    continue
                if name != TableName:
                    Default = ['', '', None, B''][k - 1]
                    Type = [NullTerminatedString, UnicodeString, StringGUID, RawBytes][k - 1]
                    Stream = NetMetaDataStream(reader, Type, Default)
                    setattr(self, name[1:], Stream)
                else:
                    self.Tables = reader.expect(NetMetaDataTables, streams=self)


class NetMetaData(Struct):
    @property
    def resources(self):
        return self.Streams.Tables.ManifestResource

    @property
    def RVAs(self):
        return self.Streams.Tables.FieldRVA

    def parse(self):
        try:
            self.Signature = self.expect(UInt32)
        except ParserEOF:
            raise InvalidSignature
        if self.Signature != 0x424A5342:
            raise InvalidSignature
        self.MajorVersion = self.expect(UInt16)
        self.MinorVersion = self.expect(UInt16)
        self._Reserved = self.expect(UInt32)
        size = self.expect(UInt32)
        self.VersionString = self.expect(StringPrimitive, size=size, align=4)
        self.Flags = self.expect(UInt16)
        self.StreamCount = self.expect(UInt16)
        self.StreamInfo = [
            self.expect(NetMetaDataStreamEntry)
            for _ in range(self.StreamCount)
        ]
        self.Streams: NetMetaDataStreams = self.expect(NetMetaDataStreams, meta=self)


class NetResourceWithName(Struct):
    def parse(self):
        self.Name = self.expect(StringPrimitive, codec='utf-16LE')
        self.Offset = self.expect(UInt32)
        with self._reader.checkpoint():
            self._reader.seek(self.Offset)
            self.Size = self.expect(UInt32)
            self.Data = self._reader.read(self.Size)


class DotNetHeader:
    def __init__(self, data, pe=None, parse_resources=True):
        try:
            self.pe = pe or pefile.PE(data=data, fast_load=True)
            self.head = NetDirectory(self.reader(
                self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]))
        except IndexError:
            if not data: raise
            # this is a temporary fix for what should really be handled in pefile,
            # see also: https://github.com/erocarrera/pefile/issues/264
            import struct
            count = self.pe.OPTIONAL_HEADER.NumberOfRvaAndSizes
            delta = (self.pe.FILE_HEADER.SizeOfOptionalHeader
                - (self.pe.OPTIONAL_HEADER.sizeof() + count * 8)) // 8
            if delta > 0:
                nt = self.pe.DOS_HEADER.e_lfanew
                data = data[:nt + 0x74] + struct.pack('<I', count + delta) + data[nt + 0x78:]
            self.pe = pefile.PE(data=data, fast_load=True)
            self.head = NetDirectory(self.reader(
                self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]))
        except pefile.PEFormatError:
            raise InvalidDotNetHeader

        try:
            self.meta = NetMetaData(self.reader(self.head.MetaData))
        except pefile.PEFormatError:
            raise InvalidDotNetHeader

        if not parse_resources:
            self.resources = []
        else:
            self.parse_resources()

    def parse_resources(self):
        def parse(reader):
            for entry in self.meta.resources:
                try:
                    reader.seek(entry.Offset)
                    size = reader.expect(UInt32)
                    yield Box(
                        Name=entry.Name,
                        Data=reader.read(size)
                    )
                except ParserEOF:
                    yield Box(
                        Name=entry.Name,
                        Data=B''
                    )
        self.resources = list(parse(self.reader(self.head.Resources)))

    def reader(self, obj):
        return StreamReader(self.pe.get_data(obj.VirtualAddress, obj.Size))
