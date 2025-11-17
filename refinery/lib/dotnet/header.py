"""
Parsing of the .NET header. The code is based on the description in [1].

References:
  [1]: https://www.ntcore.com/files/dotnetformat.htm
"""
from __future__ import annotations

import abc
import codecs
import datetime
import enum
import functools

from typing import Dict, Generic, Optional, TypeVar, Union, cast, get_args

from refinery.lib import lief
from refinery.lib.structures import (
    FlagAccessMixin,
    Struct,
    StructMeta,
    StructReader,
    struct_to_json,
)
from refinery.lib.types import NamedTuple, buf

T = TypeVar('T')
N = TypeVar('N', str, bytes, Optional[str])
R = TypeVar('R', bound=Struct)


class ParserException(RuntimeError):
    pass


class RepresentedByNameOnly(type):
    def __repr__(self):
        return self.__name__

    def __init__(cls, name, bases, nmspc):
        def representation(self):
            return repr(self.__class__)
        setattr(cls, '__repr__', representation)


class DotNetStructReader(StructReader[memoryview]):

    def _dn_raise(self, msg):
        raise ParserException(F'At offset {self.tell():#08x}: {msg}')

    def read_dn_blob(self, size: int | None = None):
        if size is None:
            size = self.read_dn_length_prefix()
        return self.read_exactly(size)

    def read_dn_length_prefix(self):
        size = self.u8fast()
        if not size & 0x80:
            return size
        elif not size & 0x40:
            size = size & 0x3f
            size = size << 8 | self.u8fast()
            return size
        elif not size & 0x20:
            size = size & 0x1f
            size = size << 8 | self.u8fast()
            size = size << 8 | self.u8fast()
            size = size << 8 | self.u8fast()
            return size
        else:
            self._dn_raise('Invalid length prefix.')

    def _decode(self, data: memoryview, codec: str):
        try:
            return codecs.decode(data, codec).rstrip('\0')
        except UnicodeDecodeError:
            codec = 'latin1' if any(data[1::2]) else 'utf-16le'
        try:
            return codecs.decode(data, codec)
        except UnicodeDecodeError:
            return codecs.decode(data, 'UNICODE_ESCAPE')

    def read_dn_string_primitive(self, size: int | None = None, align: int = 1, codec: str = 'latin1'):
        if size is None:
            size = self.read_7bit_encoded_int(35, bigendian=False)
        data = self.read_exactly(size)
        if align > 1:
            self.byte_align(align)
        return self._decode(data, codec)

    def read_dn_unicode_string(self, align: int = 1):
        data = self.read_dn_blob()
        size = len(data)
        if not size:
            return ''
        if size % 2 == 0:
            raise ParserException('Unicode String without terminator.')
        if align > 1:
            self.byte_align(align)
        return self._decode(data[:-1], 'utf-16le')

    def read_dn_encoded_integer(self):
        return self.read_7bit_encoded_int(35, bigendian=False)

    def read_dn_length_prefixed_string(self, codec='utf8'):
        return self.read_dn_string_primitive(codec=codec)

    def read_dn_null_terminated_string(self, align: int = 1, codec='latin1'):
        result = self.read_c_string(codec)
        self.byte_align(align)
        return result

    def read_dn_decimal(self, size: int = 16):
        return int.from_bytes(self.read_exactly(size), 'big')

    def read_dn_time_span(self):
        return datetime.timedelta(microseconds=0.1 * self.u64())

    def read_dn_date_time(self):
        x = self.u64()
        hi_byte = x >> 56
        lo_part = x & 0xFFFFFF_FFFFFFFF
        kind = hi_byte & 0b11
        time = (hi_byte >> 2) << 56 | lo_part
        assert kind < 3, 'invalid date kind'
        if kind == 0:
            tz = None
        elif kind == 1:
            tz = datetime.timezone.utc
        elif kind == 2:
            tz = datetime.datetime.now().astimezone().tzinfo
        else:
            self._dn_raise(F'Invalid date kind {kind}.')
        return datetime.datetime.fromtimestamp(time, tz)

    def read_dn_null(self):
        return None

    def read_dn_guid(self):
        return str(self.read_guid()).upper()


class TypeRepresentedByName(StructMeta):
    def __repr__(cls):
        return cls.__name__


class DotNetStruct(Struct[memoryview], metaclass=TypeRepresentedByName):
    @classmethod
    def Parse(cls, reader: memoryview | DotNetStructReader, *args, **kwargs):
        if isinstance(reader, memoryview):
            reader = DotNetStructReader(reader)
        return super().Parse(reader, *args, **kwargs)

    def __init__(self, reader: DotNetStructReader, *args, **kwargs):
        super().__init__(reader, *args, **kwargs)

    def __repr__(self):
        return self.__class__.__name__


class InvalidDotNetHeader(ValueError):
    def __init__(self, msg=None):
        ValueError.__init__(self, msg or '.NET parsing failed: Corrupt header.')


class InvalidSignature(InvalidDotNetHeader):
    def __init__(self):
        super().__init__('.NET parsing failed: Invalid signature.')


class BitMask:
    def __init__(self, bitmask: int):
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
        return F'{self._bitmask:b}'

    def __json__(self):
        return repr(self)


def bits_required(n: int):
    return 0 if not n else (n - 1).bit_length()


class NetMetaData(DotNetStruct):
    @property
    def resources(self):
        return self.Streams.Tables.ManifestResource

    @property
    def RVAs(self):
        return self.Streams.Tables.FieldRVA

    def __init__(self, reader: DotNetStructReader):
        try:
            self.Signature = reader.u32()
        except EOFError:
            raise InvalidSignature
        if self.Signature != 0x424A5342:
            raise InvalidSignature
        self.MajorVersion = reader.u16()
        self.MinorVersion = reader.u16()
        self._Reserved = reader.u32()
        size = reader.u32()
        self.VersionString = reader.read_dn_string_primitive(size, align=4)
        self.Flags = reader.u16()
        self.StreamCount = reader.u16()
        self.StreamInfo = [NetMetaDataStreamEntry(reader) for _ in range(self.StreamCount)]
        self.Streams = NetMetaDataStreams(reader, meta=self)


class NetMetaDataStreamEntry(DotNetStruct):
    def __init__(self, reader: DotNetStructReader):
        self.VirtualAddress = reader.u32()
        self.Size = reader.u32()
        self.Name = reader.read_dn_null_terminated_string(align=4)


class NetMetaDataStream(Dict[int, N], abc.ABC):
    default: N

    def __init__(self, reader: DotNetStructReader):
        dict.__init__(self)
        self._reader = reader
        reader.seek(offset := 0)
        while not reader.eof:
            self[offset] = self.stream_next()
            offset = reader.tell()
        self[offset] = self.default

    @abc.abstractmethod
    def stream_next(self) -> N:
        raise NotImplementedError

    def __missing__(self, offset: int) -> N:
        if offset < 0:
            return self.default
        try:
            self._reader.seek(offset)
            item = self.stream_next()
        except (EOFError, ParserException):
            pass
        else:
            self[offset] = item
            return item
        try:
            closest = max(key for key in self if key < offset)
        except ValueError:
            return self.default
        container = self[closest]
        if not isinstance(container, (str, bytes, bytearray, memoryview)):
            return self.default
        return container[offset - closest:]


class NetMetaDataStreamStrA(NetMetaDataStream[str]):
    def stream_next(self):
        return self._reader.read_dn_null_terminated_string()
    default = ''


class NetMetaDataStreamStrU(NetMetaDataStream[str]):
    def stream_next(self):
        return self._reader.read_dn_unicode_string()
    default = ''


class NetMetaDataStreamGUID(NetMetaDataStream[Optional[str]]):
    def stream_next(self):
        return self._reader.read_dn_guid()
    default = None


class NetMetaDataStreamBlob(NetMetaDataStream[bytes]):
    def stream_next(self):
        return self._reader.read_dn_blob()
    default = B''


class StreamNames(str, enum.Enum):
    TablesTilde = '#~'
    TablesDash = '#-'
    Strings = '#Strings'
    US = '#US'
    GUID = '#GUID'
    Blob = '#Blob'


class NetMetaDataStreams(Struct[memoryview]):
    Tables: NetMetaDataTables
    StrA: NetMetaDataStreamStrA
    StrU: NetMetaDataStreamStrU
    GUID: NetMetaDataStreamGUID
    Blob: NetMetaDataStreamBlob

    Strings: NetMetaDataStreamStrA
    US: NetMetaDataStreamStrU

    def __init__(self, reader: DotNetStructReader, meta: NetMetaData):
        with reader.detour():
            TableName = StreamNames.TablesTilde
            for se in meta.StreamInfo:
                if se.Name == TableName:
                    break
                if se.Name == StreamNames.TablesDash:
                    TableName = se.Name
                    break
            for name in (
                StreamNames.Blob,
                StreamNames.GUID,
                StreamNames.US,
                StreamNames.Strings,
                TableName
            ):
                for entry in meta.StreamInfo:
                    if entry.Name.upper() != name.upper():
                        continue
                    try:
                        reader.seek(entry.VirtualAddress)
                        stream = DotNetStructReader(reader.read(entry.Size))
                    except EOFError:
                        continue
                    if name == TableName:
                        self.Tables = NetMetaDataTables(stream, self)
                    elif name == StreamNames.Strings:
                        self.StrA = NetMetaDataStreamStrA(stream)
                        self.Strings = self.StrA
                    elif name == StreamNames.US:
                        self.StrU = NetMetaDataStreamStrU(stream)
                        self.US = self.StrU
                    elif name == StreamNames.Blob:
                        self.Blob = NetMetaDataStreamBlob(stream)
                    elif name == StreamNames.GUID:
                        self.GUID = NetMetaDataStreamGUID(stream)
                    break


class Module(DotNetStruct):
    def __init__(self, reader: DotNetStructReader, tables: NetMetaDataTables):
        self.Generation = reader.u16()
        self.Name = tables._read_strA()
        self.MvId = tables._read_guid()
        self.EncId = tables._read_guid()
        self.EncBaseId = tables._read_guid()


class TypeRef(DotNetStruct):
    def __init__(self, reader: DotNetStructReader, tables: NetMetaDataTables):
        self.ResolutionScope = tables._read_ResolutionScopeIndex()
        self.TypeName = tables._read_strA()
        self.TypeNamespace = tables._read_strA()


class TypeDef(DotNetStruct):
    def __init__(self, reader: DotNetStructReader, tables: NetMetaDataTables):
        self.Flags = reader.u32()
        self.TypeName = tables._read_strA()
        self.TypeNamespace = tables._read_strA()
        self.Extends = tables._read_TypeDefOrRefIndex()
        self.FieldList = tables._read_FieldIndex()
        self.MethodList = tables._read_MethodDefIndex()


class FieldPtr(DotNetStruct):
    def __init__(self, reader: DotNetStructReader, tables: NetMetaDataTables):
        self.Ref = reader.u16()


class FieldAccess(enum.IntEnum):
    CompilerControlled = 0b000 # noqa
    Private            = 0b001 # noqa
    FamAndAssem        = 0b010 # noqa
    Assembly           = 0b011 # noqa
    Family             = 0b100 # noqa
    FamOrAssem         = 0b101 # noqa
    Public             = 0b110 # noqa


class FieldFlags(FlagAccessMixin, enum.IntFlag):
    Static          = 1 << 0   # noqa
    InitOnly        = 1 << 1   # noqa
    Literal         = 1 << 2   # noqa
    NotSerialized   = 1 << 3   # noqa
    HasFieldRVA     = 1 << 4   # noqa
    SpecialName     = 1 << 5   # noqa
    RTSpecialName   = 1 << 6   # noqa
    HasFieldMarshal = 1 << 7   # noqa
    PinvokeImpl     = 1 << 8   # noqa
    HasDefault      = 1 << 9   # noqa


class Field(DotNetStruct):
    def __init__(self, reader: DotNetStructReader, tables: NetMetaDataTables):
        self.Access = FieldAccess(reader.read_integer(4) & 7)
        self.Flags = FieldFlags(reader.read_integer(12))
        self.Name = tables._read_strA()
        self.Signature = tables._read_blob()


class MethodPtr(DotNetStruct):
    def __init__(self, reader: DotNetStructReader, tables: NetMetaDataTables):
        self.Ref = reader.u16()


class MethodDef(DotNetStruct):
    def __init__(self, reader: DotNetStructReader, tables: NetMetaDataTables):
        self.RVA = reader.u32()
        self.ImplFlags = reader.u16()
        self.Flags = reader.u16()
        self.Name = tables._read_strA()
        self.Signature = tables._read_blob()
        self.ParamList = tables._read_ParamIndex()


class ParamPtr(DotNetStruct):
    def __init__(self, reader: DotNetStructReader, tables: NetMetaDataTables):
        self.Ref = reader.u16()


class Param(DotNetStruct):
    def __init__(self, reader: DotNetStructReader, tables: NetMetaDataTables):
        self.Flags = reader.u16()
        self.Sequence = reader.u16()
        self.Name = tables._read_strA()


class InterfaceImpl(DotNetStruct):
    def __init__(self, reader: DotNetStructReader, tables: NetMetaDataTables):
        self.Class = tables._read_TypeDefIndex()
        self.Interface = tables._read_TypeDefOrRefIndex()


class MemberRef(DotNetStruct):
    def __init__(self, reader: DotNetStructReader, tables: NetMetaDataTables):
        self.Class = tables._read_MemberRefParentIndex()
        self.Name = tables._read_strA()
        self.Signature = tables._read_blob()


class Constant(DotNetStruct):
    def __init__(self, reader: DotNetStructReader, tables: NetMetaDataTables):
        self.Type = reader.u16()
        self.Parent = tables._read_HasConstantIndex()
        self.Value = tables._read_blob()


class CustomAttribute(DotNetStruct):
    def __init__(self, reader: DotNetStructReader, tables: NetMetaDataTables):
        self.Parent = tables._read_HasCustomAttributeIndex()
        self.Type = tables._read_CustomAttributeTypeIndex()
        self.Value = tables._read_blob()


class FieldMarshal(DotNetStruct):
    def __init__(self, reader: DotNetStructReader, tables: NetMetaDataTables):
        self.Parent = tables._read_HasFieldMarshallIndex()
        self.NativeType = tables._read_blob()


class Permission(DotNetStruct):
    def __init__(self, reader: DotNetStructReader, tables: NetMetaDataTables):
        self.Action = reader.u16()
        self.Parent = tables._read_HasDeclSecurityIndex()
        self.PermissionSet = tables._read_blob()


class ClassLayout(DotNetStruct):
    def __init__(self, reader: DotNetStructReader, tables: NetMetaDataTables):
        self.PackingSize = reader.u16()
        self.ClassSize = reader.u32()
        self.Parent = tables._read_TypeDefIndex()


class FieldLayout(DotNetStruct):
    def __init__(self, reader: DotNetStructReader, tables: NetMetaDataTables):
        self.Offset = reader.u32()
        self.Field = tables._read_FieldIndex()


class StandAloneSig(DotNetStruct):
    def __init__(self, reader: DotNetStructReader, tables: NetMetaDataTables):
        self.Signature = tables._read_blob()


class EventMap(DotNetStruct):
    def __init__(self, reader: DotNetStructReader, tables: NetMetaDataTables):
        self.Parent = tables._read_TypeDefIndex()
        self.EventList = tables._read_EventIndex()


class EventPtr(DotNetStruct):
    def __init__(self, reader: DotNetStructReader, tables: NetMetaDataTables):
        self.Ref = reader.u16()


class Event(DotNetStruct):
    def __init__(self, reader: DotNetStructReader, tables: NetMetaDataTables):
        self.EventFlags = reader.u16()
        self.Name = tables._read_strA()
        self.EventType = tables._read_TypeDefOrRefIndex()


class PropertyMap(DotNetStruct):
    def __init__(self, reader: DotNetStructReader, tables: NetMetaDataTables):
        self.Parent = tables._read_TypeDefIndex()
        self.PropertyList = tables._read_PropertyIndex()


class PropertyPtr(DotNetStruct):
    def __init__(self, reader: DotNetStructReader, tables: NetMetaDataTables):
        self.Ref = reader.u16()


class Property(DotNetStruct):
    def __init__(self, reader: DotNetStructReader, tables: NetMetaDataTables):
        self.Flags = reader.u16()
        self.Name = tables._read_strA()
        self.Type = tables._read_blob()


class MethodSemantics(DotNetStruct):
    def __init__(self, reader: DotNetStructReader, tables: NetMetaDataTables):
        self.Semantics = reader.u16()
        self.Method = tables._read_MethodDefIndex()
        self.Association = tables._read_HasSemanticsIndex()


class MethodImpl(DotNetStruct):
    def __init__(self, reader: DotNetStructReader, tables: NetMetaDataTables):
        self.Class = tables._read_TypeDefIndex()
        self.MethodBody = tables._read_MethodDefOrRefIndex()
        self.MethodDeclaration = tables._read_MethodDefOrRefIndex()


class ModuleRef(DotNetStruct):
    def __init__(self, reader: DotNetStructReader, tables: NetMetaDataTables):
        self.Name = tables._read_strA()


class TypeSpec(DotNetStruct):
    def __init__(self, reader: DotNetStructReader, tables: NetMetaDataTables):
        self.Signature = tables._read_blob()


class ImplMap(DotNetStruct):
    def __init__(self, reader: DotNetStructReader, tables: NetMetaDataTables):
        self.MappingFlags = reader.u16()
        self.MemberForwarded = tables._read_MemberForwardedIndex()
        self.ImportName = tables._read_strA()
        self.ImportScope = tables._read_ModuleRefIndex()


class FieldRVA(DotNetStruct):
    def __init__(self, reader: DotNetStructReader, tables: NetMetaDataTables):
        self.RVA = reader.u32()
        self.Field = tables._read_FieldIndex()


class Assembly(DotNetStruct):
    def __init__(self, reader: DotNetStructReader, tables: NetMetaDataTables):
        self.HashAlgId = reader.u32()
        self.MajorVersion = reader.u16()
        self.MinorVersion = reader.u16()
        self.BuildNumber = reader.u16()
        self.RevisionNumber = reader.u16()
        self.Flags = reader.u32()
        self.PublicKey = tables._read_blob()
        self.Name = tables._read_strA()
        self.Culture = tables._read_strA()


class AssemblyProcessor(DotNetStruct):
    def __init__(self, reader: DotNetStructReader, tables: NetMetaDataTables):
        self.Processor = reader.u32()


class AssemblyOS(DotNetStruct):
    def __init__(self, reader: DotNetStructReader, tables: NetMetaDataTables):
        self.OsPlatformId = reader.u32()
        self.OsMajorVersion = reader.u32()
        self.OsMinorVersion = reader.u32()


class AssemblyRef(DotNetStruct):
    def __init__(self, reader: DotNetStructReader, tables: NetMetaDataTables):
        self.MajorVersion = reader.u16()
        self.MinorVersion = reader.u16()
        self.BuildNumber = reader.u16()
        self.RevisionNumber = reader.u16()
        self.Flags = reader.u32()
        self.PublicKeyOrToken = tables._read_blob()
        self.Name = tables._read_strA()
        self.Culture = tables._read_strA()
        self.HashValue = tables._read_blob()


class AssemblyRefProcessor(DotNetStruct):
    def __init__(self, reader: DotNetStructReader, tables: NetMetaDataTables):
        self.Processor = reader.u32()
        self.AssemblyRef = tables._read_AssemblyRefIndex()


class AssemblyRefOS(DotNetStruct):
    def __init__(self, reader: DotNetStructReader, tables: NetMetaDataTables):
        self.OsPlatformId = reader.u32()
        self.OsMajorVersion = reader.u32()
        self.OsMinorVersion = reader.u32()
        self.AssemblyRef = tables._read_AssemblyRefIndex()


class File(DotNetStruct):
    def __init__(self, reader: DotNetStructReader, tables: NetMetaDataTables):
        self.Flags = reader.u32()
        self.Name = tables._read_strA()
        self.HashValue = tables._read_blob()


class ExportedType(DotNetStruct):
    def __init__(self, reader: DotNetStructReader, tables: NetMetaDataTables):
        self.Flags = reader.u32()
        self.TypeDefId = reader.u32()
        self.TypeName = tables._read_strA()
        self.TypeNamespace = tables._read_strA()
        self.Implementation = tables._read_ImplementationIndex()


class ManifestResource(DotNetStruct):
    def __init__(self, reader: DotNetStructReader, tables: NetMetaDataTables):
        self.Offset = reader.u32()
        self.Flags = reader.u32()
        self.Name = tables._read_strA()
        self.Implementation = tables._read_ImplementationIndex()


class NestedClass(DotNetStruct):
    def __init__(self, reader: DotNetStructReader, tables: NetMetaDataTables):
        self.NestedClass = tables._read_TypeDefIndex()
        self.EnclosingClass = tables._read_TypeDefIndex()


class GenericParam(DotNetStruct):
    def __init__(self, reader: DotNetStructReader, tables: NetMetaDataTables):
        self.Number = reader.u16()
        self.Flags = reader.u16()
        self.Owner = tables._read_TypeOrMethodDefIndex()
        self.Name = tables._read_strA()


class MethodSpec(DotNetStruct):
    def __init__(self, reader: DotNetStructReader, tables: NetMetaDataTables):
        self.Method = tables._read_MethodDefOrRefIndex()
        self.Instantiation = tables._read_blob()


class GenericParamConstraint(DotNetStruct):
    def __init__(self, reader: DotNetStructReader, tables: NetMetaDataTables):
        self.Owner = tables._read_GenericParamIndex()
        self.Constraint = tables._read_TypeDefOrRefIndex()


class ENCLog(DotNetStruct):
    def __init__(self, reader: DotNetStructReader, tables: NetMetaDataTables):
        self.Token = reader.u32()
        self.FuncCode = reader.u32()


class ENCMap(DotNetStruct):
    def __init__(self, reader: DotNetStructReader, tables: NetMetaDataTables):
        self.Token = reader.u32()


class ImageDataDirectory(DotNetStruct):
    def __init__(self, reader: DotNetStructReader):
        self.VirtualAddress = reader.u32()
        self.Size = reader.u32()


class NetDirectoryFlags(FlagAccessMixin, enum.IntFlag):
    IL_ONLY = 0b1
    REQUIRE_32BIT = 0b10
    IL_LIBRARY = 0b100
    STRONG_NAME_SIGNED = 0b1000
    NATIVE_ENTRYPOINT = 0b10000
    TRACK_DEBUG_DATA = 0b10000000000000000


class NetDirectory(DotNetStruct):
    def __init__(self, reader: DotNetStructReader):
        self.Size = reader.u32()
        self.MajorRuntimeVersion = reader.u16()
        self.MinorRuntimeVersion = reader.u16()
        self.MetaData = ImageDataDirectory(reader)
        self.Flags = reader.u32()
        self.EntryPointToken = reader.u32()
        self.Resources = ImageDataDirectory(reader)
        self.StringNameSignature = ImageDataDirectory(reader)
        self.CodeManagerTable = ImageDataDirectory(reader)
        self.VTableFixups = ImageDataDirectory(reader)
        self.ExportAddressTableJumps = ImageDataDirectory(reader)
        self.ManagedNativeHeader = ImageDataDirectory(reader)
        self.KnownFlags = NetDirectoryFlags(self.Flags)


class NetMetaFlags(FlagAccessMixin, enum.IntFlag):
    LARGE_STRA = 0b1
    LARGE_GUID = 0b10
    LARGE_BLOB = 0b100
    PADDING = 0b1000
    DELTA_ONLY = 0b100000
    EXTRA_DATA = 0b1000000
    HAS_DELETE = 0b10000000


class NetMetaDataTablesHeader(DotNetStruct):
    def __init__(self, reader: DotNetStructReader):
        self._Reserved1 = reader.u32()
        self.MajorVersion = reader.u8()
        self.MinorVersion = reader.u8()
        self.Flags = NetMetaFlags(reader.u8())
        self._Reserved2 = reader.u8()
        self.ExistingRows = BitMask(reader.u64())
        self.SortedRows = BitMask(reader.u64())
        self.RowCount = {k: reader.u32() for k in self.ExistingRows}


class Index(Generic[R]):
    RowName: str | None
    RowType: int | None
    Index: int

    def __init__(
        self,
        reader: DotNetStructReader,
        tables: NetMetaDataTables,
        streams: NetMetaDataStreams,
        th: type[R]
    ):
        self._s = streams
        info = tables._read_index_info(th)
        raw = reader.u32() if info.large else reader.u16()
        masked = raw & info.mask
        try:
            self.RowName = info.names[masked]
            self.RowType = info.types[masked]
        except IndexError:
            self.RowName = None
            self.RowType = None
        self.Index = raw >> info.bits

    def __json__(self):
        return struct_to_json(self.Value)

    @functools.cached_property
    def Value(self) -> R | None:
        try:
            return cast(R, self._s.Tables[self.RowType][self.Index - 1])
        except IndexError:
            return None


TypeDefOrRefIndex = Union[
    TypeDef,
    TypeRef,
    TypeSpec,
]
HasConstantIndex = Union[
    Field,
    Param,
    Property,
]
HasCustomAttributeIndex = Union[
    MethodDef,
    Field,
    TypeRef,
    TypeDef,
    Param,
    InterfaceImpl,
    MemberRef,
    Module,
    Permission,
    Property,
    Event,
    StandAloneSig,
    ModuleRef,
    TypeSpec,
    Assembly,
    AssemblyRef,
    File,
    ExportedType,
    ManifestResource,
]
HasFieldMarshallIndex = Union[
    Field,
    Param,
]
HasDeclSecurityIndex = Union[
    TypeDef,
    MethodDef,
    Assembly,
]
MemberRefParentIndex = Union[
    TypeDef,
    TypeRef,
    ModuleRef,
    MethodDef,
    TypeSpec,
]
HasSemanticsIndex = Union[
    Event,
    Property,
]
MethodDefOrRefIndex = Union[
    MethodDef,
    MemberRef,
]
MemberForwardedIndex = Union[
    Field,
    MethodDef,
]
ImplementationIndex = Union[
    File,
    AssemblyRef,
    ExportedType,
]
CustomAttributeTypeIndex = Union[
    MethodDef,
    MemberRef,
]
ResolutionScopeIndex = Union[
    Module,
    ModuleRef,
    AssemblyRef,
    TypeRef,
]
TypeOrMethodDefIndex = Union[
    TypeDef,
    MethodDef,
]
FieldIndex = Union[
    Field,
]
MethodDefIndex = Union[
    MethodDef,
]
ParamIndex = Union[
    Param,
]
TypeDefIndex = Union[
    TypeDef,
]
EventIndex = Union[
    Event,
]
PropertyIndex = Union[
    Property,
]
ModuleRefIndex = Union[
    ModuleRef,
]
AssemblyRefIndex = Union[
    AssemblyRef,
]
GenericParamIndex = Union[
    GenericParam,
]


class NetMetaDataTables(DotNetStruct):
    lookup: dict[int, type[DotNetStruct]] = {
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

    def _read_TypeDefOrRefIndex(self) -> Index[TypeDefOrRefIndex]:
        return self._read_index(TypeDefOrRefIndex)

    def _read_HasConstantIndex(self) -> Index[HasConstantIndex]:
        return self._read_index(HasConstantIndex)

    def _read_HasCustomAttributeIndex(self) -> Index[HasCustomAttributeIndex]:
        return self._read_index(HasCustomAttributeIndex)

    def _read_HasFieldMarshallIndex(self) -> Index[HasFieldMarshallIndex]:
        return self._read_index(HasFieldMarshallIndex)

    def _read_HasDeclSecurityIndex(self) -> Index[HasDeclSecurityIndex]:
        return self._read_index(HasDeclSecurityIndex)

    def _read_MemberRefParentIndex(self) -> Index[MemberRefParentIndex]:
        return self._read_index(MemberRefParentIndex)

    def _read_HasSemanticsIndex(self) -> Index[HasSemanticsIndex]:
        return self._read_index(HasSemanticsIndex)

    def _read_MethodDefOrRefIndex(self) -> Index[MethodDefOrRefIndex]:
        return self._read_index(MethodDefOrRefIndex)

    def _read_MemberForwardedIndex(self) -> Index[MemberForwardedIndex]:
        return self._read_index(MemberForwardedIndex)

    def _read_ImplementationIndex(self) -> Index[ImplementationIndex]:
        return self._read_index(ImplementationIndex)

    def _read_CustomAttributeTypeIndex(self) -> Index[CustomAttributeTypeIndex]:
        return self._read_index(CustomAttributeTypeIndex)

    def _read_ResolutionScopeIndex(self) -> Index[ResolutionScopeIndex]:
        return self._read_index(ResolutionScopeIndex)

    def _read_TypeOrMethodDefIndex(self) -> Index[TypeOrMethodDefIndex]:
        return self._read_index(TypeOrMethodDefIndex)

    def _read_FieldIndex(self) -> Index[FieldIndex]:
        return self._read_index(FieldIndex)

    def _read_MethodDefIndex(self) -> Index[MethodDefIndex]:
        return self._read_index(MethodDefIndex)

    def _read_ParamIndex(self) -> Index[ParamIndex]:
        return self._read_index(ParamIndex)

    def _read_TypeDefIndex(self) -> Index[TypeDefIndex]:
        return self._read_index(TypeDefIndex)

    def _read_EventIndex(self) -> Index[EventIndex]:
        return self._read_index(EventIndex)

    def _read_PropertyIndex(self) -> Index[PropertyIndex]:
        return self._read_index(PropertyIndex)

    def _read_ModuleRefIndex(self) -> Index[ModuleRefIndex]:
        return self._read_index(ModuleRefIndex)

    def _read_AssemblyRefIndex(self) -> Index[AssemblyRefIndex]:
        return self._read_index(AssemblyRefIndex)

    def _read_GenericParamIndex(self) -> Index[GenericParamIndex]:
        return self._read_index(GenericParamIndex)

    @functools.lru_cache(maxsize=None)
    def _read_index_info(self, th: type):
        class IndexInfo(NamedTuple):
            names: tuple[str, ...]
            types: tuple[NetTable, ...]
            bits: int
            mask: int
            large: bool

        if not (options := get_args(th)):
            options = (th,)

        names = tuple(t.__name__ for t in options)
        types = tuple(NetTable[n] for n in names)
        row_count = self.Header.RowCount
        row_max_len = max(row_count.get(t, 0) for t in types)
        bits_index = bits_required(len(names))
        bits_total = bits_index + bits_required(row_max_len)
        mask = (1 << bits_index) - 1
        return IndexInfo(names, types, bits_index, mask, bits_total > 16)

    def __init__(self, reader: DotNetStructReader, streams: NetMetaDataStreams):
        self.Header: NetMetaDataTablesHeader = NetMetaDataTablesHeader(reader)
        if NetMetaFlags.EXTRA_DATA in self.Header.Flags:
            self.ExtraData = reader.u32()

        _index_strA = reader.u32 if (NetMetaFlags.LARGE_STRA in self.Header.Flags) else reader.u16
        _index_guid = reader.u32 if (NetMetaFlags.LARGE_GUID in self.Header.Flags) else reader.u16
        _index_blob = reader.u32 if (NetMetaFlags.LARGE_BLOB in self.Header.Flags) else reader.u16

        self._read_strA = lambda: streams.StrA[_index_strA()]
        self._read_blob = lambda: streams.Blob[_index_blob()]
        self._read_guid = lambda: streams.GUID[(_index_guid() - 1) << 4]

        def _read_index(th) -> Index:
            return Index(reader, self, streams, th)

        self._read_index = _read_index

        self.Module: list[Module] = []
        self.TypeRef: list[TypeRef] = []
        self.TypeDef: list[TypeDef] = []
        self.FieldPtr: list[FieldPtr] = []
        self.Field: list[Field] = []
        self.MethodPtr: list[MethodPtr] = []
        self.MethodDef: list[MethodDef] = []
        self.ParamPtr: list[ParamPtr] = []
        self.Param: list[Param] = []
        self.InterfaceImpl: list[InterfaceImpl] = []
        self.MemberRef: list[MemberRef] = []
        self.Constant: list[Constant] = []
        self.CustomAttribute: list[CustomAttribute] = []
        self.FieldMarshal: list[FieldMarshal] = []
        self.Permission: list[Permission] = []
        self.ClassLayout: list[ClassLayout] = []
        self.FieldLayout: list[FieldLayout] = []
        self.StandAloneSig: list[StandAloneSig] = []
        self.EventMap: list[EventMap] = []
        self.EventPtr: list[EventPtr] = []
        self.Event: list[Event] = []
        self.PropertyMap: list[PropertyMap] = []
        self.PropertyPtr: list[PropertyPtr] = []
        self.Property: list[Property] = []
        self.MethodSemantics: list[MethodSemantics] = []
        self.MethodImpl: list[MethodImpl] = []
        self.ModuleRef: list[ModuleRef] = []
        self.TypeSpec: list[TypeSpec] = []
        self.ImplMap: list[ImplMap] = []
        self.FieldRVA: list[FieldRVA] = []
        self.ENCLog: list[ENCLog] = []
        self.ENCMap: list[ENCMap] = []
        self.Assembly: list[Assembly] = []
        self.AssemblyProcessor: list[AssemblyProcessor] = []
        self.AssemblyOS: list[AssemblyOS] = []
        self.AssemblyRef: list[AssemblyRef] = []
        self.AssemblyRefProcessor: list[AssemblyRefProcessor] = []
        self.AssemblyRefOS: list[AssemblyRefOS] = []
        self.File: list[File] = []
        self.ExportedType: list[ExportedType] = []
        self.ManifestResource: list[ManifestResource] = []
        self.NestedClass: list[NestedClass] = []
        self.GenericParam: list[GenericParam] = []
        self.MethodSpec: list[MethodSpec] = []
        self.GenericParamConstraint: list[GenericParamConstraint] = []

        for k in sorted(self.Header.RowCount):
            count = self.Header.RowCount[k]
            try:
                Type = self.lookup[k]
            except KeyError:
                raise RuntimeError(F'Cannot parse unknown table index {k:#02x}; unable to continue parsing.')
            TypeEntries: list = getattr(self, repr(Type))
            for _ in range(count):
                Entry = Type(reader, tables=self)
                TypeEntries.append(Entry)

    def __getitem__(self, k) -> list[DotNetStruct]:
        try:
            Type = self.lookup[k]
        except KeyError:
            return getattr(self, k)
        else:
            return getattr(self, repr(Type))


class NetResourceWithName(DotNetStruct):
    def __init__(self, reader: DotNetStructReader):
        self.Name = reader.read_dn_string_primitive(codec='utf-16LE')
        self.Offset = reader.u32()
        with reader.detour(self.Offset):
            self.Size = reader.u32()
            self.Data = reader.read(self.Size)


class NetTable(enum.IntEnum):
    Assembly               = 0x20  # noqa
    AssemblyOS             = 0x22  # noqa
    AssemblyProcessor      = 0x21  # noqa
    AssemblyRef            = 0x23  # noqa
    AssemblyRefOS          = 0x25  # noqa
    AssemblyRefProcessor   = 0x24  # noqa
    ClassLayout            = 0x0F  # noqa
    Constant               = 0x0B  # noqa
    CustomAttribute        = 0x0C  # noqa
    ENCLog                 = 0x1E  # noqa
    ENCMap                 = 0x1F  # noqa
    Event                  = 0x14  # noqa
    EventMap               = 0x12  # noqa
    EventPtr               = 0x13  # noqa
    ExportedType           = 0x27  # noqa
    Field                  = 0x04  # noqa
    FieldLayout            = 0x10  # noqa
    FieldMarshal           = 0x0D  # noqa
    FieldPtr               = 0x03  # noqa
    FieldRVA               = 0x1D  # noqa
    File                   = 0x26  # noqa
    GenericParam           = 0x2A  # noqa
    GenericParamConstraint = 0x2C  # noqa
    ImplMap                = 0x1C  # noqa
    InterfaceImpl          = 0x09  # noqa
    ManifestResource       = 0x28  # noqa
    MemberRef              = 0x0A  # noqa
    MethodDef              = 0x06  # noqa
    MethodImpl             = 0x19  # noqa
    MethodPtr              = 0x05  # noqa
    MethodSemantics        = 0x18  # noqa
    MethodSpec             = 0x2B  # noqa
    Module                 = 0x00  # noqa
    ModuleRef              = 0x1A  # noqa
    NestedClass            = 0x29  # noqa
    Param                  = 0x08  # noqa
    ParamPtr               = 0x07  # noqa
    Permission             = 0x0E  # noqa
    Property               = 0x17  # noqa
    PropertyMap            = 0x15  # noqa
    PropertyPtr            = 0x16  # noqa
    StandAloneSig          = 0x11  # noqa
    TypeDef                = 0x02  # noqa
    TypeRef                = 0x01  # noqa
    TypeSpec               = 0x1B  # noqa


class DotNetResource(NamedTuple):
    Name: str
    Data: buf = B''


class DotNetHeader:
    def __init__(self, data, pe=None, parse_resources=True):
        try:
            view = memoryview(data)
            self.pe = pe = pe or lief.load_pe(data)
            self.data = view
            self.head = NetDirectory(self._reader_from_pe(pe.data_directory(lief.PE.DataDirectory.TYPES.CLR_RUNTIME_HEADER)))
        except Exception as E:
            raise InvalidDotNetHeader from E
        try:
            self.meta = NetMetaData(self._reader_from_dn(self.head.MetaData))
        except Exception as E:
            raise InvalidDotNetHeader from E
        self.resources = self.parse_resources() if parse_resources else []

    def parse_resources(self):
        def parse(reader: DotNetStructReader):
            for entry in self.meta.resources:
                try:
                    reader.seek(entry.Offset)
                    size = reader.u32()
                    yield DotNetResource(entry.Name, reader.read(size))
                except EOFError:
                    yield DotNetResource(entry.Name)
        return list(parse(self._reader_from_dn(self.head.Resources)))

    def _reader_from_pe(self, dir: lief.PE.DataDirectory):
        return self._reader(dir.rva, dir.size)

    def _reader_from_dn(self, dir: ImageDataDirectory | NetMetaDataStreamEntry):
        return self._reader(dir.VirtualAddress, dir.Size)

    def _reader(self, rva: int, size: int):
        start = self.pe.rva_to_offset(rva)
        end = start + size
        return DotNetStructReader(self.data[start:end])
