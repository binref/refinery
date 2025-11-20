"""
Parsing of the .NET header. The code is based on the description in [1].

References:
  [1]: https://www.ntcore.com/files/dotnetformat.htm
"""
from __future__ import annotations

import abc
import bisect
import codecs
import dataclasses
import datetime
import enum
import functools

from typing import (
    Dict,
    Generic,
    NewType,
    Optional,
    TypeVar,
    Union,
    get_args,
    get_origin,
    get_type_hints,
    overload,
)
from uuid import UUID

from refinery.lib import lief
from refinery.lib.structures import (
    FlagAccessMixin,
    Struct,
    StructMeta,
    StructReader,
)
from refinery.lib.types import NamedTuple, buf

T = TypeVar('T')
N = TypeVar('N', str, bytes, Optional[UUID])
R = TypeVar('R')


class Unused:
    def __class_getitem__(cls, _):
        return type('Unused', (), {})


UInt32 = NewType('UInt32', int)
UInt16 = NewType('UInt16', int)


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
        self._offsets = offsets = []
        while not reader.eof:
            offsets.append(offset)
            self[offset] = self.stream_next()
            offset = reader.tell()

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
            offsets = self._offsets
            closest = bisect.bisect_left(offsets, offset)
            closest = offsets[closest - 1]
        except ValueError:
            return self.default
        container = self[closest]
        if not isinstance(container, (str, bytes, bytearray, memoryview)):
            return self.default
        return container[offset - closest:]


class NetMetaDataStreamStrA(NetMetaDataStream[str]):
    def stream_next(self):
        return codecs.decode(self._reader.read_terminated_array(B'\0'), 'latin1')
    default = ''


class NetMetaDataStreamStrU(NetMetaDataStream[str]):
    def stream_next(self):
        return self._reader.read_dn_unicode_string()
    default = ''


class NetMetaDataStreamGUID(NetMetaDataStream[Optional[UUID]]):
    def stream_next(self):
        return self._reader.read_guid()
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


class Module(NamedTuple):
    Generation: UInt16
    Name: str
    MvId: UUID
    EncId: UUID
    EncBaseId: UUID


class TypeRef(NamedTuple):
    ResolutionScope: Index[ResolutionScope]
    TypeName: str
    TypeNamespace: str


class TypeDef(NamedTuple):
    Flags: UInt32
    TypeName: str
    TypeNamespace: str
    Extends: Index[TypeDefOrRef]
    FieldList: Index[Field]
    MethodList: Index[MethodDef]


class FieldPtr(NamedTuple):
    Ref: UInt16


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


@dataclasses.dataclass(frozen=True)
class Field:
    AccessAndFlags: UInt16
    Name: str
    Signature: bytes

    def __json__(self):
        return {
            'Name': self.Name,
            'Signature': self.Signature,
            'Flags': self.Flags,
            'Access': self.Access,
        }

    @functools.cached_property
    def Flags(self):
        return FieldFlags(self.AccessAndFlags >> 4)

    @functools.cached_property
    def Access(self):
        return FieldAccess(self.AccessAndFlags & 7)


class MethodPtr(NamedTuple):
    Ref: UInt16


class MethodDef(NamedTuple):
    RVA: UInt32
    ImplFlags: UInt16
    Flags: UInt16
    Name: str
    Signature: bytes
    ParamList: Index[Param]


class ParamPtr(NamedTuple):
    Ref: UInt16


class Param(NamedTuple):
    Flags: UInt16
    Sequence: UInt16
    Name: str


class InterfaceImpl(NamedTuple):
    Class: Index[TypeDef]
    Interface: Index[TypeDefOrRef]


class MemberRef(NamedTuple):
    Class: Index[MemberRefParent]
    Name: str
    Signature: bytes


class Constant(NamedTuple):
    Type: UInt16
    Parent: Index[HasConstant]
    Value: bytes


class CustomAttribute(NamedTuple):
    Parent: Index[HasCustomAttribute]
    Type: Index[CustomAttributeType]
    Value: bytes


class FieldMarshal(NamedTuple):
    Parent: Index[HasFieldMarshall]
    NativeType: bytes


class Permission(NamedTuple):
    Action: UInt16
    Parent: Index[HasDeclSecurity]
    PermissionSet: bytes


class ClassLayout(NamedTuple):
    PackingSize: UInt16
    ClassSize: UInt32
    Parent: Index[TypeDef]


class FieldLayout(NamedTuple):
    Offset: UInt32
    Field: Index[Field]


class StandAloneSig(NamedTuple):
    Signature: bytes


class EventMap(NamedTuple):
    Parent: Index[TypeDef]
    EventList: Index[Event]


class EventPtr(NamedTuple):
    Ref: UInt16


class Event(NamedTuple):
    EventFlags: UInt16
    Name: str
    EventType: Index[TypeDefOrRef]


class PropertyMap(NamedTuple):
    Parent: Index[TypeDef]
    PropertyList: Index[Property]


class PropertyPtr(NamedTuple):
    Ref: UInt16


class Property(NamedTuple):
    Flags: UInt16
    Name: str
    Type: bytes


class MethodSemantics(NamedTuple):
    Semantics: UInt16
    Method: Index[MethodDef]
    Association: Index[HasSemantics]


class MethodImpl(NamedTuple):
    Class: Index[TypeDef]
    MethodBody: Index[MethodDefOrRef]
    MethodDeclaration: Index[MethodDefOrRef]


class ModuleRef(NamedTuple):
    Name: str


class TypeSpec(NamedTuple):
    Signature: bytes


class ImplMap(NamedTuple):
    MappingFlags: UInt16
    MemberForwarded: Index[MemberForwarded]
    ImportName: str
    ImportScope: Index[ModuleRef]


class FieldRVA(NamedTuple):
    RVA: UInt32
    Field: Index[Field]


class Assembly(NamedTuple):
    HashAlgId: UInt32
    MajorVersion: UInt16
    MinorVersion: UInt16
    BuildNumber: UInt16
    RevisionNumber: UInt16
    Flags: UInt32
    PublicKey: bytes
    Name: str
    Culture: str


class AssemblyProcessor(NamedTuple):
    Processor: UInt32


class AssemblyOS(NamedTuple):
    OsPlatformId: UInt32
    OsMajorVersion: UInt32
    OsMinorVersion: UInt32


class AssemblyRef(NamedTuple):
    MajorVersion: UInt16
    MinorVersion: UInt16
    BuildNumber: UInt16
    RevisionNumber: UInt16
    Flags: UInt32
    PublicKeyOrToken: bytes
    Name: str
    Culture: str
    HashValue: bytes


class AssemblyRefProcessor(NamedTuple):
    Processor: UInt32
    AssemblyRef: Index[AssemblyRef]


class AssemblyRefOS(NamedTuple):
    OsPlatformId: UInt32
    OsMajorVersion: UInt32
    OsMinorVersion: UInt32
    AssemblyRef: Index[AssemblyRef]


class File(NamedTuple):
    Flags: UInt32
    Name: str
    HashValue: bytes


class ExportedType(NamedTuple):
    Flags: UInt32
    TypeDefId: UInt32
    TypeName: str
    TypeNamespace: str
    Implementation: Index[Implementation]


class ManifestResource(NamedTuple):
    Offset: UInt32
    Flags: UInt32
    Name: str
    Implementation: Index[Implementation]


class NestedClass(NamedTuple):
    NestedClass: Index[TypeDef]
    EnclosingClass: Index[TypeDef]


class GenericParam(NamedTuple):
    Number: UInt16
    Flags: UInt16
    Owner: Index[TypeOrMethodDef]
    Name: str


class MethodSpec(NamedTuple):
    Method: Index[MethodDefOrRef]
    Instantiation: bytes


class GenericParamConstraint(NamedTuple):
    Owner: Index[GenericParam]
    Constraint: Index[TypeDefOrRef]


class ENCLog(NamedTuple):
    Token: UInt32
    FuncCode: UInt32


class ENCMap(NamedTuple):
    Token: UInt32


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
    LargeStrA = 0b1
    LargeGUID = 0b10
    LargeBlob = 0b100
    Padding = 0b1000
    DeltaOnly = 0b100000
    ExtraData = 0b1000000
    HasDelete = 0b10000000


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
    __slots__ = 'Table', 'Index'

    def __init__(
        self,
        row: NetTable | None,
        col: int,
    ):
        self.Table = row
        self.Index = col

    def __json__(self):
        return {
            'Table': repr(self.Table),
            'Index': self.Index,
        }


TypeDefOrRef = Union[
    TypeDef,
    TypeRef,
    TypeSpec,
]
HasConstant = Union[
    Field,
    Param,
    Property,
]
HasCustomAttribute = Union[
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
HasFieldMarshall = Union[
    Field,
    Param,
]
HasDeclSecurity = Union[
    TypeDef,
    MethodDef,
    Assembly,
]
MemberRefParent = Union[
    TypeDef,
    TypeRef,
    ModuleRef,
    MethodDef,
    TypeSpec,
]
HasSemantics = Union[
    Event,
    Property,
]
MethodDefOrRef = Union[
    MethodDef,
    MemberRef,
]
MemberForwarded = Union[
    Field,
    MethodDef,
]
Implementation = Union[
    File,
    AssemblyRef,
    ExportedType,
]
CustomAttributeType = Union[
    Unused[1],
    Unused[2],
    MethodDef,
    MemberRef,
    Unused[3],
]
ResolutionScope = Union[
    Module,
    ModuleRef,
    AssemblyRef,
    TypeRef,
]
TypeOrMethodDef = Union[
    TypeDef,
    MethodDef,
]


class _IndexInfo(NamedTuple):
    rows: tuple[NetTable, ...]
    bits: int
    mask: int
    large: bool


class NetMetaDataTables(DotNetStruct):
    TypesByID: dict[int, type] = {
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

    @functools.lru_cache(maxsize=None)
    def _read_index_info(self, *options: type):
        rows = tuple(NetTable[t.__name__] for t in options)
        row_count = self.Header.RowCount
        row_max_len = max(row_count.get(t, 0) for t in rows)
        bits_index = bits_required(len(rows))
        bits_total = bits_index + bits_required(row_max_len)
        mask = (1 << bits_index) - 1
        return _IndexInfo(rows, bits_index, mask, bits_total > 16)

    def __init__(self, reader: DotNetStructReader, streams: NetMetaDataStreams):
        self.Header: NetMetaDataTablesHeader = NetMetaDataTablesHeader(reader)
        if self.Header.Flags.ExtraData:
            self.ExtraData = reader.u32()

        _index_strA = reader.u32 if self.Header.Flags.LargeStrA else reader.u16
        _index_guid = reader.u32 if self.Header.Flags.LargeGUID else reader.u16
        _index_blob = reader.u32 if self.Header.Flags.LargeBlob else reader.u16

        _strA = streams.StrA
        _blob = streams.Blob
        _guid = streams.GUID

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

        for r in sorted(self.Header.RowCount):
            count = self.Header.RowCount[r]
            try:
                Type = self.TypesByID[r]
            except KeyError:
                raise RuntimeError(F'Cannot parse unknown table index {r:#02x}; unable to continue parsing.')

            type_name = Type.__name__
            row: list = getattr(self, type_name)
            spec = []

            for hint in get_type_hints(Type).values():
                if get_origin(hint) is Index:
                    hint, = get_args(hint)
                    if not (options := get_args(hint)):
                        options = (hint,)
                    info = self._read_index_info(*options)
                    spec.append(info)
                elif hint is UInt32:
                    spec.append(reader.u32)
                elif hint is UInt16:
                    spec.append(reader.u16)
                else:
                    spec.append(hint)

            for _ in range(count):
                def args():
                    for hint in spec:
                        if hint is str:
                            yield _strA[_index_strA()]
                        elif hint is bytes:
                            yield _blob[_index_blob()]
                        elif hint is UUID:
                            yield _guid[(_index_guid() - 1) << 4]
                        elif isinstance(hint, _IndexInfo):
                            raw = reader.u32() if hint.large else reader.u16()
                            col = raw >> hint.bits
                            row = raw & hint.mask
                            try:
                                row = hint.rows[row]
                            except IndexError:
                                row = None
                            yield Index(row, col)
                        else:
                            yield hint()
                row.append(Type(*args()))

    @overload
    def __getitem__(self, k: int | str) -> list[NamedTuple]:
        ...

    @overload
    def __getitem__(self, k: Index[R]) -> R:
        ...

    def __getitem__(self, k):
        if isinstance(k, Index):
            if row := k.Table:
                if row is NetTable.Unused:
                    raise KeyError
                return self[row.name][k.Index - 1]
            raise KeyError
        if isinstance(k, int):
            k = self.TypesByID[k].__name__
        return getattr(self, k)


class NetResourceWithName(DotNetStruct):
    def __init__(self, reader: DotNetStructReader):
        self.Name = reader.read_dn_string_primitive(codec='utf-16LE')
        self.Offset = reader.u32()
        with reader.detour(self.Offset):
            self.Size = reader.u32()
            self.Data = reader.read(self.Size)


class NetTable(enum.IntEnum):
    Unused                 = 0xFF  # noqa
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

    def __repr__(self):
        return self.name


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
