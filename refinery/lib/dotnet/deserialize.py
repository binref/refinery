"""
Deserialization of .NET data which was serialized using BinaryFormatter.

This deserialization is based on the code in [2] and Microsoft's documentation
in [1], but it was only tested against configuration files of HawkEye Reborn.

References:
  [1] https://msdn.microsoft.com/en-us/library/cc236844.aspx
  [2] https://github.com/agix/NetBinaryFormatterParser/blob/master/JSON2dotnetBinaryFormatter.py
"""
from __future__ import annotations

import enum

from collections import defaultdict
from dataclasses import dataclass
from typing import Any, TypeVar, overload

from refinery.lib.dotnet.header import DotNetStruct, DotNetStructReader
from refinery.lib.structures import EOF

R = TypeVar('R', bound='Record')


@dataclass
class Context:
    object_catalogue: dict[int, Record]
    unresolved_references: defaultdict[int, list[tuple[Record, str]]]


class BinaryTypeCode(enum.IntEnum):
    Primitive = 0
    String = 1
    Object = 2
    SystemClass = 3
    Class = 4
    ObjectArray = 5
    StringArray = 6
    PrimitiveArray = 7


class PrimitiveTypeCode(enum.IntEnum):
    Boolean = 0x01
    Byte = 0x02
    Char = 0x03
    Decimal = 0x05
    Double = 0x06
    Int16 = 0x07
    Int32 = 0x08
    Int64 = 0x09
    SByte = 0x0A
    Single = 0x0B
    TimeSpan = 0x0C
    DateTime = 0x0D
    UInt16 = 0x0E
    UInt32 = 0x0F
    UInt64 = 0x10
    Null = 0x11
    LengthPrefixedString = 0x12


PrimitiveTypeCodeDispatch = {
    PrimitiveTypeCode.Null                 : DotNetStructReader.read_dn_null,
    PrimitiveTypeCode.Boolean              : DotNetStructReader.read_bool_byte,
    PrimitiveTypeCode.Byte                 : DotNetStructReader.read_byte,
    PrimitiveTypeCode.Char                 : DotNetStructReader.read_char,
    PrimitiveTypeCode.Decimal              : DotNetStructReader.read_dn_length_prefixed_string,
    PrimitiveTypeCode.Single               : DotNetStructReader.f32,
    PrimitiveTypeCode.Double               : DotNetStructReader.f64,
    PrimitiveTypeCode.Int16                : DotNetStructReader.i16,
    PrimitiveTypeCode.Int32                : DotNetStructReader.i32,
    PrimitiveTypeCode.Int64                : DotNetStructReader.i64,
    PrimitiveTypeCode.SByte                : DotNetStructReader.i8,
    PrimitiveTypeCode.TimeSpan             : DotNetStructReader.read_dn_time_span,
    PrimitiveTypeCode.DateTime             : DotNetStructReader.read_dn_date_time,
    PrimitiveTypeCode.UInt16               : DotNetStructReader.u16,
    PrimitiveTypeCode.UInt32               : DotNetStructReader.u32,
    PrimitiveTypeCode.UInt64               : DotNetStructReader.u64,
    PrimitiveTypeCode.LengthPrefixedString : DotNetStructReader.read_dn_length_prefixed_string,
}


class DotNetRsrcReader(DotNetStructReader):

    def read_dn_string_value_with_code(self):
        if (t := self.u8fast()) != 18:
            self._dn_raise(F'Invalid type {t} for string value with code.')
        return self.read_dn_length_prefixed_string()

    def read_dn_primitive_type(self, tc: PrimitiveTypeCode | None = None):
        if tc is None:
            tc = PrimitiveTypeCode(self.u8())
        if handler := PrimitiveTypeCodeDispatch.get(tc):
            return handler(self)


class Record(DotNetStruct):

    Value: Record | Any

    def unpack(self):
        try:
            value = self.Value
        except AttributeError:
            return self
        if isinstance(value, Record):
            return value.unpack()
        return value

    def __init__(self, reader: DotNetRsrcReader, context: Context, *args, **kwargs):
        self._context = context
        self._subscribers = []
        self._refcount = 0

        self._parse(reader, *args, **kwargs)

        for parent, member_name in self._subscribers:
            self._refcount += 1
            parent[member_name] = self.unpack()

        del self._subscribers
        del self._context

    @overload
    def _subrecord(self, reader: DotNetRsrcReader, record: type[R], *args, **kwargs) -> R:
        pass

    @overload
    def _subrecord(self, reader: DotNetRsrcReader, record: None, *args, **kwargs) -> Record:
        pass

    @overload
    def _subrecord(self, reader: DotNetRsrcReader, *args, **kwargs) -> Record:
        pass

    def _subrecord(self, reader: DotNetRsrcReader, record: type[Record] | None = None, *args, **kwargs):
        if record is None:
            record = RecordsByTypeCode[reader.u8()]
        return record(reader, self._context, *args, **kwargs).unpack()

    def _binary_type(self, reader: DotNetRsrcReader, tc: BinaryTypeCode):
        if tc == BinaryTypeCode.Primitive:
            return PrimitiveTypeCode(reader.u8())
        if tc == BinaryTypeCode.SystemClass:
            return reader.read_dn_length_prefixed_string()
        if tc == BinaryTypeCode.Class:
            return self._subrecord(reader, ClassTypeInfo)
        if tc == BinaryTypeCode.PrimitiveArray:
            return PrimitiveTypeCode(reader.u8())

    @property
    def ObjectId(self):
        try:
            return self._object_id
        except AttributeError:
            return None

    @ObjectId.setter
    def ObjectId(self, value: int):
        ctx = self._context
        self._object_id = value
        ctx.object_catalogue[value] = self
        try:
            unresolved = ctx.unresolved_references.pop(value)
        except KeyError:
            pass
        else:
            self._subscribers.extend(unresolved)

    def _deref(self, name: str, value):
        if isinstance((ref := getattr(value, 'IdRef', None)), int):
            if reference := self._context.object_catalogue.get(ref, None):
                value = reference
            else:
                self._context.unresolved_references[ref].append((self, name))
        return value

    def __setitem__(self, name: str, value):
        return super().__setattr__(name, value)

    def __setattr__(self, name: str, value):
        if not name.startswith('_'):
            value = self._deref(name, value)
        return super().__setattr__(name, value)

    def _parse(self, reader: DotNetRsrcReader, *args, **kwargs):
        pass

    def lookup(self, id=None):
        id = id or self.ObjectId
        if id is not None:
            return self._context.object_catalogue[id]


class Null(Record):
    pass


class MethodReturn(Null):
    pass


class MessageEnd(Record):
    pass


class ClassTypeInfo(Record):
    def _parse(self, reader: DotNetRsrcReader):
        self.TypeName = reader.read_dn_length_prefixed_string()
        self.LibraryId = reader.u32()


class ClassInfo(Record):
    def _parse(self, reader: DotNetRsrcReader):
        self.ClassName = reader.read_dn_length_prefixed_string()
        self.Members = [reader.read_dn_length_prefixed_string()
            for _ in range(reader.u32())]


class ClassRecord(Record):
    def member_count(self):
        try:
            return len(self.lookup().ClassInfo.Members)
        except AttributeError:
            return 0

    def lookup(self, id=None):
        result = super().lookup(id)
        if not isinstance(result, (ClassWithMembersAndTypes, SystemClassWithMembersAndTypes)):
            raise ValueError
        return result

    def _parse_values(self, reader: DotNetRsrcReader):
        MyClass = self.lookup()
        members = {}
        typeinfo = MyClass.MemberTypeInfo
        for name, tc, info in zip(
            MyClass.ClassInfo.Members,
            typeinfo.TypeCodes,
            typeinfo.TypeInfos,
        ):
            if tc == BinaryTypeCode.Primitive:
                assert isinstance(info, PrimitiveTypeCode)
                value = reader.read_dn_primitive_type(info)
            else:
                value = self._deref(name, self._subrecord(reader))
            members[name] = value
        self.Members = members

    def __setitem__(self, name: str, value):
        self.Members[name] = value


class MemberTypeInfo(Record):
    def _parse(self, reader: DotNetRsrcReader, count: int):
        self.TypeCodes = [BinaryTypeCode(reader.u8fast()) for _ in range(count)]
        self.TypeInfos = [self._binary_type(reader, tc) for tc in self.TypeCodes]


class ClassWithMembersAndTypes(ClassRecord):
    def _parse(self, reader: DotNetRsrcReader):
        self.ObjectId = reader.u32()
        self.ClassInfo = self._subrecord(reader, ClassInfo)
        self.MemberTypeInfo = self._subrecord(reader, MemberTypeInfo, self.member_count())
        self.LibraryId = reader.u32()
        self._parse_values(reader)


class SystemClassWithMembersAndTypes(ClassRecord):
    def _parse(self, reader: DotNetRsrcReader):
        self.ObjectId = reader.u32()
        self.ClassInfo = self._subrecord(reader, ClassInfo)
        self.MemberTypeInfo = self._subrecord(reader, MemberTypeInfo, self.member_count())
        self._parse_values(reader)


class ClassWithMembers(ClassRecord):
    def _parse(self, reader: DotNetRsrcReader):
        self.ObjectId = reader.u32()
        self.ClassInfo = self._subrecord(reader, ClassInfo)
        self.LibraryId = reader.u32()


class SystemClassWithMembers(ClassRecord):
    def _parse(self, reader: DotNetRsrcReader):
        self.ObjectId = reader.u32()
        self.ClassInfo = self._subrecord(reader, ClassInfo)


class ClassWithId(ClassRecord):
    def _parse(self, reader: DotNetRsrcReader):
        self.ObjectId = reader.u32()
        self.MetadataId = reader.u32()
        self._parse_values(reader)

    def lookup(self, id=None):
        return ClassRecord.lookup(self, id or self.MetadataId)


class SerializedStreamHeader(Record):
    def _parse(self, reader: DotNetRsrcReader):
        self.RootId = reader.u32()
        self.HeadId = reader.u32()
        self.MajorVersion = reader.u32()
        self.MinorVersion = reader.u32()


class BinaryLibrary(Record):
    def _parse(self, reader: DotNetRsrcReader):
        self.LibraryId = reader.u32()
        self.LibraryName = reader.read_dn_length_prefixed_string()


class BinaryObjectString(Record):
    def _parse(self, reader: DotNetRsrcReader):
        self.ObjectId = reader.u32()
        self.Value = reader.read_dn_length_prefixed_string()


class MemberReference(Record):
    def _parse(self, reader: DotNetRsrcReader):
        self.IdRef = reader.u32()


class BinaryArrayType(enum.IntEnum):
    Single = 0
    Jagged = 1
    Rectangular = 2
    SingleOffset = 3
    JaggedOffset = 4
    RectangularOffset = 5


class BinaryArray(Record):
    def _parse(self, reader: DotNetRsrcReader):
        self.ObjectId = reader.u32()
        self.BinaryArrayTypeEnum = BinaryArrayType(reader.u8())
        self.Rank = reader.u32()
        self.Lengths = [reader.u32() for _ in range(self.Rank)]
        self.LowerBounds = []

        if self.BinaryArrayTypeEnum.name.endswith('Offset'):
            for _ in range(self.Rank):
                self.LowerBounds.append(reader.u32())

        self.TypeEnum = tc = BinaryTypeCode(reader.u8())

        if tc == BinaryTypeCode.Primitive:
            value = reader.read_dn_primitive_type()
        elif tc == BinaryTypeCode.SystemClass:
            value = reader.read_dn_length_prefixed_string()
        elif tc == BinaryTypeCode.Class:
            value = self._subrecord(reader, ClassTypeInfo)
        elif tc == BinaryTypeCode.PrimitiveArray:
            value = reader.read_dn_primitive_type()
        else:
            value = None

        self.AdditionalTypeInfo = value


class ObjectNullMultiple256(Record):
    def _parse(self, reader: DotNetRsrcReader):
        self.NullCount = reader.u8()


class ObjectNullMultiple(Record):
    def _parse(self, reader: DotNetRsrcReader):
        self.NullCount = reader.u32()


class MemberPrimitiveTyped(Record):
    def _parse(self, reader: DotNetRsrcReader):
        self.Type = tc = PrimitiveTypeCode(reader.u8())
        self.Value = reader.read_dn_primitive_type(tc)


class ArraySingleObject(Record):
    def _parse(self, reader: DotNetRsrcReader):
        self.ObjectId = reader.u32()
        self.Length = reader.u32()
        self.Value = [self._subrecord(reader) for _ in range(self.Length)]


class ArraySinglePrimitive(Record):
    def _parse(self, reader: DotNetRsrcReader):
        self.ObjectId = reader.u32()
        self.Length = reader.u32()
        self.PrimitiveType = tc = PrimitiveTypeCode(reader.u8())
        if tc == PrimitiveTypeCode.Byte:
            self.Value = reader.read(self.Length)
        else:
            self.Value = [
                reader.read_dn_primitive_type(tc)
                for _ in range(self.Length)
            ]


class ArraySingleString(Record):
    def _parse(self, reader: DotNetRsrcReader):
        self.ObjectId = reader.u32()
        self.Length = reader.u32()
        # TODO is this correct?
        self.Value = [self._subrecord(reader) for _ in range(self.Length)]


class MsgFlags(enum.IntFlag):
    NoArgs                 = 0x00000001 # noqa
    ArgsInline             = 0x00000002 # noqa
    ArgsIsArray            = 0x00000004 # noqa
    ArgsInArray            = 0x00000008 # noqa
    NoContext              = 0x00000010 # noqa
    ContextInline          = 0x00000020 # noqa
    ContextInArray         = 0x00000040 # noqa
    MethodSignatureInArray = 0x00000080 # noqa
    PropertiesInArray      = 0x00000100 # noqa
    NoReturnValue          = 0x00000200 # noqa
    ReturnValueVoid        = 0x00000400 # noqa
    ReturnValueInline      = 0x00000800 # noqa
    ReturnValueInArray     = 0x00001000 # noqa
    ExceptionInArray       = 0x00002000 # noqa
    GenericMethod          = 0x00008000 # noqa


class MethodCall(Record):
    def _parse(self, reader: DotNetRsrcReader):
        self.MessageEnum = MsgFlags(reader.u32())
        self.MethodName = reader.read_dn_string_value_with_code()
        self.TypeName = reader.read_dn_string_value_with_code()
        self.CallContext = None if (
            self.MessageEnum & MsgFlags.NoContext
        ) else (
            reader.read_dn_string_value_with_code()
        )
        self.Args = None if (
            self.MessageEnum & MsgFlags.NoArgs
        ) else self._subrecord(reader, ArrayOfValueWithCode)


class ArrayOfValueWithCode(Record):
    def _parse(self, reader: DotNetRsrcReader):
        self.Length = reader.u32()
        self.ListOfValues = av = []
        self.ListOfTypes = at = []
        for _ in range(self.Length):
            at.append(tc := PrimitiveTypeCode(reader.u8()))
            av.append(reader.read_dn_primitive_type(tc))


class Overflow(DotNetStruct):
    def __init__(self, reader: DotNetStructReader, eof: EOF):
        self.Info = 'The following remaining data could not be processed.'
        self.Data = eof.rest


class BinaryFormatterParser(list):
    def __init__(self, data, keep_meta=False, dereference=True, ignore_errors=False):
        context = Context({}, defaultdict(list))

        def refcount(obj: Record):
            try:
                return obj._refcount
            except AttributeError:
                return 0

        reader = DotNetRsrcReader(memoryview(data))
        header_found = False

        while True:
            try:
                RecordType = RecordsByTypeCode[reader.u8()]
                if RecordType is MessageEnd:
                    break
                if not header_found and not ignore_errors:
                    if RecordType is not SerializedStreamHeader:
                        raise ValueError('The stream did not begin with a header.')
                    header_found = True
                record = RecordType.Parse(reader, context)
            except EOF as eof:
                raise
                if eof.rest:
                    self.append(Overflow(reader, eof))
                break
            except Exception:
                if ignore_errors:
                    continue
                raise
            if dereference and refcount(record):
                continue
            if not keep_meta:
                record = record.unpack()
            self.append(record)


RecordsByTypeCode: dict[int, type[Record]] = {
    0x00: SerializedStreamHeader,
    0x01: ClassWithId,
    0x02: SystemClassWithMembers,
    0x03: ClassWithMembers,
    0x04: SystemClassWithMembersAndTypes,
    0x05: ClassWithMembersAndTypes,
    0x06: BinaryObjectString,
    0x07: BinaryArray,
    0x08: MemberPrimitiveTyped,
    0x09: MemberReference,
    0x0A: Null,
    0x0B: MessageEnd,
    0x0C: BinaryLibrary,
    0x0D: ObjectNullMultiple256,
    0x0E: ObjectNullMultiple,
    0x0F: ArraySinglePrimitive,
    0x10: ArraySingleObject,
    0x11: ArraySingleString,
    0x14: ArraySingleString,
    0x15: MethodCall,
    0x16: MethodReturn,
}
