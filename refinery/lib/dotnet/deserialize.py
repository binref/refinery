# -*- coding: utf-8 -*-
"""
Deserialization of .NET data which was serialized using BinaryFormatter.

This deserialization is based on the code in [2] and Microsoft's documentation
in [1], but it was only tested against configuration files of HawkEye Reborn.

References:
  [1] https://msdn.microsoft.com/en-us/library/cc236844.aspx
  [2] https://github.com/agix/NetBinaryFormatterParser/blob/master/JSON2dotnetBinaryFormatter.py
"""

from collections import defaultdict

from .types import (
    BinaryArrayTypeEnumeration,
    Boolean,
    Box,
    Byte,
    Char,
    DateTime,
    Double,
    FixedSize,
    Int16,
    Int32,
    Int64,
    LengthPrefixedString,
    Null,
    SByte,
    Single,
    StreamReader,
    Struct,
    TimeSpan,
    TypeCode,
    UInt16,
    UInt32,
    UInt64,
    unpack,
    ParserEOF
)


class StringValueWithCode(LengthPrefixedString):
    def __init__(self, reader):
        if reader.expect(Byte) != 18:
            self._raise('invalid type for StringValueWithCode')
        LengthPrefixedString.__init__(self, reader)


class Record(Struct):
    def __setitem__(self, name, value):
        if name == 'ObjectId':
            self.RefCount = 0
            self._context.object_catalogue[value] = self
            self._subscribers.extend(self._context.unresolved_references.pop(value, []))
        elif hasattr(value, 'IdRef'):
            reference = self._context.object_catalogue.get(value.IdRef, None)
            if reference:
                value = reference
            else:
                self._context.unresolved_references[value.IdRef].append((self, name))
        return Box.__setitem__(self, name, value)

    def expect_with_meta(self, parser, **kw):
        try:
            if issubclass(parser, Record):
                kw.setdefault('context', self._context)
        except TypeError as e:
            raise TypeError('{}: {}'.format(e, repr(type(parser))))
        return Struct.expect_with_meta(self, parser, **kw)

    def decode(self):
        Type = RecordTypeCode(self._reader).Value
        return self.expect(Type)

    def lookup(self, id=None):
        id = id or self.ObjectId
        return self._context.object_catalogue[id]

    def parse(self):
        for parent, member_name in self._subscribers:
            self.RefCount += 1
            parent[member_name] = unpack(self)

    def __init__(self, reader, context=None, **kw):
        assert context, 'record parser requires context'
        Struct.__init__(self, reader, _context=context, _subscribers=[], **kw)


class MethodReturn(Null):
    pass


class MessageEnd(Record):
    pass


class ClassTypeInfo(Record):
    def parse(self):
        self.TypeName = self.expect(LengthPrefixedString)
        self.LibraryId = self.expect(UInt32)
        Record.parse(self)


class ClassInfo(Record):
    def parse(self):
        self.ClassName = self.expect(LengthPrefixedString)
        self.MemberCount = self.expect(UInt32)
        self.MemberNames = [self.expect(
            LengthPrefixedString) for _ in range(self.MemberCount)]
        Record.parse(self)


class MemberTypeInfo(Record):
    def __init__(self, reader, count=0, **kw):
        Record.__init__(self, reader, _count=count, **kw)

    def parse(self):
        self.BinaryTypeEnums = [
            BinaryTypeCode(self._reader).Value
            for _ in range(self._count)
        ]
        self.AdditionalInfos = [self.expect(b.Parser) for b in self.BinaryTypeEnums]
        self.BinaryTypeEnums = [b.Name for b in self.BinaryTypeEnums]
        Record.parse(self)


class ClassMembers(Record):
    def __init__(self, reader, Names, Types, Infos, **kw):
        Record.__init__(self, reader, _info=[(n, m == 'Primitive', t) for n, m, t in zip(Names, Types, Infos)], **kw)

    def parse(self):
        for name, is_primitive, Type in self._info:
            result = self.expect(Type) if is_primitive else self.decode()
            self[name] = result
        Record.parse(self)


class ClassRecord(Record):
    def member_count(self):
        try:
            return self.lookup().ClassInfo.MemberCount
        except AttributeError:
            return 0

    def parse_values(self):
        MyClass = self.lookup()
        self.Members = self.expect(
            ClassMembers,
            Names=MyClass.ClassInfo.MemberNames,
            Types=MyClass.MemberTypeInfo.BinaryTypeEnums,
            Infos=MyClass.MemberTypeInfo.AdditionalInfos
        )


class ClassWithMembersAndTypes(ClassRecord):
    def parse(self):
        self.ObjectId = self.expect(UInt32)
        self.ClassInfo = self.expect(ClassInfo)
        self.MemberTypeInfo = self.expect(MemberTypeInfo, count=self.member_count())
        self.LibraryId = self.expect(UInt32)
        self.parse_values()
        Record.parse(self)


class SystemClassWithMembersAndTypes(ClassRecord):
    def parse(self):
        self.ObjectId = self.expect(UInt32)
        self.ClassInfo = self.expect(ClassInfo)
        self.MemberTypeInfo = self.expect(MemberTypeInfo, count=self.member_count())
        self.parse_values()
        Record.parse(self)


class ClassWithMembers(ClassRecord):
    def parse(self):
        self.ObjectId = self.expect(UInt32)
        self.ClassInfo = self.expect(ClassInfo)
        self.LibraryId = self.expect(UInt32)
        Record.parse(self)


class SystemClassWithMembers(ClassRecord):
    def parse(self):
        self.ObjectId = self.expect(UInt32)
        self.ClassInfo = self.expect(ClassInfo)
        Record.parse(self)


class ClassWithId(ClassRecord):
    def parse(self):
        self.ObjectId = self.expect(UInt32)
        self.MetadataId = self.expect(UInt32)
        self.parse_values()
        Record.parse(self)

    def lookup(self):
        return ClassRecord.lookup(self, self.MetadataId)


class SerializedStreamHeader(Record):
    def parse(self):
        self.RootId = self.expect(UInt32)
        self.HeadId = self.expect(UInt32)
        self.MajorVersion = self.expect(UInt32)
        self.MinorVersion = self.expect(UInt32)
        Record.parse(self)


class BinaryLibrary(Record):
    def parse(self):
        self.LibraryId = self.expect(UInt32)
        self.LibraryName = self.expect(LengthPrefixedString)
        Record.parse(self)


class BinaryObjectString(Record):
    def parse(self):
        self.ObjectId = self.expect(UInt32)
        self.Value = self.expect(LengthPrefixedString)
        Record.parse(self)


class MemberReference(Record):
    def parse(self):
        self.IdRef = self.expect(UInt32)
        Record.parse(self)


class BinaryArray(Record):
    def parse(self):
        self.ObjectId = self.expect(UInt32)
        self.BinaryArrayTypeEnum = self.expect(BinaryArrayTypeEnumeration)
        self.Rank = self.expect(UInt32)
        self.Lengths = [self.expect(UInt32) for _ in range(self.Rank)]
        self.LowerBounds = []
        if 'Offset' in self.BinaryArrayTypeEnum:
            for _ in range(self.Rank):
                self.LowerBounds.append(self.expect(UInt32))
        self.TypeEnum = self.expect(BinaryTypeCode)
        self.AdditionalTypeInfo = self.expect(self.TypeEnum.Parser)
        self.TypeEnum = repr(self.TypeEnum)
        Record.parse(self)


class ObjectNullMultiple256(Record):
    def parse(self):
        self.NullCount = self.expect(Byte)
        Record.parse(self)


class ObjectNullMultiple(Record):
    def parse(self):
        self.NullCount = self.expect(UInt32)
        Record.parse(self)


class MemberPrimitiveTyped(Record):
    def parse(self):
        PrimitiveType = self.expect(PrimitiveTypeCode)
        self.PrimitiveTypeEnum = repr(PrimitiveType)
        self.Value = self.expect(PrimitiveType)
        Record.parse(self)


class ArraySingleObject(Record):
    def parse(self):
        self.ObjectId = self.expect(UInt32)
        self.Length = self.expect(UInt32)
        self.Value = [self.decode() for _ in range(self.Length)]
        Record.parse(self)


class ArraySinglePrimitive(Record):
    def parse(self):
        self.ObjectId = self.expect(UInt32)
        self.Length = self.expect(UInt32)
        PrimitiveType = self.expect(PrimitiveTypeCode)
        self.PrimitiveTypeEnum = repr(PrimitiveType)
        if self.PrimitiveTypeEnum == 'Byte':
            self.Value = self._reader.read(self.Length)
        else:
            self.Value = [
                self.expect(PrimitiveType)
                for _ in range(self.Length)
            ]
        Record.parse(self)


class ArraySingleString(Record):
    def parse(self):
        self.ObjectId = self.expect(UInt32)
        self.Length = self.expect(UInt32)
        # TODO is this correct?
        self.Value = [self.decode() for _ in range(self.Length)]
        Record.parse(self)


class MessageEnum(FixedSize):
    format = 'I'

    def parser(self, x):
        self.NoArgs = bool(x & 0x00000001)
        self.ArgsInline = bool(x & 0x00000002)
        self.ArgsIsArray = bool(x & 0x00000004)
        self.ArgsInArray = bool(x & 0x00000008)
        self.NoContext = bool(x & 0x00000010)
        self.ContextInline = bool(x & 0x00000020)
        self.ContextInArray = bool(x & 0x00000040)
        self.MethodSignatureInArray = bool(x & 0x00000080)
        self.PropertiesInArray = bool(x & 0x00000100)
        self.NoReturnValue = bool(x & 0x00000200)
        self.ReturnValueVoid = bool(x & 0x00000400)
        self.ReturnValueInline = bool(x & 0x00000800)
        self.ReturnValueInArray = bool(x & 0x00001000)
        self.ExceptionInArray = bool(x & 0x00002000)
        self.GenericMethod = bool(x & 0x00008000)


class MethodCall(Record):
    def parse(self):
        self.MessageEnum = self.expect(MessageEnum)
        self.MethodName = self.expect(StringValueWithCode)
        self.TypeName = self.expect(StringValueWithCode)
        if not self.MessageEnum.NoContext:
            self.CallContext = self.expect(StringValueWithCode)
        if not self.MessageEnum.NoArgs:
            self.Args = self.expect(ArrayOfValueWithCode)
        Record.parse(self)


class ArrayOfValueWithCode(Record):
    def parse(self):
        self.Length = self.expect(UInt32)
        self.ListOfValueWithCode = []
        for _ in range(self.Length):
            PrimitiveType = self.expect(PrimitiveTypeCode)
            self.PrimitiveTypeEnum = repr(PrimitiveType)
            self.ListOfValueWithCode.append(self.expect(PrimitiveType))
        Record.parse(self)


class PrimitiveTypeCode(TypeCode):
    lookup = {
        0x01: Boolean,
        0x02: Byte,
        0x03: Char,
        0x05: LengthPrefixedString,  # Decimal
        0x06: Double,
        0x07: Int16,
        0x08: Int32,
        0x09: Int64,
        0x0A: SByte,
        0x0B: Single,
        0x0C: TimeSpan,
        0x0D: DateTime,
        0x0E: UInt16,
        0x0F: UInt32,
        0x10: UInt64,
        0x11: Null,
        0x12: LengthPrefixedString
    }


class BinaryTypeInfo(Box):
    def __init__(self, Name, Parser=Null, **kw):
        Box.__init__(self, Name=Name, Parser=Parser, **kw)

    def __call__(self, reader):
        if self.Parser:
            return self.Parser(reader)


class BinaryTypeCode(TypeCode):
    lookup = {
        0: BinaryTypeInfo('Primitive', PrimitiveTypeCode),
        1: BinaryTypeInfo('String'),
        2: BinaryTypeInfo('Object'),
        3: BinaryTypeInfo('SystemClass', LengthPrefixedString),
        4: BinaryTypeInfo('Class', ClassTypeInfo),
        5: BinaryTypeInfo('ObjectArray'),
        6: BinaryTypeInfo('StringArray'),
        # TODO: How does PrimitiveArray really work?
        7: BinaryTypeInfo('PrimitiveArray', PrimitiveTypeCode),
    }


class RecordTypeCode(TypeCode):
    lookup = {
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
        0x16: MethodReturn
    }


class BinaryFormatterParser(list):
    def __init__(self, data, keep_meta=False, dereference=True, ignore_errors=False):
        context = Box(
            object_catalogue={},
            unresolved_references=defaultdict(list)
        )

        def refcount(obj):
            try:
                return obj.RefCount
            except AttributeError:
                return 0

        reader = StreamReader(data)
        header_found = False

        while True:
            try:
                handler = RecordTypeCode(reader).Value
                if handler is MessageEnd:
                    break
                if not header_found and not ignore_errors:
                    assert handler is SerializedStreamHeader, 'stream did not begin with a header'
                    header_found = True
                record = handler(reader, context)
            except ParserEOF as remaining:
                if remaining.data:
                    self.append(Box(
                        Info='The following remaining data could not be processed.',
                        Data=remaining.data
                    ))
                break
            except Exception:
                if ignore_errors:
                    continue
                raise

            if not keep_meta:
                record = unpack(record)
            if dereference and refcount(record):
                continue

            self.append(record)
