#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Parsing of the Java Class file format as per:
https://docs.oracle.com/javase/specs/jvms/se14/html/jvms-4.html
"""
from typing import Union, Any, Dict, List, ByteString, Type, Optional, TypeVar, Generic
from enum import IntEnum

from .structures import StructReader, Struct, StreamDetour, PerInstanceAttribute, AttrType

__all__ = (
    'opc',
    'JvAccessFlags',
    'JvAttribute',
    'JvBaseType',
    'JvClassFile',
    'JvClassMember',
    'JvClassProperty',
    'JvCode',
    'JvConstType',
    'JvDynamic',
    'JvException',
    'JvMethodHandle',
    'JvMethodHandleRefKind',
    'JvNameAndType',
    'JvOpCode',
    'JvString',
)


class Index(PerInstanceAttribute):
    def __init__(self, jtype: Type[AttrType]):
        super().__init__()
        self.jtype = jtype

    def resolve(self, parent: Any, value: int) -> AttrType:
        if not value:
            return None
        try:
            cpool = parent.pool
        except AttributeError as AE:
            raise AttributeError from AE
        try:
            result = cpool[value - 1]
        except IndexError as IE:
            raise AttributeError from IE
        if not isinstance(result, self.jtype):
            raise TypeError
        return result


class JvConstType(IntEnum):
    Utf8             = 0x01 # noqa
    Int              = 0x03 # noqa
    Float            = 0x04 # noqa
    Long             = 0x05 # noqa
    Double           = 0x06 # noqa
    Class            = 0x07 # noqa
    String           = 0x08 # noqa
    Field            = 0x09 # noqa
    Method           = 0x0A # noqa
    InterfaceMethod  = 0x0B # noqa
    NameAndType      = 0x0C # noqa
    MethodHandle     = 0x0F # noqa
    MethodType       = 0x10 # noqa
    Dynamic          = 0x11 # noqa
    InvokeDynamic    = 0x12 # noqa
    Module           = 0x13 # noqa
    Package          = 0x14 # noqa


class JvMethodHandleRefKind(IntEnum):
    GetField          = 1 # noqa
    GetStatic         = 2 # noqa
    PutField          = 3 # noqa
    PutStatic         = 4 # noqa
    InvokeVirtual     = 5 # noqa
    InvokeStatic      = 6 # noqa
    InvokeSpecial     = 7 # noqa
    InvokeSpecialNew  = 8 # noqa
    InvokeInterface   = 9 # noqa


class JvStructWithName(Struct):
    name: str = Index(str)
    def __repr__(self): return self.name


class JvNameAndType(JvStructWithName):
    descriptor: str = Index(str)

    def __init__(self, reader: StructReader):
        self.name = reader.u16()
        self.descriptor = reader.u16()


class JvString(Struct):
    value: str = Index(str)

    def __init__(self, reader: StructReader): self.value = reader.u16()
    def __repr__(self): return repr(self.value)

    def __str__(self): return self.value


class JvClassProperty(Struct):
    name: JvString = Index(JvString)
    info: JvNameAndType = Index(JvNameAndType)

    def __init__(self, reader: StructReader):
        self.name = reader.u16()
        self.info = reader.u16()

    def __repr__(self): return F'{self.name}::{self.info}'


class JvMethodHandle(Struct):
    reference: JvClassProperty = Index(JvClassProperty)

    def __init__(self, reader: StructReader):
        self.kind = JvMethodHandleRefKind(reader.read_byte())
        self.reference = reader.u16()


class JvDynamic(Struct):
    def __init__(self, reader: StructReader):
        self.bootstrap_method_attr_index = reader.u16()
        self.info = reader.u16()


class JvAccessFlags(Struct):
    def __init__(self, reader: StructReader):
        (
            self.MODULE,      # 0x8000
            self.ENUM,        # 0x4000
            self.ANNOTATION,  # 0x2000
            self.SYNTHETIC,   # 0x1000
            _,                # ...
            self.ABSTRACT,    # 0x0400
            self.INTERFACE,   # 0x0200
            _, _, _,          # ...
            self.SUPER,       # 0x0020
            self.FINAL,       # 0x0010
            _, _, _,          # ...
            self.PUBLIC,      # 0x0001
        ) = reader.read_flags(16)


ParserType = TypeVar('ParserType')


class JvAttribute(JvStructWithName, Generic[ParserType]):
    def __init__(self, reader: StructReader):
        self.name = reader.u16()
        self.data = reader.read(reader.u32())

    def parse(self, parser: Type[ParserType]) -> ParserType:
        return parser(self.data, pool=self.pool)


class JvClassMember(JvStructWithName):
    descriptor: str = Index(str)

    def __init__(self, reader: StructReader):
        self.access = JvAccessFlags(reader)
        self.name = reader.u16()
        self.descriptor = reader.u16()
        self.attributes = [JvAttribute(reader, pool=self.pool) for _ in range(reader.u16())]


class opc(IntEnum):
    nop             = 0x00  # noqa
    aconst_null     = 0x01  # noqa
    iconst_m1       = 0x02  # noqa
    iconst_0        = 0x03  # noqa
    iconst_1        = 0x04  # noqa
    iconst_2        = 0x05  # noqa
    iconst_3        = 0x06  # noqa
    iconst_4        = 0x07  # noqa
    iconst_5        = 0x08  # noqa
    lconst_0        = 0x09  # noqa
    lconst_1        = 0x0a  # noqa
    fconst_0        = 0x0b  # noqa
    fconst_1        = 0x0c  # noqa
    fconst_2        = 0x0d  # noqa
    dconst_0        = 0x0e  # noqa
    dconst_1        = 0x0f  # noqa
    bipush          = 0x10  # noqa
    sipush          = 0x11  # noqa
    ldc             = 0x12  # noqa
    ldc_w           = 0x13  # noqa
    ldc2_w          = 0x14  # noqa
    iload           = 0x15  # noqa
    lload           = 0x16  # noqa
    fload           = 0x17  # noqa
    dload           = 0x18  # noqa
    aload           = 0x19  # noqa
    iload_0         = 0x1a  # noqa
    iload_1         = 0x1b  # noqa
    iload_2         = 0x1c  # noqa
    iload_3         = 0x1d  # noqa
    lload_0         = 0x1e  # noqa
    lload_1         = 0x1f  # noqa
    lload_2         = 0x20  # noqa
    lload_3         = 0x21  # noqa
    fload_0         = 0x22  # noqa
    fload_1         = 0x23  # noqa
    fload_2         = 0x24  # noqa
    fload_3         = 0x25  # noqa
    dload_0         = 0x26  # noqa
    dload_1         = 0x27  # noqa
    dload_2         = 0x28  # noqa
    dload_3         = 0x29  # noqa
    aload_0         = 0x2a  # noqa
    aload_1         = 0x2b  # noqa
    aload_2         = 0x2c  # noqa
    aload_3         = 0x2d  # noqa
    iaload          = 0x2e  # noqa
    laload          = 0x2f  # noqa
    faload          = 0x30  # noqa
    daload          = 0x31  # noqa
    aaload          = 0x32  # noqa
    baload          = 0x33  # noqa
    caload          = 0x34  # noqa
    saload          = 0x35  # noqa
    istore          = 0x36  # noqa
    lstore          = 0x37  # noqa
    fstore          = 0x38  # noqa
    dstore          = 0x39  # noqa
    astore          = 0x3a  # noqa
    istore_0        = 0x3b  # noqa
    istore_1        = 0x3c  # noqa
    istore_2        = 0x3d  # noqa
    istore_3        = 0x3e  # noqa
    lstore_0        = 0x3f  # noqa
    lstore_1        = 0x40  # noqa
    lstore_2        = 0x41  # noqa
    lstore_3        = 0x42  # noqa
    fstore_0        = 0x43  # noqa
    fstore_1        = 0x44  # noqa
    fstore_2        = 0x45  # noqa
    fstore_3        = 0x46  # noqa
    dstore_0        = 0x47  # noqa
    dstore_1        = 0x48  # noqa
    dstore_2        = 0x49  # noqa
    dstore_3        = 0x4a  # noqa
    astore_0        = 0x4b  # noqa
    astore_1        = 0x4c  # noqa
    astore_2        = 0x4d  # noqa
    astore_3        = 0x4e  # noqa
    iastore         = 0x4f  # noqa
    lastore         = 0x50  # noqa
    fastore         = 0x51  # noqa
    dastore         = 0x52  # noqa
    aastore         = 0x53  # noqa
    bastore         = 0x54  # noqa
    castore         = 0x55  # noqa
    sastore         = 0x56  # noqa
    pop             = 0x57  # noqa
    pop2            = 0x58  # noqa
    dup             = 0x59  # noqa
    dup_x1          = 0x5a  # noqa
    dup_x2          = 0x5b  # noqa
    dup2            = 0x5c  # noqa
    dup2_x1         = 0x5d  # noqa
    dup2_x2         = 0x5e  # noqa
    swap            = 0x5f  # noqa
    iadd            = 0x60  # noqa
    ladd            = 0x61  # noqa
    fadd            = 0x62  # noqa
    dadd            = 0x63  # noqa
    isub            = 0x64  # noqa
    lsub            = 0x65  # noqa
    fsub            = 0x66  # noqa
    dsub            = 0x67  # noqa
    imul            = 0x68  # noqa
    lmul            = 0x69  # noqa
    fmul            = 0x6a  # noqa
    dmul            = 0x6b  # noqa
    idiv            = 0x6c  # noqa
    ldiv            = 0x6d  # noqa
    fdiv            = 0x6e  # noqa
    ddiv            = 0x6f  # noqa
    irem            = 0x70  # noqa
    lrem            = 0x71  # noqa
    frem            = 0x72  # noqa
    drem            = 0x73  # noqa
    ineg            = 0x74  # noqa
    lneg            = 0x75  # noqa
    fneg            = 0x76  # noqa
    dneg            = 0x77  # noqa
    ishl            = 0x78  # noqa
    lshl            = 0x79  # noqa
    ishr            = 0x7a  # noqa
    lshr            = 0x7b  # noqa
    iushr           = 0x7c  # noqa
    lushr           = 0x7d  # noqa
    iand            = 0x7e  # noqa
    land            = 0x7f  # noqa
    ior             = 0x80  # noqa
    lor             = 0x81  # noqa
    ixor            = 0x82  # noqa
    lxor            = 0x83  # noqa
    iinc            = 0x84  # noqa
    i2l             = 0x85  # noqa
    i2f             = 0x86  # noqa
    i2d             = 0x87  # noqa
    l2i             = 0x88  # noqa
    l2f             = 0x89  # noqa
    l2d             = 0x8a  # noqa
    f2i             = 0x8b  # noqa
    f2l             = 0x8c  # noqa
    f2d             = 0x8d  # noqa
    d2i             = 0x8e  # noqa
    d2l             = 0x8f  # noqa
    d2f             = 0x90  # noqa
    i2b             = 0x91  # noqa
    i2c             = 0x92  # noqa
    i2s             = 0x93  # noqa
    lcmp            = 0x94  # noqa
    fcmpl           = 0x95  # noqa
    fcmpg           = 0x96  # noqa
    dcmpl           = 0x97  # noqa
    dcmpg           = 0x98  # noqa
    ifeq            = 0x99  # noqa
    ifne            = 0x9a  # noqa
    iflt            = 0x9b  # noqa
    ifge            = 0x9c  # noqa
    ifgt            = 0x9d  # noqa
    ifle            = 0x9e  # noqa
    if_icmpeq       = 0x9f  # noqa
    if_icmpne       = 0xa0  # noqa
    if_icmplt       = 0xa1  # noqa
    if_icmpge       = 0xa2  # noqa
    if_icmpgt       = 0xa3  # noqa
    if_icmple       = 0xa4  # noqa
    if_acmpeq       = 0xa5  # noqa
    if_acmpne       = 0xa6  # noqa
    goto            = 0xa7  # noqa
    jsr             = 0xa8  # noqa
    ret             = 0xa9  # noqa
    tableswitch     = 0xaa  # noqa
    lookupswitch    = 0xab  # noqa
    ireturn         = 0xac  # noqa
    lreturn         = 0xad  # noqa
    freturn         = 0xae  # noqa
    dreturn         = 0xaf  # noqa
    areturn         = 0xb0  # noqa
    vreturn         = 0xb1  # noqa
    getstatic       = 0xb2  # noqa
    putstatic       = 0xb3  # noqa
    getfield        = 0xb4  # noqa
    putfield        = 0xb5  # noqa
    invokevirtual   = 0xb6  # noqa
    invokespecial   = 0xb7  # noqa
    invokestatic    = 0xb8  # noqa
    invokeinterface = 0xb9  # noqa
    invokedynamic   = 0xba  # noqa
    new             = 0xbb  # noqa
    newarray        = 0xbc  # noqa
    anewarray       = 0xbd  # noqa
    arraylength     = 0xbe  # noqa
    athrow          = 0xbf  # noqa
    checkcast       = 0xc0  # noqa
    instanceof      = 0xc1  # noqa
    monitorenter    = 0xc2  # noqa
    monitorexit     = 0xc3  # noqa
    wide            = 0xc4  # noqa
    multianewarray  = 0xc5  # noqa
    ifnull          = 0xc6  # noqa
    ifnonnull       = 0xc7  # noqa
    goto_w          = 0xc8  # noqa
    jsr_w           = 0xc9  # noqa
    dbgbreak        = 0xca  # noqa
    impdep1         = 0xfe  # noqa
    impdep2         = 0xff  # noqa

    def __repr__(self) -> str: return self.name


class JvBaseType(IntEnum):
    BOOLEAN = 0x4  # noqa
    CHAR    = 0x5  # noqa
    FLOAT   = 0x6  # noqa
    DOUBLE  = 0x7  # noqa
    BYTE    = 0x8  # noqa
    SHORT   = 0x9  # noqa
    INT     = 0xA  # noqa
    LONG    = 0xB  # noqa

    def __repr__(self) -> str: return self.name


class JvOpCode(Struct):

    OPC_ARGMAP = {
        opc.bipush          : 'b',
        opc.sipush          : 'h',
        opc.ldc             : 'B',
        opc.ldc_w           : 'H',
        opc.ldc2_w          : 'H',
        opc.iload           : 'B',
        opc.lload           : 'B',
        opc.fload           : 'B',
        opc.dload           : 'B',
        opc.aload           : 'B',
        opc.istore          : 'B',
        opc.lstore          : 'B',
        opc.fstore          : 'B',
        opc.dstore          : 'B',
        opc.astore          : 'B',
        opc.iinc            : 'Bb',
        opc.ifeq            : 'H',
        opc.ifne            : 'H',
        opc.iflt            : 'H',
        opc.ifge            : 'H',
        opc.ifgt            : 'H',
        opc.ifle            : 'H',
        opc.if_icmpeq       : 'H',
        opc.if_icmpne       : 'H',
        opc.if_icmplt       : 'H',
        opc.if_icmpge       : 'H',
        opc.if_icmpgt       : 'H',
        opc.if_icmple       : 'H',
        opc.if_acmpeq       : 'H',
        opc.if_acmpne       : 'H',
        opc.goto            : 'H',
        opc.jsr             : 'H',
        opc.ret             : 'B',
        opc.getstatic       : 'H',
        opc.putstatic       : 'H',
        opc.getfield        : 'H',
        opc.putfield        : 'H',
        opc.invokevirtual   : 'H',
        opc.invokespecial   : 'H',
        opc.invokestatic    : 'H',
        opc.invokeinterface : 'HBx',
        opc.invokedynamic   : 'Hxx',
        opc.new             : 'H',
        opc.anewarray       : 'H',
        opc.checkcast       : 'H',
        opc.instanceof      : 'H',
        opc.multianewarray  : 'HB',
        opc.ifnull          : 'H',
        opc.ifnonnull       : 'H',
        opc.goto_w          : 'L',
        opc.jsr_w           : 'L',
    }

    OPC_CONSTPOOL = {
        opc.ldc,
        opc.ldc_w,
        opc.ldc2_w,
        opc.getstatic,
        opc.putstatic,
        opc.getfield,
        opc.putfield,
        opc.invokevirtual,
        opc.invokespecial,
        opc.invokestatic,
        opc.new,
        opc.anewarray,
        opc.checkcast,
        opc.instanceof,
        opc.multianewarray,
    }

    def __getitem__(self, k):
        return self.arguments[k]

    def __init__(self, reader: StructReader):
        with StreamDetour(reader):
            self.code = opc(reader.read_byte())
            self.table: Optional[Dict[int, int]] = None
            try:
                fmt = self.OPC_ARGMAP[self.code]
            except KeyError:
                self.arguments = []
            else:
                self.arguments = list(reader.read_struct(fmt))
            if self.code == opc.newarray:
                self.arguments = [JvBaseType(reader.read_byte())]
            elif self.code in self.OPC_CONSTPOOL:
                try:
                    self.arguments[0] = self.pool[self.arguments[0] - 1]
                except (AttributeError, IndexError):
                    pass
            elif self.code == opc.lookupswitch:
                reader.byte_align(blocksize=4)
                default, npairs = reader.read_struct('LL')
                pairs = reader.read_struct(F'{npairs*2}L')
                self.table = dict(zip(*([iter(pairs)] * 2)))
                self.table[None] = default
            elif self.code == opc.tableswitch:
                reader.byte_align(blocksize=4)
                default, low, high = reader.read_struct('LLL')
                assert low <= high
                offsets = reader.read_struct(F'{high-low+1}L')
                self.table = {k + low: offset for k, offset in enumerate(offsets)}
                self.table[None] = default
            elif self.code == opc.wide:
                argop = opc(reader.get_byte())
                self.arguments = (argop, reader.u16())
                if argop == opc.iinc:
                    self.arguments += reader.i16(),
                else:
                    assert argop in (
                        opc.iload, opc.istore,
                        opc.fload, opc.fstore,
                        opc.aload, opc.astore,
                        opc.lload, opc.lstore,
                        opc.dload, opc.dstore,
                        opc.ret)
            offset = reader.tell()
        self.raw = bytes(reader.read(offset - reader.tell()))

    def __bytes__(self):
        return self.raw


class JvException(Struct):
    def __init__(self, reader: StructReader):
        self.start = reader.u16()
        self.end = reader.u16()
        self.handler = reader.u16()
        self.catch = reader.u16()


class JvCode(Struct):
    def __init__(self, reader: StructReader):
        reader.bigendian = True
        self.max_stack = reader.u16()
        self.max_locals = reader.u16()
        self.disassembly: List[JvOpCode] = []
        with StructReader(reader.read(reader.u32())) as code:
            code.bigendian = True
            while not code.eof:
                self.disassembly.append(JvOpCode(code, pool=self.pool))
        self.exceptions = [JvException(reader) for _ in range(reader.u16())]
        self.attributes = [JvAttribute(reader) for _ in range(reader.u16())]


class JvClassFile(Struct):

    TYPEHANDLER: Dict[JvConstType, Struct] = {
        JvConstType.Class            : JvString,
        JvConstType.String           : JvString,
        JvConstType.Field            : JvClassProperty,
        JvConstType.Method           : JvClassProperty,
        JvConstType.InterfaceMethod  : JvClassProperty,
        JvConstType.NameAndType      : JvNameAndType,
        JvConstType.MethodHandle     : JvMethodHandle,
        JvConstType.MethodType       : JvString,
        JvConstType.Dynamic          : JvDynamic,
        JvConstType.InvokeDynamic    : JvDynamic,
        JvConstType.Module           : JvString,
        JvConstType.Package          : JvString,
    }

    this: JvString = Index(JvString)
    parent: JvString = Index(JvString)

    def __init__(self, reader: StructReader):
        reader.bigendian = True
        if reader.read(4).hex() != 'cafebabe':
            raise ValueError('class file magic missing.')
        minor = reader.u16()
        major = reader.u16()
        self.version = (major, minor)

        self.pool: List[Union[Struct, int, float, str]] = []
        self._read_pool(reader)

        self.strings: List[str] = {
            s.value for s in self.pool if isinstance(s, Struct) and s.tag == JvConstType.String}

        self.access = JvAccessFlags(reader)

        self.this = reader.u16()
        self.parent = reader.u16()

        try:
            self.interfaces = [self.pool[reader.u16()]
                for _ in range(reader.u16())]
        except IndexError:
            raise ValueError('Failed parsing Interfaces.')
        try:
            self.fields = [JvClassMember(reader, pool=self.pool)
                for _ in range(reader.u16())]
        except IndexError:
            raise ValueError('Failed parsing Fields.')
        try:
            self.methods = [JvClassMember(reader, pool=self.pool)
                for _ in range(reader.u16())]
        except IndexError:
            raise ValueError('Failed parsing Methods.')
        try:
            self.attributes = [JvAttribute(reader, pool=self.pool)
                for _ in range(reader.u16())]
        except IndexError:
            raise ValueError('Failed parsing Attributes.')

    @staticmethod
    def decode_utf8m(string: ByteString) -> str:
        """
        Based on the following code:
        https://gist.github.com/BarelyAliveMau5/000e7e453b6d4ebd0cb06f39bc2e7aec
        Given in answer to the following SO question:
        https://stackoverflow.com/a/48037020
        """
        new_string = bytearray()
        length = len(string)
        i = 0
        while i < length:
            byte1 = string[i]
            if (byte1 & 0x80) == 0:
                new_string.append(byte1)
            elif (byte1 & 0xE0) == 0xC0:
                i += 1
                byte2 = string[i]
                if byte1 != 0xC0 or byte2 != 0x80:
                    new_string.append(byte1)
                    new_string.append(byte2)
                else:
                    new_string.append(0)
            elif (byte1 & 0xF0) == 0xE0:
                i += 1
                byte2 = string[i]
                i += 1
                byte3 = string[i]
                if i + 3 < length and byte1 == 0xED and (byte2 & 0xF0) == 0xA0:
                    byte4 = string[i + 1]
                    byte5 = string[i + 2]
                    byte6 = string[i + 3]
                    if byte4 == 0xED and (byte5 & 0xF0) == 0xB0:
                        i += 3
                        u21 = ((byte2 & 0x0F) + 1) << 16
                        u21 += (byte3 & 0x3F) << 10
                        u21 += (byte5 & 0x0F) << 6
                        u21 += (byte6 & 0x3F)
                        new_string.append(0xF0 + ((u21 >> 18) & 0x07))
                        new_string.append(0x80 + ((u21 >> 12) & 0x3F))
                        new_string.append(0x80 + ((u21 >> 6) & 0x3F))
                        new_string.append(0x80 + (u21 & 0x3F))
                        continue
                new_string.append(byte1)
                new_string.append(byte2)
                new_string.append(byte3)
            i += 1
        return new_string.decode('utf8')

    def _read_pool(self, reader):
        assert not self.pool, 'pool can only be read once.'
        size = reader.u16() - 1
        reserved_slot = False
        for _ in range(size):
            if reserved_slot:
                self.pool.append(NotImplemented)
                reserved_slot = False
                continue
            tid = reader.read_byte()
            try:
                tag = JvConstType(tid)
            except KeyError:
                raise ValueError(F'Encountered invalid type specifier {tid:02X}.')
            if tag == JvConstType.Utf8:
                size = reader.u16()
                data = reader.read(size)
                data = self.decode_utf8m(data)
                self.pool.append(data)
                continue
            try:
                tf, reserved_slot = {
                    JvConstType.Long   : ('Q', True),
                    JvConstType.Double : ('d', True),
                    JvConstType.Int    : ('I', False),
                    JvConstType.Float  : ('f', False),
                }[tag]
            except KeyError:
                JvType = self.TYPEHANDLER[tag]
                self.pool.append(JvType(reader, pool=self.pool, tag=tag))
            else:
                self.pool.append(reader.read_struct(tf))
                continue
