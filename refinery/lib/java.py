#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import Union, Optional, Any, Dict, List, ByteString, NewType, Generic, Type, TypeVar
from enum import IntEnum
from javaobj import JavaObjectUnmarshaller

from .structures import StructReader, Struct

String = NewType('String', str)
IndexedType = TypeVar('IndexedType')


class Index(Generic[IndexedType]):
    def __init__(self, jtype: Type[IndexedType], index: int):
        self.jtype = jtype
        self.index = index
        self.value: Optional[IndexedType] = None

    def __get__(self, parent, tp=None):
        if self.value is not None:
            return self.value
        try:
            cpool = parent.pool
        except AttributeError as AE:
            raise AttributeError(F'parent object {parent} has no pool attribute') from AE
        try:
            value = cpool[self.index]
        except IndexError as IE:
            raise AttributeError(F'invalid index {self.index} into constant pool of size {len(cpool)}') from IE
        if not isinstance(value, self.jtype):
            tp2 = self.jtype.__name__
            tp1 = type(value).__name__
            raise AttributeError(F'constant pool entry {self.index} is of type {tp1}, expected {tp2}')
        self.value = value
        return value


class JvTypeTag(IntEnum):
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


class MethodHandleReferenceKind(IntEnum):
    GetField          = 1 # noqa
    GetStatic         = 2 # noqa
    PutField          = 3 # noqa
    PutStatic         = 4 # noqa
    InvokeVirtual     = 5 # noqa
    InvokeStatic      = 6 # noqa
    InvokeSpecial     = 7 # noqa
    InvokeSpecialNew  = 8 # noqa
    InvokeInterface   = 9 # noqa


class JvNameRef(Struct):
    def __init__(self, reader: StructReader):
        self.name = Index(str, reader.u16())


class JvString(Struct):
    def __init__(self, reader: StructReader):
        self.value = Index(str, reader.u16())

    def __str__(self):
        string = self.value.value
        if string is None:
            raise ValueError
        return string


class JvNameAndType(Struct):
    def __init__(self, reader: StructReader):
        self.name = Index(str, reader.u16())
        self.descriptor = Index(str, reader.u16())


class JvClassProperty(Struct):
    def __init__(self, reader: StructReader):
        self.owner = Index(JvTypeTagMap[JvTypeTag.Class], reader.u16())
        self.info = Index(JvNameAndType, reader.u16())


class JvMethodHandle(Struct):
    def __init__(self, reader: StructReader):
        self.kind = MethodHandleReferenceKind(reader.read_byte())
        index = reader.u16()
        if self.kind is MethodHandleReferenceKind.InvokeInterface:
            self.index = Index(JvTypeTagMap[JvTypeTag.InterfaceMethod], index)
        elif self.kind in (
            MethodHandleReferenceKind.GetField,
            MethodHandleReferenceKind.PutField,
            MethodHandleReferenceKind.GetStatic,
            MethodHandleReferenceKind.PutStatic
        ):
            self.index = Index(JvTypeTagMap[JvTypeTag.Field], index)
        elif self.kind in (
            MethodHandleReferenceKind.InvokeVirtual,
            MethodHandleReferenceKind.InvokeStatic,
            MethodHandleReferenceKind.InvokeSpecial,
            MethodHandleReferenceKind.InvokeSpecialNew
        ):
            self.index = Index(JvTypeTagMap[JvTypeTag.Method], index)


class JvDynamic(Struct):
    def __init__(self, reader: StructReader):
        self.bootstrap_method_attr_index = reader.u16()
        self.name_and_type = Index(JvNameAndType, reader.u16())


JvTypeTagMap: Dict[JvTypeTag, Struct] = {
    JvTypeTag.Class            : JvNameRef,
    JvTypeTag.String           : JvString,
    JvTypeTag.Field            : JvClassProperty,
    JvTypeTag.Method           : JvClassProperty,
    JvTypeTag.InterfaceMethod  : JvClassProperty,
    JvTypeTag.NameAndType      : JvNameAndType,
    JvTypeTag.MethodHandle     : JvMethodHandle,
    JvTypeTag.MethodType       : JvNameRef,
    JvTypeTag.Dynamic          : JvDynamic,
    JvTypeTag.InvokeDynamic    : JvDynamic,
    JvTypeTag.Module           : JvNameRef,
    JvTypeTag.Package          : JvNameRef,
}

class JvField(Struct):
    def __init__(self, reader




class JavaClassFile(Struct):

    def __init__(self, reader: StructReader):
        reader.set_bitorder_big()
        if reader.read(4).hex() != 'cafebabe':
            raise ValueError('class file magic missing.')
        minor = reader.u16()
        major = reader.u16()
        self.version = (major, minor)

        self.pool: List[Union[Struct, int, float, str]] = []
        self._read_pool(reader)

        self.strings: List[str] = {
            s.value for s in self.pool if isinstance(s, Struct) and s.tag == JvTypeTag.String}

        self.access = reader.u16()
        (
            self.ACC_MODULE,      # 0x8000
            self.ACC_ENUM,        # 0x4000
            self.ACC_ANNOTATION,  # 0x2000
            self.ACC_SYNTHETIC,   # 0x1000
            _,                    # ...
            self.ACC_ABSTRACT,    # 0x0400
            self.ACC_INTERFACE,   # 0x0200
            _, _, _,              # ...
            self.ACC_SUPER,       # 0x0020
            self.ACC_FINAL,       # 0x0010
            _, _, _,              # ...
            self.ACC_PUBLIC,      # 0x0001
        ) = reader.read_flags(16)

        self.this = Index(JvNameRef, reader.u16(),)
        super_class = reader.u16()
        self.super = super_class and Index(JvNameRef, super_class) or None
        
        self.interfaces = [self.pool[reader.u16()] for _ in reader.u16()]
        self.fields = 

        self.interfaces = [r.u16() for _ in range(r.u16())]
        self.fields = [FieldData(r) for _ in range(r.u16())]
        self.methods = [MethodData(r) for _ in range(r.u16())]
        self.attributes = [AttributeData(r=self.pool) for _ in range(r.u16())]
        # assert r.done()
        self

    def getattrs(self, name):
        for attr in self.attributes:
            if self.pool.getutf(attr.name) == name:
                yield attr

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
                tag = JvTypeTag(tid)
            except KeyError:
                raise ValueError(F'Encountered invalid type specifier {tid:02X}.')
            if tag == JvTypeTag.Utf8:
                size = reader.u16()
                data = reader.read(size)
                data = self.decode_utf8m(data)
                self.pool.append(data)
                continue
            try:
                tf, reserved_slot = {
                    JvTypeTag.Long   : ('Q', True),
                    JvTypeTag.Double : ('d', True),
                    JvTypeTag.Int    : ('I', False),
                    JvTypeTag.Float  : ('f', False),
                }[tag]
            except KeyError:
                JvType = JvTypeTagMap[tag]
                self.pool.append(JvType(reader, pool=self.pool, tag=tag))
            else:
                self.pool.append(reader.read_struct(tf))
                continue



