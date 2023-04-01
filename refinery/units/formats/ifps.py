#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
The code is based on the logic implemented in IFPSTools:
 https://github.com/Wack0/IFPSTools
"""
from __future__ import annotations

import enum
import io
import uuid

from typing import Callable, Dict, Generator, List, NamedTuple, Optional, Tuple, Type, TypeVar, Union
from dataclasses import dataclass, field
from collections import OrderedDict
from functools import WRAPPER_ASSIGNMENTS, update_wrapper

from refinery.units.formats import Unit
from refinery.lib.structures import Struct, StructReader, StreamDetour

_CLS = TypeVar('_CLS')
_TAB = '\x20\x20'


def extended(_data: bytes):
    if len(_data) != 10:
        raise ValueError
    data = int.from_bytes(_data, 'little')
    sign = data >> 79
    data = data ^ (sign << 79)
    sign = -1.0 if sign else +1.0
    exponent = data >> 64
    data = data ^ (exponent << 64)
    if exponent == 0:
        if data == 0:
            return sign * 0
        exponent = -16382
    elif exponent == 0b111111111111111:
        if data == 0:
            return sign * float('Inf')
        else:
            return sign * float('NaN')
    else:
        exponent = exponent - 16383
    mantissa = data / (1 << 64)
    return sign * mantissa * (2 ** exponent)


def rfix(cls: _CLS) -> _CLS:
    cls.__repr__ = lambda self: F'{self.__class__.__name__}.{self.name}'
    cls.__str__ = lambda self: self.name
    return cls


@rfix
class Op(enum.IntEnum):
    Assign       = 0x00  # noqa
    Calculate    = 0x01  # noqa
    Push         = 0x02  # noqa
    PushVar      = 0x03  # noqa
    Pop          = 0x04  # noqa
    Call         = 0x05  # noqa
    Jump         = 0x06  # noqa
    JumpTrue     = 0x07  # noqa
    JumpFalse    = 0x08  # noqa
    Ret          = 0x09  # noqa
    StackType    = 0x0A  # noqa
    PushType     = 0x0B  # noqa
    Compare      = 0x0C  # noqa
    CallVar      = 0x0D  # noqa
    SetPtr       = 0x0E  # noqa
    LogicalNot   = 0x0F  # noqa
    Neg          = 0x10  # noqa
    SetFlag      = 0x11  # noqa
    JumpFlag     = 0x12  # noqa
    PushEH       = 0x13  # noqa
    PopEH        = 0x14  # noqa
    Not          = 0x15  # noqa
    SetCopyPtr   = 0x16  # noqa
    Inc          = 0x17  # noqa
    Dec          = 0x18  # noqa
    JumpPop1     = 0x19  # noqa
    JumpPop2     = 0x1A  # noqa
    Nop          = 0xFF  # noqa
    _INVALID     = 0xDD  # noqa

    @classmethod
    def FromInt(cls, code: int):
        try:
            return cls(code)
        except ValueError:
            return cls._INVALID


@rfix
class TC(int, enum.Enum):
    ReturnAddress       = 0x00  # noqa
    U08                 = 0x01  # noqa
    S08                 = 0x02  # noqa
    U16                 = 0x03  # noqa
    S16                 = 0x04  # noqa
    U32                 = 0x05  # noqa
    S32                 = 0x06  # noqa
    Single              = 0x07  # noqa
    Double              = 0x08  # noqa
    Extended            = 0x09  # noqa
    String              = 0x0A  # noqa
    Record              = 0x0B  # noqa
    Array               = 0x0C  # noqa
    Pointer             = 0x0D  # noqa
    PChar               = 0x0E  # noqa
    ResourcePointer     = 0x0F  # noqa
    Variant             = 0x10  # noqa
    S64                 = 0x11  # noqa
    Char                = 0x12  # noqa
    WideString          = 0x13  # noqa
    WideChar            = 0x14  # noqa
    ProcPtr             = 0x15  # noqa
    Tuple               = 0x16  # noqa
    Set                 = 0x17  # noqa
    Currency            = 0x18  # noqa
    Class               = 0x19  # noqa
    Interface           = 0x1A  # noqa
    NotificationVariant = 0x1B  # noqa
    UnicodeString       = 0x1C  # noqa
    Enum                = 0x81  # noqa
    Type                = 0x82  # noqa
    ExtClass            = 0x83  # noqa

    @property
    def width(self):
        return {
            TC.Variant       : 0x10,
            TC.Char          : 0x01,
            TC.S08           : 0x01,
            TC.U08           : 0x01,
            TC.WideChar      : 0x02,
            TC.S16           : 0x02,
            TC.U16           : 0x02,
            TC.WideString    : 0x04,
            TC.UnicodeString : 0x04,
            TC.Interface     : 0x04,
            TC.Class         : 0x04,
            TC.PChar         : 0x04,
            TC.String        : 0x04,
            TC.Single        : 0x04,
            TC.S32           : 0x04,
            TC.U32           : 0x04,
            TC.ProcPtr       : 0x0C,
            TC.Currency      : 0x08,
            TC.Pointer       : 0x0C,
            TC.Double        : 0x08,
            TC.S64           : 0x08,
            TC.Extended      : 0x0A,
            TC.ReturnAddress : 0x1C,
        }.get(self, 0)


@dataclass
class _OptionsMixin:
    symbol: Optional[str] = None
    attributes: Optional[List[Attribute]] = None

    def __str__(self):
        if self.symbol is not None:
            return self.symbol
        return super().__str__()


@dataclass
class _TypeBase:
    code: TC

    def display(self, indent=0):
        return indent * _TAB + self.code.name

    def simple(self, nested=False):
        return True

    def __str__(self):
        return self.display(0)


def optionals(cls: _CLS) -> Union[_CLS, Type[_OptionsMixin]]:
    class _mixed(_OptionsMixin, cls):
        ...
    assigned = set(WRAPPER_ASSIGNMENTS) - {'__annotations__'}
    update_wrapper(_mixed, cls, assigned=assigned, updated=())
    return dataclass(_mixed)


@optionals
@dataclass
class TGeneric(_TypeBase):
    pass


@optionals
@dataclass
class TProcPtr(_TypeBase):
    body: bytes

    def display(self, indent=0):
        display = super().display(indent)
        return F'{display}({self.body.hex()})'


@optionals
@dataclass
class TInterface(_TypeBase):
    uuid: uuid.UUID

    def display(self, indent=0):
        display = super().display(indent)
        return F'{display}({self.uuid!s})'


@optionals
@dataclass
class TClass(_TypeBase):
    name: str

    def display(self, indent=0):
        display = super().display(indent)
        return F'{display}({self.name})'


@optionals
@dataclass
class TSet(_TypeBase):
    size: int

    @property
    def size_in_bytes(self):
        q, r = divmod(self.size, 8)
        return q + (r and 1 or 0)

    def display(self, indent=0):
        display = super().display(indent)
        return F'{display}({self.size})'


@optionals
@dataclass
class TArray(_TypeBase):
    type: TGeneric

    def display(self, indent=0):
        display = F'{_TAB*indent}{self.type!s}'
        return F'{display}[]'

    def simple(self, nested=False):
        return self.type.simple(nested)


@optionals
@dataclass
class TTuple(_TypeBase):
    type: TGeneric
    size: int
    offset: Optional[int] = None

    def display(self, indent=0):
        display = F'{_TAB*indent}{self.type!s}'
        return F'{display}[{self.size}]'

    def simple(self, nested=False):
        return self.type.simple(nested)


@optionals
@dataclass
class TRecord(_TypeBase):
    members: Tuple[TGeneric, ...]

    def simple(self, nested=False):
        if nested:
            return False
        if len(self.members) > 10:
            return False
        return all(m.simple(True) for m in self.members)

    def display(self, indent=0):
        output = io.StringIO()
        output.write(indent * _TAB)
        output.write('struct {')
        if self.simple():
            output.write(', '.join(str(m) for m in self.members))
        else:
            for k, member in enumerate(self.members):
                if k > 0:
                    output.write(',')
                output.write('\n')
                output.write(member.display(indent + 1))
            if self.members:
                output.write(F'\n{indent*_TAB}')
        output.write('}')
        return output.getvalue()


TType = Union[TRecord, TTuple, TArray, TSet, TProcPtr, TClass, TInterface, TGeneric]


class Value(NamedTuple):
    type: TGeneric
    value: Union[str, int, float, bytes]

    def __repr__(self):
        value = self.value
        if isinstance(value, bytes):
            value = value.hex()
        return F'{self.type.code.name}({value!r})'

    def __str__(self):
        return repr(self.value)


class Attribute(NamedTuple):
    name: str
    fields: Tuple[Value, ...]

    def __repr__(self):
        name = self.name
        if self.fields:
            name += '[{}]'.format(','.join(repr(f) for f in self.fields))
        return name


class DeclSpecParam(NamedTuple):
    mode_in: bool
    type: Optional[TGeneric] = None


@dataclass
class DeclSpec:

    void: bool
    parameters: List[DeclSpecParam]
    name: str = ''
    calling_convention: Optional[str] = None
    return_type: Optional[TGeneric] = None
    module: Optional[str] = None
    classname: Optional[str] = None
    delay_load: bool = False
    load_with_altered_search_path: bool = False
    is_property: bool = False

    def represent(self, name: str, ref: bool = False):
        def pparam(k: int, p: DeclSpecParam):
            name = F'{VariantType.Argument!s}{k}'
            if p.type is not None:
                name = F'{name}: {p.type!s}'
            if not p.mode_in:
                name = F'*{name}'
            return name
        if self.name and name in self.name:
            name = self.name
        spec = name
        if self.classname:
            spec = F'{self.classname}.{spec}'
        if self.module:
            spec = F'{self.module}::{spec}'
        if not ref:
            if self.delay_load:
                spec = F'__delay_load {spec}'
            if self.calling_convention:
                spec = F'__{self.calling_convention} {spec}'
            spec = F'{self.type} {spec}'
            args = self.parameters
            args = args and ', '.join(pparam(*t) for t in enumerate(args)) or ''
            spec = F'{spec}({args})'
            if self.return_type:
                spec = F'{spec} -> {self.return_type.code.name}'
        return spec

    @property
    def type(self):
        return 'sub' if self.void else 'function'

    def __repr__(self):
        return self.represent(self.name or '(*)')

    @classmethod
    def ParseF(cls, reader: StructReader[bytes]):
        def readcc():
            return {
                0: 'register',
                1: 'pascal',
                2: 'cdecl',
                3: 'stdcall',
            }.get(reader.u8(), cls.calling_convention)
        kw = {}
        parameters = None
        if reader.peek(4) == b'dll:':
            reader.seekrel(4)
            if reader.peek(6) == B'files:':
                reader.seekrel(6)
            kw.update(
                module=reader.read_c_string('latin1'),
                name=reader.read_c_string('latin1'),
                calling_convention=readcc(),
                delay_load=bool(reader.u8()),
                load_with_altered_search_path=bool(reader.u8())
            )
            void = not reader.u8()
        elif reader.peek(6) == b'class:':
            reader.seekrel(6)
            if reader.remaining_bytes == 1:
                rest = reader.peek(1)
                void = False
                parameters = [DeclSpecParam(False)]
                kw.update(
                    classname='Class',
                    name={b'+': 'CastToType', B'-': 'SetNil'}.get(rest),
                    calling_convention='pascal',
                )
            else:
                kw.update(classname=reader.read_terminated_array(b'|').decode('latin1'))
                name = reader.read_terminated_array(b'|').decode('latin1')
                if name[-1] == '@':
                    kw.update(is_property=True)
                    name = name[:-1]
                kw.update(name=name, calling_convention=readcc())
                void = not reader.u8()
        else:
            void = not reader.u8()
        if parameters is not None:
            parameters = [DeclSpecParam(bool(b)) for b in reader.read()]
        return cls(void, parameters, **kw)

    @classmethod
    def ParseE(cls, data: bytes, ipfs: IFPSFile):
        decl = data.split(B'\x20')
        return_type = int(decl.pop(0))
        void = return_type == -1
        if not void:
            return_type = ipfs.types[return_type]
        else:
            return_type = None
        parameters = []
        for param in decl:
            mode_in = param[0] == B'@'[0]
            ti = int(param[1:])
            parameters.append(DeclSpecParam(mode_in, ipfs.types[ti]))
        return cls(void, parameters, return_type=return_type)


class Function(NamedTuple):
    name: str
    decl: DeclSpec
    body: Optional[List[Instruction]] = None
    exported: bool = False
    attributes: Optional[List[Attribute]] = None

    def reference(self) -> str:
        return self.decl.represent(self.name, ref=True)

    def __repr__(self):
        return self.decl.represent(self.name)


class Variable(NamedTuple):
    index: int
    flags: int
    type: TGeneric
    name: str

    def __repr__(self):
        return F'{self.name}: {self.type!s}'


@rfix
class OperandType(enum.IntEnum):
    Variant = 0
    Value = 1
    IndexedInt = 2
    IndexedVar = 3


class VariantType(str, enum.Enum):
    Global = 'GlobalVar'
    ReturnValue = 'ReturnValue'
    Variable = 'LocalVar'
    Argument = 'Argument'

    def __repr__(self):
        return self.name

    def __str__(self):
        return self.value


class Variant(NamedTuple):
    index: int
    type: VariantType

    def __repr__(self):
        return F'{self.type!s}{self.index}'


class Operand(NamedTuple):
    type: OperandType
    variant: Optional[Variant] = None
    value: Optional[Value] = None
    index: Optional[Union[Variant, int]] = None

    def __repr__(self):
        if self.type is OperandType.Value:
            return str(self.value)
        if self.type is OperandType.Variant:
            return F'{self.variant}'
        if self.type is OperandType.IndexedInt:
            return F'{self.variant}[0x{self.index:02X}]'
        if self.type is OperandType.IndexedVar:
            return F'{self.variant}[{self.index!s}]'
        raise RuntimeError(F'Unexpected OperandType {self.type!r} in {self.__class__.__name__}')


_Op_Maxlen = max(len(op.name) for op in Op)


@dataclass
class Instruction:
    offset: int
    opcode: Op
    operands: List[Union[str, int, Operand, TGeneric]] = field(default_factory=list)
    jumptarget: bool = False

    def _oprep(self, fuse_index=None, is_jump=False):
        if fuse_index is None:
            operands = list(self.operands)
        else:
            rest = self.operands[fuse_index:]
            rest = '\x20'.join((str(op) for op in rest))
            operands = [*self.operands[:fuse_index], rest]
        if is_jump:
            operands[0] = F'0x{operands[0]:X}'
        return ', '.join(str(op) for op in operands)

    def __repr__(self):
        return F'{self.opcode.name}({self._oprep()})'

    def __str__(self):
        fuse = None
        if self.opcode is Op.Compare:
            fuse = 1
        if self.opcode is Op.Calculate:
            fuse = 0
        jmp = self.opcode in (
            Op.Jump,
            Op.JumpFalse,
            Op.JumpTrue,
            Op.JumpFlag,
            Op.JumpPop1,
            Op.JumpPop2,
        )
        return F'{self.opcode!s:<{_Op_Maxlen}}{_TAB}{self._oprep(fuse,jmp)}'


class IFPSFile(Struct):
    MinVer = 12
    MaxVer = 23

    Magic = B'IFPS'

    def __init__(self, reader: StructReader[memoryview]):
        self.types: List[TType] = []
        self.functions: List[Function] = []
        self.variables: List[Variable] = []
        self.strings: List[str] = []
        self.reader = reader
        if reader.remaining_bytes < 28:
            raise ValueError('Less than 28 bytes in file, not enough data to parse.')
        magic = reader.read(4)
        if magic != self.Magic:
            raise ValueError(F'Invalid magic sequence: {magic.hex()}')
        self.version = reader.u32()
        self.count_types = reader.u32()
        self.count_functions = reader.u32()
        self.count_variables = reader.u32()
        self.entry = reader.u32()
        self.import_size = reader.u32()
        self.void = False
        if self.version not in range(self.MinVer, self.MaxVer + 1):
            ifps.log_warn(
                F'This IFPS file has version {self.version}, which is not in the supported range '
                F'[{self.MinVer},{self.MaxVer}].')
        self._load_types()
        self._load_functions()
        self._load_variables()

    def _load_types(self):
        reader = self.reader
        types = self.types
        for k in range(self.count_types):
            typecode = reader.u8()
            exported = bool(typecode & 0x80)
            typecode = typecode & 0x7F
            try:
                code = TC(typecode)
            except ValueError as V:
                raise ValueError(F'Unknown type code value 0x{typecode:02X}.') from V
            if code is TC.Class:
                t = TClass(code, reader.read_length_prefixed_ascii())
            elif code is TC.ProcPtr:
                t = TProcPtr(code, reader.read_length_prefixed())
            elif code is TC.Interface:
                guid = uuid.UUID(bytes=bytes(reader.read(0x10)))
                t = TInterface(code, guid)
            elif code is TC.Set:
                t = TSet(code, reader.u32())
            elif code is TC.Tuple:
                type = types[reader.u32()]
                size = reader.u32()
                offset = None if self.version <= 22 else reader.u32()
                t = TTuple(code, type, size, offset)
            elif code is TC.Array:
                t = TArray(code, types[reader.u32()])
            elif code is TC.Record:
                length = reader.u32()
                members = tuple(types[reader.u32()] for _ in range(length))
                t = TRecord(code, members, symbol=F'RECORD{k}')
            else:
                t = TGeneric(code, symbol=code.name)
            if exported:
                t.symbol = reader.read_length_prefixed_ascii()
            types.append(t)
            if self.version >= 21:
                t.attributes = list(self._read_attributes())

    def _read_value(self, reader: Optional[StructReader] = None) -> Value:
        if reader is None:
            reader = self.reader
        type = self.types[reader.u32()]
        size = type.code.width
        processor: Optional[Callable[[], Union[int, float, str, bytes]]] = {
            TC.U08           : reader.u8,
            TC.S08           : reader.i8,
            TC.U16           : reader.u16,
            TC.S16           : reader.i16,
            TC.U32           : reader.u32,
            TC.S32           : reader.i32,
            TC.S64           : reader.i64,
            TC.Single        : reader.f32,
            TC.Double        : reader.f64,
            TC.Extended      : lambda: extended(reader.read(10)),
            TC.String        : reader.read_length_prefixed_ascii,
            TC.PChar         : reader.read_length_prefixed_ascii,
            TC.WideString    : reader.read_length_prefixed_utf16,
            TC.UnicodeString : reader.read_length_prefixed_utf16,
            TC.Char          : lambda: chr(reader.u8()),
            TC.WideChar      : lambda: chr(reader.u16()),
            TC.ProcPtr       : reader.u32,
            TC.Set           : lambda: bytes(reader.read(type.size_in_bytes)),
            TC.Currency      : lambda: reader.u64() / 10_000,
        }.get(type.code, None)
        if processor is not None:
            data = processor()
        elif size > 0:
            data = bytes(reader.read(size))
        else:
            raise ValueError(F'Unable to read attribute of type {type!s}.')
        if isinstance(data, str) and data not in self.strings:
            self.strings.append(data)
        return Value(type, data)

    def _read_attributes(self) -> Generator[Attribute, None, None]:
        reader = self.reader
        count = reader.u32()
        for _ in range(count):
            name = reader.read_length_prefixed_ascii()
            fields = tuple(self._read_value() for _ in range(reader.u32()))
            yield Attribute(name, fields)

    def _load_functions(self):
        reader = self.reader
        width = len(F'{self.count_functions:X}')
        for k in range(self.count_functions):
            decl = None
            body = None
            name = F'F{k:0{width}X}'
            function_flags = reader.u8()
            attributes = None
            has_attributes = bool(function_flags & 4)
            imported = bool(function_flags & 1)
            exported = bool(function_flags & 2)
            if imported:
                name = reader.read_length_prefixed_ascii(8)
                if exported:
                    decl = DeclSpec.ParseF(StructReader(bytes(reader.read_length_prefixed())))
            else:
                offset = reader.u32()
                size = reader.u32()
                with StreamDetour(reader, offset):
                    body = list(self._parse_bytecode(reader.read(size)))
                self.void = False
                if exported:
                    name = reader.read_length_prefixed_ascii()
                    decl = DeclSpec.ParseE(bytes(reader.read_length_prefixed()), self)
                    self.void = decl.void
            if has_attributes:
                attributes = list(self._read_attributes())
            self.functions.append(Function(name, decl, body, exported, attributes))
        for function in self.functions:
            if function.body is None:
                continue
            for instruction in function.body:
                if instruction.opcode is Op.Call:
                    t: Function = self.functions[instruction.operands[0]]
                    instruction.operands[0] = t.reference()

    def _load_variables(self):
        reader = self.reader
        width = len(str(self.count_variables))
        for index in range(self.count_variables):
            tcode = reader.u32()
            flags = reader.u8()
            name = F'{VariantType.Global!s}{index:0{width}}'
            if flags & 1:
                name = reader.read_length_prefixed_ascii()
            self.variables.append(Variable(index, flags, self.types[tcode], name))

    def _read_variant(self, index: int) -> Variant:
        if index < 0x40000000:
            return Variant(index, VariantType.Global)
        index -= 0x60000000
        if index == -1 and not self.void:
            type = VariantType.ReturnValue
        if index >= 0:
            type = VariantType.Variable
        else:
            type = VariantType.Argument
            index = -index
            if self.void:
                index -= 1
        return Variant(index, type)

    def _read_operand(self, reader: StructReader) -> Operand:
        ot = OperandType(reader.u8())
        kw = {}
        if ot is OperandType.Variant:
            kw.update(variant=self._read_variant(reader.u32()))
        if ot is OperandType.Value:
            kw.update(value=self._read_value(reader))
        if ot >= OperandType.IndexedInt:
            kw.update(variant=self._read_variant(reader.u32()))
            index = reader.u32()
            if ot is OperandType.IndexedVar:
                index = self._read_variant(index)
            kw.update(index=index)
        return Operand(ot, **kw)

    def _parse_bytecode(self, data: memoryview) -> Generator[Instruction, None, None]:
        disassembly: Dict[int, Instruction] = OrderedDict()
        stackdepth = 0
        reader = StructReader(data)

        argcount = {
            Op.Assign: 2,
            Op.CallVar: 1,
            Op.Dec: 1,
            Op.Inc: 1,
            Op.LogicalNot: 1,
            Op.Neg: 1,
            Op.Not: 1,
            Op.SetCopyPtr: 2,
            Op.SetPtr: 2,
        }

        while not reader.eof:
            def arg(k=1):
                for _ in range(k):
                    args.append(self._read_operand(reader))
            addr = reader.tell()
            cval = reader.u8()
            code = Op.FromInt(cval)
            insn = Instruction(addr, code)
            args = insn.operands
            disassembly[insn.offset] = insn
            aryness = argcount.get(code)
            if aryness is not None:
                arg(aryness)
            elif code in (Op.Ret, Op.Nop):
                pass
            elif code is Op.Calculate:
                infix = ['+', '-', '*', '/', '%', '<<', '>>', '&', '|', '^'][reader.u8()]
                infix = F'{infix}='
                a = self._read_operand(reader)
                b = self._read_operand(reader)
                args.extend((a, infix, b))
            elif code in (Op.Push, Op.PushVar):
                stackdepth += 1
                arg()
            elif code is Op.Pop:
                if stackdepth < 1:
                    raise RuntimeError(F'Stack grew negative at instruction {len(disassembly)+1}.')
                stackdepth -= 1
            elif code in (Op.Jump, Op.JumpFlag):
                target = reader.i32()
                args.append(reader.tell() + target)
            elif code is Op.Call:
                args.append(reader.u32())
            elif code in (Op.JumpTrue, Op.JumpFalse):
                target = reader.i32()
                val = self._read_operand(reader)
                args.append(reader.tell() + target)
                args.append(val)
            elif code is Op.JumpPop1:
                stackdepth -= 1
                target = reader.i32()
                args.append(reader.tell() + target)
            elif code is Op.JumpPop2:
                stackdepth -= 2
                target = reader.i32()
                args.append(reader.tell() + target)
            elif code is Op.StackType:
                args.append(self._read_variant(reader.u32()))
                args.append(reader.u32())
            elif code is Op.PushType:
                stackdepth += 1
                args.append(self.types[reader.u32()])
            elif code is Op.Compare:
                infix = ['>=', '<=', '>', '<', '!=', '==', 'in', 'is'][reader.u8()]
                arg(2)
                args.append(infix)
                arg(1)
            elif code is Op.SetFlag:
                arg()
                args.append(reader.u8())
            elif code is Op.PushEH:
                args.extend(reader.u32() for _ in range(4))
            elif code is Op.PopEH:
                args.append(reader.u8())
            elif code is Op._INVALID:
                raise ValueError(F'Unsupported opcode: 0x{cval:02X}')
            else:
                raise ValueError(F'Unhandled opcode: {code.name}')

        for k, instruction in enumerate(disassembly.values()):
            if instruction.opcode in (
                Op.Jump,
                Op.JumpTrue,
                Op.JumpFalse,
                Op.JumpFlag,
                Op.JumpPop1,
                Op.JumpPop2,
            ):
                target = instruction.operands[0]
                try:
                    disassembly[target].jumptarget = True
                except KeyError as K:
                    raise RuntimeError(
                        F'The jump target of instruction {k} at 0x{instruction.offset:X} is invalid; '
                        F'the invalid instruction is a {instruction.opcode.name} to 0x{target:X}.'
                    ) from K

        yield from disassembly.values()

    def __str__(self):
        output = io.StringIO()
        _omax = max((
            max(insn.offset for insn in fn.body)
            for fn in self.functions if fn.body
        ), default=0)
        _omax = max(len(self.types), len(self.variables), _omax)
        width = len(F'{_omax:X}')

        if self.types:
            for type in self.types:
                if type.code is not TC.Record:
                    continue
                output.write(F'typedef {type.symbol} = {type.display()}\n')
            output.write('\n')

        if self.variables:
            for variable in self.variables:
                output.write(F'{variable!s};\n')
            output.write('\n')

        if self.functions:
            for function in self.functions:
                if function.body is None:
                    output.write(F'external {function!s};\n')
            output.write('\n')
            for function in self.functions:
                if function.body is None:
                    continue
                output.write(F'begin {function!s}\n')
                for instruction in function.body:
                    output.write(F'{_TAB}0x{instruction.offset:0{width}X}{_TAB}{instruction!s}\n')
                output.write(F'end {function.decl.type}\n\n')

        return output.getvalue()


class ifps(Unit):
    """
    Disassembles compiled Pascal script files that start with the magic sequence "IFPS". These
    scripts can be found, for example, when unpacking InnoSetup installers using innounp.
    """
    def process(self, data):
        return str(IFPSFile(data)).encode(self.codec)

    @classmethod
    def handles(self, data: bytearray) -> bool:
        return data.startswith(IFPSFile.Magic)
