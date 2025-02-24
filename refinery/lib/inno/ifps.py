#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
The code is based on the logic implemented in IFPSTools:
 https://github.com/Wack0/IFPSTools
"""
from __future__ import annotations

import abc
import enum
import io
import itertools

from typing import (
    Callable,
    Dict,
    Generator,
    List,
    NamedTuple,
    Optional,
    Tuple,
    Type,
    TypeVar,
    Union,
)

from uuid import UUID
from dataclasses import dataclass, field
from collections import OrderedDict
from functools import WRAPPER_ASSIGNMENTS, update_wrapper

from refinery.lib.structures import Struct, StructReader
from refinery.lib.inno.symbols import IFPSAPI, IFPSClasses, IFPSEvents
from refinery.lib.types import CaseInsensitiveDict

_E = TypeVar('_E', bound=Type[enum.Enum])
_C = TypeVar('_C', bound=Type)

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


def represent(cls: _E) -> _E:
    cls.__repr__ = lambda self: F'{self.__class__.__name__}.{self.name}'
    cls. __str__ = lambda self: self.name
    return cls


@represent
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
    BooleanNot   = 0x0F  # noqa
    Neg          = 0x10  # noqa
    SetFlag      = 0x11  # noqa
    JumpFlag     = 0x12  # noqa
    PushEH       = 0x13  # noqa
    PopEH        = 0x14  # noqa
    IntegerNot   = 0x15  # noqa
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


class AOp(enum.IntEnum):
    Add = 0
    Sub = 1
    Mul = 2
    Div = 3
    Mod = 4
    Shl = 5
    Shr = 6
    And = 7
    BOr = 8
    Xor = 9

    def __str__(self):
        glyph = ('+', '-', '*', '/', '%', '<<', '>>', '&', '|', '^')[self]
        return F'{glyph}='


class COp(enum.IntEnum):
    GE = 0
    LE = 1
    GT = 2
    LT = 3
    NE = 4
    EQ = 5
    IN = 6
    IS = 7

    def __str__(self):
        return ('>=', '<=', '>', '<', '!=', '==', 'in', 'is')[self]


@represent
class TC(enum.IntEnum):
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
    AnsiString          = 0x0A  # noqa
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
    StaticArray         = 0x16  # noqa
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
            TC.AnsiString    : 0x04,
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
class IFPSTypeMixin:
    symbol: Optional[str] = None
    attributes: Optional[List[Attribute]] = None

    def __str__(self):
        if self.symbol is not None:
            return self.symbol
        return super().__str__()


@dataclass
class IFPSTypeBase(abc.ABC):
    code: TC

    def simple(self, nested=False):
        return True

    def indexed(self):
        return self.code in (
            TC.StaticArray,
            TC.Array,
            TC.Record,
        )

    def display(self, indent=0):
        return indent * _TAB + self.code.name

    @abc.abstractmethod
    def py_type(self, key: Optional[int] = None) -> Optional[type]:
        ...

    @abc.abstractmethod
    def default(self, key: Optional[int] = None):
        ...

    @property
    def primitive(self) -> bool:
        return self.code not in {
            TC.Class,
            TC.ProcPtr,
            TC.Interface,
            TC.Set,
            TC.StaticArray,
            TC.Array,
            TC.Record,
        }

    @property
    def container(self) -> bool:
        return self.code in {
            TC.StaticArray,
            TC.Array,
            TC.Record,
        }

    def __str__(self):
        return self.display(0)


def ifpstype(cls: _C) -> Union[_C, Type[IFPSTypeMixin]]:
    cls = dataclass(cls)
    mix = type(cls.__qualname__, (IFPSTypeMixin, cls), {})
    assigned = set(WRAPPER_ASSIGNMENTS) - {'__annotations__'}
    update_wrapper(mix, cls, assigned=assigned, updated=())
    return dataclass(mix)


@ifpstype
class TPrimitive(IFPSTypeBase):

    def py_type(self, *_) -> Optional[type]:
        return {
            TC.ReturnAddress       : int,
            TC.U08                 : int,
            TC.S08                 : int,
            TC.U16                 : int,
            TC.S16                 : int,
            TC.U32                 : int,
            TC.S32                 : int,
            TC.Single              : float,
            TC.Double              : float,
            TC.Extended            : float,
            TC.AnsiString          : str,
            TC.Pointer             : VariableBase,
            TC.PChar               : str,
            TC.ResourcePointer     : VariableBase,
            TC.Variant             : VariableBase,
            TC.S64                 : int,
            TC.Char                : str,
            TC.WideString          : str,
            TC.WideChar            : str,
            TC.Currency            : float,
            TC.UnicodeString       : str,
            TC.Enum                : int,
            TC.Type                : IFPSType,
        }.get(self.code)

    def default(self, *_):
        tc = self.py_type()
        if issubclass(tc, (int, float, str)):
            return tc()


@ifpstype
class TProcPtr(IFPSTypeBase):
    void: bool
    args: List[DeclSpecParam]

    def py_type(self, *_):
        return None

    def default(self, *_):
        return None

    def display(self, indent=0):
        name = super().display(indent)
        args = []
        for k, spec in enumerate(self.args, 1):
            arg = F'Arg{k}'
            if not spec.const:
                arg = F'*{arg}'
            if spec.type is not None:
                arg = F'{spec.type!s} {arg}'
            args.append(arg)
        args = ', '.join(args)
        return F'{name}({args})'


@ifpstype
class TInterface(IFPSTypeBase):
    uuid: UUID

    def py_type(self, *_):
        return UUID

    def default(self, *_):
        return UUID(int=0)

    def display(self, indent=0):
        display = super().display(indent)
        return F'{display}({self.uuid!s})'


@ifpstype
class TClass(IFPSTypeBase):
    name: str

    def py_type(self, *_):
        return None

    def default(self, *_):
        return None


@ifpstype
class TSet(IFPSTypeBase):
    size: int

    def py_type(self, *_):
        return int

    def default(self, *_):
        return 0

    @property
    def size_in_bytes(self):
        q, r = divmod(self.size, 8)
        return q + (r and 1 or 0)

    def display(self, indent=0):
        display = super().display(indent)
        return F'{display}({self.size})'


@ifpstype
class TArray(IFPSTypeBase):
    type: TPrimitive

    def py_type(self, key: Optional[int] = None):
        if key is None:
            return list
        return self.type.py_type()

    def default(self, key: Optional[int] = None):
        if key is None:
            return []
        return self.type.default()

    def display(self, indent=0):
        display = F'{_TAB * indent}{self.type!s}'
        return F'{display}[]'

    def simple(self, nested=False):
        return self.type.simple(nested)


@ifpstype
class TStaticArray(IFPSTypeBase):
    type: TPrimitive
    size: int
    offset: Optional[int] = None

    def py_type(self, key: Optional[int] = None):
        if key is None:
            return list
        return self.type.py_type(key)

    def default(self, key: Optional[int] = None):
        if key is None:
            return [self.type.default() for _ in range(self.size)]
        return self.type.default()

    def display(self, indent=0):
        display = F'{_TAB * indent}{self.type!s}'
        return F'{display}[{self.size}]'

    def simple(self, nested=False):
        return self.type.simple(nested)


@ifpstype
class TRecord(IFPSTypeBase):
    members: Tuple[TPrimitive, ...]

    @property
    def size(self):
        return len(self.members)

    def py_type(self, key: Optional[int] = None):
        if key is None:
            return list
        return self.members[key].py_type()

    def default(self, key: Optional[int] = None):
        if key is None:
            return [member.default() for member in self.members]
        return self.members[key].default()

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
                output.write(F'\n{_TAB * indent}')
        output.write('}')
        return output.getvalue()


IFPSType = Union[
    TRecord,
    TStaticArray,
    TArray,
    TSet,
    TProcPtr,
    TClass,
    TInterface,
    TPrimitive,
]


class Value(NamedTuple):
    type: IFPSType
    value: Union[str, int, float, bytes, Function]

    def convert(self, *_):
        return self.type.py_type()

    def default(self, *_):
        return self.type.default()

    def __repr__(self):
        value = self.value
        if isinstance(value, bytes):
            value = value.hex()
        return F'{self.type.code.name}({value!r})'

    def __str__(self):
        v = self.value
        if isinstance(v, Function):
            return F'&{v!s}'
        return repr(v)


class Attribute(NamedTuple):
    name: str
    fields: Tuple[Value, ...]

    def __repr__(self):
        name = self.name
        if self.fields:
            name += '[{}]'.format(','.join(repr(f) for f in self.fields))
        return name


@dataclass
class DeclSpecParam:
    const: bool
    type: Optional[TPrimitive] = None
    name: Optional[str] = None


class CallType(str, enum.Enum):
    Symbol = 'symbol'
    Procedure = 'procedure'
    Function = 'function'

    def __str__(self):
        return self.value


@dataclass
class DeclSpec:
    void: bool
    parameters: List[DeclSpecParam] = field(default_factory=list)
    name: str = ''
    calling_convention: Optional[str] = None
    return_type: Optional[IFPSType] = None
    module: Optional[str] = None
    classname: Optional[str] = None
    delay_load: bool = False
    vtable_index: Optional[int] = None
    load_with_altered_search_path: bool = False
    is_property: bool = False

    @property
    def argc(self):
        return len(self.parameters)

    def represent(self, name: str, ref: bool = False, rel: bool = False):
        def pparam(k: int, p: DeclSpecParam):
            name = p.name or F'{VariantType.Argument!s}{k}'
            if p.type is not None:
                name = F'{name}: {p.type!s}'
            if not p.const:
                name = F'*{name}'
            return name
        if self.name and name in self.name:
            name = self.name
        spec = name
        if self.vtable_index is not None:
            spec = F'{self.name}[{self.vtable_index}]'
        if not rel and self.classname:
            spec = F'{self.classname}.{spec}'
        if not rel and self.module:
            spec = F'{self.module}::{spec}'
        if not ref:
            if self.delay_load:
                spec = F'__delay_load {spec}'
            if self.calling_convention:
                spec = F'__{self.calling_convention} {spec}'
            spec = F'{self.type} {spec}'
            args = self.parameters
            args = args and ', '.join(pparam(*t) for t in enumerate(args, 1)) or ''
            spec = F'{spec}({args})'
            if self.return_type:
                spec = F'{spec}: {self.return_type!s}'
        return spec

    @property
    def type(self):
        return CallType.Procedure if self.void else CallType.Function

    def __repr__(self):
        return self.represent(self.name or '(*)')

    @classmethod
    def ParseF(cls, reader: StructReader[bytes], load_flags: bool):
        def ascii():
            return reader.read_c_string('latin1')

        def boolean():
            return bool(reader.u8())

        def cc():
            return {
                0: 'register',
                1: 'pascal',
                2: 'cdecl',
                3: 'stdcall',
            }.get(reader.u8(), cls.calling_convention)

        def read_parameters():
            nonlocal void
            void = not boolean()
            parameters.extend(DeclSpecParam(not b) for b in reader.read())

        void = True
        name = None
        properties = {}
        parameters = []

        if reader.readif(b'dll:'):
            reader.readif(B'files:')
            if (module := ascii()).lower().endswith('.dll'):
                module = module[:-4]
            properties.update(module=module)
            name = ascii()
            properties.update(calling_convention=cc())
            if load_flags:
                properties.update(delay_load=boolean(), load_with_altered_search_path=boolean())
            read_parameters()
        elif reader.readif(b'class:'):
            if reader.remaining_bytes == 1:
                spec = reader.peek(1)
                void = False
                parameters.append(DeclSpecParam(False))
                name = {
                    b'+': 'CastToType',
                    B'-': 'SetNil'
                }.get(spec)
                properties.update(classname='Class', calling_convention='pascal')
            else:
                properties.update(classname=reader.read_terminated_array(b'|').decode('latin1'))
                name = reader.read_terminated_array(b'|').decode('latin1')
                if name[-1] == '@':
                    properties.update(is_property=True)
                    name = name[:-1]
                properties.update(calling_convention=cc())
                read_parameters()
        elif reader.readif(b'intf:.'):
            name = 'CoInterface'
            properties.update(vtable_index=reader.u32())
            properties.update(calling_convention=cc())
            read_parameters()
        else:
            read_parameters()
        return cls(void, parameters, name=name, **properties)

    @classmethod
    def ParseE(cls, data: bytes, ipfs: IFPSFile):
        decl = data.split(B'\x20')
        try:
            return_type = int(decl.pop(0))
        except Exception:
            void = True
        else:
            void = return_type < 0
        if not void:
            return_type = ipfs.types[return_type]
        else:
            return_type = None
        parameters = []
        for param in decl:
            try:
                i = int(param[1:])
            except Exception:
                tv = None
            else:
                tv = ipfs.types[i]
            parameters.append(
                DeclSpecParam(param[:1] == B'@', tv))
        return cls(void, parameters, return_type=return_type)


@dataclass
class Function:
    symbol: str
    decl: Optional[DeclSpec]
    body: Optional[List[Instruction]] = None
    attributes: Optional[List[Attribute]] = None
    _bbs: Optional[Dict[int, BasicBlock]] = None
    _ins: Optional[Dict[int, Instruction]] = None

    @property
    def name(self):
        symbol = self.symbol
        if (decl := self.decl) and (name := decl.name) and (symbol in name):
            symbol = name
        return symbol

    @property
    def code(self):
        if code := self._ins:
            return code
        self._ins = code = {i.offset: i for i in self.body}
        return code

    def reference(self, rel: bool = False) -> str:
        if self.decl is None:
            return self.symbol
        return self.decl.represent(self.symbol, ref=True, rel=rel)

    def __repr__(self):
        if self.decl is None:
            return F'symbol {self.symbol}'
        return self.decl.represent(self.symbol)

    def __str__(self):
        return self.reference()

    @property
    def type(self):
        if self.decl is None:
            return CallType.Symbol
        return self.decl.type

    def get_basic_blocks(self) -> Dict[int, BasicBlock]:
        if (bbs := self._bbs) is not None:
            return bbs
        if self.body is None:
            bbs = self._bbs = {}
            return bbs

        bbs: Dict[int, BasicBlock] = {0: (bb := BasicBlock(0))}
        self._bbs = bbs

        for insn in self.body:
            try:
                bb = bbs[insn.offset]
            except KeyError:
                if insn.jumptarget:
                    nb = bbs[insn.offset] = BasicBlock(insn.offset)
                    nb.sources[bb.offset] = bb
                    bb.targets[nb.offset] = nb
                    bb = nb
            bb.body.append(insn)
            if not insn.branches:
                continue
            targets = [insn.operands[0]]
            sequence = insn.offset + insn.size
            if not insn.jumps and insn.opcode != Op.Ret:
                targets.append(sequence)
            for t in targets:
                if not (bt := bbs.get(t)):
                    bt = bbs[t] = BasicBlock(t)
                bb.targets[t] = bt
                bt.sources[bb.offset] = bb

        for offset, bb in list(bbs.items()):
            if bb.body:
                continue
            del bbs[offset]
            for source in bb.sources.values():
                source.targets.pop(offset, None)

        visited: set[int] = set()
        errored: set[int] = set()

        def trace_stack(offset: int, stack: Optional[int]):
            if offset in errored:
                return
            bb = bbs[offset]
            if bb.stack is not None and stack != bb.stack:
                stack = None
            if stack is None:
                errored.add(offset)
            elif offset in visited:
                return
            else:
                visited.add(offset)
            bb.stack = stack
            body = [] if stack is None else bb.body
            for insn in body:
                insn.stack = stack
                stack += insn.stack_delta
            for t in bb.targets:
                trace_stack(t, stack)

        trace_stack(0, 0)

        for insn in self.body:
            if (stack := insn.stack) is None:
                continue
            for k, op in enumerate(insn.operands):
                if not isinstance(op, Operand):
                    continue
                if not (v := op.variant) or v.type != VariantType.Local:
                    continue
                if v.index <= stack:
                    continue
                raise IndexError(
                    F'Instruction {op!s} at offset 0x{insn.offset:X} in function {self.name} has '
                    F'variant operand {k} whose index {v.index} exceeds the stack depth {stack}.')

        return bbs


class VariableBase:
    type: IFPSType
    spec: Variant

    def __init__(self, type: IFPSType, spec: Variant):
        self.type = type
        self.spec = spec

    def __str__(self):
        return F'{self.spec}: {self.type!s}'


@represent
class OperandType(enum.IntEnum):
    Variant = 0
    Value = 1
    IndexedByInt = 2
    IndexedByVar = 3


@represent
class EHType(enum.IntEnum):
    Try = 0
    Finally = 1
    Catch = 2
    SecondFinally = 3


@represent
class NewEH(enum.IntEnum):
    Finally = 0
    CatchAt = 1
    SecondFinally = 2
    End = 3


class VariantType(str, enum.Enum):
    Global = 'GlobalVar'
    Local = 'LocalVar'
    Argument = 'Argument'

    def __repr__(self):
        return self.name

    def __str__(self):
        return self.value


class Variant(NamedTuple):
    index: int
    type: VariantType

    def __repr__(self):
        if self.index == 0 and self.type == VariantType.Argument:
            return 'ReturnValue'
        return F'{self.type!s}{self.index}'


class Operand(NamedTuple):
    type: OperandType
    variant: Optional[Variant] = None
    value: Optional[Value] = None
    index: Optional[Union[Variant, int]] = None

    def __repr__(self):
        return self.__tostring(repr)

    def __str__(self):
        return self.__tostring(str)

    def __tostring(self, converter):
        if self.type is OperandType.Value:
            return converter(self.value)
        if self.type is OperandType.Variant:
            return converter(self.variant)
        if self.type is OperandType.IndexedByInt:
            return F'{converter(self.variant)}[0x{self.index:02X}]'
        if self.type is OperandType.IndexedByVar:
            return F'{converter(self.variant)}[{self.index!s}]'
        raise RuntimeError(F'Unexpected OperandType {self.type!r} in {self.__class__.__name__}')


_Op_Maxlen = max(len(op.name) for op in Op)
_Op_StackD = {
    Op.Push     : +1,
    Op.PushVar  : +1,
    Op.PushType : +1,
    Op.Pop      : -1,
    Op.JumpPop1 : -1,
    Op.JumpPop2 : -2,
}


@dataclass
class Instruction:
    offset: int
    opcode: Op
    size: int = 0
    stack: Optional[int] = None
    operands: List[Union[str, bool, int, float, Operand, IFPSType, Function, None]] = field(default_factory=list)
    operator: Optional[Union[AOp, COp]] = None
    jumptarget: bool = False

    def op(self, index: int):
        arg = self.operands[index]
        if not isinstance(arg, Operand):
            raise TypeError
        return arg

    @property
    def branches(self):
        return self.opcode in (
            Op.Jump,
            Op.JumpFalse,
            Op.JumpTrue,
            Op.JumpFlag,
            Op.JumpPop1,
            Op.JumpPop2,
        )

    @property
    def jumps(self):
        return self.opcode in (
            Op.Jump,
            Op.JumpPop1,
            Op.JumpPop2,
        )

    @property
    def stack_delta(self):
        return _Op_StackD.get(self.opcode, 0)

    def oprep(self, labels: Optional[dict[int, str]] = None):
        if self.branches:
            dst = self.operands[0]
            if not labels or not (label := labels.get(dst)):
                label = F'0x{dst:X}'
            var = [str(op) for op in self.operands[1:]]
            return ', '.join((label, *var))
        elif self.opcode is Op.PushEH:
            ops = []
            for op, name in reversed(list(zip(self.operands, NewEH))):
                if op is None:
                    continue
                ops.append(F'{name}:0x{op:X}')
            return '\x20'.join(ops)
        elif self.opcode is Op.PopEH:
            return F'End{EHType(self.operands[0])}'
        elif self.opcode is Op.SetFlag:
            rep, negated = self.operands
            return F'!{rep}' if negated else str(rep)
        elif self.opcode is Op.Compare:
            dst, a, b = self.operands
            return F'{dst!s} := {a!s} {self.operator!s} {b!s}'
        elif self.opcode is Op.Calculate:
            dst, src = self.operands
            return F'{dst!s} {self.operator!s} {src!s}'
        elif self.opcode in (Op.Assign, Op.SetPtr):
            dst, src = self.operands
            return F'{dst!s} := {src!s}'
        else:
            return ', '.join(str(op) for op in self.operands)

    def pretty(self, labels: Optional[dict[int, str]] = None):
        return F'{self.opcode!s:<{_Op_Maxlen}}{_TAB}{self.oprep(labels)}'.strip()

    def __repr__(self):
        return F'{self.opcode.name}({self.oprep()})'

    def __str__(self):
        return self.pretty()


@dataclass
class BasicBlock:
    offset: int
    stack: Optional[int] = None
    body: List[Instruction] = field(default_factory=list)
    sources: Dict[int, BasicBlock] = field(default_factory=dict)
    targets: Dict[int, BasicBlock] = field(default_factory=dict)

    @property
    def stack_delta(self):
        return sum(insn.stack_delta for insn in self.body)

    @property
    def size(self):
        return sum(insn.size for insn in self.body)


class FTag(enum.IntFlag):
    External = 0b0001
    Exported = 0b0010
    HasAttrs = 0b0100

    def check(self, v):
        return bool(self & v)


class IFPSFile(Struct):
    MinVer = 12
    MaxVer = 23

    Magic = B'IFPS'

    def __init__(self, reader: StructReader[memoryview], codec: str = 'latin1'):
        self.codec = codec
        self.types: List[IFPSType] = []
        self.functions: List[Function] = []
        self.globals: List[VariableBase] = []
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
            raise NotImplementedError(
                F'This IFPS file has version {self.version}, which is not in the supported range '
                F'[{self.MinVer},{self.MaxVer}].')

        self._known_type_names = {
            TC.U08   : {'Byte', 'Boolean'},
            TC.S08   : {'ShortInt'},
            TC.U16   : {'Word'},
            TC.S16   : {'SmallInt'},
            TC.S32   : {'Integer', 'LongInt'},
            TC.U32   : {'LongWord', 'Cardinal'},
            TC.Char  : {'AnsiChar'},
            TC.PChar : {'PAnsiChar'},
            TC.S64   : {'Int64'},
        }

        self._load_types()
        self._name_types()
        self._load_functions()
        self._load_variables()

        del self._known_type_names

    @property
    def _load_flags(self):
        return self.version >= 23

    def _name_types(self, finalize=False):
        self.types_by_name = td = CaseInsensitiveDict()
        self.types_by_code = tc = {}
        conflicts = 0
        for t in self.types:
            name = str(t)
            code = t.code
            known = self._known_type_names.get(code)
            if name in td:
                conflicts += 1
            if known:
                known.discard(name)
            td[name] = t
            tc[code] = t
        if finalize:
            for code, names in self._known_type_names.items():
                for name in names:
                    if t := tc.get(code):
                        td[name] = t
        return conflicts

    def _load_types(self):
        def _normalize(n: str):
            return IFPSClasses.Types.get(n.casefold(), n)
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
            if code in (TC.Class, TC.ExtClass):
                t = TClass(code, _normalize(reader.read_length_prefixed_ascii()))
            elif code is TC.ProcPtr:
                spec = reader.read_length_prefixed()
                void = bool(spec[0])
                args = [DeclSpecParam(not b) for b in spec[1:]]
                t = TProcPtr(code, void, args)
            elif code is TC.Interface:
                guid = UUID(bytes=bytes(reader.read(0x10)))
                t = TInterface(code, guid)
            elif code is TC.Set:
                t = TSet(code, reader.u32())
            elif code is TC.StaticArray:
                type = types[reader.u32()]
                size = reader.u32()
                offset = None if self.version <= 22 else reader.u32()
                t = TStaticArray(code, type, size, offset)
            elif code is TC.Array:
                t = TArray(code, types[reader.u32()])
            elif code is TC.Record:
                length = reader.u32()
                members = tuple(types[reader.u32()] for _ in range(length))
                t = TRecord(code, members, symbol=F'RECORD{k}')
            else:
                t = TPrimitive(code, symbol=code.name)
            if exported:
                t.symbol = _normalize(reader.read_length_prefixed_ascii())
                if self.version <= 21:
                    t.name = _normalize(reader.read_length_prefixed_ascii())
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
            TC.AnsiString    : lambda: reader.read_length_prefixed(encoding=self.codec),
            TC.PChar         : lambda: reader.read_length_prefixed(encoding=self.codec),
            TC.WideString    : reader.read_length_prefixed_utf16,
            TC.UnicodeString : reader.read_length_prefixed_utf16,
            TC.Char          : lambda: chr(reader.u8()),
            TC.WideChar      : lambda: chr(reader.u16()),
            TC.ProcPtr       : lambda: self.functions[reader.u32() - 1],
            TC.Set           : lambda: int.from_bytes(reader.read(type.size_in_bytes), 'little'),
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
        def _signature(name: str, decl: Optional[DeclSpec]):
            signature = IFPSAPI.get(name, IFPSEvents.get(name)) if name else None
            if decl and decl.classname and (ic := IFPSClasses.Classes.get(decl.classname)):
                signature = ic.members.get(decl.name, signature)
                decl.classname = ic.name
            return signature

        reader = self.reader
        width = len(F'{self.count_functions:X}')
        for k in range(self.count_functions):
            decl = None
            body = None
            name = F'F{k:0{width}X}'
            tags = reader.u8()
            attributes = None
            exported = FTag.Exported.check(tags)
            if FTag.External.check(tags):
                name = reader.read_length_prefixed_ascii(8)
                if exported:
                    read = StructReader(bytes(reader.read_length_prefixed()))
                    decl = DeclSpec.ParseF(read, self._load_flags)
            else:
                offset = reader.u32()
                length = reader.u32()
                if exported:
                    name = reader.read_length_prefixed_ascii()
                    decl = DeclSpec.ParseE(bytes(reader.read_length_prefixed()), self)
                    self.void = decl.void
                else:
                    self.void = False
                with reader.detour(offset):
                    body = list(self._parse_bytecode(reader.read(length)))
            if FTag.HasAttrs.check(tags):
                attributes = list(self._read_attributes())

            if (signature := _signature(name, decl)) and decl and signature.argc == decl.argc:
                for old, new in itertools.zip_longest(decl.parameters, signature.parameters):
                    if not new:
                        break
                    if old and (t := old.type):
                        t.symbol = new.type
                        continue
                    if t := self.types_by_name.get(new.type):
                        t.symbol = new.type
                if sr := signature.return_type:
                    if (dr := decl.return_type) or (dr := self.types_by_name.get(sr)):
                        dr.symbol = sr

            fn = Function(name, decl, body, exported, attributes)
            self.functions.append(fn)

        self.type_name_conflicts = self._name_types(True)

        for function in self.functions:
            decl = function.decl
            if signature := _signature(function.name, decl):
                decl = decl or DeclSpec(True)
                decl.void = signature.void
                parameters = decl.parameters
                if signature.argc != len(parameters):
                    decl.parameters = parameters = [DeclSpecParam(True) for _ in range(signature.argc)]
                for old, new in zip(parameters, signature.parameters):
                    if old.type is None:
                        old.type = self.types_by_name.get(new.type)
                    old.name = new.name or old.name
                    old.const = new.const
                function.symbol = decl.name = signature.name
                if (rt := signature.return_type) and (decl.return_type is None):
                    decl.return_type = self.types_by_name.get(rt, decl.return_type)
                function.decl = decl

        for function in self.functions:
            if function.body is None:
                continue
            for instruction in function.body:
                if instruction.opcode is Op.Call:
                    t: Function = self.functions[instruction.operands[0]]
                    instruction.operands[0] = t

    def _load_variables(self):
        reader = self.reader
        for index in range(self.count_variables):
            code = reader.u32()
            spec = Variant(index, VariantType.Global)
            if reader.u8() & 1:
                spec = reader.read_length_prefixed_ascii()
            self.globals.append(VariableBase(self.types[code], spec))

    def _read_variant(self, index: int) -> Variant:
        if index < 0x40000000:
            return Variant(index, VariantType.Global)
        index -= 0x60000000
        if index >= 0:
            return Variant(index, VariantType.Local)
        index = -index if self.void else ~index
        return Variant(index, VariantType.Argument)

    def _read_operand(self, reader: StructReader) -> Operand:
        ot = OperandType(reader.u8())
        kw = {}
        if ot is OperandType.Variant:
            kw.update(variant=self._read_variant(reader.u32()))
        if ot is OperandType.Value:
            kw.update(value=self._read_value(reader))
        if ot >= OperandType.IndexedByInt:
            kw.update(variant=self._read_variant(reader.u32()))
            index = reader.u32()
            if ot is OperandType.IndexedByVar:
                index = self._read_variant(index)
            kw.update(index=index)
        return Operand(ot, **kw)

    def _parse_bytecode(self, data: memoryview) -> Generator[Instruction, None, None]:
        disassembly: Dict[int, Instruction] = OrderedDict()
        reader = StructReader(data)

        argcount = {
            Op.Assign: 2,
            Op.CallVar: 1,
            Op.Dec: 1,
            Op.Inc: 1,
            Op.BooleanNot: 1,
            Op.Neg: 1,
            Op.IntegerNot: 1,
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
            elif code in (Op.Ret, Op.Nop, Op.Pop):
                pass
            elif code is Op.Calculate:
                insn.operator = AOp(reader.u8())
                arg(2)
            elif code in (Op.Push, Op.PushVar):
                arg()
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
                target = reader.i32()
                args.append(reader.tell() + target)
            elif code is Op.JumpPop2:
                target = reader.i32()
                args.append(reader.tell() + target)
            elif code is Op.StackType:
                args.append(self._read_variant(reader.u32()))
                args.append(reader.u32())
            elif code is Op.PushType:
                args.append(self.types[reader.u32()])
            elif code is Op.Compare:
                insn.operator = COp(reader.u8())
                arg(3)
            elif code is Op.SetFlag:
                arg()
                args.append(bool(reader.u8()))
            elif code is Op.PushEH:
                args.extend(reader.i32() for _ in range(4))
                for k, a in enumerate(args):
                    args[k] = a + reader.tell() if a >= 0 else None
            elif code is Op.PopEH:
                args.append(reader.u8())
            elif code is Op._INVALID:
                raise ValueError(F'Unsupported opcode: 0x{cval:02X}')
            else:
                raise ValueError(F'Unhandled opcode: {code.name}')
            insn.size = reader.tell() - addr

        for k, instruction in enumerate(disassembly.values()):
            if not instruction.branches:
                continue
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
        return self.disassembly()

    def disassembly(self) -> str:
        def sortkey(f: Function):
            d = (d.module or '', d.classname or '', d.void) if (d := f.decl) else ('', '', True)
            return (*d, f.name)

        for function in self.functions:
            function.get_basic_blocks()

        classes: dict[str, dict[str, Function]] = {}
        external: list[Function] = []
        internal: list[Function] = []

        for t in self.types:
            if isinstance(t, TClass):
                classes[t.name] = {}

        for function in self.functions:
            if (decl := function.decl) and (name := decl.classname):
                try:
                    members = classes[name]
                except KeyError:
                    members = classes[name] = {}
                members[decl.name] = function
                continue
            dl = internal if function.body else external
            dl.append(function)

        external.sort(key=sortkey)

        output = io.StringIO()
        _omax = max((
            max(insn.offset for insn in fn.body)
            for fn in self.functions if fn.body
        ), default=0)
        _smax = max((
            max(insn.stack for insn in fn.body if insn.stack is not None)
            for fn in self.functions if fn.body
        ), default=0)
        _omax = max(len(self.types), len(self.globals), _omax)
        _omax = len(F'{_omax:X}')
        _smax = len(F'{_smax:d}')

        if classes:
            for name, members in classes.items():
                if not members:
                    output.write(F'external class {name};\n')
            output.write('\n')
            for name, members in classes.items():
                if not members:
                    continue
                output.write(F'external class {name}')
                if members:
                    for spec in members.values():
                        output.write(F'\n{_TAB}{spec.decl.represent(spec.symbol, rel=True)}')
                    output.write('\nend')
                output.write(';\n\n')

        if self.types:
            for type in self.types:
                if type.code != TC.Record and type.symbol in (type.code.name, None):
                    continue
                if isinstance(type, TClass):
                    continue
                output.write(F'typedef {type.symbol} = {type.display()}\n')
            output.write('\n')

        if self.globals:
            for variable in self.globals:
                output.write(F'global {variable!s}\n')
            output.write('\n')

        if external:
            for function in external:
                output.write(F'external {function!r}\n')
            output.write('\n')

        if internal:
            for function in internal:
                output.write(F'{function!r}\nbegin\n')
                labels = [insn.offset for insn in function.body if insn.jumptarget]
                labelw = max(len(str(len(labels))), 2)
                labeld = {v: F'JumpDestination{k:0{labelw}d}' for k, v in enumerate(labels, 1)}
                labelc = 0
                for instruction in function.body:
                    stack = instruction.stack
                    stack = '?' * _smax if stack is None else F'{stack:>{_smax}d}'
                    if instruction.jumptarget:
                        output.write(F'{labeld[labels[labelc]]}:\n')
                        labelc += 1
                    output.write(F'{_TAB}0x{instruction.offset:0{_omax}X}{_TAB}{stack}{_TAB}{instruction.pretty(labeld)}\n')
                output.write('end;\n\n')

        return output.getvalue().strip()
