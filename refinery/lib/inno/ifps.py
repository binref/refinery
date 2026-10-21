"""
The code is based on the logic implemented in IFPSTools:
 https://github.com/Wack0/IFPSTools
"""
from __future__ import annotations

import abc
import enum
import io
import itertools
import math

from collections import OrderedDict
from dataclasses import dataclass, field
from fractions import Fraction
from typing import (
    Callable,
    Generator,
    NamedTuple,
    TypeVar,
)
from uuid import UUID

from refinery.lib.inno import CaseInsensitiveDict
from refinery.lib.inno.delphi import numbers, variants, x87
from refinery.lib.inno.delphi.runtime import Platform
from refinery.lib.inno.symbols import IFPSAPI, IFPSClasses, IFPSEvents, IFPSSignature
from refinery.lib.structures import Struct, StructReader

_E = TypeVar('_E', bound=type[enum.Enum])

_TAB = '\x20\x20'


def extended(_data: bytes) -> x87.Real:
    """
    Parses the 10 bytes of an x87 extended-precision float into its exact value.
    """
    if len(_data) != 10:
        raise ValueError
    data = int.from_bytes(_data, 'little')
    negative = bool(data >> 79)
    exponent = (data >> 64) & 0x7FFF
    mantissa = data & 0xFFFFFFFFFFFFFFFF
    if exponent == 0x7FFF:
        if mantissa & 0x7FFFFFFFFFFFFFFF == 0:
            return -math.inf if negative else math.inf
        return math.nan
    if mantissa == 0:
        return -0.0 if negative else 0.0
    return x87.real(-mantissa if negative else mantissa, max(exponent, 1) - 16383 - 63)


def represent(cls: _E) -> _E:
    """
    A decorator for various IFPS integer enumeration classes to change the default string
    representation.
    """
    cls.__repr__ = lambda self: F'{self.__class__.__name__}.{self.name}'
    cls. __str__ = lambda self: self.name
    return cls


@represent
class Op(enum.IntEnum):
    """
    An enumeration of all known IFPS opcodes.
    """
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
    SetPtrToCopy = 0x16  # noqa
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


class Dialect(enum.Enum):
    """
    The versions of Pascal Script whose rules for values differ, named by the Inno Setup that ships
    them: the same rules from 5.5.3 to 6.7, and new ones from 7.0 on.
    """
    Inno6 = 6
    Inno7 = 7


class AOp(enum.IntEnum):
    """
    An enumeration of all known IFPS arithmetic opcodes.
    """
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
    As = 10

    def __str__(self):
        if self is AOp.As:
            return 'as'
        glyph = ('+', '-', '*', '/', '%', '<<', '>>', '&', '|', '^')[self]
        return F'{glyph}='


class COp(enum.IntEnum):
    """
    An enumeration of all known IFPS comparison opcodes.
    """
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
    """
    An enumeration of all known IFPS type codes.
    """
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
    U64                 = 0x1D  # noqa
    Enum                = 0x81  # noqa
    Type                = 0x82  # noqa
    ExtClass            = 0x83  # noqa

    @property
    def primitive(self) -> bool:
        """
        Indicates whether the code represents a primitive type.
        """
        return self not in _TC_NON_PRIMITIVE

    @property
    def container(self) -> bool:
        """
        Indicates whether the code represents a container type.
        """
        return self in _TC_CONTAINER

    @property
    def width(self):
        """
        For primitive types, this gives the size of an immediate of this type in bytes.
        """
        return _TC_WIDTH.get(self, 0)

    @property
    def integer_range(self) -> range | None:
        """
        For integer types, this gives the range of values that an immediate of this type can hold.
        """
        return _TC_INTEGER_RANGE.get(self)

    @property
    def integer(self) -> bool:
        """
        Indicates whether the code represents an integer type.
        """
        return self in _TC_INTEGER_RANGE

    @property
    def signed(self) -> bool:
        """
        Indicates whether the code represents a signed integer type.
        """
        return self in _TC_SIGNED

    @property
    def character(self) -> bool:
        """
        Indicates whether the code represents a character type.
        """
        return self in _TC_CHARACTER


_TC_NON_PRIMITIVE = frozenset((
    TC.Class,
    TC.ProcPtr,
    TC.Interface,
    TC.Set,
    TC.StaticArray,
    TC.Array,
    TC.Record,
))

_TC_CONTAINER = frozenset((
    TC.StaticArray,
    TC.Array,
    TC.Record,
))

_TC_CHARACTER = frozenset((
    TC.Char,
    TC.WideChar,
))

_TC_WIDTH = {
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
    TC.U64           : 0x08,
    TC.Extended      : 0x0A,
    TC.ReturnAddress : 0x1C,
}


def _integer_range(code: TC, signed: bool) -> range:
    size = 1 << (code.width * 8)
    if signed:
        return range(-(size >> 1), size >> 1)
    return range(size)


_TC_INTEGER_RANGE = {
    TC.U08 : _integer_range(TC.U08, False),
    TC.U16 : _integer_range(TC.U16, False),
    TC.U32 : _integer_range(TC.U32, False),
    TC.U64 : _integer_range(TC.U64, False),
    TC.S08 : _integer_range(TC.S08, True),
    TC.S16 : _integer_range(TC.S16, True),
    TC.S32 : _integer_range(TC.S32, True),
    TC.S64 : _integer_range(TC.S64, True),
}

_TC_SIGNED = frozenset(code for code, valid in _TC_INTEGER_RANGE.items() if valid.start < 0)


@dataclass
class IFPSTypeBase(abc.ABC):
    """
    The base class for any IFPS type.
    """
    code: TC
    symbol: str | None = field(default=None, kw_only=True)
    attributes: list[FunctionAttribute] | None = field(default=None, kw_only=True)

    def simple(self, nested: bool = False) -> bool:
        """
        Indicate whether the type requires more than one line to pretty print.
        """
        return True

    def display(self, indent=0):
        """
        Compute a display string that can be used to represent the type in disassembly.
        """
        return indent * _TAB + self.code.name

    @property
    def primitive(self) -> bool:
        """
        Indicates whether the type is primitive.
        """
        return self.code.primitive

    @property
    def container(self) -> bool:
        """
        Indicates whether the type is a container.
        """
        return self.code.container

    @property
    def boolean(self) -> bool:
        """
        Indicates whether the type is the Boolean type of Pascal Script: a byte that the runtime
        recognizes by its exported name and converts into a truth value for a Variant.
        """
        return self.code is TC.U08 and (self.symbol or '').upper() == 'BOOLEAN'

    def __str__(self):
        if self.symbol is not None:
            return self.symbol
        return self.display(0)


@dataclass
class TPrimitive(IFPSTypeBase):
    """
    A primitive IFPS type.
    """


@dataclass
class TProcPtr(IFPSTypeBase):
    """
    The procedure pointer IFPS type.
    """
    void: bool
    args: tuple[DeclSpecParam, ...]

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


@dataclass
class TInterface(IFPSTypeBase):
    """
    An IFPS type representing a COM interface.
    """
    uuid: UUID

    def display(self, indent=0):
        display = super().display(indent)
        return F'{display}({self.uuid!s})'


@dataclass
class TClass(IFPSTypeBase):
    """
    An IFPS type representing an IFPS class.
    """
    name: str


@dataclass
class TSet(IFPSTypeBase):
    """
    An IFPS type representing a bit vector.
    """
    size: int

    @property
    def size_in_bytes(self):
        q, r = divmod(self.size, 8)
        return q + (r and 1 or 0)

    def display(self, indent=0):
        display = super().display(indent)
        return F'{display}({self.size})'


@dataclass
class TArray(IFPSTypeBase):
    """
    An IFPS type representing a dynamic array.
    """
    type: IFPSType

    def display(self, indent=0):
        display = F'{_TAB * indent}{self.type!s}'
        return F'array of {display}'

    def simple(self, nested: bool = False) -> bool:
        return self.type.simple(nested)


@dataclass
class TStaticArray(IFPSTypeBase):
    """
    An IFPS type representing a static array (i.e. a tuple).
    """
    type: IFPSType
    size: int
    offset: int | None = None

    def display(self, indent=0):
        display = F'{_TAB * indent}{self.type!s}'
        return F'{display}[{self.size}]'

    def simple(self, nested: bool = False) -> bool:
        return self.type.simple(nested)


@dataclass
class TRecord(IFPSTypeBase):
    """
    An IFPS type representing a structure.
    """
    members: tuple[IFPSType, ...]

    @property
    def size(self):
        return len(self.members)

    def simple(self, nested: bool = False) -> bool:
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


IFPSType = (
    TRecord
    | TStaticArray
    | TArray
    | TSet
    | TProcPtr
    | TClass
    | TInterface
    | TPrimitive
)
"""
Represents any of the possible IFPS data types:

- `refinery.lib.inno.ifps.TRecord`
- `refinery.lib.inno.ifps.TStaticArray`
- `refinery.lib.inno.ifps.TArray`
- `refinery.lib.inno.ifps.TSet`
- `refinery.lib.inno.ifps.TProcPtr`
- `refinery.lib.inno.ifps.TClass`
- `refinery.lib.inno.ifps.TInterface`
- `refinery.lib.inno.ifps.TPrimitive`
"""


class Value(NamedTuple):
    """
    A value of the given type within the IFPS runtime.
    """
    type: IFPSType
    value: str | int | float | x87.Extended | Fraction | bytes | Function

    def __repr__(self):
        value = self.value
        if isinstance(value, bytes):
            value = value.hex()
        return F'{self.type.code.name}({value!r})'

    def __str__(self):
        v = self.value
        if isinstance(v, Function):
            return F'&{v!s}'
        if isinstance(v, x87.Extended):
            return numbers.shortest(v)
        if isinstance(v, Fraction):
            return variants.currency_text(v, numbers.FormatSettings())
        return repr(v)


class FunctionAttribute(NamedTuple):
    """
    A function attribute.
    """
    name: str
    fields: tuple[Value, ...]

    def __repr__(self):
        name = self.name
        if self.fields:
            name += '[{}]'.format(','.join(repr(f) for f in self.fields))
        return name


@dataclass
class DeclSpecParam:
    """
    A function parameter specification.
    """
    const: bool
    """
    True if this parameter is passed by value, not by reference.
    """
    type: IFPSType | None = None
    """
    The type of this parameter.
    """
    name: str | None = None
    """
    The name of this parameter.
    """


class CallType(str, enum.Enum):
    """
    This enumeration classifies the different call types.
    """
    Symbol = 'symbol'
    Procedure = 'procedure'
    Function = 'function'

    def __str__(self):
        return self.value


@dataclass
class DeclSpec:
    """
    This class captures the declaration info of a function symbol.
    """
    void: bool
    parameters: list[DeclSpecParam] = field(default_factory=list)
    name: str = ''
    calling_convention: str | None = None
    return_type: IFPSType | None = None
    module: str | None = None
    classname: str | None = None
    method: bool = False
    """
    True for a method of a class, which Pascal Script calls with its object before the parameters
    that the declaration lists.
    """
    delay_load: bool = False
    vtable_index: int | None = None
    load_with_altered_search_path: bool = False

    @property
    def argc(self):
        return len(self.parameters)

    def represent(self, name: str, ref: bool = False, rel: bool = False):
        def pparam(k: int, p: DeclSpecParam):
            name = p.name or F'{VariableType.Argument!s}{k}'
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
        if self.void:
            return CallType.Procedure
        return CallType.Function

    def __repr__(self):
        return self.represent(self.name or '(*)')

    @classmethod
    def ParseF(cls, reader: StructReader[bytes], load_flags: int, max_argc: int):
        """
        Parses the declaration of an import. Pascal Script writes `load_flags` flag bytes into the
        declaration of a DLL import. The parameter count of a property is a number that no other
        data backs; a count above `max_argc` is refused.
        """
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
            if load_flags > 0:
                properties.update(delay_load=boolean())
            if load_flags > 1:
                properties.update(load_with_altered_search_path=boolean())
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
                if write := name.endswith('@'):
                    name = name[:-1]
                if write or reader.peek(1) != bytes(1):
                    void = write
                    if (argc := reader.u32() + write) > max_argc:
                        raise ValueError(F'The property {name} takes {argc} arguments, more than any call can pass.')
                    parameters.extend(DeclSpecParam(True) for _ in range(argc))
                    name = F'Set{name}' if write else F'Get{name}'
                else:
                    properties.update(calling_convention=cc(), method=True)
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


def _trace_stack(bbs: dict[int, BasicBlock]) -> None:
    """
    Traces the stack depth from the entry block through every block that is reachable from it, in
    depth-first order. A block that is reached with two different depths has no known depth.
    """
    visited: set[int] = set()
    errored: set[int] = set()
    pending: list[tuple[int, int | None]] = [(0, 0)]
    while pending:
        offset, stack = pending.pop()
        if offset in errored:
            continue
        bb = bbs[offset]
        if bb.stack is not None and stack != bb.stack:
            stack = None
        if stack is None:
            errored.add(offset)
        elif offset in visited:
            continue
        else:
            visited.add(offset)
        bb.stack = stack
        if stack is not None:
            for insn in bb.body:
                insn.stack = stack
                stack += insn.stack_delta
        pending.extend((target, stack) for target in reversed(bb.targets))


@dataclass
class Function:
    """
    Represents a function in the IFPS runtime.
    """
    symbol: str = ''
    decl: DeclSpec | None = None
    body: list[Instruction] | None = None
    attributes: list[FunctionAttribute] | None = None
    _bbs: dict[int, BasicBlock] | None = None
    _ins: dict[int, Instruction] | None = None

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

    def get_basic_blocks(self) -> dict[int, BasicBlock]:
        if (bbs := self._bbs) is not None:
            return bbs
        if self.body is None:
            bbs = self._bbs = {}
            return bbs

        bbs: dict[int, BasicBlock] = {0: (bb := BasicBlock(0))}
        self._bbs = bbs
        jump = False

        for insn in self.body:
            try:
                bb = bbs[insn.offset]
            except KeyError:
                if jump or insn.jumptarget:
                    nb = bbs[insn.offset] = BasicBlock(insn.offset)
                    if not jump:
                        nb.sources[bb.offset] = bb
                        bb.targets[nb.offset] = nb
                    bb = nb
            bb.body.append(insn)
            if not insn.branches:
                jump = False
                continue
            targets = [insn.operands[0]]
            sequence = insn.offset + insn.size
            jump = insn.jumps
            if not jump and insn.opcode != Op.Ret:
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

        _trace_stack(bbs)

        for insn in self.body:
            if (stack := insn.stack) is None:
                continue
            for k, op in enumerate(insn.operands):
                if not isinstance(op, Operand):
                    continue
                if not (v := op.variable) or v.type != VariableType.Local:
                    continue
                if v.index <= stack:
                    continue
                raise IndexError(
                    F'Instruction {op!s} at offset 0x{insn.offset:X} in function {self.name} has '
                    F'variable operand {k} whose index {v.index} exceeds the stack depth {stack}.')

        return bbs


class VariableBase:
    """
    This class represents a variable within the IFPS runtime. This is primarily a base class for
    the more sophisticated `refinery.lib.inno.emulator.Variable`.
    """
    type: IFPSType
    """
    The type of the variable, see `refinery.lib.inno.ifps.IFPSType`.
    """
    spec: VariableSpec | str | None
    """
    A `refinery.lib.inno.ifps.VariableSpec` that uniquely identifies the base variable, or the
    name of a global variable that the script exports. If this property is `None`, the variable is
    unbound: The `refinery.lib.inno.ifps.Op.SetPtrToCopy` opcode can create such variables.
    """

    __slots__ = 'type', 'spec'

    def __init__(self, type: IFPSType, spec: VariableSpec | str | None):
        self.type = type
        self.spec = spec

    def __str__(self):
        return F'{self.spec}: {self.type!s}'


@represent
class OperandType(enum.IntEnum):
    """
    Classifies the type of an `refinery.lib.inno.ifps.Operand`.
    """
    Variable = 0
    Value = 1
    IndexedByInt = 2
    IndexedByVar = 3


@represent
class EHType(enum.IntEnum):
    """
    This enumeration lists the possible types of code region covered by an exception handler.
    """
    Try = 0
    Finally = 1
    Catch = 2
    SecondFinally = 3


@represent
class NewEH(enum.IntEnum):
    """
    This enumeration gives names to the 4 arguments of the opcode responsible for registering a new
    exception handler. The first argument specifies the location of a finally, the second argument
    specifies the location of a catch handler, and so on.
    """
    Finally = 0
    CatchAt = 1
    SecondFinally = 2
    End = 3


class VariableType(str, enum.Enum):
    Global = 'GlobalVar'
    Local = 'LocalVar'
    Argument = 'Argument'

    def __repr__(self):
        return self.name

    def __str__(self):
        return self.value


class VariableSpec(NamedTuple):
    """
    Represents a reference to a variable within the IFPS runtime. There are three variable types:
    Locals, globals, and function arguments; see `refinery.lib.inno.ifps.VariableType`. A variable
    is then uniquely defined by its type and index within the (localized) list of such variables.
    The function argument of index zero is the return value of a function.
    """
    index: int
    type: VariableType

    def __repr__(self):
        if self.index == 0 and self.type == VariableType.Argument:
            return 'ReturnValue'
        return F'{self.type!s}{self.index}'


class Operand(NamedTuple):
    """
    Represends an operand to an IFPS opcode. An operand can either contain a value, which is an
    immediate that is encoded into the opcode, or a reference to a variable. A variable is given
    by its `refinery.lib.inno.ifps.VariableSpec`. Additionally, the operand can specify an index
    for this variable which can either be given by an immediate, or by another variable. In the
    latter case, the encoded index is also a `refinery.lib.inno.ifps.VariableSpec`. The type of
    operand is encoded as an `refinery.lib.inno.ifps.OperandType`.
    """
    type: OperandType
    variable: VariableSpec | None = None
    value: Value | None = None
    index: VariableSpec | int | None = None

    def __repr__(self):
        return self.__tostring(repr)

    def __str__(self):
        return self.__tostring(str)

    @property
    def immediate(self):
        return self.type == OperandType.Value

    def __tostring(self, converter):
        if self.type is OperandType.Value:
            return converter(self.value)
        if self.type is OperandType.Variable:
            return converter(self.variable)
        if self.type is OperandType.IndexedByInt:
            return F'{converter(self.variable)}[0x{self.index:02X}]'
        if self.type is OperandType.IndexedByVar:
            return F'{converter(self.variable)}[{self.index!s}]'
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
    encoded: bytes = B''
    stack: int | None = None
    operands: list[str | bool | int | float | Operand | IFPSType | Function | None] = field(default_factory=list)
    operator: AOp | COp | None = None
    jumptarget: bool = False

    def callee(self) -> Function:
        """
        The function that this instruction calls; it must be a `refinery.lib.inno.ifps.Op.Call`.
        """
        if not isinstance(target := self.operands[0], Function):
            raise TypeError(F'The instruction at offset 0x{self.offset:X} calls no function.')
        return target

    def op(self, index: int):
        arg = self.operands[index]
        if not isinstance(arg, Operand):
            raise TypeError
        return arg

    @property
    def size(self):
        return len(self.encoded)

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

    def oprep(self, labels: dict[int, str] | None = None):
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
        elif self.opcode in (Op.Assign, Op.SetPtr, Op.SetPtrToCopy):
            dst, src = self.operands
            return F'{dst!s} := {src!s}'
        else:
            return ', '.join(str(op) for op in self.operands)

    def pretty(self, labels: dict[int, str] | None = None):
        return F'{self.opcode!s:<{_Op_Maxlen}}{_TAB}{self.oprep(labels)}'.strip()

    def __repr__(self):
        return F'{self.opcode.name}({self.oprep()})'

    def __str__(self):
        return self.pretty()


@dataclass
class BasicBlock:
    offset: int
    stack: int | None = None
    body: list[Instruction] = field(default_factory=list)
    sources: dict[int, BasicBlock] = field(default_factory=dict)
    targets: dict[int, BasicBlock] = field(default_factory=dict)

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


class _BuiltinParameter(NamedTuple):
    name: str
    const: bool


_BUILTIN_PARAMETERS: dict[str, tuple[_BuiltinParameter, ...]] = {
    'getarraylength' : (_BuiltinParameter('Arr', True),),
    'setarraylength' : (_BuiltinParameter('arr', False), _BuiltinParameter('count', True)),
    'length'         : (_BuiltinParameter('S', True),),
    'setlength'      : (_BuiltinParameter('s', False), _BuiltinParameter('NewLength', True)),
    'low'            : (_BuiltinParameter('X', True),),
    'high'           : (_BuiltinParameter('X', True),),
    'dec'            : (_BuiltinParameter('x', False),),
    'inc'            : (_BuiltinParameter('x', False),),
    'include'        : (_BuiltinParameter('s', False), _BuiltinParameter('m', True)),
    'exclude'        : (_BuiltinParameter('s', False), _BuiltinParameter('m', True)),
    'sizeof'         : (_BuiltinParameter('Data', True),),
}
"""
The built-in functions of Pascal Script that get their parameters after their declaration was
compiled, so that their compiled declaration has none; with the parameters they get.
"""


_ARGUMENT_SIZE = 6
"""
The fewest bytes of code that an argument of a call takes: Pascal Script pushes each argument with
an instruction of five bytes or more and pops it with one of one byte.
"""


class _CallSite(NamedTuple):
    """
    What a call of a function shows about its declaration. Pascal Script passes the variable for
    the result right before the call, and frees the argument slots and the result right after it,
    one `Pop` each; the expression around the call may free more.
    """
    result: bool
    pops: int

    def contradicts(self, decl: DeclSpec) -> bool:
        return self.result == decl.void or self.pops < decl.argc + self.result

    def slack(self, decl: DeclSpec) -> int:
        return self.pops - decl.argc - self.result


def _shapes_agree(decl: DeclSpec, signature: IFPSSignature) -> bool:
    return (
        decl.void == signature.void
        and decl.argc == signature.argc
        and all(old.const == new.const for old, new in zip(decl.parameters, signature.parameters))
    )


class IFPSFile(Struct):
    MinVer = 12
    MaxVer = 23

    Magic = B'IFPS'

    def __init__(
        self,
        reader: StructReader[memoryview],
        codec: str = 'latin1',
        unicode: bool | None = None,
        load_flags: int | None = None,
    ):
        """
        The setup that compiled the script decides whether `String` is a Unicode string and how many
        load flags a DLL import has. When the caller does not know them, they are read from the
        script: it is Unicode unless its only string type is `AnsiString`, and the load flags are
        decided by the calls of the DLL imports. The script's standard types tell which Pascal
        Script compiled it and for which platform.
        """
        self.codec = codec
        self.load_flags = load_flags
        self.types: list[IFPSType] = []
        self.functions: list[Function] = []
        self.globals: list[VariableBase] = []
        self._strings: dict[str, None] = {}
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

        if self.version not in range(self.MinVer, self.MaxVer + 1):
            raise NotImplementedError(
                F'This IFPS file has version {self.version}, which is not in the supported range '
                F'[{self.MinVer},{self.MaxVer}].')

        self._known_type_names = {
            TC.U08        : {'Byte', 'Boolean'},
            TC.S08        : {'ShortInt'},
            TC.U16        : {'Word'},
            TC.S16        : {'SmallInt'},
            TC.S32        : {'Integer', 'LongInt'},
            TC.U32        : {'LongWord', 'Cardinal', 'HWND', 'TSetupProcessorArchitecture'},
            TC.Char       : {'AnsiChar'},
            TC.PChar      : {'PAnsiChar'},
            TC.AnsiString : {'AnyString'},
            TC.S64        : {'Int64', 'NativeInt'},
            TC.U64        : {'UInt64', 'NativeUInt'},
        }

        self._load_types()
        if unicode is None:
            codes = {t.code for t in self.types}
            unicode = TC.UnicodeString in codes or TC.AnsiString not in codes
        self.unicode = unicode
        self.dialect = self._dialect()
        self.platform = self._platform()
        self._name_types()
        self._load_functions()
        self._load_variables()

        del self._known_type_names
        self.strings: list[str] = list(self._strings)
        del self._strings

    def _dialect(self) -> Dialect:
        """
        The Pascal Script that compiled the script. The compiler of Inno Setup 7 declares the type
        `UInt64` in every script, and Pascal Script has no such type before Inno Setup 7.
        """
        if any(t.code is TC.U64 for t in self.types):
            return Dialect.Inno7
        return Dialect.Inno6

    def _platform(self) -> Platform:
        """
        The platform of the Setup that the script was compiled for. The compiler declares its
        standard types first, in a fixed order; from Inno Setup 7 on, `NativeUInt` follows the first
        `Single` and is 64 bits wide in a script for a 64-bit Setup. Earlier versions only build
        32-bit Setups and have no 64-bit unsigned type. The standard types decide, so the types
        read so far decide while the type table is read.
        """
        types = self.types
        for k, t in enumerate(types):
            if t.code is TC.Single:
                if k + 1 < len(types) and types[k + 1].code is TC.U64:
                    return Platform.Win64
                break
        return Platform.Win32

    def _read_extended(self, reader: StructReader) -> x87.Real:
        """
        An Extended constant, which is a Double in a script for a 64-bit Setup.
        """
        if self._platform() is Platform.Win64:
            return reader.f64()
        return extended(reader.read(10))

    def _name_types(self, missing_types: set[str] | None = None):
        tbn: dict[str, IFPSType] = CaseInsensitiveDict()
        self.types_by_name = tbn
        for t in self.types:
            name = str(t)
            code = t.code
            known = self._known_type_names.get(code)
            if known:
                known.discard(name)
            tbn[name] = t

        if missing_types:
            def add_type(name: str, type: IFPSType):
                tbn[name] = type
                self.types.append(type)
                return type

            def make_string(name: str = 'String'):
                try:
                    return tbn[name]
                except KeyError:
                    pass
                code = TC.UnicodeString if self.unicode else TC.AnsiString
                for type in tbn.values():
                    if type.code is code:
                        break
                else:
                    return add_type(name, TPrimitive(code, symbol=name))
                tbn[name] = type
                return type

            for name in tbn:
                missing_types.discard(name)

            if 'TGUID' in missing_types:
                missing_types |= {'LongWord', 'Word', 'Byte'}

            for code in TC:
                name = code.name
                if name not in missing_types:
                    continue
                missing_types.discard(name)
                add_type(name, TPrimitive(code, symbol=name))

            for code, names in self._known_type_names.items():
                for name in names:
                    if name not in missing_types:
                        continue
                    missing_types.discard(name)
                    add_type(name, TPrimitive(code, symbol=name))

            for name in [
                'TVarType',
                'TInputQueryWizardPage',
                'TInputOptionWizardPage',
                'TInputDirWizardPage',
                'TInputFileWizardPage',
                'TOutputMsgWizardPage',
                'TOutputMsgMemoWizardPage',
                'TOutputProgressWizardPage',
                'TOutputMarqueeProgressWizardPage',
                'TDownloadWizardPage',
                'ExtractionWizardPage',
                'TWizardPage',
                'TSetupForm',
                'TComponent',
                'TNewNotebookPage',
            ]:
                if name not in missing_types:
                    continue
                add_type(name, TClass(TC.Class, name, symbol=name))

            if (name := 'String') in missing_types:
                make_string(name)

            if (name := 'TArrayOfString') in missing_types:
                add_type(name, TArray(TC.Array, make_string()))

            if (name := 'IUnknown') in missing_types:
                add_type(name, TInterface(TC.Interface, UUID('{00000000-0000-0000-C000-000000000046}')))

            if (name := 'TGUID') in missing_types:
                add_type(name, TRecord(TC.Record, (
                    tbn['LongWord'],
                    tbn['Word'],
                    tbn['Word'],
                    TStaticArray(TC.StaticArray, tbn['Byte'], 8)
                ), symbol=name))

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
                args = tuple(DeclSpecParam(not b) for b in spec[1:])
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

    def _read_value(self, reader: StructReader | None = None) -> Value:
        if reader is None:
            reader = self.reader
        type = self.types[reader.u32()]
        size = type.code.width
        processor: Callable[[], int | float | str | bytes] | None = {
            TC.U08           : reader.u8,
            TC.S08           : reader.i8,
            TC.U16           : reader.u16,
            TC.S16           : reader.i16,
            TC.U32           : reader.u32,
            TC.S32           : reader.i32,
            TC.S64           : reader.i64,
            TC.U64           : reader.u64,
            TC.Single        : reader.f32,
            TC.Double        : reader.f64,
            TC.Extended      : lambda: self._read_extended(reader),
            TC.AnsiString    : lambda: reader.read_length_prefixed(encoding=self.codec),
            TC.PChar         : lambda: reader.read_length_prefixed(encoding=self.codec),
            TC.WideString    : reader.read_length_prefixed_utf16,
            TC.UnicodeString : reader.read_length_prefixed_utf16,
            TC.Char          : lambda: chr(reader.u8()),
            TC.WideChar      : lambda: chr(reader.u16()),
            TC.ProcPtr       : lambda: self.functions[reader.u32()],
            TC.Set           : lambda: int.from_bytes(reader.read(type.size_in_bytes), 'little'),
            TC.Currency      : lambda: Fraction(reader.i64(), 10_000),
        }.get(type.code, None)
        if processor is not None:
            data = processor()
        elif size > 0:
            data = bytes(reader.read(size))
        else:
            raise ValueError(F'Unable to read attribute of type {type!s}.')
        if isinstance(data, str):
            self._strings[data] = None
        return Value(type, data)

    def _read_attributes(self) -> Generator[FunctionAttribute]:
        reader = self.reader
        count = reader.u32()
        for _ in range(count):
            name = reader.read_length_prefixed_ascii()
            fields = tuple(self._read_value() for _ in range(reader.u32()))
            yield FunctionAttribute(name, fields)

    def _load_functions(self):
        reader = self.reader
        width = len(F'{self.count_functions:X}')
        dll_imports: list[tuple[Function, bytes]] = []
        max_argc = len(reader) // _ARGUMENT_SIZE

        for k in range(self.count_functions):
            decl = None
            body = None
            name = F'F{k:0{width}X}'
            tags = reader.u8()
            attributes = None
            exported = FTag.Exported.check(tags)
            spec = None
            if FTag.External.check(tags):
                name = reader.read_length_prefixed_ascii(8)
                if exported:
                    spec = bytes(reader.read_length_prefixed())
                    if not spec.startswith(B'dll:'):
                        decl = DeclSpec.ParseF(StructReader(spec), 0, max_argc)
            else:
                offset = reader.u32()
                length = reader.u32()
                if exported:
                    name = reader.read_length_prefixed_ascii()
                    decl = DeclSpec.ParseE(bytes(reader.read_length_prefixed()), self)
                with reader.detour(offset):
                    body = reader.read(length)
            if FTag.HasAttrs.check(tags):
                attributes = list(self._read_attributes())
            fn = Function(name, decl=decl, body=body, attributes=attributes)
            self.functions.append(fn)
            if decl is None and spec is not None:
                dll_imports.append((fn, spec))

        for function in self.functions:
            if body := function.body:
                void = decl.void if (decl := function.decl) else False
                function.body = list(self._parse_bytecode(body, void))

        calls: dict[int, list[_CallSite]] = {}

        for function in self.functions:
            body = function.body or ()
            for k, instruction in enumerate(body):
                if instruction.opcode is not Op.Call:
                    continue
                callee = instruction.operands[0] = self.functions[instruction.operands[0]]
                pops = 0
                for after in itertools.islice(body, k + 1, None):
                    if after.opcode is not Op.Pop:
                        break
                    pops += 1
                result = k > 0 and body[k - 1].opcode is Op.PushVar
                calls.setdefault(id(callee), []).append(_CallSite(result, pops))

        self._load_dll_imports(dll_imports, calls, max_argc)

        missing_types = set()
        signatures: list[tuple[Function, IFPSSignature]] = []

        for function in self.functions:
            decl = function.decl
            if (
                decl is not None
                and not decl.parameters
                and not decl.module
                and not decl.classname
                and function.body is None
                and (builtin := _BUILTIN_PARAMETERS.get(function.name.casefold()))
            ):
                decl.parameters = [DeclSpecParam(p.const, name=p.name) for p in builtin]
            if (signature := self._signature(function, missing_types)) is None:
                continue
            if decl is None:
                decl = function.decl = DeclSpec(
                    signature.void or any(not call.result for call in calls.get(id(function), ())),
                    [DeclSpecParam(p.const) for p in signature.parameters],
                )
            function.symbol = decl.name = signature.name
            if not _shapes_agree(decl, signature):
                continue
            signatures.append((function, signature))
            for old, new in zip(decl.parameters, signature.parameters):
                if (t := old.type) is not None:
                    t.symbol = new.type
                elif t := self.types_by_name.get(new.type):
                    t.symbol = new.type
                else:
                    missing_types.add(new.type)
            if sr := signature.return_type:
                if (dr := decl.return_type) or (dr := self.types_by_name.get(sr)):
                    dr.symbol = sr
                else:
                    missing_types.add(sr)

        self.type_name_conflicts = self._name_types(missing_types)

        for function, signature in signatures:
            decl = function.decl
            assert decl is not None
            for old, new in zip(decl.parameters, signature.parameters):
                if old.type is None:
                    old.type = self.types_by_name.get(new.type)
                old.name = new.name or old.name
            if (rt := signature.return_type) and (decl.return_type is None):
                decl.return_type = self.types_by_name.get(rt)

    def _load_dll_imports(
        self,
        imports: list[tuple[Function, bytes]],
        calls: dict[int, list[_CallSite]],
        max_argc: int,
    ):
        """
        Parses the declarations of the DLL imports. Depending on its revision, Pascal Script wrote
        zero, one or two load flags into them, independent of the version of the script. Unless the
        caller gave the count, it is the one that the calls of the imports contradict least, then
        the one that leaves the fewest extra pops after the calls, then the larger one. A count for
        which a declaration cannot be parsed is out.
        """
        def parse(load_flags: int) -> list[DeclSpec]:
            return [DeclSpec.ParseF(StructReader(spec), load_flags, max_argc) for _, spec in imports]

        def fit(load_flags: int) -> tuple[int, int, int]:
            contradictions = slack = 0
            for (function, _), decl in zip(imports, candidates[load_flags]):
                for call in calls.get(id(function), ()):
                    if call.contradicts(decl):
                        contradictions += 1
                    else:
                        slack += call.slack(decl)
            return contradictions, slack, -load_flags

        if (load_flags := self.load_flags) is None:
            candidates: dict[int, list[DeclSpec]] = {}
            for count in (0, 1, 2):
                try:
                    candidates[count] = parse(count)
                except EOFError:
                    continue
            if not candidates:
                raise ValueError('The declarations of the DLL imports do not parse with any count of load flags.')
            load_flags = min(candidates, key=fit)
            decls = candidates[load_flags]
        else:
            decls = parse(load_flags)
        for (function, _), decl in zip(imports, decls):
            function.decl = decl

    def _signature(self, function: Function, missing_types: set[str]) -> IFPSSignature | None:
        """
        The declaration that Inno Setup documents for the given function: an event for a function
        of the script, a member of a class for a method or a property, else one of the functions
        that Inno Setup and Pascal Script provide. Imports from a DLL have none.
        """
        decl = function.decl
        if function.body is not None:
            return IFPSEvents.get(function.name)
        if decl is not None and decl.module is not None:
            return None
        if decl is not None and decl.classname:
            if (info := IFPSClasses.Classes.get(decl.classname)) is None:
                return None
            if info.name not in self.types_by_name:
                missing_types.add(info.name)
            decl.classname = info.name
            return info.members.get(decl.name)
        return IFPSAPI.get(function.name)

    def _load_variables(self):
        reader = self.reader
        for index in range(self.count_variables):
            code = reader.u32()
            spec = VariableSpec(index, VariableType.Global)
            if reader.u8() & 1:
                spec = reader.read_length_prefixed_ascii()
            self.globals.append(VariableBase(self.types[code], spec))

    def _read_variable_spec(self, index: int, void: bool) -> VariableSpec:
        if index < 0x40000000:
            return VariableSpec(index, VariableType.Global)
        index -= 0x60000000
        if index >= 0:
            return VariableSpec(index, VariableType.Local)
        index = -index if void else ~index
        return VariableSpec(index, VariableType.Argument)

    def _read_operand(self, reader: StructReader, void: bool) -> Operand:
        ot = OperandType(reader.u8())
        kw = {}
        if ot is OperandType.Variable:
            kw.update(variable=self._read_variable_spec(reader.u32(), void))
        if ot is OperandType.Value:
            kw.update(value=self._read_value(reader))
        if ot >= OperandType.IndexedByInt:
            kw.update(variable=self._read_variable_spec(reader.u32(), void))
            index = reader.u32()
            if ot is OperandType.IndexedByVar:
                index = self._read_variable_spec(index, void)
            kw.update(index=index)
        return Operand(ot, **kw)

    def _parse_bytecode(self, data: memoryview, void: bool) -> Generator[Instruction]:
        disassembly: dict[int, Instruction] = OrderedDict()
        reader = StructReader(data)

        argcount = {
            Op.Assign: 2,
            Op.CallVar: 1,
            Op.Dec: 1,
            Op.Inc: 1,
            Op.BooleanNot: 1,
            Op.Neg: 1,
            Op.IntegerNot: 1,
            Op.SetPtrToCopy: 2,
            Op.SetPtr: 2,
        }

        while not reader.eof:
            def arg(k=1):
                for _ in range(k):
                    args.append(self._read_operand(reader, void))
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
                val = self._read_operand(reader, void)
                args.append(reader.tell() + target)
                args.append(val)
            elif code is Op.JumpPop1:
                target = reader.i32()
                args.append(reader.tell() + target)
            elif code is Op.JumpPop2:
                target = reader.i32()
                args.append(reader.tell() + target)
            elif code is Op.StackType:
                args.append(self._read_variable_spec(reader.u32(), void))
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
            size = reader.tell() - addr
            reader.seekrel(-size)
            insn.encoded = bytes(reader.read(size))

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

    def disassembly(self, print_bytes: bool = False, print_bytes_count: int = 12) -> str:
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
            max((insn.stack for insn in fn.body if insn.stack is not None), default=1)
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
            typedefs = []
            for type in self.types:
                if type.code != TC.Record and type.symbol in (type.code.name, None):
                    continue
                if isinstance(type, TClass):
                    continue
                typedefs.append((type.symbol, type.display()))
            typedefs.sort()
            for symbol, display in typedefs:
                output.write(F'typedef {symbol} = {display}\n')
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
            def create_prefix(instruction: Instruction):
                stack = instruction.stack
                stack = '?' * _smax if stack is None else F'{stack:>{_smax}d}'
                return F'{_TAB}0x{instruction.offset:0{_omax}X}{_TAB}{stack}{_TAB}'

            for function in internal:
                labels = [insn.offset for insn in function.body if insn.jumptarget]
                labelw = max(len(str(len(labels))), 2)
                labeld = {v: F'JumpDestination{k:0{labelw}d}' for k, v in enumerate(labels, 1)}

                output.write(F'{function!r}\nbegin\n')
                labelc = 0

                for instruction in function.body:
                    prefix = create_prefix(instruction)
                    if instruction.jumptarget:
                        output.write(F'{labeld[labels[labelc]]}:\n')
                        labelc += 1
                    if print_bytes:
                        hexbytes = instruction.encoded.hex(' ').split()
                    else:
                        hexbytes = ['']
                    hexbytes_iter = iter(hexbytes)
                    instruction_written = False
                    prefix_length = len(prefix)
                    ic = instruction.pretty(labeld)
                    while line := list(itertools.islice(hexbytes_iter, 0, print_bytes_count)):
                        output.write(prefix)
                        if print_bytes:
                            prefix = prefix_length * '\x20'
                            output.write('\x20'.join(line).ljust(3 * print_bytes_count - 1))
                        if not instruction_written:
                            output.write(ic)
                            instruction_written = True
                        output.write('\n')

                output.write('end;\n\n')

        return output.getvalue().strip()
