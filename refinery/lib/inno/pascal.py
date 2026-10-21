"""
Pascal Script's rules for the values of its types: how it reads a value of one type as another,
stores a value into a variable, computes with two values, and compares them. Integers, sets, and
strings follow Pascal Script's own code; floats, Currency, and Variants are left to the Delphi
run-time library of `refinery.lib.inno.delphi`, which Pascal Script calls for them.
"""
from __future__ import annotations

import enum
import math
import operator
import struct

from dataclasses import dataclass
from fractions import Fraction
from typing import Any, Callable, TypeVar

from refinery.lib.inno.delphi import variants, x87
from refinery.lib.inno.delphi.errors import (
    DelphiException,
    EDivByZero,
    EIntOverflow,
    EMathError,
    EZeroDivide,
)
from refinery.lib.inno.delphi.runtime import Operation, Runtime, truncated_division, units
from refinery.lib.inno.delphi.variants import Variant, VarType
from refinery.lib.inno.delphi.x87 import FPU, MASKED_CONTROL_WORD, Format, Real
from refinery.lib.inno.ifps import (
    TC,
    AOp,
    COp,
    Dialect,
    IFPSType,
    TArray,
    TRecord,
    TSet,
    TStaticArray,
)

_T = TypeVar('_T')


@dataclass
class Machine:
    """
    The state that Pascal Script's rules for values read: the version of the rules and the state
    of the Delphi run-time library that Pascal Script runs on.
    """
    dialect: Dialect
    runtime: Runtime


class PSError(enum.IntEnum):
    """
    The kinds of runtime error that Pascal Script distinguishes, numbered as Pascal Script numbers
    them. Pascal Script keeps the kind with every error of the script.
    """
    InvalidType = 2
    InvalidOpcodeParameter = 6
    OutOfRange = 10
    TypeMismatch = 12
    DivideByZero = 15
    MathError = 16
    CouldNotCallProc = 17
    OutOfRecordRange = 18
    Exception = 20
    NullPointerException = 21
    CustomError = 24

    @property
    def text(self) -> str:
        """
        The message that Pascal Script gives an error of this kind when it carries no exception of
        Delphi.
        """
        return _PS_ERROR_TEXT[self]


_PS_ERROR_TEXT = {
    PSError.InvalidType      : 'Invalid Type',
    PSError.InvalidOpcodeParameter : 'Invalid Opcode Parameter',
    PSError.OutOfRange       : 'Out Of Range',
    PSError.TypeMismatch     : 'Type Mismatch',
    PSError.DivideByZero     : 'divide by Zero',
    PSError.MathError        : 'Math error',
    PSError.CouldNotCallProc : 'Could not call proc',
    PSError.OutOfRecordRange : 'Out of Record Fields Range',
    PSError.Exception        : 'Exception: ',
    PSError.NullPointerException : 'Null Pointer Exception',
    PSError.CustomError      : '',
}


class IFPSException(RuntimeError):
    """
    An error of the script, which its exception handlers can handle. Pascal Script keeps the `kind`
    of every error, and the exception of Delphi that raised it, if any. The script reads the
    `message` of that exception with `GetExceptionMessage`, or the text of the kind when there is
    no exception. An error that escapes from a call of an emulated function names the `called`
    function in its report. An emulated function that both raises the error and reports that it
    could not be called sets `failed_call`: when an except block takes the error, Pascal Script
    raises `Could not call proc` at the start of that block.
    """
    def __init__(
        self,
        message: str | None = None,
        kind: PSError = PSError.Exception,
        called: str | None = None,
        failed_call: bool = False,
    ):
        message = kind.text if message is None else str(message)
        report = message if called is None else F'Error calling {called}: {message}'
        super().__init__(report)
        self.kind = kind
        self.message = message
        self.called = called
        self.failed_call = failed_call


def type_mismatch() -> IFPSException:
    return IFPSException(kind=PSError.TypeMismatch)


def delphi_error(error: DelphiException) -> IFPSException:
    """
    The error of the script that Pascal Script makes of an exception of Delphi: a float division
    by zero and an integer division by zero keep the kind of a division by zero, the other float
    errors are math errors.
    """
    if isinstance(error, (EZeroDivide, EDivByZero)):
        kind = PSError.DivideByZero
    elif isinstance(error, EMathError):
        kind = PSError.MathError
    else:
        kind = PSError.Exception
    return IFPSException(str(error), kind)


def _delphi(function: Callable[..., _T], *args) -> _T:
    """
    Calls a function of the Delphi run-time library; an exception of Delphi becomes the error of
    the script that Pascal Script makes of it.
    """
    try:
        return function(*args)
    except DelphiException as error:
        raise delphi_error(error) from error


def signed32(value: int) -> int:
    return ((value + 0x80000000) & 0xFFFFFFFF) - 0x80000000


def _signed(value: int, bits: int) -> int:
    value &= (1 << bits) - 1
    return value - (1 << bits) if value >> (bits - 1) else value


_FLOAT_FORMATS = {
    TC.Single   : Format.Single,
    TC.Double   : Format.Double,
    TC.Extended : Format.Extended,
}

_STRINGS = frozenset((TC.AnsiString, TC.PChar, TC.WideString, TC.UnicodeString))
_TEXTS = _STRINGS | {TC.Char, TC.WideChar}


def representation(t: IFPSType, value: Any) -> Any:
    """
    The value that a variable of the given primitive type holds for a value of Python code, like
    the result of an emulated function: integers are wrapped into their range, a one-character
    string is read as its code, floats are rounded to their format, a character holds the first
    character of a string, and a Variant holds the value with the Variant type that matches its
    Python type.
    """
    code = t.code
    if (valid := code.integer_range) is not None:
        if type(value) is not int:
            value = _python_integer(t, value)
        start = valid.start
        return start + (value - start) % (valid.stop - start)
    if code in _TEXTS:
        if type(value) is not str:
            if not isinstance(value, int) or isinstance(value, bool):
                raise _python_mismatch(t, value)
            value = chr(value)
        if code.character and len(value) != 1:
            return value[:1] or '\0'
        return value
    if code is TC.Variant:
        return variants.from_python(value)
    if (fmt := _FLOAT_FORMATS.get(code)) is not None:
        if isinstance(value, bool) or not isinstance(value, (int, float, x87.Extended)):
            raise _python_mismatch(t, value)
        if isinstance(value, int):
            value = x87.real(value)
        return _NEAREST.store(value, fmt)
    if code is TC.Currency:
        if isinstance(value, bool) or not isinstance(value, (int, Fraction)):
            raise _python_mismatch(t, value)
        return Fraction(round(Fraction(value) * 10000), 10000)
    if code is TC.Set and not isinstance(value, int):
        raise _python_mismatch(t, value)
    return value


def _python_integer(t: IFPSType, value: Any) -> int:
    if isinstance(value, str) and len(value) == 1:
        return ord(value)
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, float) and math.isfinite(value):
        return int(value)
    if not isinstance(value, int):
        raise _python_mismatch(t, value)
    return value


def _python_mismatch(t: IFPSType, value: Any) -> TypeError:
    return TypeError(F'Assigning value {value!r} to variable of type {t}.')


_NEAREST = FPU(MASKED_CONTROL_WORD)
"""
Rounds values from Python code to the nearest value of a float format.
"""


def default(t: IFPSType) -> Any:
    """
    The value of a new variable of a type that holds no other variables. Pascal Script fills a new
    variable with zero bytes: zero, the empty string, the character 0, the empty set, nil, and an
    unassigned Variant. It leaves a return address, a resource pointer, and a type as they are;
    these start as zero and nil.
    """
    code = t.code
    if code.integer or code is TC.Enum or code is TC.Set or code is TC.ReturnAddress:
        return 0
    if code in _FLOAT_FORMATS:
        return 0.0
    if code is TC.Currency:
        return Fraction(0)
    if code.character:
        return '\0'
    if code in _STRINGS:
        return ''
    if code is TC.Variant:
        return variants.EMPTY
    if code in (TC.Class, TC.Interface, TC.ProcPtr, TC.ResourcePointer, TC.Type):
        return None
    raise TypeError(F'The type {t} has no default value.')


def read_cardinal(t: IFPSType, value: Any, runtime: Runtime) -> int:
    """
    Pascal Script's `PSGetUInt`: a value read as a Cardinal.
    """
    code = t.code
    if code.integer:
        return value & 0xFFFFFFFF
    if code.character:
        return ord(value)
    if code is TC.Variant:
        if value.type in (VarType.String, VarType.OleStr):
            if len(value.value) != 1:
                raise type_mismatch()
            return ord(value.value)
        return _delphi(variants.to_cardinal, value, runtime)
    raise type_mismatch()


def read_integer(t: IFPSType, value: Any, runtime: Runtime) -> int:
    """
    Pascal Script's `PSGetInt`: a value read as a Longint.
    """
    code = t.code
    if code.integer:
        return signed32(value)
    if code.character:
        return ord(value)
    if code is TC.Variant:
        return _delphi(variants.to_integer, value, runtime)
    raise type_mismatch()


def read_int64(t: IFPSType, value: Any, runtime: Runtime) -> int:
    """
    Pascal Script's `PSGetInt64`: a value read as an Int64.
    """
    code = t.code
    if code.integer:
        return value if code is not TC.U64 else _signed(value, 64)
    if code.character:
        return ord(value)
    if code is TC.Variant:
        return _delphi(variants.to_int64, value, runtime)
    raise type_mismatch()


def read_uint64(t: IFPSType, value: Any, runtime: Runtime) -> int:
    """
    Pascal Script's `PSGetUInt64` of Inno Setup 7: a value read as a UInt64.
    """
    code = t.code
    if code.integer:
        return value & 0xFFFFFFFFFFFFFFFF
    if code.character:
        return ord(value)
    if code is TC.Variant:
        return _delphi(variants.to_uint64, value, runtime)
    raise type_mismatch()


def read_real(t: IFPSType, value: Any, runtime: Runtime) -> Real:
    """
    Pascal Script's `PSGetReal`: a value read as an Extended.
    """
    code = t.code
    if code.integer:
        return runtime.fpu.load(value)
    if code in _FLOAT_FORMATS:
        return value
    if code is TC.Currency:
        return _delphi(runtime.currency_to_real, value)
    if code is TC.Variant:
        return _delphi(variants.to_real, value, runtime)
    raise type_mismatch()


def read_currency(t: IFPSType, value: Any, runtime: Runtime) -> Fraction:
    """
    Pascal Script's `PSGetCurrency`: a value read as a Currency.
    """
    code = t.code
    if code.integer:
        return _delphi(runtime.currency_of_integer, value)
    if code in _FLOAT_FORMATS:
        return _delphi(runtime.currency, value)
    if code is TC.Currency:
        return value
    if code is TC.Variant:
        return _delphi(variants.to_currency, value, runtime)
    raise type_mismatch()


def read_string(t: IFPSType, value: Any, runtime: Runtime, target: TC = TC.UnicodeString) -> str:
    """
    Pascal Script's `PSGetAnsiString`, `PSGetWideString`, and `PSGetUnicodeString`: a value read as
    a string of the given type.
    """
    code = t.code
    if code is TC.U08:
        return chr(value)
    if code is TC.U16 and target is not TC.AnsiString:
        return chr(value)
    if code.character or code in _STRINGS:
        return value
    if code is TC.Variant:
        name = 'String' if target is TC.AnsiString else 'OleStr'
        return _delphi(variants.to_string, value, runtime, name)
    raise type_mismatch()


def to_variant(t: IFPSType, value: Any, machine: Machine) -> Variant:
    """
    Pascal Script's `IntPIFVariantToVariant`: the Variant that holds a value of the given type.
    Before Inno Setup 7, Pascal Script asks for the length of a static array as for a dynamic
    array, which fails.
    """
    runtime = machine.runtime
    code = t.code
    if code is TC.Variant:
        return value
    if code is TC.U08:
        if t.boolean:
            return Variant(VarType.Boolean, value != 0)
        return Variant(VarType.Byte, value)
    vtype = _VARIANT_TYPES.get(code)
    if vtype is not None:
        if code is TC.Extended:
            return Variant(vtype, _delphi(runtime.fpu.store, value, Format.Double))
        if code is TC.Single:
            return Variant(vtype, float(value))
        return Variant(vtype, value)
    if isinstance(t, TStaticArray) and machine.dialect is Dialect.Inno6:
        raise IFPSException('Invalid array')
    if isinstance(t, (TArray, TStaticArray)):
        element = t.type
        return Variant(VarType.Array | VarType.Variant, [to_variant(element, v, machine) for v in value])
    if code is TC.Interface:
        return Variant(VarType.Dispatch, value)
    raise type_mismatch()


_VARIANT_TYPES = {
    TC.S08           : VarType.ShortInt,
    TC.U16           : VarType.Word,
    TC.S16           : VarType.SmallInt,
    TC.U32           : VarType.LongWord,
    TC.S32           : VarType.Integer,
    TC.S64           : VarType.Int64,
    TC.U64           : VarType.UInt64,
    TC.Single        : VarType.Double,
    TC.Double        : VarType.Double,
    TC.Extended      : VarType.Double,
    TC.Currency      : VarType.Currency,
    TC.AnsiString    : VarType.String,
    TC.PChar         : VarType.String,
    TC.Char          : VarType.String,
    TC.WideString    : VarType.OleStr,
    TC.WideChar      : VarType.OleStr,
    TC.UnicodeString : VarType.UString,
}


def store(target: IFPSType, source: IFPSType, value: Any, machine: Machine) -> Any:
    """
    Pascal Script's `SetVariantValue` for a primitive destination: the value that a variable of the
    target type holds after the assignment of a value of the source type.
    """
    runtime = machine.runtime
    code = target.code
    sc = source.code
    if code is TC.U08:
        return read_cardinal(source, value, runtime) & 0xFF
    if code is TC.S08:
        return _signed(read_integer(source, value, runtime), 8)
    if code is TC.U16:
        return read_cardinal(source, value, runtime) & 0xFFFF
    if code is TC.S16:
        return _signed(read_integer(source, value, runtime), 16)
    if code is TC.U32:
        if sc.integer:
            return value & 0xFFFFFFFF
        if sc.character:
            return ord(value)
        if sc is TC.Variant:
            return _delphi(variants.to_cardinal, value, runtime)
        raise type_mismatch()
    if code is TC.S32:
        if sc.integer:
            return signed32(value)
        if sc.character:
            return ord(value)
        if sc is TC.Variant:
            return _delphi(variants.to_integer, value, runtime)
        if sc is TC.Class:
            return value
        raise type_mismatch()
    if code is TC.S64:
        return read_int64(source, value, runtime)
    if code is TC.U64:
        return read_uint64(source, value, runtime)
    if (fmt := _FLOAT_FORMATS.get(code)) is not None:
        if sc.integer:
            real = x87.real(value)
        elif sc in _FLOAT_FORMATS or sc is TC.Currency or sc is TC.Variant:
            real = read_real(source, value, runtime)
        else:
            raise type_mismatch()
        return _delphi(runtime.fpu.store, real, fmt)
    if code is TC.Currency:
        return read_currency(source, value, runtime)
    if code is TC.AnsiString or code is TC.PChar:
        return read_string(source, value, runtime, TC.AnsiString)
    if code is TC.WideString:
        return read_string(source, value, runtime, TC.WideString)
    if code is TC.UnicodeString:
        return read_string(source, value, runtime, TC.UnicodeString)
    if code is TC.Char:
        return chr(read_cardinal(source, value, runtime) & 0xFF)
    if code is TC.WideChar:
        return chr(read_cardinal(source, value, runtime) & 0xFFFF)
    if code is TC.Variant:
        if sc is TC.Interface:
            return Variant(VarType.Dispatch, value)
        return to_variant(source, value, machine)
    if code is TC.Interface:
        if sc is TC.Variant:
            return _delphi(variants.to_dispatch, value, runtime)
        if sc is TC.Interface or sc is TC.Class:
            return value
        raise type_mismatch()
    if code is TC.Set:
        if target != source:
            raise type_mismatch()
        return value
    if code is TC.Class or code is TC.ProcPtr:
        return value
    raise type_mismatch()


def assignable(target: IFPSType, source: IFPSType, machine: Machine) -> bool:
    """
    Whether Pascal Script assigns a value of the source type to a variable of the target type that
    holds other variables: a dynamic array only takes a dynamic array whose elements have the same
    type, and from Inno Setup 7 on also one whose elements have the same base type, unless that is
    a record, a set, or an array.
    """
    if (
        isinstance(target, TArray)
        and isinstance(source, TArray)
        and target.code is TC.Array
        and source.code is TC.Array
    ):
        if target.type is source.type:
            return True
        if machine.dialect is Dialect.Inno6:
            return False
        code = target.type.code
        return code is source.type.code and code not in _CONTAINERS
    return True


_CONTAINERS = frozenset((TC.Record, TC.Set, TC.StaticArray, TC.Array))


def _in_range(code: TC, value: int) -> int:
    valid = code.integer_range
    assert valid is not None
    start = valid.start
    return start + (value - start) % (valid.stop - start)


def ordinal(code: TC, value) -> int:
    """
    Reads an operand as Pascal Script reads it for integer arithmetic and comparisons: an integer as
    its value and a character as its code point. Any other operand is a type mismatch.
    """
    if code.integer:
        return value
    if code.character:
        return ord(value)
    raise type_mismatch()


_INTEGER_OPERATIONS = {
    AOp.Add : operator.add,
    AOp.Sub : operator.sub,
    AOp.Mul : operator.mul,
    AOp.And : operator.and_,
    AOp.BOr : operator.or_,
    AOp.Xor : operator.xor,
}

_SET_OPERATIONS = {
    AOp.Add: operator.or_,
    AOp.Sub: lambda a, b: a & ~b,
    AOp.Mul: operator.and_,
}

_VARIANT_OPERATORS = {
    AOp.Add : variants.Operator.Add,
    AOp.Sub : variants.Operator.Subtract,
    AOp.Mul : variants.Operator.Multiply,
    AOp.Mod : variants.Operator.Modulus,
    AOp.Shl : variants.Operator.ShiftLeft,
    AOp.Shr : variants.Operator.ShiftRight,
    AOp.And : variants.Operator.And,
    AOp.BOr : variants.Operator.Or,
    AOp.Xor : variants.Operator.Xor,
}

_VARIANT_ARITHMETIC = frozenset((AOp.Add, AOp.Sub, AOp.Mul, AOp.Div, AOp.Mod))

_OPERATIONS = {
    AOp.Add : Operation.Add,
    AOp.Sub : Operation.Subtract,
    AOp.Mul : Operation.Multiply,
    AOp.Div : Operation.Divide,
}


def _integer_arithmetic(aop: AOp, target: TC, a: int, source: TC, b: int, runtime: Runtime) -> int:
    """
    Pascal Script's arithmetic for a destination of an integer type. Addition, subtraction,
    multiplication, and the bitwise operators give the bits that the destination keeps however the
    operands are read. For division and shifts, the destination's type decides how the source is
    read and how wide the computation is. An Int64 destination reads the source as an Int64 and a
    UInt64 destination as a UInt64. A 32-bit destination with a 64-bit source divides on 64 bits,
    without a sign when the source is a UInt64. Otherwise the division takes 32 bits, unsigned for
    an unsigned destination.
    """
    if (calculate := _INTEGER_OPERATIONS.get(aop)) is not None:
        return calculate(a, b)
    wide = target.width > 4
    if aop is AOp.Shl:
        return a << (b & (63 if wide else 31))
    if aop is AOp.Shr:
        if wide:
            return (a & 0xFFFFFFFFFFFFFFFF) >> (b & 63)
        return (a & 0xFFFFFFFF) >> (b & 31)
    if target is TC.S64:
        quotient, remainder = _delphi(runtime.int64_division, a, _signed(b, 64))
        return quotient if aop is AOp.Div else remainder
    if target is TC.U64:
        b &= 0xFFFFFFFFFFFFFFFF
    elif not wide and (target.width < 4 or source.width <= 4):
        if target.signed:
            b = signed32(b)
            if a == -0x80000000 and b == -1:
                raise delphi_error(EIntOverflow())
        else:
            b &= 0xFFFFFFFF
    elif source is TC.U64:
        a &= 0xFFFFFFFFFFFFFFFF
    quotient, remainder = _delphi(truncated_division, a, b)
    return quotient if aop is AOp.Div else remainder


def _variant_operator(aop: AOp, left: Variant) -> variants.Operator:
    if aop is AOp.Div:
        return variants.Operator.Divide if variants.is_float(left) else variants.Operator.IntDivide
    return _VARIANT_OPERATORS[aop]


def _operate(aop: AOp, left: Variant, right: Variant, runtime: Runtime, divide: bool = False) -> Variant:
    op = variants.Operator.Divide if divide and aop is AOp.Div else _variant_operator(aop, left)
    return _delphi(variants.operate, op, left, right, runtime)


def calculate(aop: AOp, target: IFPSType, a: Any, source: IFPSType, b: Any, machine: Machine) -> Any:
    """
    Pascal Script's `DoCalc`: the value that a variable of the target type holds after computing
    with the source operand. Byte, ShortInt, Word, SmallInt, and Int64 destinations read a Variant
    operand as an integer; Cardinal and Integer destinations compute with Delphi's Variant
    operators for addition, subtraction, multiplication, and division; float and Currency
    destinations compute with Delphi's Variant operators for any Variant operand. From Inno Setup
    7 on, `as` keeps the object; Setup's classes are not modelled, so its class is not checked.
    """
    runtime = machine.runtime
    code = target.code
    sc = source.code
    if aop is AOp.As:
        if machine.dialect is Dialect.Inno6:
            raise IFPSException(kind=PSError.InvalidOpcodeParameter)
        return a
    if code.integer:
        if sc is TC.Variant:
            if code in (TC.U32, TC.S32) and aop in _VARIANT_ARITHMETIC:
                vtype = VarType.LongWord if code is TC.U32 and aop is not AOp.Mod else VarType.Integer
                left = Variant(vtype, a if vtype is VarType.LongWord else signed32(a))
                result = _operate(aop, left, b, runtime)
                if code is TC.U32:
                    return _delphi(variants.to_cardinal, result, runtime)
                return _delphi(variants.to_integer, result, runtime)
            if code is TC.S64:
                b, sc = read_int64(source, b, runtime), TC.S64
            elif code is TC.U64:
                b, sc = read_uint64(source, b, runtime), TC.U64
            elif code.signed:
                b, sc = read_integer(source, b, runtime), TC.S32
            else:
                b, sc = read_cardinal(source, b, runtime), TC.U32
        return _in_range(code, _integer_arithmetic(aop, code, a, sc, ordinal(sc, b), runtime))
    if code is TC.Set:
        if (operation := _SET_OPERATIONS.get(aop)) is None or not isinstance(source, TSet):
            raise type_mismatch()
        return operation(a, b)
    if (fmt := _FLOAT_FORMATS.get(code)) is not None:
        if aop not in (AOp.Add, AOp.Sub, AOp.Mul, AOp.Div):
            raise type_mismatch()
        if sc is TC.Variant:
            double = a if code is not TC.Extended else _delphi(runtime.fpu.store, a, Format.Double)
            result = _operate(aop, Variant(VarType.Double, double), b, runtime, True)
            real = _delphi(variants.to_real, result, runtime)
            return _delphi(runtime.fpu.store, real, fmt)
        if not (sc.integer or sc in _FLOAT_FORMATS or sc is TC.Currency):
            raise type_mismatch()
        if sc is TC.Currency and aop is AOp.Div:
            return _delphi(runtime.real_divided_by_currency, a, b, fmt)
        other = read_real(source, b, runtime)
        return _delphi(runtime.real_arithmetic, _OPERATIONS[aop], a, other, fmt)
    if code is TC.Currency:
        if aop not in (AOp.Add, AOp.Sub, AOp.Mul, AOp.Div):
            raise type_mismatch()
        if sc is TC.Variant:
            result = _operate(aop, Variant(VarType.Currency, a), b, runtime, True)
            return _delphi(variants.to_currency, result, runtime)
        if not (sc.integer or sc in _FLOAT_FORMATS or sc is TC.Currency):
            raise type_mismatch()
        if machine.dialect is Dialect.Inno6 and (sc is TC.U32 or sc is TC.S64):
            return _delphi(_currency_read_as_double, runtime, aop, a, b)
        return _delphi(runtime.currency_arithmetic, _OPERATIONS[aop], a, b)
    if code in _STRINGS:
        if aop is not AOp.Add:
            raise type_mismatch()
        target_code = TC.AnsiString if code is TC.PChar else code
        return a + read_string(source, b, runtime, target_code)
    if code is TC.Char:
        if aop is not AOp.Add:
            raise type_mismatch()
        return chr((ord(a) + read_cardinal(source, b, runtime)) & 0xFF)
    if code is TC.WideChar:
        if aop is not AOp.Add:
            raise type_mismatch()
        return chr((ord(a) + read_cardinal(source, b, runtime)) & 0xFFFF)
    if code is TC.Variant:
        return _operate(aop, a, to_variant(source, b, machine), runtime)
    raise type_mismatch()


def _currency_read_as_double(runtime: Runtime, aop: AOp, a: Fraction, b: int) -> Fraction:
    """
    Pascal Script before Inno Setup 7 computes a Currency with a Cardinal or an Int64 from the eight
    bytes of the Currency read as a Double, and stores the result as a Currency.
    """
    double, = struct.unpack('<d', struct.pack('<q', _signed(units(a), 64)))
    return runtime.currency(runtime.real_arithmetic(_OPERATIONS[aop], double, runtime.fpu.load(b)))


def _integer_comparands(left: TC, a: int, right: TC, b) -> tuple:
    """
    Reads the operands of a comparison whose left operand has an integer type as Pascal Script
    reads them. The left operand's type decides how the right operand is read.
    """
    if left is TC.S32:
        if right is TC.U32:
            return a, signed32(b)
        if right.integer or right in _FLOAT_FORMATS:
            return a, b
        if right.character:
            return a, ord(b)
        raise type_mismatch()
    if left is TC.U64:
        return a, b & 0xFFFFFFFFFFFFFFFF if right.integer else ordinal(right, b)
    if left is TC.S64 and right is TC.U64:
        return a, _signed(b, 64)
    if left is TC.U08 and right in (TC.AnsiString, TC.PChar):
        return chr(a), b
    b = ordinal(right, b)
    if left.width > 4:
        return a, b
    if left.signed:
        return a, signed32(b)
    return a, b & 0xFFFFFFFF


def _set_contains(members: int, set_type: TSet, ordinal_value: int) -> bool:
    ordinal_value &= 0xFFFFFFFF
    if ordinal_value >= set_type.size:
        raise IFPSException(kind=PSError.OutOfRecordRange)
    return bool((members >> ordinal_value) & 1)


_TESTS = {
    COp.GE : operator.ge,
    COp.LE : operator.le,
    COp.GT : operator.gt,
    COp.LT : operator.lt,
    COp.NE : operator.ne,
    COp.EQ : operator.eq,
}


def compare(cop: COp, left: IFPSType, a: Any, right: IFPSType, b: Any, machine: Machine) -> bool:
    """
    Pascal Script's `DoBooleanCalc`: compares `a`, which has the type `left`, with `b`, which has
    the type `right`. The left operand's type decides how the right one is read. From Inno Setup 7
    on, an Integer compares with a Currency as floats.
    """
    runtime = machine.runtime
    lc = left.code
    rc = right.code
    if cop is COp.IN:
        if isinstance(right, TSet):
            return _set_contains(b, right, read_cardinal(left, a, runtime))
        return a in b
    if cop is COp.IS:
        return a is b
    test = _TESTS[cop]
    if lc.integer:
        if rc is TC.Variant:
            if lc is TC.S32:
                return test(_variant_order(Variant(VarType.Integer, a), b, runtime), 0)
            if lc is TC.S64:
                return test(a, read_int64(right, b, runtime))
            if lc is TC.U64:
                return test(a, read_uint64(right, b, runtime))
            if lc.signed:
                return test(a, read_integer(right, b, runtime))
            return test(a, read_cardinal(right, b, runtime))
        if lc is TC.S32 and (rc in _FLOAT_FORMATS or rc is TC.Currency and machine.dialect is Dialect.Inno7):
            return _real_test(test, read_real(left, a, runtime), read_real(right, b, runtime), runtime)
        a, b = _integer_comparands(lc, a, rc, b)
        return test(a, b)
    if lc is TC.Set:
        if not isinstance(right, TSet) or right != left:
            raise type_mismatch()
        if cop is COp.GE:
            return b & ~a == 0
        if cop is COp.LE:
            return a & ~b == 0
        if cop is COp.EQ:
            return a == b
        if cop is COp.NE:
            return a != b
        raise type_mismatch()
    if lc in _FLOAT_FORMATS:
        return _real_test(test, a, read_real(right, b, runtime), runtime)
    if lc is TC.Currency:
        return test(a, read_currency(right, b, runtime))
    if lc is TC.AnsiString or lc is TC.PChar or lc is TC.Char:
        return test(a, read_string(right, b, runtime, TC.AnsiString))
    if lc is TC.WideChar or lc is TC.WideString:
        return test(a, read_string(right, b, runtime, TC.WideString))
    if lc is TC.UnicodeString:
        return test(a, read_string(right, b, runtime, TC.UnicodeString))
    if lc is TC.Variant:
        return test(_variant_order(a, to_variant(right, b, machine), runtime), 0)
    if lc in _REFERENCES and cop in (COp.EQ, COp.NE):
        if rc is not lc:
            raise type_mismatch()
        return test(0 if a is b or a == b else 1, 0)
    if lc is TC.Record and cop in (COp.EQ, COp.NE) and right == left:
        return test(0 if a == b else 1, 0)
    raise type_mismatch()


_REFERENCES = frozenset((TC.Class, TC.Interface, TC.ProcPtr))


def _real_test(test, a: Real, b: Real, runtime: Runtime) -> bool:
    order = _delphi(runtime.fpu.compare, a, b)
    if order is None:
        return test is operator.ne
    return test(order, 0)


def _variant_order(a: Variant, b: Variant, runtime: Runtime) -> int:
    return _delphi(variants.compare, a, b, runtime)


def boolean(t: IFPSType, value: bool, machine: Machine) -> Any:
    """
    The value that a comparison writes into a destination of the given type: an integer of up to
    32 bits, and from Inno Setup 7 on any integer, holds 1 or 0, and a Variant holds a Boolean.
    """
    code = t.code
    if code.integer and (code.width <= 4 or machine.dialect is Dialect.Inno7):
        return int(value)
    if code is TC.Variant:
        return Variant(VarType.Boolean, value)
    raise type_mismatch()


def negate(t: IFPSType, value: Any, runtime: Runtime) -> Any:
    """
    Pascal Script's `DoMinus`; a Variant that Delphi cannot negate is a type mismatch.
    """
    code = t.code
    if code in _FLOAT_FORMATS:
        return runtime.fpu.negate(value)
    if code.integer:
        return _in_range(code, -value)
    if code is TC.Currency:
        return Fraction(_signed(-units(value), 64), 10000)
    if code is TC.Variant:
        try:
            return variants.negate(value, runtime)
        except DelphiException:
            raise type_mismatch()
    raise type_mismatch()


def invert(t: IFPSType, value: Any, runtime: Runtime) -> Any:
    """
    Pascal Script's `DoIntegerNot`; a Variant that Delphi cannot invert is a type mismatch.
    """
    code = t.code
    if code.integer:
        return _in_range(code, ~value)
    if code is TC.Variant:
        try:
            return variants.invert(value, runtime)
        except DelphiException:
            raise type_mismatch()
    raise type_mismatch()


def logical_not(t: IFPSType, value: Any, runtime: Runtime) -> Any:
    """
    Pascal Script's `DoBooleanNot`: an integer becomes 1 when it is zero and 0 otherwise, a Variant
    becomes the Boolean of its comparison with zero.
    """
    code = t.code
    if code.integer:
        return int(value == 0)
    if code is TC.Variant:
        try:
            return Variant(VarType.Boolean, variants.compare(value, Variant(VarType.Integer, 0), runtime) == 0)
        except DelphiException:
            raise type_mismatch()
    raise type_mismatch()


def size_of(t: IFPSType, runtime: Runtime) -> int:
    """
    Pascal Script's `SizeOf`: the size of a variable of the given type on the Setup's platform.
    """
    code = t.code
    pointer = runtime.pointer_size
    if isinstance(t, TStaticArray):
        return t.size * size_of(t.type, runtime)
    if isinstance(t, TRecord):
        return sum(size_of(m, runtime) for m in t.members)
    if isinstance(t, TSet):
        return t.size_in_bytes
    if code in (TC.AnsiString, TC.WideString, TC.UnicodeString, TC.PChar, TC.Class, TC.Interface, TC.Array):
        return pointer
    if code is TC.Variant:
        return runtime.variant_size
    if code is TC.Extended:
        return runtime.extended_size
    if code in (TC.ProcPtr, TC.Pointer):
        return 3 * pointer
    return code.width


def step(t: IFPSType, value: Any, up: bool, machine: Machine) -> Any:
    """
    Pascal Script's increment or decrement of the counter of a for loop: an integer wraps around in
    its range; from Inno Setup 7 on, a Variant counts with Delphi's Variant addition or subtraction.
    """
    code = t.code
    if code.integer:
        return _in_range(code, value + 1 if up else value - 1)
    if code is TC.Variant and machine.dialect is Dialect.Inno7:
        op = variants.Operator.Add if up else variants.Operator.Subtract
        return _delphi(variants.operate, op, value, Variant(VarType.Integer, 1), machine.runtime)
    raise type_mismatch()


def truth(t: IFPSType, value: Any) -> bool:
    """
    The condition of a jump: Pascal Script accepts integers up to 32 bits.
    """
    if t.code.integer and t.code.width <= 4:
        return value != 0
    raise IFPSException(kind=PSError.InvalidType)
