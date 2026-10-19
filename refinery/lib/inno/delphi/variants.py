"""
Delphi's Variants: a value with its Variant type, the conversions of a Variant to the types of
Delphi, and the operators and comparisons of Variants. The rules follow what Delphi 12 computes;
the oracle log of the IFPS ground-truth tests holds them for every pair of the common types.
"""
from __future__ import annotations

import enum

from dataclasses import dataclass
from fractions import Fraction
from typing import Any

from refinery.lib.inno.delphi import x87
from refinery.lib.inno.delphi.errors import (
    EDivByZero,
    EIntOverflow,
    EVariantInvalidOpError,
    EVariantOverflowError,
    EVariantTypeCastError,
)
from refinery.lib.inno.delphi.numbers import (
    FormatSettings,
    OleNumber,
    float_to_str,
    ole_number,
    val_integer,
    val_unsigned,
)
from refinery.lib.inno.delphi.runtime import Runtime, units
from refinery.lib.inno.delphi.x87 import FPU, Format, Real


class VarType(enum.IntEnum):
    """
    The type codes of Delphi's Variants, as the function `VarType` returns them.
    """
    Empty    = 0x0000  # noqa
    Null     = 0x0001  # noqa
    SmallInt = 0x0002  # noqa
    Integer  = 0x0003  # noqa
    Single   = 0x0004  # noqa
    Double   = 0x0005  # noqa
    Currency = 0x0006  # noqa
    Date     = 0x0007  # noqa
    OleStr   = 0x0008  # noqa
    Dispatch = 0x0009  # noqa
    Error    = 0x000A  # noqa
    Boolean  = 0x000B  # noqa
    Variant  = 0x000C  # noqa
    Unknown  = 0x000D  # noqa
    ShortInt = 0x0010  # noqa
    Byte     = 0x0011  # noqa
    Word     = 0x0012  # noqa
    LongWord = 0x0013  # noqa
    Int64    = 0x0014  # noqa
    UInt64   = 0x0015  # noqa
    String   = 0x0100  # noqa
    UString  = 0x0102  # noqa
    Array    = 0x2000  # noqa

    @property
    def text(self) -> str:
        """
        The name that Delphi's messages give the type.
        """
        return _TYPE_TEXT.get(self, self.name)


_TYPE_TEXT = {
    VarType.SmallInt : 'Smallint',
    VarType.UString  : 'UnicodeString',
}


@dataclass(frozen=True)
class Variant:
    """
    A Delphi Variant: its type and its value. An integer type holds an `int`, Single and Double a
    `float`, Currency a `Fraction` with at most four decimals, a string type a `str`, Boolean a
    `bool`, Dispatch the object, an array the list of its Variants, and Empty and Null nothing.
    """
    type: int
    value: Any = None

    def __repr__(self):
        try:
            name = VarType(self.type).name
        except ValueError:
            name = F'0x{self.type:04X}'
        return F'Variant({name}, {self.value!r})'


EMPTY = Variant(VarType.Empty)
NULL = Variant(VarType.Null)

_INT32 = range(-0x80000000, 0x80000000)
_CURRENCY_UNITS = 0x8000000000000000


class _Kind(enum.Enum):
    Empty = enum.auto()
    Null = enum.auto()
    Integer = enum.auto()
    Int64 = enum.auto()
    UInt64 = enum.auto()
    Float = enum.auto()
    Currency = enum.auto()
    String = enum.auto()
    Boolean = enum.auto()
    Other = enum.auto()


_KINDS = {
    VarType.Empty    : _Kind.Empty,
    VarType.Null     : _Kind.Null,
    VarType.SmallInt : _Kind.Integer,
    VarType.Integer  : _Kind.Integer,
    VarType.ShortInt : _Kind.Integer,
    VarType.Byte     : _Kind.Integer,
    VarType.Word     : _Kind.Integer,
    VarType.LongWord : _Kind.Int64,
    VarType.Int64    : _Kind.Int64,
    VarType.UInt64   : _Kind.UInt64,
    VarType.Single   : _Kind.Float,
    VarType.Double   : _Kind.Float,
    VarType.Currency : _Kind.Currency,
    VarType.OleStr   : _Kind.String,
    VarType.String   : _Kind.String,
    VarType.UString  : _Kind.String,
    VarType.Boolean  : _Kind.Boolean,
}

_INTEGERS = frozenset((_Kind.Integer, _Kind.Int64, _Kind.UInt64))

_INTEGER_WIDTHS = {
    VarType.ShortInt : (8, True),
    VarType.Byte     : (8, False),
    VarType.SmallInt : (16, True),
    VarType.Word     : (16, False),
    VarType.Integer  : (32, True),
    VarType.LongWord : (32, False),
    VarType.Int64    : (64, True),
    VarType.UInt64   : (64, False),
}


def _kind(v: Variant) -> _Kind:
    return _KINDS.get(v.type, _Kind.Other)  # type: ignore


def _in_currency_range(value: Fraction) -> bool:
    return -_CURRENCY_UNITS <= value * 10000 < _CURRENCY_UNITS


def type_text(v: Variant) -> str:
    """
    The name of the Variant's type in Delphi's messages.
    """
    if v.type & VarType.Array:
        return 'Array Variant'
    try:
        return VarType(v.type).text
    except ValueError:
        return F'${v.type:04X}'


def _wrap(value: int, bits: int, signed: bool = True) -> int:
    value &= (1 << bits) - 1
    if signed and value >> (bits - 1):
        value -= 1 << bits
    return value


def from_python(value: Any) -> Variant:
    """
    The Variant that holds a value that Python code produced: `None` is Empty, and the type follows
    the Python type of the value.
    """
    if isinstance(value, Variant):
        return value
    if value is None:
        return EMPTY
    if isinstance(value, bool):
        return Variant(VarType.Boolean, value)
    if isinstance(value, int):
        if value in _INT32:
            return Variant(VarType.Integer, value)
        return Variant(VarType.Int64, _wrap(value, 64))
    if isinstance(value, float):
        return Variant(VarType.Double, value)
    if isinstance(value, x87.Extended):
        return Variant(VarType.Double, _NEAREST.store(value, Format.Double))
    if isinstance(value, Fraction):
        return Variant(VarType.Currency, value)
    if isinstance(value, str):
        return Variant(VarType.UString, value)
    if isinstance(value, (list, tuple)):
        return Variant(VarType.Array | VarType.Variant, [from_python(item) for item in value])
    return Variant(VarType.Dispatch, value)


_NEAREST = FPU(x87.MASKED_CONTROL_WORD)


def _string_to_integer(v: Variant, runtime: Runtime, bits: int, target: str) -> int:
    text: str = v.value
    value, error = val_integer(text, bits)
    if not error:
        return value
    if (number := ole_number(text, runtime.settings)) is not None:
        double = _ole_double(number, v, target, runtime)
        if x87.is_special(double):
            raise EVariantOverflowError(type_text(v), target)
        integer = runtime.fpu.integer(double)
        if integer not in range(-(1 << (bits - 1)), 1 << (bits - 1)):
            raise EVariantOverflowError(type_text(v), target)
        return integer
    if (truth := _text_truth(text)) is not None:
        return int(truth)
    raise EVariantTypeCastError(type_text(v), target)


def _ole_double(number: OleNumber, v: Variant, target: str, runtime: Runtime) -> Real:
    """
    The Double that Windows makes of a number it read from a string; a number beyond the range of a
    Double overflows the conversion to the target type. On 64-bit Windows, a number written without
    an exponent becomes an infinity instead.
    """
    exact = number.value
    value = _NEAREST.rational(exact.numerator, exact.denominator, Format.Double)
    if x87.is_special(value):
        if runtime.parses_long_digits_as_infinity and not number.exponent:
            return value
        raise EVariantOverflowError(type_text(v), target)
    assert isinstance(value, float)
    return value


def _text_truth(text: str) -> bool | None:
    lowered = text.lower()
    if lowered == 'true':
        return True
    if lowered == 'false':
        return False
    return None


def _integer(v: Variant, runtime: Runtime, bits: int, target: str) -> int:
    kind = _kind(v)
    valid = range(-(1 << (bits - 1)), 1 << (bits - 1))
    if kind is _Kind.Empty:
        return 0
    if kind is _Kind.UInt64 and bits == 64:
        value = _wrap(v.value, 64)
    elif kind in _INTEGERS:
        value = v.value
    elif kind is _Kind.Boolean:
        return -1 if v.value else 0
    elif kind is _Kind.Float:
        value = runtime.fpu.integer(v.value)
    elif kind is _Kind.Currency:
        value = runtime.fpu.integer(runtime.currency_to_real(v.value))
    elif kind is _Kind.String:
        return _string_to_integer(v, runtime, bits, target)
    else:
        raise EVariantTypeCastError(type_text(v), target)
    if value not in valid:
        raise EVariantOverflowError(type_text(v), target)
    return value


def to_integer(v: Variant, runtime: Runtime) -> int:
    """
    Delphi's conversion of a Variant to an Integer: floats are rounded by the x87, strings parsed.
    """
    return _integer(v, runtime, 32, 'Integer')


def to_int64(v: Variant, runtime: Runtime) -> int:
    """
    Delphi's conversion of a Variant to an Int64.
    """
    return _integer(v, runtime, 64, 'Int64')


def to_uint64(v: Variant, runtime: Runtime) -> int:
    """
    Delphi's conversion of a Variant to a UInt64: a negative integer or a float out of range
    overflows, a string is read as an unsigned number, and Null cannot be converted.
    """
    kind = _kind(v)
    if kind is _Kind.UInt64:
        return v.value
    if kind is _Kind.Null:
        raise EVariantTypeCastError(type_text(v), 'Cardinal')
    if kind is _Kind.String:
        value, error = val_unsigned(v.value)
        if not error:
            return value
    if kind is _Kind.Float:
        value = runtime.fpu.integer(v.value)
        if x87.is_special(v.value) or not 0 <= x87.exact(v.value) < (1 << 64):
            raise EVariantOverflowError(type_text(v), 'UInt64')
        return value & 0xFFFFFFFFFFFFFFFF
    value = to_int64(v, runtime)
    if value < 0 and kind in (_Kind.Integer, _Kind.Int64):
        raise EVariantOverflowError(type_text(v), 'UInt64')
    return value & 0xFFFFFFFFFFFFFFFF


def to_cardinal(v: Variant, runtime: Runtime) -> int:
    """
    Delphi's conversion of a Variant to a Cardinal, which converts it to an Int64 and keeps the low
    32 bits.
    """
    return to_int64(v, runtime) & 0xFFFFFFFF


def to_real(v: Variant, runtime: Runtime) -> Real:
    """
    Delphi's conversion of a Variant to a float. An integer is loaded as the unit loads it, and a
    string is read as Windows reads a number in the regional format, as a Double.
    """
    kind = _kind(v)
    if kind is _Kind.Empty:
        return 0.0
    if kind in _INTEGERS:
        return runtime.fpu.load(v.value)
    if kind is _Kind.Boolean:
        return -1.0 if v.value else 0.0
    if kind is _Kind.Float:
        return v.value
    if kind is _Kind.Currency:
        return runtime.currency_to_real(v.value)
    if kind is _Kind.String and (number := ole_number(v.value, runtime.settings)) is not None:
        return _ole_double(number, v, 'Double', runtime)
    raise EVariantTypeCastError(type_text(v), 'Double')


def to_currency(v: Variant, runtime: Runtime) -> Fraction:
    """
    Delphi's conversion of a Variant to a Currency.
    """
    kind = _kind(v)
    if kind is _Kind.Empty:
        return Fraction(0)
    if kind in _INTEGERS:
        value = Fraction(v.value)
    elif kind is _Kind.Boolean:
        value = Fraction(-1 if v.value else 0)
    elif kind is _Kind.Currency:
        return v.value
    elif kind is _Kind.Float:
        if x87.is_special(v.value) or not _in_currency_range(x87.exact(v.value)):
            raise EVariantOverflowError(type_text(v), 'Currency')
        return runtime.variant_currency(v.value)
    elif kind is _Kind.String and (number := ole_number(v.value, runtime.settings)) is not None:
        value = Fraction(round(number.value * 10000), 10000)
    else:
        raise EVariantTypeCastError(type_text(v), 'Currency')
    if not _in_currency_range(value):
        raise EVariantOverflowError(type_text(v), 'Currency')
    return value


def currency_text(value: Fraction, settings: FormatSettings) -> str:
    """
    Delphi's `CurrToStr`: all digits of a Currency without trailing zeros, with the regional
    decimal separator.
    """
    count = units(value)
    whole, fraction = divmod(abs(count), 10000)
    text = str(whole)
    if decimals := F'{fraction:04d}'.rstrip('0'):
        text = F'{text}{settings.decimal_separator}{decimals}'
    return F'-{text}' if count < 0 else text


def to_string(v: Variant, runtime: Runtime, target: str = 'OleStr') -> str:
    """
    Delphi's conversion of a Variant to a string; the target names the string type in the message
    for a Variant that cannot be converted.
    """
    kind = _kind(v)
    if kind is _Kind.Empty:
        return ''
    if kind in _INTEGERS:
        return str(v.value)
    if kind is _Kind.Float:
        return float_to_str(v.value, runtime)
    if kind is _Kind.Currency:
        return currency_text(v.value, runtime.settings)
    if kind is _Kind.String:
        return v.value
    if kind is _Kind.Boolean:
        return 'True' if v.value else 'False'
    raise EVariantTypeCastError(type_text(v), target)


def to_text(v: Variant, runtime: Runtime) -> str:
    """
    The text of a Variant in `Format`: Null is empty.
    """
    if _kind(v) is _Kind.Null:
        return ''
    return to_string(v, runtime)


def to_dispatch(v: Variant, runtime: Runtime) -> Any:
    """
    Delphi's conversion of a Variant to an IDispatch: the object that it holds, and nil for Empty.
    """
    if v.type == VarType.Dispatch:
        return v.value
    if v.type == VarType.Empty:
        return None
    raise EVariantTypeCastError(type_text(v), 'Dispatch')


def to_boolean(v: Variant, runtime: Runtime) -> bool:
    """
    Delphi's conversion of a Variant to a Boolean.
    """
    kind = _kind(v)
    if kind is _Kind.Empty:
        return False
    if kind is _Kind.Boolean:
        return bool(v.value)
    if kind in _INTEGERS or kind is _Kind.Float or kind is _Kind.Currency:
        return v.value != 0
    if kind is _Kind.String:
        if (truth := _text_truth(v.value)) is not None:
            return truth
        if ole_number(v.value, runtime.settings) is not None:
            return _string_to_integer(v, runtime, 64, 'Int64') & 0xFFFFFFFF != 0
    raise EVariantTypeCastError(type_text(v), 'Boolean')


class Operator(enum.Enum):
    """
    The binary operators of Variants. Pascal Script divides with `Divide` when the left operand
    holds a Single, Double or Currency, and with `IntDivide` otherwise.
    """
    Add = '+'
    Subtract = '-'
    Multiply = '*'
    Divide = '/'
    IntDivide = 'div'
    Modulus = 'mod'
    ShiftLeft = 'shl'
    ShiftRight = 'shr'
    And = 'and'
    Or = 'or'
    Xor = 'xor'


def is_float(v: Variant) -> bool:
    """
    Whether the Variant holds a Single, a Double, or a Currency.
    """
    return v.type in (VarType.Single, VarType.Double, VarType.Currency)


_LOGICAL = frozenset((_Kind.Boolean, _Kind.String, _Kind.Empty))
_INT64_OPERANDS = frozenset((_Kind.Empty, _Kind.Integer, _Kind.Int64, _Kind.UInt64, _Kind.Boolean))


def _is_logical(ka: _Kind, kb: _Kind) -> bool:
    return (ka is _Kind.Boolean and kb in _LOGICAL) or (kb is _Kind.Boolean and ka in _LOGICAL)


def operate(op: Operator, a: Variant, b: Variant, runtime: Runtime) -> Variant:
    """
    Delphi's binary operator on two Variants.
    """
    ka = _kind(a)
    kb = _kind(b)
    if ka is _Kind.Other or kb is _Kind.Other:
        raise EVariantInvalidOpError
    if op is Operator.And or op is Operator.Or:
        return _logic(op, a, b, ka, kb, runtime)
    if ka is _Kind.Null or kb is _Kind.Null:
        return NULL
    if ka is _Kind.Empty and kb is _Kind.Empty:
        if op is Operator.IntDivide or op is Operator.Modulus:
            raise EDivByZero
        return EMPTY
    if op is Operator.Xor and _is_logical(ka, kb):
        return Variant(VarType.Boolean, to_boolean(a, runtime) != to_boolean(b, runtime))
    if op is Operator.Add and (ka is _Kind.String or kb is _Kind.String):
        if ka is _Kind.String and kb is _Kind.String:
            return Variant(a.type, a.value + b.value)
        if ka is _Kind.Empty:
            return Variant(VarType.OleStr, b.value)
        if kb is _Kind.Empty:
            return a
    if _is_unsigned(ka, kb):
        return _unsigned(op, a, b, runtime)
    if op in (Operator.Add, Operator.Subtract, Operator.Multiply):
        return _arithmetic(op, a, b, ka, kb, runtime)
    if op is Operator.Divide:
        return _divide(a, b, runtime)
    return _integral(op, a, b, ka, kb, runtime)


def _logic(op: Operator, a: Variant, b: Variant, ka: _Kind, kb: _Kind, runtime: Runtime) -> Variant:
    conjunction = op is Operator.And
    if ka is _Kind.Null or kb is _Kind.Null:
        if ka is kb:
            return NULL
        other = b if ka is _Kind.Null else a
        if to_boolean(other, runtime) is conjunction:
            return NULL
        return other
    if ka is _Kind.Empty and kb is _Kind.Empty:
        return EMPTY
    if _is_logical(ka, kb):
        left = to_boolean(a, runtime)
        if left is not conjunction:
            return Variant(VarType.Boolean, left)
        return Variant(VarType.Boolean, to_boolean(b, runtime))
    if _is_unsigned(ka, kb):
        return _unsigned(op, a, b, runtime)
    return _integral(op, a, b, ka, kb, runtime)


def _arithmetic(op: Operator, a: Variant, b: Variant, ka: _Kind, kb: _Kind, runtime: Runtime) -> Variant:
    kinds = {ka, kb}
    fpu = runtime.fpu
    if _Kind.Currency in kinds:
        if op is Operator.Multiply:
            x = to_real(a, runtime)
            y = to_real(b, runtime)
            return Variant(VarType.Currency, runtime.currency(fpu.multiply(x, y)))
        x = to_currency(a, runtime)
        y = to_currency(b, runtime)
        result = x + y if op is Operator.Add else x - y
        if not _in_currency_range(result):
            raise EVariantOverflowError('Currency', 'Currency')
        return Variant(VarType.Currency, result)
    if (
        _Kind.Float in kinds
        or _Kind.String in kinds
        or kinds <= {_Kind.Boolean, _Kind.Empty}
    ):
        x = to_real(a, runtime)
        y = to_real(b, runtime)
        if op is Operator.Add:
            result = fpu.add(x, y)
        elif op is Operator.Subtract:
            result = fpu.subtract(x, y)
        else:
            result = fpu.multiply(x, y)
        return Variant(VarType.Double, fpu.store(result, Format.Double))
    if _Kind.Int64 in kinds:
        x = to_int64(a, runtime)
        y = to_int64(b, runtime)
        return Variant(VarType.Int64, _wrap(_ARITHMETIC[op](x, y), 64))
    x = to_integer(a, runtime)
    y = to_integer(b, runtime)
    result = _ARITHMETIC[op](x, y)
    if result in _INT32:
        return Variant(VarType.Integer, result)
    return Variant(VarType.Double, float(result))


_ARITHMETIC = {
    Operator.Add      : lambda x, y: x + y,
    Operator.Subtract : lambda x, y: x - y,
    Operator.Multiply : lambda x, y: x * y,
}


def _divide(a: Variant, b: Variant, runtime: Runtime) -> Variant:
    """
    Delphi's division of Variants. A float divided by a Currency becomes a Currency first, which
    can overflow; a float that divides a Currency counts with its value. The quotient is a Currency
    when the dividend is one and a Double otherwise.
    """
    fpu = runtime.fpu
    x = to_real(a, runtime)
    if b.type == VarType.Currency:
        if _kind(a) is _Kind.Float:
            x = runtime.currency_to_real(to_currency(a, runtime))
        if _kind(a) in (_Kind.Float, _Kind.Currency):
            runtime.check_currency_divisor(b.value)
    quotient = fpu.divide(x, to_real(b, runtime))
    if a.type == VarType.Currency:
        return Variant(VarType.Currency, runtime.currency(quotient))
    return Variant(VarType.Double, fpu.store(quotient, Format.Double))


def _is_unsigned(ka: _Kind, kb: _Kind) -> bool:
    return _Kind.UInt64 in (ka, kb) and ka in _INT64_OPERANDS and kb in _INT64_OPERANDS


def _unsigned(op: Operator, a: Variant, b: Variant, runtime: Runtime) -> Variant:
    """
    Delphi's operators on a UInt64 and another integer: both operands become UInt64 values, which
    overflows for a negative one, and the operator computes on 64 bits without a sign. Both
    divisions give the integer quotient.
    """
    x = to_uint64(a, runtime)
    y = to_uint64(b, runtime)
    if op is Operator.Add:
        result = x + y
    elif op is Operator.Subtract:
        result = x - y
    elif op is Operator.Multiply:
        result = x * y
    elif op in (Operator.Divide, Operator.IntDivide, Operator.Modulus):
        if y == 0:
            raise EDivByZero
        result = x // y if op is not Operator.Modulus else x % y
    elif op is Operator.ShiftLeft:
        result = x << (y & 63)
    elif op is Operator.ShiftRight:
        result = x >> (y & 63)
    elif op is Operator.And:
        result = x & y
    elif op is Operator.Or:
        result = x | y
    else:
        result = x ^ y
    return Variant(VarType.UInt64, result & 0xFFFFFFFFFFFFFFFF)


def _integral(op: Operator, a: Variant, b: Variant, ka: _Kind, kb: _Kind, runtime: Runtime) -> Variant:
    if (ka is _Kind.Int64 or kb is _Kind.Int64) and ka in _INT64_OPERANDS and kb in _INT64_OPERANDS:
        bits = 64
        vtype = VarType.Int64
        x = to_int64(a, runtime)
        y = to_int64(b, runtime)
    else:
        bits = 32
        vtype = VarType.Integer
        x = to_integer(a, runtime)
        y = to_integer(b, runtime)
    if op is Operator.IntDivide or op is Operator.Modulus:
        if y == 0:
            raise EDivByZero
        if x == -(1 << (bits - 1)) and y == -1:
            raise EIntOverflow
        quotient = abs(x) // abs(y)
        if (x < 0) != (y < 0):
            quotient = -quotient
        result = quotient if op is Operator.IntDivide else x - quotient * y
    elif op is Operator.ShiftLeft:
        result = x << (y & (bits - 1))
    elif op is Operator.ShiftRight:
        result = (x & ((1 << bits) - 1)) >> (y & (bits - 1))
    elif op is Operator.And:
        result = x & y
    elif op is Operator.Or:
        result = x | y
    else:
        result = x ^ y
    return Variant(vtype, _wrap(result, bits))


def compare(a: Variant, b: Variant, runtime: Runtime) -> int:
    """
    Delphi's comparison of two Variants: negative, zero, or positive. Null is below every other
    value and Empty below every value but Null; strings compare by their characters; a string and
    a Boolean compare as Booleans, two integers as integers, a string and a number as numbers.
    """
    ka = _kind(a)
    kb = _kind(b)
    if ka is _Kind.Other or kb is _Kind.Other:
        raise EVariantInvalidOpError
    for low in (_Kind.Null, _Kind.Empty):
        if ka is low or kb is low:
            if ka is kb:
                return 0
            return -1 if ka is low else 1
    if ka is _Kind.String and kb is _Kind.String:
        return (a.value > b.value) - (a.value < b.value)
    if (ka is _Kind.Boolean or kb is _Kind.Boolean) and (ka in _LOGICAL and kb in _LOGICAL):
        x = -1 if to_boolean(a, runtime) else 0
        y = -1 if to_boolean(b, runtime) else 0
        return (x > y) - (x < y)
    if ka is _Kind.Currency or kb is _Kind.Currency:
        if ka is _Kind.String or kb is _Kind.String:
            x = to_currency(a, runtime)
            y = to_currency(b, runtime)
            return (x > y) - (x < y)
    if ka in _INTEGERS and kb in _INTEGERS:
        return (a.value > b.value) - (a.value < b.value)
    order = runtime.fpu.compare(to_real(a, runtime), to_real(b, runtime))
    return 0 if order is None else order


def negate(v: Variant, runtime: Runtime) -> Variant:
    """
    Delphi's negation of a Variant.
    """
    kind = _kind(v)
    if kind is _Kind.Empty:
        return Variant(VarType.SmallInt, 0)
    if kind is _Kind.Null:
        return NULL
    if kind is _Kind.Integer:
        return Variant(VarType.Integer, _wrap(-v.value, 32))
    if kind is _Kind.Int64 or kind is _Kind.UInt64:
        return Variant(VarType.Int64, _wrap(-v.value, 64))
    if kind is _Kind.Float or kind is _Kind.Currency:
        return Variant(v.type, -v.value)
    if kind is _Kind.Boolean:
        return Variant(VarType.SmallInt, -1 if v.value else 0)
    if kind is _Kind.String:
        return Variant(VarType.Double, runtime.fpu.negate(to_real(v, runtime)))
    raise EVariantInvalidOpError


def invert(v: Variant, runtime: Runtime) -> Variant:
    """
    Delphi's `not` of a Variant: logical for a Boolean, bitwise otherwise.
    """
    kind = _kind(v)
    if kind is _Kind.Empty:
        return Variant(VarType.ShortInt, -1)
    if kind is _Kind.Null:
        return NULL
    if kind is _Kind.Boolean:
        return Variant(VarType.Boolean, not v.value)
    if kind in _INTEGERS:
        bits, signed = _INTEGER_WIDTHS[v.type]  # type: ignore
        return Variant(v.type, _wrap(~v.value, bits, signed))
    return Variant(VarType.Integer, ~to_integer(v, runtime))
