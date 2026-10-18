"""
Pascal Script's rules for the values of its types: the errors that its machine raises, how it
computes with two values, and how it compares them.
"""
from __future__ import annotations

import enum
import operator

from refinery.lib.inno.ifps import TC, AOp, COp, IFPSType, TSet


class PSError(enum.IntEnum):
    """
    The kinds of runtime error that Pascal Script distinguishes, numbered as Pascal Script numbers
    them. Pascal Script keeps the kind with every error of the script.
    """
    OutOfRange = 10
    TypeMismatch = 12
    DivideByZero = 15
    MathError = 16
    OutOfRecordRange = 18
    Exception = 20

    @property
    def text(self) -> str:
        """
        The message that Pascal Script gives an error of this kind when it carries no exception of
        Delphi.
        """
        return _PS_ERROR_TEXT[self]


_PS_ERROR_TEXT = {
    PSError.OutOfRange       : 'Out Of Range',
    PSError.TypeMismatch     : 'Type Mismatch',
    PSError.DivideByZero     : 'divide by Zero',
    PSError.MathError        : 'Math error',
    PSError.OutOfRecordRange : 'Out of Record Fields Range',
    PSError.Exception        : 'Exception: ',
}


class IFPSException(RuntimeError):
    """
    An error of the script, which its exception handlers can handle. Pascal Script keeps the `kind`
    of every error, and the exception of Delphi that raised it, if any. The script reads the
    `message` of that exception with `GetExceptionMessage`, or the text of the kind when there is
    no exception. An error that escapes from a call of an emulated function names the `called`
    function in its report.
    """
    def __init__(
        self,
        message: str | None = None,
        kind: PSError = PSError.Exception,
        called: str | None = None,
    ):
        message = kind.text if message is None else str(message)
        report = message if called is None else F'Error calling {called}: {message}'
        super().__init__(report)
        self.kind = kind
        self.message = message
        self.called = called


def type_mismatch() -> IFPSException:
    return IFPSException(kind=PSError.TypeMismatch)


def signed32(value: int) -> int:
    return ((value + 0x80000000) & 0xFFFFFFFF) - 0x80000000


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


def truncated_division(a: int, b: int) -> tuple[int, int]:
    """
    Divides as Delphi's `div` and `mod` do: The quotient is truncated toward zero, and the remainder
    has the sign of the dividend.
    """
    if b == 0:
        raise ZeroDivisionError('division by zero')
    quotient = abs(a) // abs(b)
    if (a < 0) != (b < 0):
        quotient = -quotient
    return quotient, a - quotient * b


def _python_division(a, b):
    return a // b if isinstance(a, int) and isinstance(b, int) else a / b


_PYTHON_ARITHMETIC = {
    AOp.Add: operator.add,
    AOp.Sub: operator.sub,
    AOp.Mul: operator.mul,
    AOp.Div: _python_division,
    AOp.Mod: operator.mod,
    AOp.Shl: operator.lshift,
    AOp.Shr: operator.rshift,
    AOp.And: operator.and_,
    AOp.BOr: operator.or_,
    AOp.Xor: operator.xor,
}

_SET_ARITHMETIC = {
    AOp.Add: operator.or_,
    AOp.Sub: lambda a, b: a & ~b,
    AOp.Mul: operator.and_,
}

_BIT_EXACT_ARITHMETIC = frozenset((
    AOp.Add,
    AOp.Sub,
    AOp.Mul,
    AOp.And,
    AOp.BOr,
    AOp.Xor,
))


def _integer_arithmetic(aop: AOp, target: TC, a: int, source: TC, b) -> int:
    """
    Pascal Script's arithmetic for a destination of an integer type. Addition, subtraction,
    multiplication, and the bitwise operators give the bits that the destination keeps however the
    operands are read. For division and shifts, the destination's type decides how the source is
    read and how wide the computation is: 64 bits for an Int64 destination and for a 32-bit
    destination with an Int64 source, 32 bits otherwise, unsigned for an unsigned destination.
    """
    b = ordinal(source, b)
    if aop in _BIT_EXACT_ARITHMETIC:
        return _PYTHON_ARITHMETIC[aop](a, b)
    wide = target.width > 4
    if aop is AOp.Shl:
        return a << (b & (63 if wide else 31))
    if aop is AOp.Shr:
        if wide:
            return (a & 0xFFFFFFFFFFFFFFFF) >> (b & 63)
        return (a & 0xFFFFFFFF) >> (b & 31)
    if not wide and (target.width < 4 or source.width <= 4):
        if target.signed:
            b = signed32(b)
            if a == -0x80000000 and b == -1:
                raise OverflowError('Integer overflow')
        else:
            b &= 0xFFFFFFFF
    quotient, remainder = truncated_division(a, b)
    return quotient if aop is AOp.Div else remainder


def calculate(aop: AOp, target: TC, a, source: TC, b):
    """
    Pascal Script's arithmetic for a destination with type code `target` that holds `a` and a
    source with type code `source` that holds `b`. Python's operators compute it for destinations
    of other types than integers and sets, and for Variant sources.
    """
    if source is not TC.Variant:
        if target.integer:
            return _integer_arithmetic(aop, target, a, source, b)
        if target is TC.Set:
            if (calculate := _SET_ARITHMETIC.get(aop)) is None:
                raise type_mismatch()
            return calculate(a, b)
    return _PYTHON_ARITHMETIC[aop](a, b)


_PYTHON_COMPARISON = {
    COp.GE: operator.ge,
    COp.LE: operator.le,
    COp.GT: operator.gt,
    COp.LT: operator.lt,
    COp.NE: operator.ne,
    COp.EQ: operator.eq,
    COp.IN: lambda a, b: a in b,
    COp.IS: operator.is_,
}


def _integer_comparands(left: TC, a: int, right: TC, b) -> tuple:
    """
    Reads the operands of a comparison whose left operand has an integer type as Pascal Script
    reads them. The left operand's type decides how the right operand is read.
    """
    if left is TC.S32:
        if right is TC.U32:
            return a, signed32(b)
        if right.integer or right in (TC.Single, TC.Double, TC.Extended):
            return a, b
        if right.character:
            return a, ord(b)
        raise type_mismatch()
    if left is TC.U08 and right in (TC.AnsiString, TC.PChar):
        return chr(a), b
    b = ordinal(right, b)
    if left.width > 4:
        return a, b
    if left.signed:
        return a, signed32(b)
    return a, b & 0xFFFFFFFF


def _set_contains(members: int, set_type: TSet, code: TC, element) -> bool:
    ordinal_value = ordinal(code, element) & 0xFFFFFFFF
    if ordinal_value >= set_type.size:
        raise IFPSException(kind=PSError.OutOfRecordRange)
    return bool((members >> ordinal_value) & 1)


def compare(cop: COp, left: IFPSType, a, right: IFPSType, b) -> bool:
    """
    Pascal Script's comparison of `a`, which has the type `left`, with `b`, which has the type
    `right`. Python's operators compare operands of other types than integers and sets, and
    Variants.
    """
    lc = left.code
    rc = right.code
    if cop is COp.IN:
        if isinstance(right, TSet) and lc is not TC.Variant:
            return _set_contains(b, right, lc, a)
    elif cop is not COp.IS and lc is not TC.Variant and rc is not TC.Variant:
        if lc.integer:
            a, b = _integer_comparands(lc, a, rc, b)
        elif lc is TC.Set:
            if cop is COp.GE:
                return b & ~a == 0
            if cop is COp.LE:
                return a & ~b == 0
            if cop is not COp.EQ and cop is not COp.NE:
                raise type_mismatch()
    return _PYTHON_COMPARISON[cop](a, b)
