"""
The x87 floating-point unit that Delphi's 32-bit code computes with. It computes with 64-bit
mantissas unless its control word lowers the precision, rounds each result as its control word
says, and raises an exception for an error that the control word does not mask. Storing a result
into a `Single` or a `Double` rounds it again.

A value is a `Real`: a `float` when a `float` holds it exactly, which includes zeros, infinities,
and NaN, and an `Extended` otherwise. Only `real` makes an `Extended`, so every value has exactly
one encoding.
"""
from __future__ import annotations

import decimal
import enum
import math

from fractions import Fraction
from typing import Callable, Union

from refinery.lib.inno.delphi.errors import (
    EInvalidOp,
    EMathError,
    EOverflow,
    EUnderflow,
    EZeroDivide,
    Undefined,
)


class Extended:
    """
    A finite value that a `float` cannot hold: `mantissa * 2 ** exponent` with an odd mantissa.
    """
    __slots__ = 'mantissa', 'exponent'

    mantissa: int
    exponent: int

    def __init__(self, mantissa: int, exponent: int):
        self.mantissa = mantissa
        self.exponent = exponent

    def __eq__(self, other):
        if not isinstance(other, Extended):
            return NotImplemented
        return self.mantissa == other.mantissa and self.exponent == other.exponent

    def __hash__(self):
        return hash((self.mantissa, self.exponent))

    def __repr__(self):
        return F'Extended({self.mantissa}, {self.exponent})'


Real = Union[float, Extended]


def real(mantissa: int, exponent: int = 0) -> Real:
    """
    The value `mantissa * 2 ** exponent`, exactly.
    """
    if not mantissa:
        return 0.0
    if not mantissa & 1:
        zeros = (mantissa & -mantissa).bit_length() - 1
        mantissa >>= zeros
        exponent += zeros
    size = mantissa.bit_length()
    if size <= 53 and -1074 <= exponent and exponent + size <= 1024:
        return math.ldexp(mantissa, exponent)
    return Extended(mantissa, exponent)


def parts(value: Real) -> tuple[int, int]:
    """
    The integer mantissa and the exponent of a finite value other than zero.
    """
    if isinstance(value, Extended):
        return value.mantissa, value.exponent
    if not isinstance(value, float):
        raise TypeError(F'not a value of the x87: {value!r}')
    numerator, denominator = value.as_integer_ratio()
    return numerator, 1 - denominator.bit_length()


def exact(value: Real) -> Fraction:
    """
    The exact value of a finite value.
    """
    if not isinstance(value, Extended):
        return Fraction(value)
    m, e = value.mantissa, value.exponent
    return Fraction(m << e) if e >= 0 else Fraction(m, 1 << -e)


def is_special(value: Real) -> bool:
    """
    Whether the value is an infinity or NaN.
    """
    return isinstance(value, float) and not math.isfinite(value)


def is_negative(value: Real) -> bool:
    """
    Whether the sign of the value is negative; true for negative zero.
    """
    if isinstance(value, Extended):
        return value.mantissa < 0
    return math.copysign(1.0, value) < 0


class Format(enum.Enum):
    """
    The floating-point formats of Delphi: the number of mantissa bits and the range of exponents of
    normal values.
    """
    Single = (24, -126, 127)
    Double = (53, -1022, 1023)
    Extended = (64, -16382, 16383)

    bits: int
    emin: int
    emax: int

    def __init__(self, bits: int, emin: int, emax: int):
        self.bits = bits
        self.emin = emin
        self.emax = emax


class Rounding(enum.IntEnum):
    """
    The rounding modes of the x87, as the rounding control field of its control word holds them.
    """
    Nearest = 0
    Down = 1
    Up = 2
    TowardZero = 3


class Fault(enum.IntFlag):
    """
    The exceptions of the x87; each has a mask bit of the same value in the control word.
    """
    Invalid = 0x01
    Denormal = 0x02
    ZeroDivide = 0x04
    Overflow = 0x08
    Underflow = 0x10
    Precision = 0x20


_TRAPS: dict[Fault, type[EMathError]] = {
    Fault.Invalid    : EInvalidOp,
    Fault.ZeroDivide : EZeroDivide,
    Fault.Overflow   : EOverflow,
    Fault.Underflow  : EUnderflow,
}

_PRECISION_CONTROL = {
    0: Format.Single,
    1: Format.Single,
    2: Format.Double,
    3: Format.Extended,
}

DEFAULT_CONTROL_WORD = 0x1332
"""
The control word that Delphi sets before Delphi 12: it masks denormal operands, underflow, and
inexact results, and computes with 64-bit mantissas, rounding to the nearest value.
"""

MASKED_CONTROL_WORD = 0x037F
"""
The control word with every exception masked, which Delphi 12 sets.
"""

WIN64_CONTROL_WORD = 0x027F
"""
The control word that Delphi's 64-bit code sets: every exception masked, 53-bit mantissas.
"""

RESERVED_BIT = 0x0040
"""
A bit of the control word that the x87 always reports as set.
"""

INTEGER_INDEFINITE = -0x8000000000000000
"""
The integer that the x87 stores for a value it cannot convert when invalid operations are masked.
"""


def _proxy(value: Real) -> float:
    """
    The value itself if it is a zero, an infinity, or NaN; otherwise one with its sign, which
    stands for it in arithmetic with infinities and zeros.
    """
    if isinstance(value, float) and (value == 0 or not math.isfinite(value)):
        return value
    return -1.0 if is_negative(value) else 1.0


class FPU:
    """
    The state of an x87: its control word.
    """
    rounding: Rounding
    precision: Format
    range: Format = Format.Extended

    def __init__(self, control: int = DEFAULT_CONTROL_WORD):
        self.control = control

    @property
    def control(self) -> int:
        return self._control

    @control.setter
    def control(self, control: int):
        control &= 0xFFFF
        self._control = control
        self.rounding = Rounding((control >> 10) & 3)
        self.precision = _PRECISION_CONTROL[(control >> 8) & 3]
        self._inexact_traps = ~control & (Fault.Underflow | Fault.Precision).value

    def masks(self, fault: Fault) -> bool:
        return bool(self.control & fault)

    def fault(self, fault: Fault):
        """
        Signals the given exception: it is raised unless the control word masks it.
        """
        if not self.masks(fault):
            raise _TRAPS.get(fault, EMathError)()

    def _round(
        self,
        mantissa: int,
        exponent: int,
        fmt: Format,
        range: Format,
        sticky: bool = False,
        rounding: Rounding | None = None,
    ) -> Real:
        """
        Rounds `mantissa * 2 ** exponent` to the mantissa width of the given format in the exponent
        range of the given range format. A set `sticky` flag says that the exact value is a little
        more in magnitude, less than one unit of the mantissa's last bit, which needs a mantissa of
        at least two more bits than the format.
        """
        if rounding is None:
            rounding = self.rounding
        bits = fmt.bits
        negative = mantissa < 0
        magnitude = -mantissa if negative else mantissa
        top = exponent + magnitude.bit_length() - 1
        tiny = top < range.emin
        quantum = max(top, range.emin) - bits + 1
        shift = quantum - exponent
        if shift > 0:
            q = magnitude >> shift
            r = magnitude & ((1 << shift) - 1)
            inexact = bool(r) or sticky
            if not inexact:
                up = False
            elif rounding is Rounding.Nearest:
                half = 1 << (shift - 1)
                up = r > half or r == half and (sticky or bool(q & 1))
            elif rounding is Rounding.Down:
                up = negative
            elif rounding is Rounding.Up:
                up = not negative
            else:
                up = False
            q += up
        else:
            q = magnitude
            quantum = exponent
            inexact = False
        if tiny and self._inexact_traps & Fault.Underflow:
            self.fault(Fault.Underflow)
        if inexact and self._inexact_traps:
            self.fault(Fault.Precision)
        if q >> bits:
            q >>= 1
            quantum += 1
        if q == 0:
            return -0.0 if negative else 0.0
        if q.bit_length() - 1 + quantum > range.emax:
            self.fault(Fault.Overflow)
            self.fault(Fault.Precision)
            if (
                rounding is Rounding.TowardZero
                or rounding is Rounding.Down and not negative
                or rounding is Rounding.Up and negative
            ):
                largest = (1 << bits) - 1
                return real(-largest if negative else largest, range.emax - bits + 1)
            return -math.inf if negative else math.inf
        return real(-q if negative else q, quantum)

    def round(self, value: Real, fmt: Format, rounding: Rounding | None = None) -> Real:
        """
        Rounds a value to the given format.
        """
        if isinstance(value, float):
            if value == 0 or not math.isfinite(value) or fmt is not Format.Single:
                return value
        elif fmt is Format.Extended:
            return value
        m, e = parts(value)
        return self._round(m, e, fmt, fmt, rounding=rounding)

    def rational(self, numerator: int, denominator: int, fmt: Format | None = None) -> Real:
        """
        Rounds the exact value of a fraction to the given format, or as the result of an instruction.
        """
        if numerator == 0:
            return 0.0
        precision = self.precision if fmt is None else fmt
        negative = (numerator < 0) != (denominator < 0)
        n, d = abs(numerator), abs(denominator)
        k = max(0, precision.bits + 2 + d.bit_length() - n.bit_length())
        q, r = divmod(n << k, d)
        return self._round(-q if negative else q, -k, precision, fmt or self.range, sticky=bool(r))

    def result(self, value: Real) -> Real:
        """
        Rounds an exact value as the x87 rounds the result of an instruction: to the precision of
        the control word, in the exponent range of an Extended.
        """
        precision = self.precision
        if isinstance(value, float):
            if value == 0 or not math.isfinite(value) or precision is not Format.Single:
                return value
        elif precision is Format.Extended:
            return value
        m, e = parts(value)
        return self._round(m, e, precision, self.range)

    def load(self, value: int) -> Real:
        """
        An integer loaded into the unit to compute with floats; the x87 holds every 64-bit integer
        exactly.
        """
        return real(value)

    def store(self, value: Real, fmt: Format) -> Real:
        """
        Rounds a value as storing it into a variable of the given format rounds it. A `Single` or a
        `Double` is a `float`.
        """
        if isinstance(value, float):
            if fmt is not Format.Single or value == 0 or not math.isfinite(value):
                return value
        elif fmt is Format.Extended:
            return value
        m, e = parts(value)
        return self._round(m, e, fmt, fmt)

    def _special(self, value: float, *operands: float) -> float:
        if math.isnan(value) and not any(math.isnan(x) for x in operands):
            self.fault(Fault.Invalid)
        return value

    def add(self, a: Real, b: Real) -> Real:
        if is_special(a) or is_special(b):
            pa, pb = _proxy(a), _proxy(b)
            return self._special(pa + pb, pa, pb)
        if a == 0:
            if b == 0:
                if is_negative(a) != is_negative(b):
                    return -0.0 if self.rounding is Rounding.Down else 0.0
                return a
            return self.result(b)
        if b == 0:
            return self.result(a)
        m1, e1 = parts(a)
        m2, e2 = parts(b)
        if e1 < e2:
            m1, e1, m2, e2 = m2, e2, m1, e1
        m = (m1 << (e1 - e2)) + m2
        if m == 0:
            return -0.0 if self.rounding is Rounding.Down else 0.0
        return self._round(m, e2, self.precision, self.range)

    def subtract(self, a: Real, b: Real) -> Real:
        return self.add(a, self.negate(b))

    def multiply(self, a: Real, b: Real) -> Real:
        if is_special(a) or is_special(b) or a == 0 or b == 0:
            pa, pb = _proxy(a), _proxy(b)
            return self._special(pa * pb, pa, pb)
        m1, e1 = parts(a)
        m2, e2 = parts(b)
        return self._round(m1 * m2, e1 + e2, self.precision, self.range)

    def divide(self, a: Real, b: Real) -> Real:
        if b == 0:
            if is_special(a):
                assert isinstance(a, float)
                return a if math.isnan(a) else -math.inf if is_negative(a) != is_negative(b) else math.inf
            if a == 0:
                self.fault(Fault.Invalid)
                return math.nan
            self.fault(Fault.ZeroDivide)
            return -math.inf if is_negative(a) != is_negative(b) else math.inf
        if is_special(a) or is_special(b) or a == 0:
            pa, pb = _proxy(a), _proxy(b)
            return self._special(pa / pb, pa, pb)
        m1, e1 = parts(a)
        m2, e2 = parts(b)
        negative = (m1 < 0) != (m2 < 0)
        m1, m2 = abs(m1), abs(m2)
        bits = self.precision.bits
        k = max(0, bits + 2 + m2.bit_length() - m1.bit_length())
        q, r = divmod(m1 << k, m2)
        return self._round(-q if negative else q, e1 - e2 - k, self.precision, self.range, sticky=bool(r))

    def negate(self, a: Real) -> Real:
        if isinstance(a, Extended):
            return Extended(-a.mantissa, a.exponent)
        return -a

    def absolute(self, a: Real) -> Real:
        if isinstance(a, Extended):
            return Extended(abs(a.mantissa), a.exponent)
        return abs(a)

    def compare(self, a: Real, b: Real) -> int | None:
        """
        Compares two values: -1, 0, or 1, and `None` for NaN, which signals an invalid operation.
        """
        if isinstance(a, float) and isinstance(b, float):
            if math.isnan(a) or math.isnan(b):
                self.fault(Fault.Invalid)
                return None
            return (a > b) - (a < b)
        if a == b:
            return 0
        if is_special(a) or is_special(b) or a == 0 or b == 0:
            pa, pb = _proxy(a), _proxy(b)
            if math.isnan(pa) or math.isnan(pb):
                self.fault(Fault.Invalid)
                return None
            return (pa > pb) - (pa < pb)
        m1, e1 = parts(a)
        m2, e2 = parts(b)
        if (m1 < 0) != (m2 < 0):
            return -1 if m1 < 0 else 1
        if e1 > e2:
            m1 <<= e1 - e2
        else:
            m2 <<= e2 - e1
        return (m1 > m2) - (m1 < m2)

    def integer(self, value: Real, rounding: Rounding | None = None) -> int:
        """
        Converts a value to a 64-bit integer as the x87 stores it: rounded as the control word says,
        or as the given rounding mode. A value out of range signals an invalid operation and gives
        the integer indefinite.
        """
        if is_special(value):
            self.fault(Fault.Invalid)
            return INTEGER_INDEFINITE
        if value == 0:
            return 0
        if rounding is None:
            rounding = self.rounding
        m, e = parts(value)
        if e >= 0:
            integer = m << e
            inexact = False
        else:
            shift = -e
            floor = m >> shift
            remainder = m & ((1 << shift) - 1)
            inexact = bool(remainder)
            if not inexact:
                integer = floor
            elif rounding is Rounding.Nearest:
                half = 1 << (shift - 1)
                integer = floor + (remainder > half or remainder == half and bool(floor & 1))
            elif rounding is Rounding.Down:
                integer = floor
            elif rounding is Rounding.Up:
                integer = floor + 1
            else:
                integer = floor + (m < 0)
        if not -0x8000000000000000 <= integer < 0x8000000000000000:
            self.fault(Fault.Invalid)
            return INTEGER_INDEFINITE
        if inexact:
            self.fault(Fault.Precision)
        return integer

    def square_root(self, a: Real) -> Real:
        """
        The square root, rounded as the result of an instruction; a negative operand is an invalid
        operation.
        """
        if isinstance(a, float) and (math.isnan(a) or a == 0 or a == math.inf):
            return a
        if is_negative(a):
            self.fault(Fault.Invalid)
            return math.nan
        m, e = parts(a)
        bits = self.precision.bits
        shift = max(0, 2 * (bits + 2) - m.bit_length() + 1)
        if (e - shift) & 1:
            shift += 1
        scaled = m << shift
        root = math.isqrt(scaled)
        return self._round(root, (e - shift) // 2, self.precision, self.range, sticky=root * root != scaled)

    def round_integral(self, a: Real, rounding: Rounding | None = None) -> Real:
        """
        Rounds a value to an integer as `FRNDINT` does, as the control word says or as the given
        rounding mode; the result keeps the sign of the value.
        """
        if is_special(a) or a == 0:
            return a
        m, e = parts(a)
        if e >= 0:
            return a
        if rounding is None:
            rounding = self.rounding
        negative = m < 0
        magnitude = -m if negative else m
        shift = -e
        whole = magnitude >> shift
        remainder = magnitude & ((1 << shift) - 1)
        if remainder:
            if rounding is Rounding.Nearest:
                half = 1 << (shift - 1)
                whole += remainder > half or remainder == half and bool(whole & 1)
            elif rounding is Rounding.Down:
                whole += negative
            elif rounding is Rounding.Up:
                whole += not negative
            if self._inexact_traps:
                self.fault(Fault.Precision)
        if whole == 0:
            return -0.0 if negative else 0.0
        return real(-whole if negative else whole)

    def pi(self) -> Real:
        """
        The constant that `FLDPI` loads: pi, rounded to 64 bits as the control word says.
        """
        return self.rational(_PI.numerator, _PI.denominator, Format.Extended)

    def sine(self, a: Real) -> Real:
        """
        The sine, rounded as the result of an instruction. The x87 leaves an operand of 2**63 or
        more unchanged.
        """
        if a == 0:
            return a
        return self._trigonometric(a, 0)

    def cosine(self, a: Real) -> Real:
        """
        The cosine, rounded as the result of an instruction. The x87 leaves an operand of 2**63 or
        more unchanged.
        """
        return self._trigonometric(a, 1)

    def _trigonometric(self, a: Real, quadrant: int) -> Real:
        """
        The x87 reduces the operand by multiples of half its pi of 66 bits and then computes
        exactly. The cosine is the sine one quadrant on.
        """
        if is_special(a):
            assert isinstance(a, float)
            if math.isnan(a):
                return a
            self.fault(Fault.Invalid)
            return math.nan
        if a != 0:
            m, e = parts(a)
            if e + m.bit_length() > 63:
                return a
        with decimal.localcontext(prec=_SERIES_DIGITS):
            x = exact(a)
            turns = round(x / _PI66 * 2)
            reduced = x - turns * _PI66 / 2
            value = decimal.Decimal(reduced.numerator) / decimal.Decimal(reduced.denominator)
            quadrant = (quadrant + turns) % 4
            result = Fraction((_cosine if quadrant % 2 else _sine)(value))
            if quadrant >= 2:
                result = -result
        return self.rational(result.numerator, result.denominator)


class SSE(FPU):
    """
    The SSE unit that Delphi's 64-bit code computes floats with: every result is a Double, rounded
    to the nearest value, and no exception raises. An Extended is a Double. Converting to an integer
    rounds to the nearest integer. The sine and cosine are those of Delphi's 64-bit library, which
    are correctly rounded for operands below 2**53; their value for larger operands depends on an
    argument reduction that is not modelled.
    """
    range = Format.Double

    def __init__(self):
        super().__init__(WIN64_CONTROL_WORD)

    def masks(self, fault: Fault) -> bool:
        return True

    def round(self, value: Real, fmt: Format, rounding: Rounding | None = None) -> Real:
        return super().round(value, Format.Double if fmt is Format.Extended else fmt, rounding)

    def load(self, value: int) -> Real:
        """
        An integer converted to a Double, rounded to the nearest value.
        """
        return super().store(real(value), Format.Double)

    def store(self, value: Real, fmt: Format) -> Real:
        return super().store(value, Format.Double if fmt is Format.Extended else fmt)

    def rational(self, numerator: int, denominator: int, fmt: Format | None = None) -> Real:
        return super().rational(numerator, denominator, Format.Double if fmt in (None, Format.Extended) else fmt)

    def integer(self, value: Real, rounding: Rounding | None = None) -> int:
        return super().integer(value, Rounding.Nearest if rounding is None else rounding)

    def pi(self) -> Real:
        return math.pi

    def sine(self, a: Real) -> Real:
        if a == 0:
            return a
        return self._library(a, _sine)

    def cosine(self, a: Real) -> Real:
        return self._library(a, _cosine)

    def _library(self, a: Real, series: Callable[[decimal.Decimal], decimal.Decimal]) -> Real:
        if is_special(a):
            assert isinstance(a, float)
            return math.nan
        if abs(exact(a)) >= _LIBRARY_LIMIT:
            raise Undefined('The sine and cosine of 64-bit Delphi reduce an operand of 2**53 or more in a way that is not modelled.')
        with decimal.localcontext(prec=_SERIES_DIGITS):
            x = exact(a)
            value = decimal.Decimal(x.numerator) / decimal.Decimal(x.denominator)
            tau = 2 * _PI_DIGITS
            value -= tau * (value / tau).to_integral_value(decimal.ROUND_FLOOR)
            result = Fraction(series(value))
        return self.rational(result.numerator, result.denominator)


_LIBRARY_LIMIT = 1 << 53
_SERIES_DIGITS = 80
_PI_DIGITS = decimal.Decimal(
    '3.14159265358979323846264338327950288419716939937510582097494459230781640628620899862803482534211706798')
_PI = Fraction(_PI_DIGITS)
_PI66 = Fraction(0x3243F6A8885A308D3, 1 << 64)


def _taylor(x: decimal.Decimal, term: decimal.Decimal, start: int) -> decimal.Decimal:
    total = term
    square = x * x
    k = start
    while True:
        term = -term * square / ((k + 1) * (k + 2))
        if not term:
            return total
        next_total = total + term
        if next_total == total:
            return total
        total = next_total
        k += 2


def _sine(x: decimal.Decimal) -> decimal.Decimal:
    return _taylor(x, x, 1)


def _cosine(x: decimal.Decimal) -> decimal.Decimal:
    return _taylor(x, decimal.Decimal(1), 0)
