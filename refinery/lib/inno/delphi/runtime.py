"""
The state that Delphi's run-time library keeps for a process, and what Delphi's compiled code does
on the platform that it was built for. A 32-bit Setup computes floats on the x87 under the control
word that a script can change. A 64-bit Setup computes with SSE; it keeps the control word that a
script sets, but nothing computes under it.
"""
from __future__ import annotations

import abc
import enum

from fractions import Fraction

from refinery.lib.inno.delphi.errors import EDivByZero, EIntOverflow, EZeroDivide, Undefined
from refinery.lib.inno.delphi.numbers import EXPONENT_LIMIT, FormatSettings, Library
from refinery.lib.inno.delphi.x87 import (
    FPU,
    MASKED_CONTROL_WORD,
    SSE,
    WIN64_CONTROL_WORD,
    Format,
    Real,
)


class Platform(enum.Enum):
    """
    The platforms that Delphi compiles Inno Setup for.
    """
    Win32 = 32
    Win64 = 64


class Operation(enum.Enum):
    """
    The arithmetic of Delphi's compiled code.
    """
    Add = '+'
    Subtract = '-'
    Multiply = '*'
    Divide = '/'


def units(value: Fraction) -> int:
    """
    A Currency as its integer number of units of 1/10000.
    """
    return value.numerator * (10000 // value.denominator)


def truncated_division(a: int, b: int) -> tuple[int, int]:
    """
    Divides as Delphi's `div` and `mod` do: The quotient is truncated toward zero, and the remainder
    has the sign of the dividend.
    """
    if b == 0:
        raise EDivByZero
    quotient = abs(a) // abs(b)
    if (a < 0) != (b < 0):
        quotient = -quotient
    return quotient, a - quotient * b


def _signed64(value: int) -> int:
    value &= 0xFFFFFFFFFFFFFFFF
    return value - (1 << 64) if value >> 63 else value


_INT64 = range(-0x8000000000000000, 0x8000000000000000)


class Runtime(abc.ABC):
    """
    The regional settings that numbers are formatted and parsed with, the control word that a
    script reads and writes, the unit that compiled code computes floats with (`fpu`), and the
    routines that convert floats to text and back (`library`). The methods answer how Delphi's
    compiled code computes where the platforms differ.
    """
    platform: Platform
    pointer_size: int
    variant_size: int
    extended_size: int
    parses_long_digits_as_infinity: bool
    """
    Whether Windows reads a number without exponent beyond the range of a Double from a string as
    an infinity instead of failing to convert it.
    """
    fpu: FPU
    library: Library

    def __init__(self, settings: FormatSettings, control: FPU):
        self.settings = settings
        self._control = control

    @property
    def control_word(self) -> int:
        """
        The control word that `Get8087CW` reads and `Set8087CW` writes.
        """
        return self._control.control

    @control_word.setter
    def control_word(self, value: int):
        self._control.control = value

    def real_arithmetic(self, op: Operation, a: Real, b: Real, fmt: Format = Format.Extended) -> Real:
        """
        Computes with two floats and stores the result into a variable of the given format.
        """
        fpu = self.fpu
        if op is Operation.Add:
            result = fpu.add(a, b)
        elif op is Operation.Subtract:
            result = fpu.subtract(a, b)
        elif op is Operation.Multiply:
            result = fpu.multiply(a, b)
        else:
            result = fpu.divide(a, b)
        return fpu.store(result, fmt)

    def currency(self, value: Real) -> Fraction:
        """
        Converts a float to a Currency: the value times 10000, rounded as a result, and then to an
        integer as the unit rounds. On the x87, a value out of range signals an invalid operation
        and gives the smallest Currency.
        """
        fpu = self.fpu
        return Fraction(fpu.integer(fpu.multiply(value, 10000.0)), 10000)

    def currency_to_real(self, value: Fraction) -> Real:
        """
        Converts a Currency to a float: its units of 1/10000 divided by 10000.
        """
        return self.fpu.divide(self.fpu.load(units(value)), 10000.0)

    def currency_arithmetic(self, op: Operation, a: Fraction, b: Fraction | int | Real) -> Fraction:
        """
        Computes with a Currency and a Currency, an integer, or a float, and stores the result as a
        Currency. The unit loads the units of 1/10000 of the Currency, computes with the other
        operand, and stores the result as an integer, rounded as the unit rounds. A Currency operand
        counts in units, an integer in whole numbers, a float as its value.
        """
        fpu = self.fpu
        left = fpu.load(units(a))
        if isinstance(b, Fraction):
            right = fpu.load(units(b))
            if op is Operation.Multiply:
                result = fpu.divide(fpu.multiply(left, right), 10000.0)
            elif op is Operation.Divide:
                result = fpu.multiply(fpu.divide(left, right), 10000.0)
            else:
                result = self.real_arithmetic(op, left, right)
        elif op is Operation.Add or op is Operation.Subtract:
            right = fpu.load(b * 10000) if isinstance(b, int) else fpu.multiply(b, 10000.0)
            result = self.real_arithmetic(op, left, right)
        else:
            result = self.real_arithmetic(op, left, fpu.load(b) if isinstance(b, int) else b)
        return Fraction(fpu.integer(result), 10000)

    @abc.abstractmethod
    def currency_of_integer(self, value: int) -> Fraction:
        """
        Converts an integer to a Currency.
        """

    @abc.abstractmethod
    def variant_currency(self, value: Real) -> Fraction:
        """
        Converts the float of a Variant to a Currency; the caller checks the range.
        """

    @abc.abstractmethod
    def real_divided_by_currency(self, a: Real, b: Fraction, fmt: Format) -> Real:
        """
        Divides a float by a Currency and stores the result into a variable of the given format.
        """

    @abc.abstractmethod
    def check_currency_divisor(self, b: Fraction):
        """
        Raises the error of a division by a Currency of zero, if the platform raises one.
        """

    @abc.abstractmethod
    def int64_division(self, a: int, b: int) -> tuple[int, int]:
        """
        The quotient and the remainder of Int64 operands, truncated toward zero.
        """


class Win32(Runtime):
    """
    Delphi's 32-bit code: the x87 computes under the control word of the script, and the library
    computes on the same x87.
    """
    platform = Platform.Win32
    pointer_size = 4
    variant_size = 16
    extended_size = 10
    parses_long_digits_as_infinity = False

    def __init__(self, settings: FormatSettings, control_word: int):
        fpu = FPU(control_word)
        super().__init__(settings, fpu)
        self.fpu = fpu
        self.library = Library(
            unit=fpu,
            digits=18,
            table_end=15,
            exponent_limit=EXPONENT_LIMIT,
            minimum_power_is_infinite=False,
        )

    def currency_of_integer(self, value: int) -> Fraction:
        """
        The x87 loads the integer and converts it as a float: a value out of range signals an
        invalid operation and gives the smallest Currency.
        """
        return self.currency(self.fpu.load(value))

    def variant_currency(self, value: Real) -> Fraction:
        return self.currency(value)

    def real_divided_by_currency(self, a: Real, b: Fraction, fmt: Format) -> Real:
        """
        The x87 multiplies the float by 10000 and divides by the units of the Currency.
        """
        fpu = self.fpu
        return fpu.store(fpu.divide(fpu.multiply(a, 10000.0), fpu.load(units(b))), fmt)

    def check_currency_divisor(self, b: Fraction):
        return

    def int64_division(self, a: int, b: int) -> tuple[int, int]:
        """
        The run-time library divides; the smallest Int64 divided by -1 gives itself.
        """
        return truncated_division(a, b)


class Win64(Runtime):
    """
    Delphi's 64-bit code: SSE computes every float as a Double. The library computes as an x87
    with the control word of 64-bit code, whatever the script sets; its table of powers of ten ends
    at `10 ** 256` and its `Val` has no limit on the exponent.
    """
    platform = Platform.Win64
    pointer_size = 8
    variant_size = 24
    extended_size = 8
    parses_long_digits_as_infinity = True

    def __init__(self, settings: FormatSettings):
        super().__init__(settings, FPU(WIN64_CONTROL_WORD))
        self.fpu = SSE()
        self.library = Library(
            unit=FPU(WIN64_CONTROL_WORD),
            digits=17,
            table_end=8,
            exponent_limit=None,
            minimum_power_is_infinite=True,
        )

    def currency_of_integer(self, value: int) -> Fraction:
        """
        64-bit code multiplies the integer by 10000 as a 64-bit integer, which wraps around.
        """
        return Fraction(_signed64(value * 10000), 10000)

    def variant_currency(self, value: Real) -> Fraction:
        """
        Windows' 64-bit conversion rounds the value times 10000 as an x87 with every exception
        masked does: at 64 bits of mantissa, then to the nearest integer.
        """
        fpu = _NEAREST
        return Fraction(fpu.integer(fpu.multiply(value, 10000.0)), 10000)

    def currency_arithmetic(self, op: Operation, a: Fraction, b: Fraction | int | Real) -> Fraction:
        """
        Two Currency values, and a Currency and an integer that are added or subtracted, compute in
        units as 64-bit integers: sums wrap around, a product out of range raises an overflow, and
        a quotient by zero a division by zero. Products and quotients round half to even. What a
        quotient out of range gives is not known.
        """
        if not isinstance(b, Fraction) and not (isinstance(b, int) and op in (Operation.Add, Operation.Subtract)):
            return super().currency_arithmetic(op, a, b)
        left = units(a)
        right = units(b) if isinstance(b, Fraction) else b * 10000
        if op is Operation.Add:
            return Fraction(_signed64(left + right), 10000)
        if op is Operation.Subtract:
            return Fraction(_signed64(left - right), 10000)
        if op is Operation.Multiply:
            result = round(Fraction(left * right, 10000))
            if result not in _INT64:
                raise EIntOverflow
            return Fraction(result, 10000)
        if right == 0:
            raise EZeroDivide
        result = round(Fraction(left * 10000, right))
        if result not in _INT64:
            raise Undefined('64-bit Delphi divides two Currency values whose quotient is out of range in a way that is not modelled.')
        return Fraction(result, 10000)

    def real_divided_by_currency(self, a: Real, b: Fraction, fmt: Format) -> Real:
        """
        64-bit code divides the float by the units of the Currency and multiplies by 10000.
        """
        fpu = self.fpu
        return fpu.store(fpu.multiply(fpu.divide(a, fpu.load(units(b))), 10000.0), fmt)

    def check_currency_divisor(self, b: Fraction):
        if b == 0:
            raise EZeroDivide

    def int64_division(self, a: int, b: int) -> tuple[int, int]:
        """
        The processor divides; the smallest Int64 divided by -1 overflows.
        """
        if a == -0x8000000000000000 and b == -1:
            raise EIntOverflow
        return truncated_division(a, b)


_NEAREST = FPU(MASKED_CONTROL_WORD)
