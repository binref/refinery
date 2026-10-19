"""
The state that Delphi's run-time library keeps for a process, and what Delphi's compiled code does
on the platform that it was built for. A 32-bit Setup computes floats on the x87 under the control
word that a script can change.
"""
from __future__ import annotations

import abc
import enum

from fractions import Fraction

from refinery.lib.inno.delphi import x87
from refinery.lib.inno.delphi.errors import EDivByZero
from refinery.lib.inno.delphi.numbers import EXPONENT_LIMIT, FormatSettings, Library
from refinery.lib.inno.delphi.x87 import FPU, Format, Real


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


_INT64 = range(-0x8000000000000000, 0x8000000000000000)
_SMALLEST_CURRENCY = Fraction(-0x8000000000000000, 10000)


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
        return self.fpu.divide(x87.real(units(value)), 10000.0)

    def currency_arithmetic(self, op: Operation, a: Fraction, b: Fraction | int | Real) -> Fraction:
        """
        Computes with a Currency and a Currency, an integer, or a float, and stores the result as a
        Currency. The unit loads the units of 1/10000 of the Currency, computes with the other
        operand, and stores the result as an integer, rounded as the unit rounds. A Currency operand
        counts in units, an integer in whole numbers, a float as its value.
        """
        fpu = self.fpu
        left = x87.real(units(a))
        if isinstance(b, Fraction):
            right = x87.real(units(b))
            if op is Operation.Multiply:
                result = fpu.divide(fpu.multiply(left, right), 10000.0)
            elif op is Operation.Divide:
                result = fpu.multiply(fpu.divide(left, right), 10000.0)
            else:
                result = self.real_arithmetic(op, left, right)
        elif op is Operation.Add or op is Operation.Subtract:
            right = x87.real(b * 10000) if isinstance(b, int) else fpu.multiply(b, 10000.0)
            result = self.real_arithmetic(op, left, right)
        else:
            result = self.real_arithmetic(op, left, x87.real(b) if isinstance(b, int) else b)
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

    def __init__(self, settings: FormatSettings, control_word: int):
        fpu = FPU(control_word)
        super().__init__(settings, fpu)
        self.fpu = fpu
        self.library = Library(unit=fpu, digits=18, table_end=15, exponent_limit=EXPONENT_LIMIT)

    def currency_of_integer(self, value: int) -> Fraction:
        """
        The x87 loads the integer, multiplies by 10000, and stores the smallest Currency for a value
        out of range.
        """
        if value * 10000 not in _INT64:
            return _SMALLEST_CURRENCY
        return Fraction(value)

    def variant_currency(self, value: Real) -> Fraction:
        return self.currency(value)

    def real_divided_by_currency(self, a: Real, b: Fraction, fmt: Format) -> Real:
        """
        The x87 multiplies the float by 10000 and divides by the units of the Currency.
        """
        fpu = self.fpu
        return fpu.store(fpu.divide(fpu.multiply(a, 10000.0), x87.real(units(b))), fmt)

    def check_currency_divisor(self, b: Fraction):
        return

    def int64_division(self, a: int, b: int) -> tuple[int, int]:
        """
        The run-time library divides; the smallest Int64 divided by -1 gives itself.
        """
        return truncated_division(a, b)
