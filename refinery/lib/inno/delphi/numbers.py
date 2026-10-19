"""
Delphi's text of numbers and its parsing of numbers: `Val`, `Str`, the SysUtils functions that
convert integers, and `FloatToText`, which formats floating-point values with regional settings.
"""
from __future__ import annotations

import enum
import functools
import json
import math
import re

from dataclasses import dataclass
from fractions import Fraction
from typing import TYPE_CHECKING, NamedTuple

from refinery.lib.inno.delphi import x87
from refinery.lib.inno.delphi.errors import EConvertError, SysConst, Undefined
from refinery.lib.inno.delphi.x87 import FPU, Real
from refinery.lib.resources import datapath

if TYPE_CHECKING:
    from refinery.lib.inno.delphi.runtime import Runtime


@dataclass(frozen=True)
class FormatSettings:
    """
    The regional settings that Delphi formats numbers with, named as the fields of Delphi's record
    `TFormatSettings`. The defaults are those of English (United States).
    """
    decimal_separator: str = '.'
    thousand_separator: str = ','
    currency_string: str = '$'
    currency_format: int = 0
    negative_currency_format: int = 0
    currency_decimals: int = 2

    @classmethod
    def of_locale(cls, lcid: int) -> FormatSettings:
        """
        The regional settings that Windows 11 has for the locale with the given ID, as Delphi reads
        them: the first character of each separator.
        """
        try:
            _, *fields = _regional_formats()[F'{lcid:04x}']
        except KeyError:
            raise ValueError(F'Windows has no regional format for the locale 0x{lcid:04X}.') from None
        return cls(*fields)


@functools.cache
def _regional_formats() -> dict[str, list]:
    return json.loads(datapath('windows-locales.json').read_text(encoding='utf8'))


def val_integer(text: str, bits: int) -> tuple[int, int]:
    """
    Delphi's `Val` for an integer of the given width: the value and the error code, which is 0 on
    success and otherwise the position of the first character that is not part of the number,
    counting from 1. Leading spaces are skipped; a sign may follow; `$`, `x`, `X`, `0x` and `0X`
    start a hexadecimal number. A hexadecimal number may fill all bits, a decimal number must fit
    the signed range.
    """
    limit = (1 << (bits - 1)) - 1
    wrap = 1 << bits

    def at(position: int) -> str:
        if 1 <= position <= len(text):
            return text[position - 1]
        return '\0'

    def signed(value: int) -> int:
        value %= wrap
        return value - wrap if value > limit else value

    if not text:
        return 0, 1
    position = 1
    while at(position) == ' ':
        position += 1
    negative = False
    if at(position) == '-':
        negative = True
        position += 1
    elif at(position) == '+':
        position += 1
    result = 0
    empty = True
    first = at(position)
    if first == '$' or first in 'xX' or first == '0' and position < len(text) and at(position + 1) in 'xX':
        if first == '0':
            position += 1
        position += 1
        while (digit := _HEX_DIGITS.get(at(position))) is not None:
            if result < 0 or result > limit >> 3:
                break
            result = signed((result << 4) + digit)
            position += 1
            empty = False
        if negative:
            result = signed(-result)
    else:
        while (digit := _DECIMAL_DIGITS.get(at(position))) is not None:
            if result < 0 or result > limit // 10:
                break
            result = signed(result * 10 + digit)
            position += 1
            empty = False
        if negative:
            result = signed(-result)
        if result != 0 and negative != (result < 0):
            position -= 1
    if at(position) != '\0' or empty:
        return result, position
    return result, 0


def val_unsigned(text: str) -> tuple[int, int]:
    """
    Delphi's `Val` for a UInt64: as for an Int64, but a decimal number may fill all 64 bits and only
    zero may have a minus sign.
    """
    stripped = text.lstrip(' ')
    negative = stripped.startswith('-')
    if negative:
        stripped = stripped[1:]
    elif stripped.startswith('+'):
        stripped = stripped[1:]
    offset = len(text) - len(stripped)
    if not stripped:
        return 0, offset + 1 if text else 1
    hexadecimal = stripped[0] in '$xX' or stripped[:2] in ('0x', '0X')
    body = stripped[2:] if stripped[:2] in ('0x', '0X') else stripped[1:] if hexadecimal else stripped
    head = len(stripped) - len(body)
    digits = _HEX_DIGITS if hexadecimal else _DECIMAL_DIGITS
    base = 16 if hexadecimal else 10
    value = 0
    for k, character in enumerate(body):
        digit = digits.get(character)
        if digit is None:
            return value, offset + head + k + 1
        value = value * base + digit
        if value >> 64:
            return 0, offset + head + k + 1
    if not body:
        return 0, offset + head + 1
    if negative and value:
        return 0, 1
    return value, 0


_DECIMAL_DIGITS = {chr(48 + k): k for k in range(10)}
_HEX_DIGITS = {
    **_DECIMAL_DIGITS,
    **{chr(65 + k): 10 + k for k in range(6)},
    **{chr(97 + k): 10 + k for k in range(6)},
}


def str_to_int64(text: str) -> int:
    """
    SysUtils' `StrToInt64`: raises an `EConvertError` for a text that `Val` does not read as an
    Int64.
    """
    value, error = val_integer(text, 64)
    if error:
        raise EConvertError(SysConst.SInvalidInteger % text)
    return value


def str_to_int64_default(text: str, default: int) -> int:
    """
    SysUtils' `StrToInt64Def`: the default for a text that `Val` does not read as an Int64.
    """
    value, error = val_integer(text, 64)
    return default if error else value


def str_to_uint64(text: str) -> int:
    """
    SysUtils' `StrToUInt64`: raises an `EConvertError` for a text that `Val` does not read as a
    UInt64.
    """
    value, error = val_unsigned(text)
    if error:
        raise EConvertError(SysConst.SInvalidInteger % text)
    return value


def str_to_uint64_default(text: str, default: int) -> int:
    """
    SysUtils' `StrToUInt64Def`: the default for a text that `Val` does not read as a UInt64.
    """
    value, error = val_unsigned(text)
    return default if error else value


class Special(enum.Enum):
    """
    The values of a float that have no digits.
    """
    Infinity = 'INF'
    NegativeInfinity = '-INF'
    NaN = 'NAN'


@dataclass(frozen=True)
class Library:
    """
    The routines of Delphi's run-time library that convert between floats and text, as Delphi builds
    them for a platform. They compute on `unit` and write at most `digits` significant digits. They
    scale by powers of ten from a table whose powers `10 ** (32 * k)` end at `k = table_end`. `Val`
    gives an infinity when the exponent and the number of decimals add up to more than
    `exponent_limit`, if there is a limit. The power `-2**31`, which the library cannot negate, gives
    an infinity when `minimum_power_is_infinite` holds; otherwise the library reads a power after
    the end of its table.
    """
    unit: FPU
    digits: int
    table_end: int
    exponent_limit: int | None
    minimum_power_is_infinite: bool


@dataclass(frozen=True)
class Decimal:
    """
    A float as decimal digits: the value is `0.digits * 10 ** exponent`, negative or not. Delphi's
    record `TFloatRec` holds a float in this way.
    """
    negative: bool
    digits: str
    exponent: int


def decimal(
    value: Real,
    precision: int,
    decimals: int | None = None,
    *,
    library: Library,
    denormal_is_zero: bool = True,
) -> Decimal | Special:
    """
    Delphi's `FloatToDecimal`: the digits of the value rounded to the given number of significant
    digits, at most those of the library, and to the given number of digits after the decimal point.
    The digits come from `_stored_digits` and are rounded half up. Trailing zeros are removed; zero
    has no digits, and so has a denormal Extended unless the caller is `Str`, which writes its
    digits.
    """
    if isinstance(value, float):
        if math.isnan(value):
            return Special.NaN
        if math.isinf(value):
            return Special.NegativeInfinity if value < 0 else Special.Infinity
    negative = x87.is_negative(value)
    if value == 0:
        return Decimal(negative, '', 0)
    mantissa, power = x87.parts(value)
    if denormal_is_zero and abs(mantissa).bit_length() + power <= _EXTENDED_DENORMAL:
        return Decimal(negative, '', 0)
    text, exponent = _stored_digits(value, library)
    return _rounded(negative, text, exponent, min(precision, library.digits), decimals)


def _stored_digits(value: Real, library: Library) -> tuple[str, int]:
    """
    The 18 decimal digits that Delphi's `FloatToDecimal` stores for a finite value other than zero,
    and the exponent of the value `0.digits * 10 ** exponent`. The library estimates the decimal
    exponent from the binary one, multiplies by a power of ten to leave 18 integer digits, rounds
    to an integer, divides by ten when that has 19 digits, and stores the integer as 18 digits. The
    estimate is one too high for some small values, whose digits then start with a zero.
    """
    unit = library.unit
    mantissa, power = x87.parts(value)
    mantissa = abs(mantissa)
    exponent = ((mantissa.bit_length() - 1 + power) * 19728 >> 16) + 1
    scaled = unit.round_integral(_power_of_ten(library, x87.real(mantissa, power), 18 - exponent))
    if unit.compare(scaled, 1e18) != -1:
        scaled = unit.divide(scaled, 10.0)
        exponent += 1
    digits = unit.integer(scaled)
    if digits >= 10 ** 18:
        raise Undefined('Delphi stores a value of 19 decimal digits, which the x87 cannot store as 18.')
    return F'{digits:018d}', exponent


def _rounded(negative: bool, text: str, exponent: int, keep: int, decimals: int | None) -> Decimal:
    """
    The stored digits rounded half up to the given number of significant digits and to the given
    number of digits after the decimal point, without trailing zeros.
    """
    if decimals is not None:
        keep = min(keep, exponent + decimals)
    if keep < 0:
        return Decimal(negative, '', 0)
    if keep < len(text):
        rounded = int(text[:keep] or '0')
        if text[keep] >= '5':
            rounded += 1
        if keep == 0:
            if rounded:
                return Decimal(negative, '1', exponent + 1)
            return Decimal(negative, '', 0)
        if rounded >= 10 ** keep:
            exponent += 1
        text = str(rounded).zfill(keep)
    text = text.rstrip('0')
    if not text:
        return Decimal(negative, '', 0)
    return Decimal(negative, text, exponent)


def _scaled(mantissa: int, power: int, scale: int) -> tuple[int, int]:
    """
    The numerator and denominator of `mantissa * 2 ** power * 10 ** scale`.
    """
    numerator, denominator = mantissa, 1
    if power >= 0:
        numerator <<= power
    else:
        denominator <<= -power
    if scale >= 0:
        numerator *= 10 ** scale
    else:
        denominator *= 10 ** -scale
    return numerator, denominator


def _decimal_exponent(mantissa: int, power: int) -> int:
    """
    The exponent e with `10 ** (e - 1) <= mantissa * 2 ** power < 10 ** e` for a positive mantissa.
    """
    e = math.floor((mantissa.bit_length() + power - 1) * _LOG10_2) + 1
    while True:
        numerator, denominator = _scaled(mantissa, power, 1 - e)
        if numerator >= denominator:
            break
        e -= 1
    while True:
        numerator, denominator = _scaled(mantissa, power, -e)
        if numerator < denominator:
            break
        e += 1
    return e


_LOG10_2 = math.log10(2)
_EXTENDED_DENORMAL = -16382


class FloatFormat(enum.Enum):
    """
    The formats of Delphi's `FloatToText`.
    """
    General = 'general'
    Exponent = 'exponent'
    Fixed = 'fixed'
    Number = 'number'
    Currency = 'currency'


_POSITIVE_CURRENCY = (
    '{c}{n}',
    '{n}{c}',
    '{c} {n}',
    '{n} {c}',
)

_NEGATIVE_CURRENCY = (
    '({c}{n})',
    '-{c}{n}',
    '{c}-{n}',
    '{c}{n}-',
    '({n}{c})',
    '-{n}{c}',
    '{n}-{c}',
    '{n}{c}-',
    '-{n} {c}',
    '-{c} {n}',
    '{n} {c}-',
    '{c} {n}-',
    '{c} -{n}',
    '{n}- {c}',
    '({c} {n})',
    '({n} {c})',
)


def float_to_text(
    value: Real,
    style: FloatFormat,
    precision: int,
    digits: int,
    runtime: Runtime,
) -> str:
    """
    Delphi's `FloatToText`: the general format writes the shortest text of at most `precision`
    significant digits and switches to scientific notation with at least `digits` exponent digits
    for large and small values; the exponent format writes `precision` significant digits and an
    exponent of at least `digits` digits; the fixed, number and currency formats write `digits`
    decimals and use the general format for values with more than `precision` integer digits. The
    number and currency formats separate thousands, and the currency format places the currency
    string as the settings say.
    """
    settings = runtime.settings
    library = runtime.library
    if style is FloatFormat.General or style is FloatFormat.Exponent:
        precision = min(precision, library.digits)
        rounded = decimal(value, precision, library=library)
    else:
        rounded = decimal(value, 18, library=library)
        if isinstance(rounded, Decimal) and rounded.exponent > min(precision, library.digits):
            return float_to_text(value, FloatFormat.General, precision, digits, runtime)
        rounded = decimal(value, 18, digits, library=library)
    if isinstance(rounded, Special):
        return rounded.value
    point = settings.decimal_separator
    if style is FloatFormat.General:
        if not rounded.digits:
            return '0'
        sign = '-' if rounded.negative else ''
        exponent = rounded.exponent
        if exponent > precision or exponent < -3:
            mantissa = rounded.digits[0]
            if len(rounded.digits) > 1:
                mantissa = F'{mantissa}{point}{rounded.digits[1:]}'
            e = exponent - 1
            return F'{sign}{mantissa}E{"-" if e < 0 else ""}{abs(e):0{digits}d}'
        return F'{sign}{_fixed(rounded, None, point)}'
    if style is FloatFormat.Exponent:
        mantissa = rounded.digits.ljust(precision, '0')
        e = rounded.exponent - 1 if rounded.digits else 0
        sign = '-' if rounded.negative and rounded.digits else ''
        if precision > 1:
            mantissa = F'{mantissa[0]}{point}{mantissa[1:]}'
        return F'{sign}{mantissa}E{"-" if e < 0 else "+"}{abs(e):0{digits}d}'
    thousands = '' if style is FloatFormat.Fixed else settings.thousand_separator
    number = _fixed(rounded, digits, point, thousands)
    negative = rounded.negative and bool(rounded.digits)
    if style is FloatFormat.Currency:
        if negative:
            return _NEGATIVE_CURRENCY[settings.negative_currency_format].format(c=settings.currency_string, n=number)
        return _POSITIVE_CURRENCY[settings.currency_format].format(c=settings.currency_string, n=number)
    return F'-{number}' if negative else number


def _fixed(rounded: Decimal, decimals: int | None, point: str, thousands: str = '') -> str:
    """
    The digits of a decimal as a number without exponent: with the given number of decimals, or
    with as many as the digits need.
    """
    digits = rounded.digits
    exponent = rounded.exponent
    if exponent > 0:
        whole = digits[:exponent].ljust(exponent, '0')
        fraction = digits[exponent:]
    else:
        whole = '0'
        fraction = '0' * -exponent + digits
    if thousands:
        groups = []
        while len(whole) > 3:
            groups.append(whole[-3:])
            whole = whole[:-3]
        groups.append(whole)
        whole = thousands.join(reversed(groups))
    if decimals is not None:
        fraction = fraction[:decimals].ljust(decimals, '0')
    if fraction:
        return F'{whole}{point}{fraction}'
    return whole


def float_to_str(value: Real, runtime: Runtime) -> str:
    """
    SysUtils' `FloatToStr`: the general format with 15 significant digits.
    """
    return float_to_text(value, FloatFormat.General, 15, 0, runtime)


def str_fixed(value: Real, decimals: int, library: Library) -> str:
    """
    Delphi's `Str(Value:0:Decimals)`, which Pascal Script's `FloatToStr` calls with 12 decimals. It
    writes the value with a point and the given number of decimals, and a value below 2**-116 or
    from 2**119 on in scientific notation with two significant digits and a four-digit exponent;
    those digits start after a leading zero of the stored digits.
    """
    if isinstance(value, float):
        if math.isnan(value):
            return 'Nan'
        if math.isinf(value):
            return '-Inf' if value < 0 else '+Inf'
    magnitude = abs(x87.exact(value))
    if magnitude != 0 and not _STR_FIXED_RANGE[0] <= magnitude < _STR_FIXED_RANGE[1]:
        text, exponent = _stored_digits(value, library)
        if text.startswith('0'):
            text, exponent = text[1:], exponent - 1
        rounded = _rounded(x87.is_negative(value), text, exponent, 2, None)
        mantissa = rounded.digits.ljust(2, '0')
        e = rounded.exponent - 1
        sign = '-' if rounded.negative else ' '
        return F'{sign}{mantissa[0]}.{mantissa[1]}E{"-" if e < 0 else "+"}{abs(e):04d}'
    rounded = decimal(value, 18, decimals, library=library, denormal_is_zero=False)
    assert isinstance(rounded, Decimal)
    number = _fixed(rounded, decimals, '.')
    return F'-{number}' if rounded.negative and magnitude != 0 else number


_STR_FIXED_RANGE = (Fraction(1, 1 << 116), Fraction(1 << 119))


def val_float(text: str, library: Library) -> tuple[Real | None, int]:
    """
    Delphi's `Val` for a float: the value that the text spells and the error code, which is 0 on
    success and otherwise the position of the first character that is not part of the number,
    counting from 1. Leading spaces are skipped, a sign may follow, then digits with an optional
    point and an optional exponent with at least one digit. The digits may be missing, which reads
    as zero, but the text may not be empty after the spaces. The library's unit computes the value:
    it takes the digits one by one, multiplying by ten and adding the digit, and scales the result
    by ten to the exponent minus the number of decimals. The exponent is read as a 32-bit integer
    that wraps around; when the exponent and the number of decimals add up to more than the
    library's limit, the value is an infinity, whatever the digits.
    """
    match = _VAL_FLOAT.match(text)
    assert match is not None
    spaces, sign, whole, fraction, exponent_mark, exponent_sign, exponent = match.groups()
    end = match.end()
    if len(spaces) == len(text):
        return None, len(text) + 1
    if exponent_mark and not exponent:
        return None, end + 1
    if end < len(text):
        return None, end + 1
    fraction = fraction or ''
    fpu = library.unit
    value: Real = 0.0
    for digit in (whole + fraction).lstrip('0'):
        value = fpu.add(fpu.multiply(value, 10.0), _DIGIT_VALUES[digit])
        if x87.is_special(value):
            break
    power = -len(fraction)
    if exponent:
        exponent_value = _wrapped_exponent(exponent_sign, exponent)
        limit = library.exponent_limit
        if limit is not None and exponent_value + len(fraction) > limit:
            value = math.inf
        power = _signed32(power + exponent_value)
    if power == -0x80000000 and library.minimum_power_is_infinite:
        value = math.inf
    else:
        value = _power_of_ten(library, value, power)
    return (fpu.negate(value) if sign == '-' else value), 0


_VAL_FLOAT = re.compile(r'( *)([+-]?)([0-9]*)(?:\.([0-9]*))?(?:([eE])([+-]?)([0-9]*))?')
_DIGIT_VALUES = {str(k): float(k) for k in range(10)}
_POWER_LIMIT = 5120


EXPONENT_LIMIT = 5197
"""
The largest sum of the exponent and the number of decimals that 32-bit Delphi's `Val` scales by;
this bound fits every probe of the oracle (exponents from 4932 to 6000 with up to 5201 decimals).
"""


def _signed32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - (1 << 32) if value >> 31 else value


def _wrapped_exponent(sign: str, digits: str) -> int:
    """
    The exponent that the digits spell as a 32-bit integer, negated for a minus sign, both with
    wraparound; only the last 32 digits decide it, since `10 ** 32` is a multiple of `2 ** 32`.
    """
    value = int(digits[-32:]) & 0xFFFFFFFF
    if sign == '-':
        value = -value & 0xFFFFFFFF
    return value - (1 << 32) if value >> 31 else value


def _bounded_exponent(sign: str, digits: str, limit: int) -> int:
    """
    The exponent that the digits spell, or the given limit with the sign when it is larger.
    """
    digits = digits.lstrip('0')
    exponent = int(digits) if len(digits) <= len(str(limit)) else limit
    exponent = min(exponent, limit)
    return -exponent if sign == '-' else exponent


def _table(power: int) -> Real:
    return _NEAREST.rational(10 ** power, 1, x87.Format.Extended)


_NEAREST = FPU(x87.MASKED_CONTROL_WORD)
_POWERS = [_table(k) for k in range(32)]
_POWERS_32 = [_table(32 * k) for k in range(16)]
_POWERS_512 = [_table(512 * k) for k in range(10)]


def _power_of_ten(library: Library, value: Real, power: int) -> Real:
    """
    The value times ten to the given power, as Delphi's `FPower10` computes it: it multiplies by a
    power of ten, or divides by it for a negative power, as the product of three powers from a table
    of Extended values: `10 ** a`, `10 ** (32 * b)`, and `10 ** (512 * c)`. When `b` is beyond the
    end of the library's table, the library scales by two of its powers. A power of 5120 or more
    gives an infinity, and one of -5120 or less zero. The power -2**31, which Delphi cannot negate,
    reads a power after the end of the table, which is `Undefined`.
    """
    if power == 0:
        return value
    if power == -0x80000000:
        raise Undefined('Delphi scales by a power of ten from after the end of its table.')
    negative = power < 0
    power = abs(power)
    if power >= _POWER_LIMIT:
        return 0.0 if negative else math.inf
    fpu = library.unit
    scale = fpu.divide if negative else fpu.multiply
    value = scale(value, _POWERS[power & 31])
    if b := (power >> 5) & 15:
        end = library.table_end
        if b > end:
            value = scale(value, _POWERS_32[b - end])
            b = end
        value = scale(value, _POWERS_32[b])
    if c := power >> 9:
        value = scale(value, _POWERS_512[c])
    return value


class OleNumber(NamedTuple):
    """
    A number that Windows read from a text, and whether the text wrote it with an exponent.
    """
    value: Fraction
    exponent: bool


def ole_number(text: str, settings: FormatSettings) -> OleNumber | None:
    """
    The number that Windows reads from a text when Delphi converts a Variant that holds a string,
    with the regional settings: white space around it; `&H` before hexadecimal and `&O` before
    octal digits; otherwise a sign before or after the number, or parentheses around it for a
    negative number, the currency string before or after it, digits among which the thousand
    separator may stand, the decimal separator and more digits, and an exponent. Returns `None` for
    any other text. The value is exact, except that a value of more than 10**400 in magnitude
    becomes 10**400 and a value of less than 10**-400 becomes 10**-400, with its sign, and that the
    digits after the first 800 significant ones only count as a small amount beyond them; no format
    that Windows converts to tells these values apart.
    """
    text = text.strip(_OLE_WHITESPACE)
    prefix = text[:2].upper()
    if prefix in ('&H', '&O'):
        digits = text[2:]
        base = 16 if prefix == '&H' else 8
        if not digits or not digits.isalnum():
            return None
        digits = digits.lstrip('0') or '0'
        if len(digits) > _OLE_DIGITS:
            return OleNumber(Fraction(10) ** _OLE_EXPONENT, False)
        try:
            return OleNumber(Fraction(int(digits, base)), False)
        except ValueError:
            return None
    negative = False
    if text.startswith('(') and text.endswith(')'):
        negative = True
        text = text[1:-1].strip(_OLE_WHITESPACE)
    currency = settings.currency_string
    sign = None
    if text[:1] in ('+', '-'):
        sign = text[0]
        text = text[1:].strip(_OLE_WHITESPACE)
    if currency and text.startswith(currency):
        text = text[len(currency):].strip(_OLE_WHITESPACE)
    elif currency and text.endswith(currency):
        text = text[:-len(currency)].strip(_OLE_WHITESPACE)
    if sign is None and text[:1] in ('+', '-'):
        sign = text[0]
        text = text[1:].strip(_OLE_WHITESPACE)
    if sign is None and text[-1:] in ('+', '-'):
        sign = text[-1]
        text = text[:-1].strip(_OLE_WHITESPACE)
    if sign is not None and negative:
        return None
    number = _ole_magnitude(text, settings)
    if number is None:
        return None
    if negative or sign == '-':
        return OleNumber(-number.value, number.exponent)
    return number


_OLE_WHITESPACE = ' \t'
_OLE_DIGITS = 800
_OLE_EXPONENT = 400


def _ole_magnitude(text: str, settings: FormatSettings) -> OleNumber | None:
    thousands = settings.thousand_separator
    point = settings.decimal_separator
    pattern = F'([0-9](?:[0-9]|{re.escape(thousands)})*)?(?:{re.escape(point)}([0-9]*))?(?:[eE]([+-]?)([0-9]*))?'
    match = re.fullmatch(pattern, text)
    if match is None:
        return None
    whole, fraction, exponent_sign, exponent = match.groups()
    whole = whole or ''
    if thousands:
        whole = whole.replace(thousands, '')
    fraction = fraction or ''
    if not whole and not fraction:
        return None
    if exponent is not None and not exponent:
        return None
    written = exponent is not None
    digits = (whole + fraction).lstrip('0')
    if not digits:
        return OleNumber(Fraction(0), written)
    scale = -len(fraction)
    if exponent:
        scale += _bounded_exponent(exponent_sign, exponent, 2 * _OLE_EXPONENT + len(whole) + len(fraction))
    if len(digits) > _OLE_DIGITS:
        sticky = digits[_OLE_DIGITS:].strip('0') != ''
        scale += len(digits) - _OLE_DIGITS
        digits = digits[:_OLE_DIGITS]
        if sticky:
            digits += '1'
            scale -= 1
    top = len(digits) + scale
    if top > _OLE_EXPONENT:
        return OleNumber(Fraction(10) ** _OLE_EXPONENT, written)
    if top < -_OLE_EXPONENT:
        return OleNumber(Fraction(1, 10 ** _OLE_EXPONENT), written)
    return OleNumber(Fraction(int(digits)) * Fraction(10) ** scale, written)


def shortest(value: Real) -> str:
    """
    The shortest text that names the value exactly, in the style of Python's text of a float: for
    an `refinery.lib.inno.delphi.x87.Extended`, the fewest significant digits whose nearest Extended
    is the value.
    """
    if not isinstance(value, x87.Extended):
        return repr(value)
    negative = value.mantissa < 0
    mantissa = abs(value.mantissa)
    power = value.exponent
    exponent = _decimal_exponent(mantissa, power)
    target = x87.Extended(mantissa, power)
    for count in range(1, 22):
        numerator, denominator = _scaled(mantissa, power, count - exponent)
        digits, remainder = divmod(numerator, denominator)
        if 2 * remainder > denominator or 2 * remainder == denominator and digits & 1:
            digits += 1
        scale = exponent - count
        if scale >= 0:
            back = _NEAREST.rational(digits * 10 ** scale, 1, x87.Format.Extended)
        else:
            back = _NEAREST.rational(digits, 10 ** -scale, x87.Format.Extended)
        if back == target:
            break
    else:
        raise ValueError(value)
    text = str(digits)
    point = scale + len(text)
    text = text.rstrip('0')
    if -4 < point <= 16:
        if point <= 0:
            number = F'0.{"0" * -point}{text}'
        elif point >= len(text):
            number = F'{text}{"0" * (point - len(text))}.0'
        else:
            number = F'{text[:point]}.{text[point:]}'
    else:
        mantissa_text = text[0] if len(text) == 1 else F'{text[0]}.{text[1:]}'
        e = point - 1
        number = F'{mantissa_text}e{"-" if e < 0 else "+"}{abs(e):02d}'
    return F'-{number}' if negative else number
