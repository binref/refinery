"""
Delphi's function `Format`, which Inno Setup registers for scripts.
"""
from __future__ import annotations

import enum
import re

from typing import Callable, NamedTuple, Sequence

from refinery.lib.inno.delphi import variants
from refinery.lib.inno.delphi.errors import EConvertError, Undefined
from refinery.lib.inno.delphi.numbers import FloatFormat, float_to_text
from refinery.lib.inno.delphi.runtime import Runtime


class VType(enum.IntEnum):
    """
    The kinds of values that a Delphi `array of const` holds, i.e. the values of the `VType`
    field of a `TVarRec`.
    """
    Integer       = 0x00  # noqa
    Boolean       = 0x01  # noqa
    Char          = 0x02  # noqa
    Extended      = 0x03  # noqa
    String        = 0x04  # noqa
    Pointer       = 0x05  # noqa
    PChar         = 0x06  # noqa
    Object        = 0x07  # noqa
    Class         = 0x08  # noqa
    WideChar      = 0x09  # noqa
    PWideChar     = 0x0A  # noqa
    AnsiString    = 0x0B  # noqa
    Currency      = 0x0C  # noqa
    Variant       = 0x0D  # noqa
    Interface     = 0x0E  # noqa
    WideString    = 0x0F  # noqa
    Int64         = 0x10  # noqa
    UnicodeString = 0x11  # noqa


class VarRec(NamedTuple):
    """
    One element of a Delphi `array of const`: a value and its kind. An `Integer` holds a signed
    32-bit value, an `Int64` a signed 64-bit value, and a `Variant` the value it holds.
    """
    kind: VType
    value: int | float | str | object | None


_TEXT_KINDS = frozenset((
    VType.Char,
    VType.String,
    VType.PChar,
    VType.WideChar,
    VType.PWideChar,
    VType.AnsiString,
    VType.WideString,
    VType.UnicodeString,
))

_INTEGER_MASK = {
    VType.Integer : 0xFFFFFFFF,
    VType.Int64   : 0xFFFFFFFFFFFFFFFF,
}

_ASTERISK_KINDS = frozenset((
    VType.Integer,
    VType.Int64,
))

_INTEGER_RANGE = range(-0x80000000, 0x80000000)

_DIGITS = frozenset('0123456789')
_TYPE_LETTER = re.compile('[A-Za-z]')

_INVALID_FORMAT = 'Format \'%s\' invalid or incompatible with argument'
_MISSING_ARGUMENT = 'No argument for format \'%s\''


def _number(fmt: str, cursor: int) -> tuple[str, int]:
    """
    Reads the digits at the cursor. Returns them and the cursor after them.
    """
    end = cursor
    while end < len(fmt) and fmt[end] in _DIGITS:
        end += 1
    if end - cursor > _LONGEST_NUMBER:
        raise Undefined(F'Delphi overruns its buffer for a number of {end - cursor} digits in a format.')
    return fmt[cursor:end], end


_LONGEST_NUMBER = 40
"""
The most digits of an index, width, or precision that Delphi's `Format` is known to read safely;
5000 digits crash the Setup.
"""


def _integer(number: str) -> int:
    """
    The value of digits that spell an Integer, and -1 for no digits or a value beyond the range of
    an Integer.
    """
    number = number.lstrip('0') or number[:1]
    if number and len(number) <= 10 and (value := int(number)) in _INTEGER_RANGE:
        return value
    return -1


def format(
    fmt: str,
    args: Sequence[VarRec],
    runtime: Runtime,
    reserve: Callable[[int], None] | None = None,
) -> str:
    """
    Delphi's `Format` function as Delphi 12 implements it: Each format specifier has the form

        "%" [index ":"] ["-"] [width] ["." precision] type

    where index is a decimal number and a colon without a number is the index 0. Width and
    precision are decimal numbers or an asterisk, which takes the number from the next argument:
    an Integer, or an Int64 in the range of an Integer. A negative width from an argument pads on
    the other side. An index or width whose digits do not spell a non-negative Integer is an
    error, and such a precision is ignored. A specifier without an index takes the argument after
    the one that the previous specifier took. The type is one of `d u x s p e f g n m`, in any
    case, and `%%` writes a percent sign. A specifier that does not end in a letter ends the
    output. Hex digits are upper case, a precision is the minimum number of digits for an integer
    and the maximum length of a string, and the width pads with spaces. The floating-point types
    are written as `refinery.lib.inno.delphi.numbers.float_to_text` writes them, with the regional
    settings of the runtime: `e` and `g` with 15 significant digits by default and at least three
    exponent digits, `f` and `n` with two decimals by default, and `m` with the currency decimals
    of the settings, at most 18 digits. A Variant is accepted only by `s`, and Null is empty.
    Before the text grows, `reserve` is called with the length that it would reach.
    """
    output: list[str] = []
    length = 0

    def grow(text: str):
        nonlocal length
        length += len(text)
        output.append(text)
    cursor = 0
    index = -1

    def error(message: str):
        return EConvertError(message % fmt[:31])

    def argument() -> VarRec:
        if index >= len(args):
            raise error(_MISSING_ARGUMENT)
        return args[index]

    def spelled(number: str) -> int:
        if (value := _integer(number)) < 0:
            raise error(_INVALID_FORMAT)
        return value

    def asterisk() -> int:
        nonlocal index
        kind, value = argument()
        index += 1
        if kind in _ASTERISK_KINDS and isinstance(value, int) and value in _INTEGER_RANGE:
            return value
        raise error(_INVALID_FORMAT)

    while (percent := fmt.find('%', cursor)) >= 0:
        grow(fmt[cursor:percent])
        cursor = percent + 1
        if fmt.startswith('%', cursor):
            grow('%')
            cursor += 1
            continue
        index += 1
        width = precision = -1
        number, cursor = _number(fmt, cursor)
        if not number:
            if fmt.startswith(':', cursor):
                cursor += 1
                index = 0
        elif fmt.startswith(':', cursor):
            cursor += 1
            index = spelled(number)
        else:
            width = spelled(number)
        if left := fmt.startswith('-', cursor):
            cursor += 1
        if star_width := fmt.startswith('*', cursor):
            cursor += 1
        else:
            number, cursor = _number(fmt, cursor)
            if number:
                width = spelled(number)
        star_precision = False
        if fmt.startswith('.', cursor):
            cursor += 1
            if star_precision := fmt.startswith('*', cursor):
                cursor += 1
            else:
                number, cursor = _number(fmt, cursor)
                precision = _integer(number)
        if not _TYPE_LETTER.match(fmt, cursor):
            return ''.join(output)
        letter = fmt[cursor]
        cursor += 1
        if star_width:
            width = asterisk()
            if width < 0:
                left = not left
                width = -width & 0x7FFFFFFF
        if star_precision:
            precision = asterisk()
        if reserve is not None:
            reserve(length + max(width, precision if letter in 'dDuUxX' else 0))
        kind, value = argument()
        if (text := _convert(letter, kind, value, precision, runtime)) is None:
            raise error(_INVALID_FORMAT)
        if reserve is not None:
            reserve(length + max(width, len(text)))
        grow(text.ljust(width) if left else text.rjust(width))
    grow(fmt[cursor:])
    return ''.join(output)


def _convert(letter: str, kind: VType, value, precision: int, runtime: Runtime) -> str | None:
    conversion = letter.upper()
    if conversion in 'DUX':
        if (mask := _INTEGER_MASK.get(kind)) is None or not isinstance(value, int):
            return None
        if conversion == 'D':
            sign = '-' if value < 0 else ''
            return F'{sign}{abs(value):0{max(precision, 0)}d}'
        if conversion == 'U':
            return F'{value & mask:0{max(precision, 0)}d}'
        return F'{value & mask:0{max(precision, 0)}X}'
    if conversion == 'S':
        if kind in _TEXT_KINDS and isinstance(value, str):
            text = value
        elif kind is VType.Variant:
            text = variants.to_text(value, runtime)
        else:
            return None
        return text if precision < 0 else text[:precision]
    if conversion == 'P':
        if kind is not VType.Pointer:
            return None
        return F'{value or 0:08X}'
    if (style := _FLOAT_FORMATS.get(conversion)) is not None:
        if kind is not VType.Extended:
            return None
        settings = runtime.settings
        precision = min(precision, 18)
        if style is FloatFormat.General or style is FloatFormat.Exponent:
            return float_to_text(value, style, 15 if precision < 0 else precision, 3, runtime)
        if precision < 0:
            precision = settings.currency_decimals if style is FloatFormat.Currency else 2
        return float_to_text(value, style, 18, precision, runtime)
    return None


_FLOAT_FORMATS = {
    'E': FloatFormat.Exponent,
    'F': FloatFormat.Fixed,
    'G': FloatFormat.General,
    'N': FloatFormat.Number,
    'M': FloatFormat.Currency,
}
