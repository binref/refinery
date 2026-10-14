"""
Behavior of the Delphi run-time library that Inno Setup scripts reach through functions which Inno
Setup registers from it, like `format`.
"""
from __future__ import annotations

import enum
import re

from typing import NamedTuple, Sequence


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


class EConvertError(ValueError):
    """
    Delphi's exception for a value that cannot be converted. The function `format` raises it for an
    invalid format and for an argument that is missing or does not fit its format specifier.
    """


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

_FORMAT_SPECIFIER = re.compile(r'(?:(\d+|\*):)?(-)?(\d+|\*)?(?:\.(\*|\d*))?(.)?', re.DOTALL)


def _variant_text(value) -> str:
    if value is None:
        return ''
    return str(value)


def format(fmt: str, args: Sequence[VarRec]) -> str:
    """
    Delphi's `Format` function: Each format specifier has the form

        "%" [index ":"] ["-"] [width] ["." precision] type

    where index, width, and precision are decimal numbers or an asterisk, which takes the number
    from the next argument. The type is one of `d u x s p e f g n m`, in any case, and `%%` writes a
    percent sign. A specifier without an index takes the argument after the one that the previous
    specifier took. Hex digits are upper case, a precision is the minimum number of digits for an
    integer and the maximum length of a string, and the width pads with spaces. The floating-point
    types are converted by the Python format operator with the same type and precision.
    """
    output: list[str] = []
    index = 0
    cursor = 0

    def error(message: str):
        return EConvertError(message % fmt[:31])

    def take() -> VarRec:
        nonlocal index
        if index >= len(args):
            raise error('No argument for format \'%s\'')
        arg = args[index]
        index += 1
        return arg

    def number(spelled: str | None, default: int) -> int:
        if spelled is None:
            return default
        if spelled != '*':
            return int(spelled or '0')
        kind, value = take()
        if kind is not VType.Integer or not isinstance(value, int):
            raise error('Format \'%s\' invalid or incompatible with argument')
        return value

    while (percent := fmt.find('%', cursor)) >= 0:
        output.append(fmt[cursor:percent])
        cursor = percent + 1
        if fmt.startswith('%', cursor):
            output.append('%')
            cursor += 1
            continue
        if (specifier := _FORMAT_SPECIFIER.match(fmt, cursor)) is None:
            raise error('Format \'%s\' invalid or incompatible with argument')
        cursor = specifier.end()
        spelled_index, left, spelled_width, spelled_precision, letter = specifier.groups()
        if letter is None:
            raise error('Format \'%s\' invalid or incompatible with argument')
        index = number(spelled_index, index)
        width = number(spelled_width, 0)
        precision = number(spelled_precision, -1)
        kind, value = take()
        text = _convert(letter, kind, value, precision)
        if text is None:
            raise error('Format \'%s\' invalid or incompatible with argument')
        output.append(text.ljust(width) if left else text.rjust(width))
    output.append(fmt[cursor:])
    return ''.join(output)


def _convert(letter: str, kind: VType, value, precision: int) -> str | None:
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
            text = _variant_text(value)
        else:
            return None
        return text if precision < 0 else text[:precision]
    if conversion == 'P':
        if kind is not VType.Pointer:
            return None
        return F'{value or 0:08X}'
    if conversion in 'EFGNM':
        if kind is not VType.Extended or not isinstance(value, float):
            return None
        spec = letter if precision < 0 else F'.{precision}{letter}'
        try:
            return F'%{spec}' % value
        except ValueError:
            return None
    return None
