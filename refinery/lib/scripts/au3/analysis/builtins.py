"""
The AutoIt3 builtin emulation table: the functions a call folds over when every argument is a
known value. A rule is pinned by the probe outputs in `temp/au3_semantics_probe/` or by the
official docs; a case neither pins is refused — the evaluator answers `None` and the fold leaves
the call standing. The facts a rule rests on are named on the evaluator that applies it.

The binary functions share one string→binary coercion: a `0x…`-shaped string hex-decodes
(probe 100/104), any other ASCII-only string is its own bytes (probe3 43), and everything else
refuses — a number's little-endian int64 bytes (probe3 44) and a non-ASCII string are unpinned.

`Execute` and `Assign` are known builtin names for the transforms' callee gates and the
may-write summaries but have no evaluator: `Execute`'s argument is code rather than data, and
`Assign` writes rather than returns — `refinery.lib.scripts.au3.deobfuscation` owns both
structurally. `IsDeclared` and `IsFunc` read runtime declaration state, and `Eval` and `Call`
have unpinned effects; none of the four is emulated.
"""
from __future__ import annotations

import decimal
import math
import operator
import re

from typing import Callable

from refinery.lib.scripts.au3.analysis.values import (
    HEX_DIGITS,
    Au3Value,
    Kind,
    as_array,
    as_binary,
    as_string,
    of_array,
    of_binary,
    of_bool,
    of_double_result,
    of_int,
    of_int_result,
    of_number,
    of_string,
    to_number,
    to_string,
)

_Evaluator = Callable[[tuple[Au3Value, ...]], Au3Value | None]

_HEX_SHAPE = re.compile(r'0x(?:[0-9a-fA-F]{2})+')

_INT32_MIN = -0x80000000
_INT32_MAX = 0x7FFFFFFF
_UINT32 = 0x100000000
_UINT64 = 0x10000000000000000

#: The bound beyond which an int no longer converts to a double exactly: `Mod`'s integer mode
#: runs through one, so past it the remainder is not a value any probe pinned.
_EXACT_INT = 9007199254740992


def _number_argument(arguments: tuple[Au3Value, ...], index: int) -> int | float | None:
    if index >= len(arguments):
        return None
    return to_number(arguments[index])


def _int_argument(arguments: tuple[Au3Value, ...], index: int) -> int | None:
    number = _number_argument(arguments, index)
    if number is None or not isinstance(number, int):
        return None
    return number


def _optional_int_argument(
    arguments: tuple[Au3Value, ...],
    index: int,
    default: int,
) -> int | None:
    if index >= len(arguments):
        return default
    return _int_argument(arguments, index)


def _to_int32(value: int) -> int:
    """
    The 32-bit signed reading of *value*, the width every bitwise builtin works in: pinned by
    `BitXOR(0xFFFFFFFF, 0)` = -1 and `BitAND(0xFFFFFFFFFFFFFFFF, 0xFF)` = 255.
    """
    masked = value & 0xFFFFFFFF
    return masked - _UINT32 if masked >= 0x80000000 else masked


def _to_int64_signed(value: int) -> int:
    masked = value & 0xFFFFFFFFFFFFFFFF
    return masked - _UINT64 if masked >= 0x8000000000000000 else masked


def _string_bytes(text: str) -> bytes | None:
    """
    The bytes a string-kind argument becomes inside the binary builtins: a `0x…`-shaped string
    hex-decodes, any other ASCII-only string is its own bytes, and a non-ASCII string refuses.
    """
    if _HEX_SHAPE.fullmatch(text):
        return bytes.fromhex(text[2:])
    if not text.isascii():
        return None
    return text.encode('ascii')


def _binary_argument(arguments: tuple[Au3Value, ...], index: int) -> bytes | None:
    if index >= len(arguments):
        return None
    text = as_string(arguments[index])
    if text is not None:
        return _string_bytes(text)
    return as_binary(arguments[index])


def _evaluate_abs(arguments: tuple[Au3Value, ...]) -> Au3Value | None:
    if len(arguments) != 1:
        return None
    number = to_number(arguments[0])
    if number is None:
        return None
    if isinstance(number, int):
        return of_int_result(abs(number))
    return of_double_result(abs(number))


def _evaluate_int(arguments: tuple[Au3Value, ...]) -> Au3Value | None:
    if len(arguments) != 1:
        return None
    number = to_number(arguments[0])
    if number is None:
        return None
    if isinstance(number, int):
        return of_int_result(number)
    return of_int_result(int(number))


def _evaluate_floor(arguments: tuple[Au3Value, ...]) -> Au3Value | None:
    if len(arguments) != 1:
        return None
    number = to_number(arguments[0])
    if number is None:
        return None
    return of_int_result(math.floor(number))


def _evaluate_ceiling(arguments: tuple[Au3Value, ...]) -> Au3Value | None:
    if len(arguments) != 1:
        return None
    number = to_number(arguments[0])
    if number is None:
        return None
    return of_int_result(math.ceil(number))


def _evaluate_number(arguments: tuple[Au3Value, ...]) -> Au3Value | None:
    if len(arguments) != 1:
        return None
    number = to_number(arguments[0])
    if number is None:
        return None
    return of_number(number)


def _evaluate_round(arguments: tuple[Au3Value, ...]) -> Au3Value | None:
    number = _number_argument(arguments, 0)
    digits = _optional_int_argument(arguments, 1, 0)
    if (
        number is None
        or len(arguments) > 2
        or digits is None
        or digits < 0
        or digits > 15
    ):
        return None
    if isinstance(number, int) and digits == 0:
        return of_int_result(number)
    try:
        quantized = decimal.Decimal(number).quantize(
            decimal.Decimal(1).scaleb(-digits), rounding=decimal.ROUND_HALF_UP)
    except decimal.InvalidOperation:
        return None
    return of_double_result(float(quantized))


def _evaluate_sqrt(arguments: tuple[Au3Value, ...]) -> Au3Value | None:
    if len(arguments) != 1:
        return None
    number = to_number(arguments[0])
    if number is None or number < 0:
        return None
    return of_double_result(math.sqrt(number))


def _math_evaluator(function: Callable[[int | float], float]) -> _Evaluator:
    def evaluator(arguments: tuple[Au3Value, ...]) -> Au3Value | None:
        if len(arguments) != 1:
            return None
        number = to_number(arguments[0])
        if number is None:
            return None
        try:
            result = function(number)
        except (ValueError, OverflowError):
            return None
        return of_double_result(result)
    return evaluator


def _evaluate_mod(arguments: tuple[Au3Value, ...]) -> Au3Value | None:
    if len(arguments) != 2:
        return None
    one = to_number(arguments[0])
    two = to_number(arguments[1])
    if one is None or two is None or two == 0:
        return None
    if isinstance(one, int) and isinstance(two, int):
        if abs(one) > _EXACT_INT or abs(two) > _EXACT_INT:
            return None
        return of_int_result(int(math.fmod(one, two)))
    return of_double_result(math.fmod(one, two))


def _bitwise_result(
        arguments: tuple[Au3Value, ...],
        combine: Callable[[int, int], int]) -> Au3Value | None:
    numbers = []
    for argument in arguments:
        number = to_number(argument)
        if number is None or not isinstance(number, int):
            return None
        numbers.append(_to_int32(number))
    if len(numbers) < 2:
        return None
    result = numbers[0]
    for number in numbers[1:]:
        result = combine(result, number)
    return of_int_result(result)


def _evaluate_bitand(arguments: tuple[Au3Value, ...]) -> Au3Value | None:
    return _bitwise_result(arguments, operator.and_)


def _evaluate_bitor(arguments: tuple[Au3Value, ...]) -> Au3Value | None:
    return _bitwise_result(arguments, operator.or_)


def _evaluate_bitxor(arguments: tuple[Au3Value, ...]) -> Au3Value | None:
    return _bitwise_result(arguments, operator.xor)


def _evaluate_bitnot(arguments: tuple[Au3Value, ...]) -> Au3Value | None:
    if len(arguments) != 1:
        return None
    number = to_number(arguments[0])
    if number is None or not isinstance(number, int):
        return None
    return of_int_result(~_to_int32(number))


def _evaluate_bitshift(arguments: tuple[Au3Value, ...]) -> Au3Value | None:
    """
    A 32-bit signed shift: a positive count shifts right arithmetically (probe 73/74 —
    `BitShift(1, 60)` is 0, `BitShift(-1, 1)` is -1), a negative count shifts left and refuses
    when the result leaves int32.
    """
    if len(arguments) != 2:
        return None
    one = to_number(arguments[0])
    two = to_number(arguments[1])
    if (
        one is None
        or two is None
        or not isinstance(one, int)
        or not isinstance(two, int)
    ):
        return None
    value = _to_int32(one)
    if two >= 0:
        return of_int_result(value >> two)
    if value == 0:
        return of_int(0)
    if -two >= 32:
        return None
    result = value << -two
    if result > _INT32_MAX or result < _INT32_MIN:
        return None
    return of_int_result(result)


def _evaluate_bitrotate(arguments: tuple[Au3Value, ...]) -> Au3Value | None:
    """
    A rotate of the low *width* bits, left for a positive count, with a sign-extended result
    only at width 32: pinned by `BitRotate(1, 4)` = 16 (default width 16, default count 1).
    """
    if not 1 <= len(arguments) <= 3:
        return None
    number = _int_argument(arguments, 0)
    shift = _optional_int_argument(arguments, 1, 1)
    width = _optional_int_argument(arguments, 2, 16)
    if number is None or shift is None or width is None or width not in (8, 16, 32):
        return None
    mask = (1 << width) - 1
    value = number & mask
    count = shift % width
    rotated = ((value << count) | (value >> (width - count))) & mask
    if width == 32:
        return of_int_result(_to_int32(rotated))
    return of_int_result(rotated)


def _chr_evaluator(limit: int) -> _Evaluator:
    """
    The character for *number*: above *limit* the empty string, at or below it the uint16 wrap
    (probe2 50-54 — `Chr(-1)` and `ChrW(-1)` are both U+FFFF, `Chr(321)` and `ChrW(65601)` are
    both empty). `Chr(0)` answers the NUL character, which the literal renderer then refuses.
    """
    def evaluator(arguments: tuple[Au3Value, ...]) -> Au3Value | None:
        if len(arguments) != 1:
            return None
        number = to_number(arguments[0])
        if number is None or not isinstance(number, int):
            return None
        if number > limit:
            return of_string('')
        return of_string(chr(number & 0xFFFF))
    return evaluator


def _evaluate_asc(arguments: tuple[Au3Value, ...]) -> Au3Value | None:
    if len(arguments) != 1:
        return None
    text = as_string(arguments[0])
    if text is None or not text:
        return None
    first = text[0]
    if ord(first) > 0x7F:
        return None
    return of_int(ord(first))


def _evaluate_dec(arguments: tuple[Au3Value, ...]) -> Au3Value | None:
    """
    The hex reading of a string: unsigned by default, flag 1 reads the low 32 bits signed
    (`Dec("FFFFFFFF", 1)` = -1), flag 2 the low 64 bits signed (`Dec("FFFFFFFF", 2)` =
    4294967295). Anything but hex digits refuses, as does a value no flag can hold.
    """
    if not 1 <= len(arguments) <= 2:
        return None
    text = as_string(arguments[0])
    flag = _optional_int_argument(arguments, 1, 0)
    if text is None or flag is None or flag not in (0, 1, 2) or not text:
        return None
    if any(character not in HEX_DIGITS for character in text):
        return None
    value = int(text, 16)
    if value > 0xFFFFFFFFFFFFFFFF:
        return None
    if flag == 1:
        return of_int_result(_to_int32(value))
    if flag == 2:
        return of_int_result(_to_int64_signed(value))
    return of_int_result(value)


def _evaluate_hex(arguments: tuple[Au3Value, ...]) -> Au3Value | None:
    """
    The unsigned 64-bit hex of a number: eight digits by default when the value fits signed
    int32 and sixteen otherwise, an explicit length zero-padding on the left or keeping the
    rightmost digits (all seven pinned facts, probe 86-87 and probe3 20-24). A length above
    sixteen is not a reading any probe pinned, so it refuses rather than spell an unbounded
    string of zeroes.
    """
    if not 1 <= len(arguments) <= 2:
        return None
    number = _int_argument(arguments, 0)
    if number is None:
        return None
    unsigned = number & 0xFFFFFFFFFFFFFFFF
    if len(arguments) == 2:
        length = _int_argument(arguments, 1)
        if length is None or not 1 <= length <= 16:
            return None
    else:
        length = 8 if _INT32_MIN <= number <= _INT32_MAX else 16
    return of_string(F'{unsigned:016X}'[16 - length:])


def _evaluate_string(arguments: tuple[Au3Value, ...]) -> Au3Value | None:
    if len(arguments) != 1:
        return None
    text = to_string(arguments[0])
    if text is None:
        return None
    return of_string(text)


def _evaluate_stringlen(arguments: tuple[Au3Value, ...]) -> Au3Value | None:
    if len(arguments) != 1:
        return None
    text = as_string(arguments[0])
    if text is None:
        return None
    return of_int(len(text))


def _slice_evaluator(take: Callable[[str, int], str]) -> _Evaluator:
    """
    The substring builtin family: the text and a non-negative count, answering *take* of the two.
    """
    def evaluator(arguments: tuple[Au3Value, ...]) -> Au3Value | None:
        if len(arguments) != 2:
            return None
        text = as_string(arguments[0])
        count = _int_argument(arguments, 1)
        if text is None or count is None or count < 0:
            return None
        return of_string(take(text, count))
    return evaluator


_evaluate_stringleft = _slice_evaluator(lambda text, count: text[:count])
_evaluate_stringright = _slice_evaluator(lambda text, count: text[max(0, len(text) - count):])
_evaluate_stringtrimleft = _slice_evaluator(lambda text, count: text[count:])
_evaluate_stringtrimright = _slice_evaluator(lambda text, count: text[:max(0, len(text) - count)])


def _evaluate_stringmid(arguments: tuple[Au3Value, ...]) -> Au3Value | None:
    if not 2 <= len(arguments) <= 3:
        return None
    text = as_string(arguments[0])
    start = _int_argument(arguments, 1)
    if text is None or start is None or start < 1:
        return None
    if len(arguments) == 3:
        count = _int_argument(arguments, 2)
        if count is None or count < 0:
            return None
        return of_string(text[start - 1:start - 1 + count])
    return of_string(text[start - 1:])


def _evaluate_stringupper(arguments: tuple[Au3Value, ...]) -> Au3Value | None:
    if len(arguments) != 1:
        return None
    text = as_string(arguments[0])
    if text is None or not text.isascii():
        return None
    return of_string(text.upper())


def _evaluate_stringlower(arguments: tuple[Au3Value, ...]) -> Au3Value | None:
    if len(arguments) != 1:
        return None
    text = as_string(arguments[0])
    if text is None or not text.isascii():
        return None
    return of_string(text.lower())


def _evaluate_stringinstr(arguments: tuple[Au3Value, ...]) -> Au3Value | None:
    """
    The 1-based position of a needle, 0 when absent, case-insensitive by default and under
    flag 1 case-sensitive (probe 91-92, probe2 30-32). The case-insensitive search is ASCII-only:
    how AutoIt lowercases text beyond ASCII is not a fact any probe pinned.
    """
    if not 2 <= len(arguments) <= 3:
        return None
    haystack = as_string(arguments[0])
    needle = as_string(arguments[1])
    flag = _optional_int_argument(arguments, 2, 0)
    if haystack is None or needle is None or flag not in (0, 1) or not needle:
        return None
    if flag == 1:
        position = haystack.find(needle)
    elif haystack.isascii() and needle.isascii():
        position = haystack.lower().find(needle.lower())
    else:
        return None
    return of_int(position + 1)


def _evaluate_stringreplace(arguments: tuple[Au3Value, ...]) -> Au3Value | None:
    if not 3 <= len(arguments) <= 4:
        return None
    text = as_string(arguments[0])
    search = as_string(arguments[1])
    replacement = as_string(arguments[2])
    flag = _optional_int_argument(arguments, 3, 0)
    if (
        text is None
        or search is None
        or replacement is None
        or flag is None
        or flag not in (0, 1)
        or not search
        or not text.isascii()
        or not search.isascii()
        or not replacement.isascii()
    ):
        return None
    if flag == 1:
        return of_string(text.replace(search, replacement))
    pattern = re.escape(search)
    return of_string(re.sub(
        pattern,
        replacement.replace('\\', '\\\\'),
        text,
        flags=re.IGNORECASE,
    ))


def _evaluate_stringreverse(arguments: tuple[Au3Value, ...]) -> Au3Value | None:
    if len(arguments) != 1:
        return None
    text = as_string(arguments[0])
    if text is None:
        return None
    return of_string(text[::-1])


def _evaluate_stringsplit(arguments: tuple[Au3Value, ...]) -> Au3Value | None:
    """
    The array `StringSplit` builds: the delimiter a character set under the default flag, an
    empty delimiter one element per character (probe2 61), an empty input a single empty element
    (probe 122, probe2 60), the element count in `[0]` unless flag 2 drops it (probe 120-121).
    """
    if not 2 <= len(arguments) <= 3:
        return None
    text = as_string(arguments[0])
    delimiter = as_string(arguments[1])
    flag = _optional_int_argument(arguments, 2, 0)
    if text is None or delimiter is None or flag is None or flag not in (0, 2):
        return None
    if not text:
        parts = ['']
    elif not delimiter:
        parts = list(text)
    else:
        parts = re.split('[' + re.escape(delimiter) + ']', text)
    if flag == 2:
        return of_array(tuple(of_string(part) for part in parts))
    return of_array((
        of_int(len(parts)),
        *(of_string(part) for part in parts)
    ))


def _evaluate_binary(arguments: tuple[Au3Value, ...]) -> Au3Value | None:
    if len(arguments) != 1:
        return None
    text = as_string(arguments[0])
    if text is None:
        return None
    data = _string_bytes(text)
    if data is None:
        return None
    return of_binary(data)


def _evaluate_binarylen(arguments: tuple[Au3Value, ...]) -> Au3Value | None:
    if len(arguments) != 1:
        return None
    data = as_binary(arguments[0])
    if data is None:
        return None
    return of_int(len(data))


def _evaluate_binarymid(arguments: tuple[Au3Value, ...]) -> Au3Value | None:
    if not 2 <= len(arguments) <= 3:
        return None
    data = as_binary(arguments[0])
    start = _int_argument(arguments, 1)
    if data is None or start is None or start < 1:
        return None
    if len(arguments) == 3:
        count = _int_argument(arguments, 2)
        if count is None or count < 0:
            return None
        return of_binary(data[start - 1:start - 1 + count])
    return of_binary(data[start - 1:])


def _evaluate_binarytostring(arguments: tuple[Au3Value, ...]) -> Au3Value | None:
    """
    The string the argument's bytes spell: flag 1 (the default) ASCII, refusing any byte at or
    above `0x80`; flag 2 UTF-16-LE, refusing an odd byte count (probe 100/104).
    """
    if not 1 <= len(arguments) <= 2:
        return None
    data = _binary_argument(arguments, 0)
    flag = _optional_int_argument(arguments, 1, 1)
    if data is None or flag is None or flag not in (1, 2):
        return None
    if flag == 2:
        if len(data) % 2:
            return None
        try:
            return of_string(data.decode('utf-16-le'))
        except UnicodeDecodeError:
            return None
    if any(byte >= 0x80 for byte in data):
        return None
    return of_string(data.decode('ascii'))


def _evaluate_stringtobinary(arguments: tuple[Au3Value, ...]) -> Au3Value | None:
    if not 1 <= len(arguments) <= 2:
        return None
    text = as_string(arguments[0])
    flag = _optional_int_argument(arguments, 1, 1)
    if text is None or flag is None or flag not in (1, 2):
        return None
    if flag == 2:
        try:
            return of_binary(text.encode('utf-16-le'))
        except UnicodeEncodeError:
            return None
    data = _string_bytes(text)
    if data is None:
        return None
    return of_binary(data)


def _evaluate_ubound(arguments: tuple[Au3Value, ...]) -> Au3Value | None:
    if not 1 <= len(arguments) <= 2:
        return None
    elements = as_array(arguments[0])
    dimension = _optional_int_argument(arguments, 1, 1)
    if elements is None or dimension != 1:
        return None
    return of_int(len(elements))


def _is_evaluator(kinds: frozenset[Kind]) -> _Evaluator:
    def evaluator(arguments: tuple[Au3Value, ...]) -> Au3Value | None:
        if len(arguments) != 1:
            return None
        return of_bool(arguments[0].kind in kinds)
    return evaluator


def _evaluate_never(arguments: tuple[Au3Value, ...]) -> Au3Value | None:
    """
    The answer for `IsKeyword`, `IsObj`, `IsHWnd`, and `IsPtr` over any value this domain can
    hold: none of the four can appear in a folded constant.
    """
    if len(arguments) != 1:
        return None
    return of_bool(False)


_EVALUATORS: dict[str, _Evaluator] = {
    'abs'             : _evaluate_abs,
    'int'             : _evaluate_int,
    'floor'           : _evaluate_floor,
    'ceiling'         : _evaluate_ceiling,
    'number'          : _evaluate_number,
    'round'           : _evaluate_round,
    'sqrt'            : _evaluate_sqrt,
    'sin'             : _math_evaluator(math.sin),
    'cos'             : _math_evaluator(math.cos),
    'tan'             : _math_evaluator(math.tan),
    'asin'            : _math_evaluator(math.asin),
    'acos'            : _math_evaluator(math.acos),
    'atan'            : _math_evaluator(math.atan),
    'exp'             : _math_evaluator(math.exp),
    'log'             : _math_evaluator(math.log),
    'mod'             : _evaluate_mod,
    'bitand'          : _evaluate_bitand,
    'bitor'           : _evaluate_bitor,
    'bitxor'          : _evaluate_bitxor,
    'bitnot'          : _evaluate_bitnot,
    'bitshift'        : _evaluate_bitshift,
    'bitrotate'       : _evaluate_bitrotate,
    'chr'             : _chr_evaluator(255),
    'chrw'            : _chr_evaluator(65535),
    'asc'             : _evaluate_asc,
    'dec'             : _evaluate_dec,
    'hex'             : _evaluate_hex,
    'string'          : _evaluate_string,
    'stringlen'       : _evaluate_stringlen,
    'stringleft'      : _evaluate_stringleft,
    'stringright'     : _evaluate_stringright,
    'stringtrimleft'  : _evaluate_stringtrimleft,
    'stringtrimright' : _evaluate_stringtrimright,
    'stringmid'       : _evaluate_stringmid,
    'stringupper'     : _evaluate_stringupper,
    'stringlower'     : _evaluate_stringlower,
    'stringinstr'     : _evaluate_stringinstr,
    'stringreplace'   : _evaluate_stringreplace,
    'stringreverse'   : _evaluate_stringreverse,
    'stringsplit'     : _evaluate_stringsplit,
    'binary'          : _evaluate_binary,
    'binarylen'       : _evaluate_binarylen,
    'binarymid'       : _evaluate_binarymid,
    'binarytostring'  : _evaluate_binarytostring,
    'stringtobinary'  : _evaluate_stringtobinary,
    'ubound'          : _evaluate_ubound,
    'isarray'         : _is_evaluator(frozenset({Kind.ARRAY})),
    'isbinary'        : _is_evaluator(frozenset({Kind.BINARY})),
    'isbool'          : _is_evaluator(frozenset({Kind.BOOL})),
    'isint'           : _is_evaluator(frozenset({Kind.INT})),
    'isfloat'          : _is_evaluator(frozenset({Kind.DOUBLE})),
    'isnumber'        : _is_evaluator(frozenset({Kind.INT, Kind.DOUBLE})),
    'isstring'        : _is_evaluator(frozenset({Kind.STRING})),
    'iskeyword'       : _evaluate_never,
    'isobj'           : _evaluate_never,
    'ishwnd'          : _evaluate_never,
    'isptr'           : _evaluate_never,
}

#: Every builtin the pipeline knows by name: the emulated functions above plus `Execute` and
#: `Assign`, which the transforms resolve structurally and never fold as a value — `Execute`'s
#: argument is code, and `Assign`'s effect is a write the may-write summaries read.
BUILTIN_NAMES = frozenset(_EVALUATORS) | {'execute', 'assign'}


def evaluate_builtin(name: str, arguments: tuple[Au3Value, ...]) -> Au3Value | None:
    """
    The value builtin *name* returns over *arguments*: `None` when the builtin is not emulated,
    the arity is wrong, or an argument sits outside the builtin's pinned domain — every refusal
    leaves the call standing.
    """
    evaluator = _EVALUATORS.get(name)
    if evaluator is None:
        return None
    return evaluator(arguments)
