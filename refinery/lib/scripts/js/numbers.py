"""
The JavaScript Number value domain. A Number is an IEEE-754 double, so the Python type that models
one is `float` and nothing else: `float` arithmetic *is* double arithmetic, whereas Python's `int` is
an arbitrary-precision integer whose arithmetic silently disagrees with the language everywhere past
2^53. Holding a Number as an `int` therefore does not merely spell a value differently, it computes
different answers, which is why the coercion lives here and is applied where a Number enters the tree
rather than at the places that happen to have been noticed.

This module sits beside `model.py` and `token.py` because what a Number is, how it prints, and which
Number a piece of text names are properties of the language rather than of any one pass over a
program. Both directions live here so that neither is written twice: a fold and an emulated execution
that disagreed about `Number('1e3')` would each be reading a grammar of its own.
"""
from __future__ import annotations

import math
import re

from decimal import Decimal

from refinery.lib.scripts.js.token import LINE_TERMINATORS, WHITESPACE


def to_js_number(value: int | float) -> float:
    """
    Coerce a Python number to the JavaScript Number it denotes. An integer too large for a double
    becomes an infinity, which is what the language does with a numeric literal of that magnitude —
    `1e400` is `Infinity` in JavaScript, and so is a literal written out with 400 digits.
    """
    try:
        return float(value)
    except OverflowError:
        return float('-inf') if value < 0 else float('inf')


TRIMMABLE_WHITESPACE = WHITESPACE + LINE_TERMINATORS
"""
The characters ECMA-262 TrimString removes: WhiteSpace plus the line terminators. It is what a
string may be padded with and still name a Number, and it is equally what `String.prototype.trim`
takes off, one set, because the specification defines the second in terms of the first.

It is the union of the two lexical productions rather than a list of its own, so that the set the
lexer skips between tokens and the set a Number tolerates around itself cannot drift apart; they are
the same characters read for two purposes. Neither is `str.strip`'s notion of a space, which is a
third set: Python takes `U+001C` through `U+001F`, which JavaScript does not, and leaves `U+FEFF`,
which JavaScript takes.
"""


def is_negative_zero(value: float) -> bool:
    """
    Whether *value* is negative zero. It is the one Number that neither `==` nor
    `js_number_to_string` can tell from its positive counterpart, so any code that must preserve it
    has to ask for the sign directly; `1 / -0` is `-Infinity` where `1 / 0` is `Infinity`.
    """
    return value == 0 and math.copysign(1.0, value) < 0


ARRAY_INDEX_LIMIT = 0xFFFFFFFF
"""
One past the largest array index. An array's length is a `uint32`, so the largest index one can hold
is `2**32 - 2` and the spelling `'4294967295'` names an ordinary property of the array object.
"""

_ARRAY_INDEX_DIGITS = len(str(ARRAY_INDEX_LIMIT))


def canonical_array_index(key: str) -> int | None:
    """
    The integer index *key* denotes as an array index, or `None` when it is not one. JavaScript treats
    a property key as an index only when it is the canonical decimal spelling of a non-negative
    integer below `ARRAY_INDEX_LIMIT`, so `'1'` indexes but `'+1'`, `'01'`, `'1.0'`, `' 1 '`, `'1_0'`,
    and `'0x1'` are ordinary property names that resolve to `undefined`. Python's `int` accepts every
    one of those spellings, and `str.isdigit` additionally accepts non-ASCII digits such as `'²'`, so
    neither is usable alone.

    The upper bound belongs to the definition rather than guarding against large numbers. A key at or
    above it is a property name, which is stored where an index is not, enumerates with the names
    rather than ahead of them, and does not move the array's length. Reading it as an index answers a
    different question about a different slot.

    The digit count is tested before the value because a key is arbitrary program text: converting a
    numeral of a few thousand digits raises rather than answers, and no such spelling could name an
    index in any case.
    """
    if not key or len(key) > _ARRAY_INDEX_DIGITS or not all(c in '0123456789' for c in key):
        return None
    index = int(key)
    if str(index) != key or index >= ARRAY_INDEX_LIMIT:
        return None
    return index


def exact_integer(value: int | float) -> int | None:
    """
    The integer *value* is, or `None` when it is not one. A consumer that needs a Python `int` — an
    index, a count, a radix — must ask this rather than call `int` on the Number, because the domain
    contains `NaN` and the infinities, on which `int` raises rather than answers.
    """
    if not math.isfinite(value):
        return None
    integer = int(value)
    return integer if integer == value else None


def apply_sign(magnitude: float, negative: bool) -> float:
    """
    The Number of the given *magnitude* carrying the sign that *negative* names. Zero decides how
    this has to be written: Python's integers have a single zero, so a sign carried through them is
    lost exactly where JavaScript keeps it, and `Number('-0')` and `parseInt('-0')` are both `-0`.
    """
    return math.copysign(magnitude, -1.0 if negative else 1.0)


_STR_DECIMAL_LITERAL = re.compile(
    r'[+-]?(?:'
    r'Infinity'
    r'|[0-9]+\.[0-9]*(?:[eE][+-]?[0-9]+)?'
    r'|\.[0-9]+(?:[eE][+-]?[0-9]+)?'
    r'|[0-9]+(?:[eE][+-]?[0-9]+)?'
    r')'
)
"""
The ECMA-262 StrDecimalLiteral production, transcribed. Three of its properties are the ones a hand
written scan gets wrong. The sign is consumed once, ahead of the alternation, because `Infinity`
belongs to the unsigned production and a sign read inside it would leave `-Infinity` naming nothing.
An exponent that is begun and not finished is not an error but a shorter literal, so `1e+` names the
same Number as `1`; the engine supplies that backtracking. And a decimal digit is `0` through `9`
alone, never `str.isdigit`, which is true of every Unicode digit and of the superscripts.

The alternatives are ordered rather than longest-match, and the order that is correct is the
specification's own: the two that begin with a digit are tried with the fraction first, and a
fraction is never shorter than the integer part it extends.
"""

_NON_DECIMAL_INTEGER = re.compile(r'0[bB][01]+|0[oO][0-7]+|0[xX][0-9a-fA-F]+')
"""
The ECMA-262 NonDecimalIntegerLiteral production, in the form StrNumericLiteral admits it: with the
numeric separator forbidden, and with no sign, since the sign belongs to the decimal alternative.
"""

_PREFIXED_RADIX = {'b': 2, 'o': 8, 'x': 16}
"""
The base each NonDecimalIntegerLiteral prefix letter selects.
"""

_MAX_DIGITS_IN_A_DOUBLE = {
    radix: math.ceil(1024 / math.log2(radix)) for radix in range(2, 37)
}
"""
Per radix, the digit count past which a written-out integer is certainly outside the double range
and so denotes an infinity. Answering from the count rather than from the value keeps `parseInt`
total: building the integer first would make it hostage to CPython's limit on converting a long
decimal string, which raises rather than returning the `Infinity` the language specifies.
"""


def _denotes_an_infinity(digits: str, radix: int) -> bool:
    """
    Whether a run of *digits* read in *radix* is certainly outside the double range, and so denotes
    an infinity rather than a Number. The leading zeros are no digits of the number they precede, so
    they are taken off before the count is read; taking them off is what a short literal would pay
    for, and it is asked for only once the whole run is already long enough to be worth asking about.
    """
    limit = _MAX_DIGITS_IN_A_DOUBLE[radix]
    return len(digits) > limit and len(digits.lstrip('0')) > limit


def _decimal_literal(match: re.Match[str] | None) -> float | None:
    """
    The Number named by a StrDecimalLiteral that `_STR_DECIMAL_LITERAL` has matched, and `None` when
    it matched none. Which match is asked for is the whole difference between the two readers of the
    production: `Number` reads the string it is given and so asks for a `fullmatch`, where
    `parseFloat` reads what the string begins with and so asks for a `match`.

    The matched text goes to Python's `float`, which reads it identically, because the grammar has
    already excluded every spelling on which the two disagree: `inf`, `nan`, the numeric separator,
    and the Unicode digits outside `0` through `9`. `Infinity` is the one alternative that never
    reaches `float`, the language and Python spelling that value differently. The digits are not
    truncated first — `float` is linear in them, and shortening them would move the rounding that
    makes `5e-324` and `1e309` come out at all.
    """
    if match is None:
        return None
    literal = match[0]
    negative = literal[0] == '-'
    magnitude = literal[1:] if literal[0] in '+-' else literal
    return apply_sign(float('inf') if magnitude == 'Infinity' else float(magnitude), negative)


def integer_of_numeral(digits: str) -> int:
    """
    The integer a NumericLiteral spells once its separators and any BigInt suffix are gone: the
    digits behind a `0x`, `0o` or `0b` prefix in that base, a `0`-led run of octal digits as the
    legacy octal literal it is, and anything else in base ten.
    """
    if len(digits) > 1 and digits[0] == '0':
        radix = _PREFIXED_RADIX.get(digits[1].lower())
        if radix is not None:
            return int(digits[2:], radix)
        if all(d in '01234567' for d in digits):
            return int(digits, 8)
    return int(digits)


def number_of_numeral(digits: str) -> float:
    """
    The Number a NumericLiteral spells once its separators are gone. A decimal spelling goes to
    `float` as it stands, which is linear in the digits and answers an infinity past the double
    range, where building the integer first would run into the interpreter's limit on the digits
    of a decimal conversion and raise for a literal the language reads. A prefixed or legacy octal
    spelling has no such limit and is read as the integer it is.
    """
    if len(digits) > 1 and digits[0] == '0' and (
        digits[1].lower() in _PREFIXED_RADIX
        or all(d in '01234567' for d in digits)
    ):
        return to_js_number(integer_of_numeral(digits))
    return float(digits)


def _read_non_decimal_integer(text: str) -> float | None:
    """
    The Number named by *text* when the whole of it is a NonDecimalIntegerLiteral, and `None`
    otherwise. Because this alternative carries neither a sign nor a numeric separator,
    `Number('-0x10')` and `Number('0x1_0')` are both `NaN`, where the same text is a perfectly good
    numeric literal in source and a perfectly good expression at runtime.

    Once the production has matched, the text is also a Python integer literal, so the base it names
    is read by asking for base zero rather than by decoding the prefix a second time.

    The digit count is answered before the integer is built, as `js_parse_int` answers it: a
    literal past the double range denotes an infinity, and building it first spends the length of
    the text to produce a value that is discarded.
    """
    if _NON_DECIMAL_INTEGER.fullmatch(text) is None:
        return None
    if _denotes_an_infinity(text[2:], _PREFIXED_RADIX[text[1].lower()]):
        return float('inf')
    return to_js_number(int(text, 0))


def js_string_to_number(text: str) -> float:
    """
    Apply the ECMA-262 StringToNumber abstract operation, which is the Number that `Number(string)`
    answers. The whole of the string, once its padding is removed, has to be a StrNumericLiteral: a
    literal the text merely begins with is not an answer here, so `Number('1x')` is `NaN` where
    `parseFloat('1x')` is `1`. Padding and nothing else names zero.
    """
    text = text.strip(TRIMMABLE_WHITESPACE)
    if not text:
        return 0.0
    integer = _read_non_decimal_integer(text)
    if integer is not None:
        return integer
    value = _decimal_literal(_STR_DECIMAL_LITERAL.fullmatch(text))
    return float('nan') if value is None else value


def js_parse_float(text: str) -> float:
    """
    Apply the `parseFloat` global function to a string. It reads the longest prefix of the text that
    is a StrDecimalLiteral and disregards the rest, so it answers a Number for text that only begins
    as one, and `NaN` only for text that does not begin as one at all. It reads no
    NonDecimalIntegerLiteral, which is why `parseFloat('0x10')` is `0`, stopped at the `x`.
    """
    value = _decimal_literal(_STR_DECIMAL_LITERAL.match(text.lstrip(TRIMMABLE_WHITESPACE)))
    return float('nan') if value is None else value


def js_parse_int(text: str, radix: int = 0) -> float | None:
    """
    Replicate the semantics of JavaScript's `parseInt(string, radix)`. Strips leading whitespace,
    handles an optional `+`/`-` sign, and skips a leading `0x`/`0X` prefix for radix 16. Parses
    leading characters valid for the given radix (2-36) and stops at the first invalid one. Returns
    `None` when no valid digits are found (JS would return `NaN`).

    A radix of `0` is the language's "not supplied" — `parseInt(s)` and `parseInt(s, 0)` are the
    same call — and it is not a synonym for 10: an unsupplied radix reads a `0x` prefix as selecting
    base 16, so `parseInt('0x1f')` is `31`. A caller that defaults the radix to 10 instead answers
    `0` for that string, having stopped at the `x`.

    The digits are accumulated exactly and only then coerced, because `parseInt` reads the whole
    digit string before producing a Number: enough digits and the result is `Infinity`, and a digit
    string past 2^53 names the nearest double rather than itself. The count is answered as soon as it
    passes the bound, and the leading zeros are taken off ahead of the scan rather than tested for
    inside it, so a digit string of any length costs what its significant prefix costs rather than
    what it is. A zero is a digit in every radix this reads, which is what makes that legitimate.
    """
    text = text.strip(TRIMMABLE_WHITESPACE)
    if not text:
        return None
    negative = False
    if text[0] in '+-':
        negative = text[0] == '-'
        text = text[1:]
    hex_prefixed = len(text) >= 2 and text[0] == '0' and text[1] in 'xX'
    if radix == 0:
        radix = 16 if hex_prefixed else 10
    if not (2 <= radix <= 36):
        return None
    if radix == 16 and hex_prefixed:
        text = text[2:]
    significant = text.lstrip('0')
    scanned = len(significant) < len(text)
    limit = _MAX_DIGITS_IN_A_DOUBLE[radix]
    digits: list[str] = []
    for ch in significant:
        if '0' <= ch <= '9':
            if ord(ch) - ord('0') >= radix:
                break
        elif 'a' <= ch <= 'z' or 'A' <= ch <= 'Z':
            if ord(ch.lower()) - ord('a') + 10 >= radix:
                break
        else:
            break
        scanned = True
        digits.append(ch)
        if len(digits) > limit:
            return apply_sign(float('inf'), negative)
    if not scanned:
        return None
    return apply_sign(to_js_number(int(''.join(digits) or '0', radix)), negative)


def _significant_digits_to_string(value: float) -> str:
    """
    Format a finite, non-zero double as the ECMA-262 Number::toString algorithm would. That
    algorithm is stated over the *shortest* decimal digit string that round-trips to the double,
    which is what Python's `repr` produces; the exact mathematical value would carry digits past the
    ones the double determines, and no engine prints those. This also controls the
    decimal/exponential cutoff (exponential at magnitudes >= 1e21 or < 1e-6) and the exponent format
    (`1e-7`, not Python's `1e-07`).
    """
    negative = value < 0
    decimal = Decimal(repr(abs(value)))
    digits = ''.join(str(digit) for digit in decimal.as_tuple().digits).rstrip('0') or '0'
    count = len(digits)
    point = decimal.adjusted() + 1
    if count <= point <= 21:
        result = digits + '0' * (point - count)
    elif 0 < point <= 21:
        result = digits[:point] + '.' + digits[point:]
    elif -6 < point <= 0:
        result = '0.' + '0' * -point + digits
    else:
        mantissa = digits if count == 1 else digits[0] + '.' + digits[1:]
        exponent = point - 1
        result = F"{mantissa}e{'+' if exponent >= 0 else '-'}{abs(exponent)}"
    return F'-{result}' if negative else result


def js_number_to_string(value: int | float) -> str:
    """
    Apply `Number.prototype.toString` to a Number. Total over the domain, including the values that
    have no literal spelling: `NaN`, the infinities, and negative zero, which prints as `0` because
    the algorithm reads the mathematical value and the sign of a zero is not part of it.

    A `repr` that ends in `.0` is already the answer: Python writes a double positionally only below
    1e16, so such a value is an integer that the shortest round-tripping digits spell in full, which
    is the same branch of the algorithm `_significant_digits_to_string` would take. Spelling it as
    `int(value)` instead would be wrong past 2^53, where the double's exact value has more digits
    than it determines — `2 ** 60` is `1152921504606847000`, not `1152921504606846976`.

    That reasoning is also why a Python `int` is coerced here rather than refused. This module
    exists because integers leak in, and an integer arriving with more digits than a double
    determines is exactly the case the paragraph above describes: it has to print as the Number it
    denotes, not as itself.
    """
    if not isinstance(value, float):
        value = to_js_number(value)
    if value != value:
        return 'NaN'
    if value == float('inf'):
        return 'Infinity'
    if value == float('-inf'):
        return '-Infinity'
    if value == 0:
        return '0'
    plain = repr(value)
    if plain.endswith('.0'):
        return plain[:-2]
    return _significant_digits_to_string(value)
