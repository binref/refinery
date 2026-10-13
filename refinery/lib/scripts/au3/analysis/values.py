"""
The AutoIt3 value domain: the kinds a value can have, the coercions between them, and the result
of every operator over known values. Operator semantics live here and nowhere else.

The source of truth is a probe of the real interpreter (AutoIt 3.3.18.0; the probe scripts and
their outputs in `temp/au3_semantics_probe/`), then the official docs, then nothing: a rule
neither of those pins is refused rather than guessed, so an unpinned operator returns `None` and
the fold that asked leaves the expression standing. Which cases are refused is documented on
the operator that refuses them.

The domain keeps int and double distinct because AutoIt prints them differently at magnitude
`1e15` and above: an int64 prints its full digits while a double goes scientific. All-digit
decimal literals saturate at int64 max (probe3 60), and arithmetic that leaves the int64 range
is refused (probe3 63 keeps `99999999999999999999 + 0` an int) — whether AutoIt wraps or
promotes on int64 overflow is not a fact any probe pinned, so the fold declines rather than
print a digit the interpreter might not.
"""
from __future__ import annotations

import enum
import math
import re

from dataclasses import dataclass
from typing import cast

from refinery.lib.scripts import Node
from refinery.lib.scripts.au3 import ast
from refinery.lib.scripts.au3.lexer import LINE_BREAKS, encode_au3_string
from refinery.lib.scripts.au3.limits import MAX_PIECE_SPELLING
from refinery.lib.scripts.au3.model import (
    Au3ArrayLiteral,
    Au3BinaryExpression,
    Au3BooleanLiteral,
    Au3Call,
    Au3FloatLiteral,
    Au3Identifier,
    Au3IntLiteral,
    Au3Macro,
    Au3StringLiteral,
    Au3UnaryExpression,
    Expression,
)

#: The int64 bounds of the domain: an int result outside them is refused, because whether AutoIt
#: wraps or promotes on int64 overflow is not a fact any probe pinned.
INT64_MIN = -0x8000000000000000
INT64_MAX = 0x7FFFFFFFFFFFFFFF

#: The most decimal digits an int64 magnitude spells: a longer run is out of range without being
#: converted, a conversion Python refuses past its integer string-digit limit.
_INT64_DIGITS = len(str(INT64_MAX))

#: The hex digits, shared with the builtin table's `Dec` reader: the one alphabet both spell and
#: read a `0x…` payload in.
HEX_DIGITS = frozenset('0123456789abcdefABCDEF')

#: The decimal digits of a number's text: `str.isdigit` admits the non-ASCII digits of other
#: scripts, whose numeric value AutoIt's reader never pinned, so only these parse.
ASCII_DIGITS = frozenset('0123456789')

#: The characters no AutoIt string literal can express: `encode_au3_string` escapes only the
#: quote, and a line break — every character the lexer ends a literal on — ends the literal
#: itself, so a result carrying any of these never folds. A surrogate has no encoding at all and
#: would break the synthesizer's output stream.
_UNSPELLABLE = re.compile('[\x00\ud800-\udfff' + re.escape(''.join(LINE_BREAKS)) + ']')


def _spellable(text: str) -> bool:
    return _UNSPELLABLE.search(text) is None


#: The macros that are the same in every run of every script (docs-pinned). Every other macro
#: depends on the machine, the process, or the moment and is unknown in this domain.
MACRO_CONSTANTS = {
    'cr'  : '\r',
    'lf'  : '\n',
    'crlf': '\r\n',
    'tab' : '\t',
}


class Kind(enum.Enum):
    """
    The AutoIt3 types a folded value can carry. `UNKNOWN` is the absence of knowledge, not the
    keyword `Null`, which this phase does not model.
    """
    UNKNOWN = enum.auto()
    INT = enum.auto()
    DOUBLE = enum.auto()
    STRING = enum.auto()
    BOOL = enum.auto()
    BINARY = enum.auto()
    ARRAY = enum.auto()


@dataclass(frozen=True)
class Au3Value:
    """
    One AutoIt3 value: a kind and its payload — `int`, `float`, `str`, `bool`, `bytes`, or a tuple
    of `Au3Value` for an array. Values are compared by kind and payload, so two folds that reach
    the same value agree. Construct one through the `of_*` functions rather than directly: they
    are where the invariants live (an `INT` within int64, a finite `DOUBLE`).
    """
    kind: Kind = Kind.UNKNOWN
    payload: object = None


def of_int(value: int) -> Au3Value:
    return Au3Value(Kind.INT, value)


def of_double(value: float) -> Au3Value:
    return Au3Value(Kind.DOUBLE, value)


def of_string(value: str) -> Au3Value:
    return Au3Value(Kind.STRING, value)


def of_bool(value: bool) -> Au3Value:
    return Au3Value(Kind.BOOL, value)


def of_binary(value: bytes) -> Au3Value:
    return Au3Value(Kind.BINARY, value)


def of_array(elements: tuple[Au3Value, ...]) -> Au3Value:
    return Au3Value(Kind.ARRAY, elements)


def of_number(value: int | float) -> Au3Value:
    if isinstance(value, bool) or isinstance(value, int):
        return of_int(value)
    return of_double(value)


def as_string(value: Au3Value) -> str | None:
    if value.kind is Kind.STRING:
        return cast(str, value.payload)
    return None


def as_bool(value: Au3Value) -> bool | None:
    if value.kind is Kind.BOOL:
        return cast(bool, value.payload)
    return None


def as_binary(value: Au3Value) -> bytes | None:
    if value.kind is Kind.BINARY:
        return cast(bytes, value.payload)
    return None


def as_array(value: Au3Value) -> tuple[Au3Value, ...] | None:
    if value.kind is Kind.ARRAY:
        return cast(tuple[Au3Value, ...], value.payload)
    return None


def format_double(value: float) -> str | None:
    """
    The text AutoIt prints a double as: `%.15g`, verified against every probe fact — `1.0` prints
    `1`, `1/3` prints `0.333333333333333`, `0.1 + 0.2` prints `0.3`, `1e15` prints `1e+15`. A
    non-finite double has no text any AutoIt literal spells and answers `None`.
    """
    if not math.isfinite(value):
        return None
    return F'{value:.15g}'


def to_string(value: Au3Value) -> str | None:
    """
    The string a value becomes under `&`, `String`, and the `==` comparison's boolean mode. A
    binary renders as its `0x`-prefixed uppercase hex; an array and an unknown have no single text.
    """
    if value.kind is Kind.INT:
        return str(cast(int, value.payload))
    if value.kind is Kind.DOUBLE:
        return format_double(cast(float, value.payload))
    if value.kind is Kind.STRING:
        return cast(str, value.payload)
    if value.kind is Kind.BOOL:
        return 'True' if value.payload else 'False'
    if value.kind is Kind.BINARY:
        return '0x' + cast(bytes, value.payload).hex().upper()
    return None


def _prefix_number(text: str) -> int | float | None:
    """
    The number AutoIt reads off the front of `text`: whitespace skipped, optional sign, a hex
    literal `0x…` or a decimal with optional fraction and exponent, each form backtracking to the
    shorter prefix when it is incomplete (`"1e"` is 1, `"0x"` is 0), and 0 when nothing parses.
    Only ASCII digits parse — the digits of other scripts are not a reading any probe pinned.
    An all-digit prefix beyond int64 is refused: whether AutoIt saturates or promotes there is
    not a fact any probe pinned either. Pinned by probe3 50-57 and probe 60-68.
    """
    length = len(text)
    i = 0
    while i < length and text[i] in ' \t\r\n\f\v':
        i += 1
    start = i
    if i < length and text[i] in '+-':
        i += 1
    if text[i:i + 2].lower() == '0x':
        end = i + 2
        while end < length and text[end] in HEX_DIGITS:
            end += 1
        if end > i + 2:
            value = int(text[i + 2:end], 16)
            if value > INT64_MAX:
                return None
            return -value if text[start] == '-' else value
    j = i
    while j < length and text[j] in ASCII_DIGITS:
        j += 1
    k = j
    if k < length and text[k] == '.' and k + 1 < length and text[k + 1] in ASCII_DIGITS:
        k += 1
        while k < length and text[k] in ASCII_DIGITS:
            k += 1
    if k == j and k == i:
        return 0
    if k < length and text[k] in 'eE':
        peek = k + 1
        if peek < length and text[peek] in '+-':
            peek += 1
        if peek < length and text[peek] in ASCII_DIGITS:
            while peek < length and text[peek] in ASCII_DIGITS:
                peek += 1
            k = peek
    matched = text[start:k]
    if any(c in matched for c in '.eE'):
        result = float(matched)
        return result if math.isfinite(result) else None
    digits = matched.lstrip('+-').lstrip('0')
    if len(digits) > _INT64_DIGITS:
        return None
    result = int(digits or '0')
    if matched.startswith('-'):
        result = -result
    if result > INT64_MAX or result < INT64_MIN:
        return None
    return result


def to_number(value: Au3Value) -> int | float | None:
    """
    The number a value coerces to under arithmetic: strings by the prefix parse, booleans as 1/0,
    numbers as themselves. A binary, an array, and an unknown coerce to nothing this domain can
    name.
    """
    if value.kind in (Kind.INT, Kind.DOUBLE):
        return cast(int | float, value.payload)
    if value.kind is Kind.BOOL:
        return 1 if value.payload else 0
    if value.kind is Kind.STRING:
        return _prefix_number(cast(str, value.payload))
    return None


def _left_operand(value: Au3Value) -> int | float | None:
    """
    The number a value becomes in an arithmetic left-operand position: a number stays its own
    type, a boolean becomes a double, and a string becomes the number its text spells — an
    integer unless the text carries a fraction or an exponent (probe6 12-17, 30-33; probe7
    10-18). A unary sign converts its operand the same way (probe6 18, 32; probe7 19).
    """
    if value.kind in (Kind.INT, Kind.DOUBLE):
        return cast(int | float, value.payload)
    if value.kind is Kind.BOOL:
        return 1.0 if value.payload else 0.0
    if value.kind is Kind.STRING:
        return _prefix_number(cast(str, value.payload))
    return None


def _right_operand(value: Au3Value) -> int | float | None:
    """
    The number a value becomes in an arithmetic right-operand position: a number stays its own
    type, and a string or a boolean becomes a double (probe6 10, 11, 14; probe7 10-18).
    """
    if value.kind in (Kind.INT, Kind.DOUBLE):
        return cast(int | float, value.payload)
    if value.kind in (Kind.BOOL, Kind.STRING):
        number = to_number(value)
        return None if number is None else float(number)
    return None


def to_bool(value: Au3Value) -> bool | None:
    """
    The boolean a value coerces to under the `=` comparison's boolean mode and under `Not`:
    a string by non-emptiness, a number by non-zero. A binary, an array, and an unknown have no
    such reading.
    """
    if value.kind is Kind.BOOL:
        return cast(bool, value.payload)
    if value.kind is Kind.STRING:
        return bool(cast(str, value.payload))
    if value.kind in (Kind.INT, Kind.DOUBLE):
        return cast(int | float, value.payload) != 0
    return None


def truthy(value: Au3Value) -> bool | None:
    """
    Whether a value decides a condition: a string or binary by non-emptiness, a number by
    non-zero, a boolean by itself. Pinned by probe2 40-45 (`"0"`, `"0.0"`, `"00"`, and
    `Binary("0x00")` are all truthy). An array's truthiness is unpinned and answers `None`.
    """
    if value.kind is Kind.BOOL:
        return cast(bool, value.payload)
    if value.kind in (Kind.STRING, Kind.BINARY):
        return bool(value.payload)
    if value.kind in (Kind.INT, Kind.DOUBLE):
        return cast(int | float, value.payload) != 0
    return None


def _numeric_operands(left: Au3Value, right: Au3Value) -> tuple[int | float, int | float] | None:
    one = to_number(left)
    two = to_number(right)
    if one is None or two is None:
        return None
    return one, two


def of_int_result(result: int) -> Au3Value | None:
    """
    An int the interpreter would hand back for arithmetic: `None` outside the int64 range, where
    whether AutoIt wraps or promotes to double is unpinned and the two print differently.
    """
    if result > INT64_MAX or result < INT64_MIN:
        return None
    return of_int(result)


def of_double_result(result: float) -> Au3Value | None:
    if not math.isfinite(result):
        return None
    return of_double(result)


def compare(operator: str, left: Au3Value, right: Au3Value) -> Au3Value | None:
    """
    The result of comparing two known values, or `None` where the comparison is refused:

    - either operand binary or array: unpinned, every operator refuses;
    - `=`: both strings compare case-insensitively; with a boolean operand both sides go to bool
      (`False = ""` is true, `True = -1` is true — probe2 10-13, probe3 36); otherwise numeric;
    - `==`: both strings compare case-sensitively; with a boolean operand both sides go to their
      text and compare case-sensitively (`True == 1` is false — probe3 30-32); otherwise numeric;
    - the relationals: both strings compare case-insensitively and lexicographically
      (`"a" > "B"` is false and `"10" > "9"` is false — probe3 37/38, probe 13-16); a boolean
      operand is refused (numeric and case-insensitive-string both fit every probe fact);
      otherwise numeric.

    Case-insensitive string comparison is ASCII-only: how AutoIt lowercases text beyond ASCII is
    not a fact any probe pinned, so non-ASCII operands refuse.
    """
    if left.kind in (Kind.BINARY, Kind.ARRAY) or right.kind in (Kind.BINARY, Kind.ARRAY):
        return None
    result = _compare_values(operator, left, right)
    if result is None:
        return None
    return of_bool(result)


def _compare_values(operator: str, left: Au3Value, right: Au3Value) -> bool | None:
    if operator in ('=', '==', '<>'):
        if left.kind is Kind.STRING and right.kind is Kind.STRING:
            one = cast(str, left.payload)
            two = cast(str, right.payload)
            if operator == '==':
                return one == two
            if not one.isascii() or not two.isascii():
                return None
            return one.lower() == two.lower()
        if left.kind is Kind.BOOL or right.kind is Kind.BOOL:
            if operator == '==':
                one = to_string(left)
                two = to_string(right)
                if one is None or two is None:
                    return None
                return one == two
            one = to_bool(left)
            two = to_bool(right)
            if one is None or two is None:
                return None
            equal = one == two
        else:
            operands = _numeric_operands(left, right)
            if operands is None:
                return None
            equal = operands[0] == operands[1]
        return not equal if operator == '<>' else equal
    if left.kind is Kind.BOOL or right.kind is Kind.BOOL:
        return None
    if left.kind is Kind.STRING and right.kind is Kind.STRING:
        one = cast(str, left.payload)
        two = cast(str, right.payload)
        if not one.isascii() or not two.isascii():
            return None
        one = one.lower()
        two = two.lower()
        if operator == '<':
            return one < two
        if operator == '>':
            return one > two
        if operator == '<=':
            return one <= two
        return one >= two
    operands = _numeric_operands(left, right)
    if operands is None:
        return None
    one, two = operands
    if operator == '<':
        return one < two
    if operator == '>':
        return one > two
    if operator == '<=':
        return one <= two
    return one >= two


def apply_binary(operator: str, left: Au3Value, right: Au3Value) -> Au3Value | None:
    """
    The result of a binary operator over two known values, or `None` where the operator is
    refused:

    - `+ - * / ^`: numeric, the operands converted by position — see `_left_operand` and
      `_right_operand`; the result is an integer only when both converted operands are integers,
      and an int result outside the int64 range is refused (`1e15` and above is where int64 and
      double print differently); `/` is always double (`10 / 2` prints `5`, `10 / 4` is 2.5) and
      a zero divisor is fatal in AutoIt and never folds; `^` is always double and refuses a
      negative base under a fractional exponent;
    - `and`/`or`: the truth of both operands, a boolean (probe4 62-65);
    - `&`: string `&` string, with numbers joining through their printed text; binary `&` binary
      concatenates; string `&` binary appends the binary's `0x…` text (probe3 40); binary `&`
      anything else is refused — a binary result and a plain string both fit every probe fact
      (probe3 41-42), so the type is unpinned.
    """
    if operator == '&':
        return _concatenate(left, right)
    if operator in ('and', 'or'):
        one = truthy(left)
        two = truthy(right)
        if one is None or two is None:
            return None
        return of_bool(one and two if operator == 'and' else one or two)
    one = _left_operand(left)
    two = _right_operand(right)
    if one is None or two is None:
        return None
    if operator == '+':
        if isinstance(one, int) and isinstance(two, int):
            return of_int_result(one + two)
        return of_double_result(one + two)
    if operator == '-':
        if isinstance(one, int) and isinstance(two, int):
            return of_int_result(one - two)
        return of_double_result(one - two)
    if operator == '*':
        if isinstance(one, int) and isinstance(two, int):
            return of_int_result(one * two)
        return of_double_result(one * two)
    if operator == '/':
        if two == 0:
            return None
        return of_double_result(one / two)
    if operator == '^':
        if one < 0 and two != int(two):
            return None
        try:
            result = math.pow(one, two)
        except (OverflowError, ValueError):
            return None
        return of_double_result(result)
    return None


def _concatenate(left: Au3Value, right: Au3Value) -> Au3Value | None:
    if left.kind is Kind.BINARY and right.kind is Kind.BINARY:
        return of_binary(cast(bytes, left.payload) + cast(bytes, right.payload))
    if right.kind is Kind.BINARY:
        if left.kind is not Kind.STRING:
            return None
        one = cast(str, left.payload)
        two = to_string(right)
    else:
        if left.kind is Kind.BINARY:
            return None
        one = to_string(left)
        two = to_string(right)
    if one is None or two is None:
        return None
    return of_string(one + two)


def apply_unary(operator: str, operand: Au3Value) -> Au3Value | None:
    """
    The result of a unary operator over one known value: `Not` answers a boolean (pinned by
    `Not True & ""` printing `False`), and a sign converts its operand like an arithmetic left
    operand (probe6 18, 32; probe7 19) — `-"2"` is an int, `-"2.5"` and `-True` are doubles —
    with the same int64 refusal on int results as the binary arithmetic.
    """
    if operator == 'not':
        verdict = truthy(operand)
        if verdict is None:
            return None
        return of_bool(not verdict)
    number = _left_operand(operand)
    if number is None:
        return None
    if operator == '+':
        return of_number(number)
    if operator == '-':
        if isinstance(number, int):
            return of_int_result(-number)
        return of_double_result(-number)
    return None


def literal_value(
    expression: Expression | None,
    functions: frozenset[str],
    memo: dict[Expression, Au3Value | None] | None = None,
) -> Au3Value | None:
    """
    The value an expression holds when it is nothing but a literal shape: a number, a string, a
    boolean, a run-time-constant macro, a unary minus over a number, an array literal of such, a
    `Binary("0x…")` call, or an `&` chain of string literals and the pieces that spell the
    characters no literal expresses — the spellings `render_literal` writes, read back. These
    are the shapes a fold leaves behind, which is what a binding walk reads. An all-digit
    literal beyond int64 saturates, the way the interpreter reads it.

    *functions* names the script's own functions, because a script function named `Binary` shadows
    the builtin and the call would run foreign code: while one exists, the call is not a literal.

    A *memo* remembers one answer per node for as long as the tree it was computed over stands:
    the constant evaluator asks the same subtree at every level of the expressions above it, so
    a chain nothing proves pays its whole descent once, not once per level above it.
    """
    if expression is None:
        return None
    if memo is None:
        return _literal_shape(expression, functions, None)
    if expression in memo:
        return memo[expression]
    value = _literal_shape(expression, functions, memo)
    memo[expression] = value
    return value


def _literal_shape(
    expression: Expression | None,
    functions: frozenset[str],
    memo: dict[Expression, Au3Value | None] | None,
) -> Au3Value | None:
    node = ast.unwrap_parens(expression)
    if isinstance(node, Au3IntLiteral):
        return of_int(min(node.value, INT64_MAX))
    if isinstance(node, Au3FloatLiteral):
        if not math.isfinite(node.value):
            return None
        return of_double(node.value)
    if isinstance(node, Au3StringLiteral):
        return of_string(node.value)
    if isinstance(node, Au3BooleanLiteral):
        return of_bool(node.value)
    if isinstance(node, Au3Macro):
        macro = MACRO_CONSTANTS.get(node.name)
        return None if macro is None else of_string(macro)
    if isinstance(node, Au3BinaryExpression):
        if node.operator != '&' or node.left is None or node.right is None:
            return None
        one = literal_value(node.left, functions, memo)
        two = literal_value(node.right, functions, memo)
        if one is None or two is None:
            return None
        return apply_binary('&', one, two)
    if isinstance(node, Au3Call):
        character = _character_literal(node, functions)
        if character is not None:
            return character
        return _binary_literal(node, functions)
    if isinstance(node, Au3UnaryExpression):
        if node.operator != '-' or node.operand is None:
            return None
        inner = literal_value(node.operand, functions, memo)
        if inner is None:
            return None
        return apply_unary('-', inner)
    if isinstance(node, Au3ArrayLiteral):
        elements = []
        for element in node.elements:
            value = literal_value(element, functions, memo)
            if value is None:
                return None
            elements.append(value)
        return of_array(tuple(elements))
    return None


def _character_literal(call: Au3Call, functions: frozenset[str]) -> Au3Value | None:
    """
    The character one piece of a rendered chain spells — `Chr(0)` for the NUL, `ChrW(n)` for a
    surrogate or a Unicode line break — read back, so the chain a payload renders to stays a
    literal shape. No other argument spells a piece the renderer writes, and a script function
    shadowing the builtin would run foreign code.
    """
    callee = ast.direct_callee(call)
    if callee is None or len(call.arguments) != 1:
        return None
    literal = ast.unwrap_parens(call.arguments[0])
    if not isinstance(literal, Au3IntLiteral):
        return None
    if callee.name == 'chr':
        if literal.value != 0 or 'chr' in functions:
            return None
        return of_string('\x00')
    if callee.name == 'chrw':
        if 'chrw' in functions:
            return None
        code = literal.value
        if not (0xD800 <= code <= 0xDFFF or code in (0x2028, 0x2029)):
            return None
        return of_string(chr(code))
    return None


def _binary_literal(call: Au3Call, functions: frozenset[str]) -> Au3Value | None:
    """
    The binary a `Binary("0x…")` call spells — the exact shape `render_literal` writes for one,
    and the only binary shape that reads back. Any other argument is a coercion the builtin table
    owns, and the fold rewrites it into this shape before anything reads the value.
    """
    if 'binary' in functions:
        return None
    callee = ast.direct_callee(call)
    if callee is None or callee.name != 'binary':
        return None
    if len(call.arguments) != 1:
        return None
    literal = ast.unwrap_parens(call.arguments[0])
    if not isinstance(literal, Au3StringLiteral):
        return None
    digits = literal.value
    if (
        len(digits) < 4
        or len(digits) % 2
        or digits[:2].lower() != '0x'
        or any(character not in HEX_DIGITS for character in digits[2:])
    ):
        return None
    return of_binary(bytes.fromhex(digits[2:]))


def render_literal(value: Au3Value, functions: frozenset[str]) -> Expression | None:
    """
    The expression node that spells `value` in AutoIt3 source, or `None` where no expression can:

    - a string carrying a character no literal expresses (NUL, a line break, a surrogate),
      spelled as the `&` chain of the pieces that spell it — unless a script function shadows
      the builtin one of those pieces names;
    - a non-finite double, and a negative zero: AutoIt prints the latter `-0`, which the unary
      minus over a zero literal does not spell;
    - an int64 at its floor: it spells only as the minus over `2^63`, which re-reads as the
      int64 ceiling;
    - a binary, spelled as the call `Binary("0x…")` it round-trips through, but only when no
      script function of that name exists — a script function shadows the builtin, so the call
      would run foreign code — and never an empty one, whose spelling re-reads as the two
      characters `0x`;
    - an array, spelled as an array literal, only when every element renders.

    A render deeper than `MAX_RENDERED_DEPTH` spells none either: the synthesizer emits a tree
    by recursion and cannot print one that deep, so the value keeps whatever spelling it
    already has. A literal whose spelling outgrows a line is cut into pieces that each fit
    one and joined by `&`, so the synthesizer can break behind every piece.

    A negative number is spelled as the unary minus over the positive literal, because the lexer
    reads a sign as an operator: a literal holding `-3` would print text that re-parses as a
    different tree than the one that holds it.
    """
    rendered = _render_value(value, functions)
    if rendered is None or not _within_depth(rendered):
        return None
    return rendered


def _render_value(value: Au3Value, functions: frozenset[str]) -> Expression | None:
    if value.kind is Kind.INT:
        return _render_int(cast(int, value.payload))
    if value.kind is Kind.DOUBLE:
        number = cast(float, value.payload)
        if not math.isfinite(number):
            return None
        if number == 0 and math.copysign(1.0, number) < 0:
            return None
        literal = Au3FloatLiteral(value=abs(number), raw=repr(abs(number)))
        if number < 0:
            return Au3UnaryExpression(operator='-', operand=literal)
        return literal
    if value.kind is Kind.STRING:
        return _render_string(cast(str, value.payload), functions)
    if value.kind is Kind.BOOL:
        return Au3BooleanLiteral(value=cast(bool, value.payload))
    if value.kind is Kind.BINARY:
        if 'binary' in functions:
            return None
        payload = cast(bytes, value.payload)
        if not payload:
            return None
        return _render_binary(payload)
    if value.kind is Kind.ARRAY:
        elements = []
        for element in cast(tuple[Au3Value, ...], value.payload):
            rendered = _render_value(element, functions)
            if rendered is None:
                return None
            elements.append(rendered)
        return Au3ArrayLiteral(elements=elements)
    return None


#: The bytes one `Binary("0x…")` piece of a split binary spells: the call's wrapper leaves the
#: rest of the piece budget to its hex digits, two per byte.
_BINARY_PIECE_BYTES = (MAX_PIECE_SPELLING - len('Binary("0x")')) // 2


def _encoded_length(text: str) -> int:
    """
    The characters the literal spelling of *text* occupies: the length `encode_au3_string`
    writes, so the encoder stays the one spelling of the literal budget.
    """
    return len(encode_au3_string(text))


def _render_binary(payload: bytes) -> Expression:
    """
    The spelling of a binary: the `Binary("0x…")` call it round-trips through, cut into one call
    per piece of bytes where the whole would outgrow a line, joined by `&` — the concatenation
    `literal_value` reads back.
    """
    chunks = [
        payload[at:at + _BINARY_PIECE_BYTES]
        for at in range(0, len(payload), _BINARY_PIECE_BYTES)
    ]
    result: Expression = _binary_call(chunks[0])
    for chunk in chunks[1:]:
        result = Au3BinaryExpression(operator='&', left=result, right=_binary_call(chunk))
    return result


def _binary_call(chunk: bytes) -> Au3Call:
    digits = '0x' + chunk.hex().upper()
    return Au3Call(
        callee=Au3Identifier(name='binary', raw='Binary'),
        arguments=[Au3StringLiteral(value=digits, raw=encode_au3_string(digits))],
    )


def _render_string(text: str, functions: frozenset[str]) -> Expression | None:
    """
    The spelling of a string: the literal itself when every character spells and its spelling
    fits a single line, and otherwise the left-associated `&` chain of the literal runs and the
    pieces that spell the characters no literal expresses (probe5 14 loads such a chain as an
    array element). A run whose spelling outgrows a line is cut where the next piece still fits
    one, so a long value re-renders as a chain the synthesizer breaks behind continuations
    rather than as a line the interpreter refuses. The chain is refused where a script function
    shadows the builtin one of its pieces names.
    """
    if _spellable(text) and _encoded_length(text) <= MAX_PIECE_SPELLING:
        return Au3StringLiteral(value=text, raw=encode_au3_string(text))
    pieces: list[Expression] = []
    run: list[str] = []
    length = len('""')

    def flush() -> None:
        nonlocal length
        if run:
            spelled = ''.join(run)
            pieces.append(Au3StringLiteral(value=spelled, raw=encode_au3_string(spelled)))
            run.clear()
            length = len('""')

    index = 0
    while index < len(text):
        if text[index:index + 2] == '\r\n':
            flush()
            pieces.append(Au3Macro(name='crlf', raw='@CRLF'))
            index += 2
            continue
        character = text[index]
        if _spellable(character):
            width = 2 if character == '"' else 1
            if length + width > MAX_PIECE_SPELLING:
                flush()
            run.append(character)
            length += width
        else:
            piece = _rendered_piece(character, functions)
            if piece is None:
                return None
            flush()
            pieces.append(piece)
        index += 1
    flush()
    result: Expression = pieces[0]
    for piece in pieces[1:]:
        result = Au3BinaryExpression(operator='&', left=result, right=piece)
    return result


def _rendered_piece(character: str, functions: frozenset[str]) -> Expression | None:
    """
    The piece that spells one character no literal expresses: the macro of a line break, `Chr(0)`
    for the NUL, or `ChrW(n)` for a surrogate or a Unicode line break.
    """
    if character == '\r':
        return Au3Macro(name='cr', raw='@CR')
    if character == '\n':
        return Au3Macro(name='lf', raw='@LF')
    if character == '\x00':
        if 'chr' in functions:
            return None
        return Au3Call(
            callee=Au3Identifier(name='chr', raw='Chr'),
            arguments=[Au3IntLiteral(value=0, raw='0')])
    code = ord(character)
    if 0xD800 <= code <= 0xDFFF or code in (0x2028, 0x2029):
        if 'chrw' in functions:
            return None
        return Au3Call(
            callee=Au3Identifier(name='chrw', raw='ChrW'),
            arguments=[Au3IntLiteral(value=code, raw=str(code))])
    return None


#: The depth beyond which a rendered literal is refused: the synthesizer emits a tree by
#: recursion, several stack frames per level, and dies just past two hundred levels under the
#: default recursion limit, so a chain deeper than this would crash every pass that prints the
#: pipeline's own product. An array literal emits breadth-wise in a loop, so only depth counts
#: against the bound, never the element count.
MAX_RENDERED_DEPTH = 128


def _within_depth(node: Node) -> bool:
    """
    Whether the subtree at *node* stays within `MAX_RENDERED_DEPTH`.
    """
    stack: list[tuple[Node, int]] = [(node, 1)]
    while stack:
        current, depth = stack.pop()
        if depth > MAX_RENDERED_DEPTH:
            return False
        for child in current.children():
            stack.append((child, depth + 1))
    return True


def render_at(
    node: Node,
    value: Au3Value,
    functions: frozenset[str],
) -> Expression | None:
    """
    The spelling of `value` where *node* stands, or `None` where the position accepts none: an
    array literal is legal AutoIt only where a declaration initializes, so an array value spells
    only there. Every other value spells wherever an expression does, and `render_literal` says
    which values spell at all.
    """
    if value.kind is Kind.ARRAY and not ast.in_declaration_initializer(node):
        return None
    return render_literal(value, functions)


def _render_int(value: int) -> Expression | None:
    """
    The literal spelling of an int, or `None` at the int64 floor: the minus over `2^63` is the
    only spelling, and it re-reads as the ceiling.
    """
    if value == INT64_MIN:
        return None
    if value < 0:
        return Au3UnaryExpression(
            operator='-', operand=Au3IntLiteral(value=-value, raw=str(-value)))
    return Au3IntLiteral(value=value, raw=str(value))
