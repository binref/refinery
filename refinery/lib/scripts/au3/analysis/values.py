"""
The AutoIt3 value domain: the kinds a value can have, the coercions between them, and the result
of every operator over known values. Operator semantics live here and nowhere else.

The source of truth is a probe of the real interpreter (AutoIt 3.3.18.0; three probe scripts and
outputs in `temp/au3_semantics_probe/`), then the official docs, then nothing: a rule neither of
those pins is refused rather than guessed, so an unpinned operator returns `None` and the fold
that asked leaves the expression standing. Which cases are refused is documented on the operator
that refuses them.

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

from typing import cast

from dataclasses import dataclass

from refinery.lib.scripts.au3 import ast
from refinery.lib.scripts.au3.lexer import encode_au3_string
from refinery.lib.scripts.au3.model import (
    Au3ArrayLiteral,
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

_HEX_DIGITS = frozenset('0123456789abcdefABCDEF')

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


UNKNOWN = Au3Value()


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


def is_known(value: Au3Value | None) -> bool:
    return value is not None and value.kind is not Kind.UNKNOWN


def as_int(value: Au3Value) -> int | None:
    if value.kind is Kind.INT:
        return cast(int, value.payload)
    return None


def as_double(value: Au3Value) -> float | None:
    if value.kind is Kind.DOUBLE:
        return cast(float, value.payload)
    return None


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
    Pinned by probe3 50-57 and probe 60-68.
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
        while end < length and text[end] in _HEX_DIGITS:
            end += 1
        if end > i + 2:
            value = int(text[i + 2:end], 16)
            if value > INT64_MAX:
                return None
            return -value if text[start] == '-' else value
    j = i
    while j < length and text[j].isdigit():
        j += 1
    k = j
    if k < length and text[k] == '.' and k + 1 < length and text[k + 1].isdigit():
        k += 1
        while k < length and text[k].isdigit():
            k += 1
    if k == j and k == i:
        return 0
    if k < length and text[k] in 'eE':
        peek = k + 1
        if peek < length and text[peek] in '+-':
            peek += 1
        if peek < length and text[peek].isdigit():
            while peek < length and text[peek].isdigit():
                peek += 1
            k = peek
    matched = text[start:k]
    if any(c in matched for c in '.eE'):
        result = float(matched)
        return result if math.isfinite(result) else None
    result = int(matched)
    if result > INT64_MAX or result < INT64_MIN:
        return float(result)
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
        one = cast(str, left.payload).lower()
        two = cast(str, right.payload).lower()
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

    - `+ - *`: numeric; two ints stay int below `1e15` (above that, int64-versus-double is
      unpinned); otherwise double;
    - `/`: always double (`10 / 2` prints `5`, `10 / 4` is 2.5); a zero divisor is fatal in
      AutoIt and never folds;
    - `^`: always double; a negative base under a fractional exponent is refused;
    - `&`: string `&` string, with numbers joining through their printed text; binary `&` binary
      concatenates; string `&` binary appends the binary's `0x…` text (probe3 40); binary `&`
      anything else is refused — a binary result and a plain string both fit every probe fact
      (probe3 41-42), so the type is unpinned;
    - `and`/`or` never fold here: their value in expression position is unpinned. Only the
      conditions that consume them fold, and they read the operands through `truthy`.
    """
    if operator == '&':
        return _concatenate(left, right)
    if operator in ('and', 'or'):
        return None
    operands = _numeric_operands(left, right)
    if operands is None:
        return None
    one, two = operands
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
    `Not True & ""` printing `False`), `+` and `-` coerce to number, with the same `1e15` refusal
    on int results as the binary arithmetic.
    """
    if operator == 'not':
        verdict = truthy(operand)
        if verdict is None:
            return None
        return of_bool(not verdict)
    number = to_number(operand)
    if number is None:
        return None
    if operator == '+':
        return of_number(number)
    if operator == '-':
        if isinstance(number, int):
            return of_int_result(-number)
        return of_double_result(-number)
    return None


#: The characters no AutoIt string literal can express: `encode_au3_string` escapes only the
#: quote, and a line break ends the literal, so a result carrying any of these never folds.
#: A surrogate has no encoding at all and would break the synthesizer's output stream.
def _spellable(text: str) -> bool:
    return not any(
        character == '\x00' or character == '\r' or character == '\n'
        or 0xD800 <= ord(character) <= 0xDFFF
        for character in text
    )


def literal_value(
        expression: Expression | None,
        functions: frozenset[str]) -> Au3Value | None:
    """
    The value an expression holds when it is nothing but a literal shape: a number, a string, a
    boolean, a run-time-constant macro, a unary minus over a number, an array literal of such, or
    a `Binary("0x…")` call — the spelling a binary renders to, read back. These are the shapes a
    fold leaves behind, which is what a binding walk reads. An all-digit literal beyond int64
    saturates, the way the interpreter reads it.

    *functions* names the script's own functions, because a script function named `Binary` shadows
    the builtin and the call would run foreign code: while one exists, the call is not a literal.
    """
    node = ast.unwrap_parens(expression)
    if isinstance(node, Au3IntLiteral):
        return of_int(min(node.value, INT64_MAX))
    if isinstance(node, Au3FloatLiteral):
        return of_double(node.value)
    if isinstance(node, Au3StringLiteral):
        return of_string(node.value)
    if isinstance(node, Au3BooleanLiteral):
        return of_bool(node.value)
    if isinstance(node, Au3Macro):
        macro = MACRO_CONSTANTS.get(node.name)
        return None if macro is None else of_string(macro)
    if isinstance(node, Au3Call):
        return _binary_literal(node, functions)
    if isinstance(node, Au3UnaryExpression):
        if node.operator != '-' or node.operand is None:
            return None
        inner = literal_value(node.operand, functions)
        if inner is None:
            return None
        return apply_unary('-', inner)
    if isinstance(node, Au3ArrayLiteral):
        elements = []
        for element in node.elements:
            value = literal_value(element, functions)
            if value is None:
                return None
            elements.append(value)
        return of_array(tuple(elements))
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
        or any(character not in _HEX_DIGITS for character in digits[2:])
    ):
        return None
    return of_binary(bytes.fromhex(digits[2:]))


def render_literal(value: Au3Value, functions: frozenset[str]) -> Expression | None:
    """
    The expression node that spells `value` in AutoIt3 source, or `None` where no expression can:

    - a string carrying a character no literal expresses (NUL, CR, LF, a surrogate) — `@CR` never
      becomes a literal, while `StringLen(@CR)` still folds to 1;
    - a non-finite double;
    - a binary, spelled as the call `Binary("0x…")` it round-trips through, but only when no
      script function of that name exists — a script function shadows the builtin, so the call
      would run foreign code;
    - an array, spelled as an array literal, only when every element renders.

    A negative number is spelled as the unary minus over the positive literal, because the lexer
    reads a sign as an operator: a literal holding `-3` would print text that re-parses as a
    different tree than the one that holds it.
    """
    if value.kind is Kind.INT:
        return _render_int(cast(int, value.payload))
    if value.kind is Kind.DOUBLE:
        number = cast(float, value.payload)
        if not math.isfinite(number):
            return None
        literal = Au3FloatLiteral(value=abs(number), raw=repr(abs(number)))
        if number < 0:
            return Au3UnaryExpression(operator='-', operand=literal)
        return literal
    if value.kind is Kind.STRING:
        text = cast(str, value.payload)
        if not _spellable(text):
            return None
        return Au3StringLiteral(value=text, raw=encode_au3_string(text))
    if value.kind is Kind.BOOL:
        return Au3BooleanLiteral(value=cast(bool, value.payload))
    if value.kind is Kind.BINARY:
        if 'binary' in functions:
            return None
        digits = '0x' + cast(bytes, value.payload).hex().upper()
        return Au3Call(
            callee=Au3Identifier(name='binary', raw='Binary'),
            arguments=[Au3StringLiteral(value=digits, raw=encode_au3_string(digits))],
        )
    if value.kind is Kind.ARRAY:
        elements = []
        for element in cast(tuple[Au3Value, ...], value.payload):
            rendered = render_literal(element, functions)
            if rendered is None:
                return None
            elements.append(rendered)
        return Au3ArrayLiteral(elements=elements)
    return None


def _render_int(value: int) -> Expression:
    if value < 0:
        return Au3UnaryExpression(
            operator='-', operand=Au3IntLiteral(value=-value, raw=str(-value)))
    return Au3IntLiteral(value=value, raw=str(value))
