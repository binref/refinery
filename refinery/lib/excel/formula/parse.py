"""
The text parser for Excel formula sources: the `<f>` element text of an OOXML cell, the body of
a defined name, or any other formula text with or without the leading `=`. The precedence chain
follows the Microsoft-documented order, loosest to tightest: comparisons, concatenation,
addition, multiplication, exponentiation, the postfix percent, the unary sign, and finally the
reference operators, of which the union binds loosest, the intersection is tighter, and the
range is tightest. The union operator is recognized only inside parentheses, so the separator
of call arguments is never read as one. On any input the parser cannot read in full it returns
`XlUnparsedFormula` rather than raising, so that hostile text never breaks a caller.
"""
from __future__ import annotations

import re

from typing import NamedTuple

from refinery.lib.excel.common import ERROR_TEXT, ref2rc
from refinery.lib.excel.formula.model import (
    Expression,
    XlA1Reference,
    XlArrayConstant,
    XlBinaryExpression,
    XlBinaryOperator,
    XlBoolean,
    XlDefinedName,
    XlError,
    XlFunctionCall,
    XlLiteral,
    XlMissingArgument,
    XlNumber,
    XlParenExpression,
    XlR1C1Reference,
    XlString,
    XlUnaryExpression,
    XlUnaryOperator,
    XlUnparsedFormula,
)


class International(NamedTuple):
    """
    The locale-dependent characters of formula text: the separator between the arguments of a
    call and between the columns of an array constant, and the brackets around a relative R1C1
    offset.
    """

    list_separator: str = ','
    left_bracket: str = '['
    right_bracket: str = ']'


class _ParseFailure(Exception):
    pass


_RE_STRING = re.compile(R'"(?:[^"]|"")*"')
_RE_NUMBER = re.compile(r'(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?')
_RE_NAME = re.compile(R'[a-zA-Z_\\][a-zA-Z0-9_.\\?]*')
_RE_BOOLEAN = re.compile(R'TRUE|FALSE', re.IGNORECASE)
_RE_A1 = re.compile(R'(\$?)([A-Za-z]{1,3})(\$?)(\d+)')
_RE_ERROR = re.compile(
    '|'.join(re.escape(e) for e in sorted(ERROR_TEXT.values(), key=len, reverse=True)),
    re.IGNORECASE,
)
_NAME_CONTINUATION = frozenset(
    'abcdefghijklmnopqrstuvwxyz'
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    '0123456789_.\\?'
)
_NAME_START = frozenset('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_.\\?')
_COMPARISONS = ('<=', '>=', '<>', '<', '>', '=')
_SPACES = ' \t\r\n'

_OPERATORS = {
    '=': XlBinaryOperator.EQ,
    '<>': XlBinaryOperator.NE,
    '<': XlBinaryOperator.LT,
    '<=': XlBinaryOperator.LE,
    '>': XlBinaryOperator.GT,
    '>=': XlBinaryOperator.GE,
    '&': XlBinaryOperator.CONCAT,
    '+': XlBinaryOperator.ADD,
    '-': XlBinaryOperator.SUB,
    '*': XlBinaryOperator.MUL,
    '/': XlBinaryOperator.DIV,
    '^': XlBinaryOperator.POW,
    ':': XlBinaryOperator.RANGE,
}

_RE_COLUMN = re.compile(R'[A-Za-z]{1,3}')


def _spells_whole_span(left: Expression, right: Expression) -> bool:
    """
    Whether the operands of a range operator spell a whole-column reference such as `A:C` or a
    whole-row reference such as `1:3`. The model has no node for either yet, and bare letters
    would otherwise read as defined names and bare digits as numbers, so the range they form
    would be a different program; such input is refused.
    """
    if isinstance(left, XlNumber) and isinstance(right, XlNumber):
        return True
    if not isinstance(left, XlDefinedName) or not isinstance(right, XlDefinedName):
        return False
    return (
        _RE_COLUMN.fullmatch(left.name) is not None
        and _RE_COLUMN.fullmatch(right.name) is not None
    )


def parse_formula(
    text: str,
    international: International | None = None,
) -> Expression:
    """
    Parse formula text into the AST model. The leading `=` of a stored formula is optional. Any
    input that does not read as one whole formula becomes an `XlUnparsedFormula` carrying the
    text, never an exception.
    """
    if not text or not text.strip():
        return XlUnparsedFormula(text=text)
    parser = _Parser(text.strip(), international or International())
    try:
        expression = parser.parse()
    except (_ParseFailure, RecursionError, ValueError, IndexError):
        return XlUnparsedFormula(text=text)
    return expression


class _Parser:
    """
    A recursive-descent reader over formula text. Every token is consumed through a method that
    also skips the whitespace behind it and records whether it skipped any, which is how the
    intersection level tells an operand apart from spacing around an operator.
    """

    def __init__(self, text: str, international: International):
        self._src = text
        self._pos = 0
        self._sep = international.list_separator
        self._lb = international.left_bracket
        self._rb = international.right_bracket
        self._spaced = False

    def parse(self) -> Expression:
        if self._src.startswith('='):
            self._pos = 1
        expression = self._parse_comparison()
        self._skip_spaces()
        if self._pos != len(self._src):
            raise _ParseFailure
        return expression

    def _at_end(self) -> bool:
        return self._pos >= len(self._src)

    def _peek(self) -> str:
        return self._src[self._pos] if self._pos < len(self._src) else ''

    def _skip_spaces(self) -> None:
        moved = False
        while self._pos < len(self._src) and self._src[self._pos] in _SPACES:
            self._pos += 1
            moved = True
        self._spaced = moved

    def _consume(self, char: str) -> None:
        if self._peek() != char:
            raise _ParseFailure
        self._pos += 1
        self._skip_spaces()

    def _match(self, pattern: re.Pattern[str]) -> re.Match[str] | None:
        match = pattern.match(self._src, self._pos)
        if match is None:
            return None
        self._pos = match.end()
        self._skip_spaces()
        return match

    def _begins_operand(self) -> bool:
        """
        Whether the input at the cursor starts another operand, which is what turns skipped
        whitespace into an intersection operator rather than spacing. A sign never begins one:
        `A1 -B1` is a subtraction however it is spaced.
        """
        char = self._peek()
        if not char:
            return False
        return (
            char in '"{#$\'('
            or char.isdigit()
            or char == '.'
            or char in _NAME_START
        )

    def _binary(
        self,
        level,
        operators: tuple[str, ...],
    ) -> Expression:
        """
        Parse one left-associative binary level: operands of the next tighter level separated
        by any of the given operator texts.
        """
        left = level()
        while not self._at_end():
            for text in operators:
                if self._src.startswith(text, self._pos):
                    self._pos += len(text)
                    self._skip_spaces()
                    left = XlBinaryExpression(
                        left=left,
                        operator=_OPERATORS[text],
                        right=level(),
                    )
                    break
            else:
                return left
        return left

    def _parse_comparison(self) -> Expression:
        return self._binary(self._parse_concat, _COMPARISONS)

    def _parse_concat(self) -> Expression:
        return self._binary(self._parse_additive, ('&',))

    def _parse_additive(self) -> Expression:
        return self._binary(self._parse_multiplicative, ('+', '-'))

    def _parse_multiplicative(self) -> Expression:
        return self._binary(self._parse_power, ('*', '/'))

    def _parse_power(self) -> Expression:
        return self._binary(self._parse_percent, ('^',))

    def _parse_percent(self) -> Expression:
        left = self._parse_unary()
        while not self._at_end() and self._peek() == '%':
            self._pos += 1
            self._skip_spaces()
            left = XlUnaryExpression(operator=XlUnaryOperator.PERCENT, operand=left)
        return left

    def _parse_unary(self) -> Expression:
        if self._peek() in ('-', '+'):
            operator = XlUnaryOperator.NEG if self._peek() == '-' else XlUnaryOperator.POS
            self._pos += 1
            self._skip_spaces()
            return XlUnaryExpression(operator=operator, operand=self._parse_unary())
        return self._parse_isect()

    def _parse_isect(self) -> Expression:
        left = self._parse_range()
        while not self._at_end():
            if not self._spaced or not self._begins_operand():
                return left
            left = XlBinaryExpression(
                left=left,
                operator=XlBinaryOperator.ISECT,
                right=self._parse_range(),
            )
        return left

    def _parse_range(self) -> Expression:
        left = self._parse_primary()
        while not self._at_end() and self._peek() == ':':
            self._pos += 1
            self._skip_spaces()
            right = self._parse_primary()
            if _spells_whole_span(left, right):
                raise _ParseFailure
            left = XlBinaryExpression(
                left=left,
                operator=XlBinaryOperator.RANGE,
                right=right,
            )
        return left

    def _parse_primary(self) -> Expression:
        char = self._peek()
        if char == '(':
            self._pos += 1
            self._skip_spaces()
            inner = self._parse_union()
            self._consume(')')
            return XlParenExpression(operand=inner)
        if char == '"':
            return self._parse_string_literal()
        if char == '#':
            return self._parse_error_literal()
        if char == '{':
            return self._parse_array()
        if char.isdigit() or char == '.':
            return self._parse_number()
        return self._parse_reference_or_name()

    def _parse_union(self) -> Expression:
        left = self._parse_comparison()
        while not self._at_end() and self._peek() == self._sep:
            self._pos += 1
            self._skip_spaces()
            left = XlBinaryExpression(
                left=left,
                operator=XlBinaryOperator.UNION,
                right=self._parse_comparison(),
            )
        return left

    def _parse_number(self) -> XlNumber:
        match = self._match(_RE_NUMBER)
        if match is None:
            raise _ParseFailure
        raw = match.group()
        if '.' in raw or 'e' in raw or 'E' in raw:
            value: int | float = float(raw)
            if value.is_integer():
                value = int(value)
        else:
            value = int(raw)
        return XlNumber(value=value, raw=raw)

    def _parse_string_literal(self) -> XlString:
        match = self._match(_RE_STRING)
        if match is None:
            raise _ParseFailure
        return XlString(value=match.group()[1:-1].replace('""', '"'))

    def _parse_error_literal(self) -> XlError:
        match = self._match(_RE_ERROR)
        if match is None:
            raise _ParseFailure
        return XlError(value=match.group().upper())

    def _parse_array(self) -> XlArrayConstant:
        self._consume('{')
        rows: list[tuple[XlLiteral, ...]] = []
        row: list[XlLiteral] = [self._parse_array_item()]
        while not self._at_end():
            char = self._peek()
            if char == '}':
                break
            if char == ';':
                self._pos += 1
                self._skip_spaces()
                rows.append(tuple(row))
                row = [self._parse_array_item()]
                continue
            if char == self._sep:
                self._pos += 1
                self._skip_spaces()
                row.append(self._parse_array_item())
                continue
            raise _ParseFailure
        self._consume('}')
        rows.append(tuple(row))
        return XlArrayConstant(rows=rows)

    def _parse_array_item(self) -> XlLiteral:
        char = self._peek()
        if char == '"':
            return self._parse_string_literal()
        if char == '#':
            return self._parse_error_literal()
        if char in ('-', '+'):
            negative = char == '-'
            self._pos += 1
            self._skip_spaces()
            number = self._parse_number()
            return XlNumber(
                value=-number.value if negative else number.value,
                raw=F'-{number.raw}' if negative else number.raw,
            )
        match = _RE_BOOLEAN.match(self._src, self._pos)
        if match is not None and (
            match.end() >= len(self._src)
            or self._src[match.end()] not in _NAME_CONTINUATION
        ):
            self._pos = match.end()
            self._skip_spaces()
            return XlBoolean(value=match.group().upper() == 'TRUE')
        return self._parse_number()

    def _parse_sheet_prefix(self) -> tuple[str, ...] | None:
        """
        Consume a sheet qualification such as `Sheet1!`, `'My Sheet'!`, or the 3-D span
        `Sheet1:Sheet2!`, and return the sheet names it names, or `None` when the input carries
        no qualification at all. A name-like token that no `!` follows is not a prefix: the
        cursor rewinds and the caller reads it as a reference or name instead.
        """
        start = self._pos
        first = self._parse_sheet_name()
        if first is None:
            if self._peek() != '!':
                return None
            self._pos += 1
            self._skip_spaces()
            return ()
        if self._peek() == ':':
            self._pos += 1
            self._skip_spaces()
            second = self._parse_sheet_name()
            if second is None:
                self._pos = start
                return None
            sheets = (first, second)
        else:
            sheets = (first,)
        if self._peek() != '!':
            self._pos = start
            return None
        self._pos += 1
        self._skip_spaces()
        return sheets

    def _parse_sheet_name(self) -> str | None:
        if self._peek() == "'":
            end = self._src.find("'", self._pos + 1)
            while end >= 0 and end + 1 < len(self._src) and self._src[end + 1] == "'":
                end = self._src.find("'", end + 2)
            if end < 0:
                raise _ParseFailure
            name = self._src[self._pos + 1:end].replace("''", "'")
            self._pos = end + 1
            return name
        match = _RE_NAME.match(self._src, self._pos)
        if match is None:
            return None
        self._pos = match.end()
        return match.group()

    def _parse_reference_or_name(self) -> Expression:
        sheets = self._parse_sheet_prefix()
        reference = self._try_parse_r1c1(sheets)
        if reference is not None:
            return self._maybe_call(reference)
        reference = self._try_parse_a1(sheets)
        if reference is not None:
            return self._maybe_call(reference)
        match = self._match(_RE_NAME)
        if match is None:
            raise _ParseFailure
        name = match.group()
        if sheets:
            return self._maybe_call(XlDefinedName(name=name, sheet=sheets[0]))
        boolean = _RE_BOOLEAN.fullmatch(name)
        if boolean is not None:
            return XlBoolean(value=name.upper() == 'TRUE')
        return self._maybe_call(name)

    def _try_parse_a1(self, sheets: tuple[str, ...] | None) -> XlA1Reference | None:
        match = _RE_A1.match(self._src, self._pos)
        if match is None:
            return None
        end = match.end()
        if end < len(self._src) and self._src[end] in _NAME_CONTINUATION:
            return None
        self._pos = end
        self._skip_spaces()
        _, col = ref2rc(F'{match.group(2)}1')
        return XlA1Reference(
            sheets=sheets,
            row=int(match.group(4)),
            col=col,
            relative_row=match.group(3) != '$',
            relative_col=match.group(1) != '$',
        )

    def _try_parse_r1c1(self, sheets: tuple[str, ...] | None) -> XlR1C1Reference | None:
        """
        Read an R1C1 reference such as `R1C2`, `RC`, or `R[1]C[-1]`. A bracketed axis number is
        an offset from the containing cell; an unbracketed one is absolute, and a missing one is
        a relative zero. The attempt gives up when the text continues like a name, so that
        `R1C1X` stays a name and `R1C1()` stays the call of a macro cell.
        """
        start = self._pos
        if self._peek().upper() != 'R':
            return None
        self._pos += 1
        row_relative, row = self._try_parse_r1c1_axis()
        if self._peek().upper() != 'C':
            self._pos = start
            return None
        self._pos += 1
        col_relative, col = self._try_parse_r1c1_axis()
        if self._pos < len(self._src) and self._src[self._pos] in _NAME_CONTINUATION:
            self._pos = start
            return None
        self._skip_spaces()
        return XlR1C1Reference(
            sheets=sheets,
            row=row,
            col=col,
            relative_row=row_relative,
            relative_col=col_relative,
        )

    def _try_parse_r1c1_axis(self) -> tuple[bool, int]:
        char = self._peek()
        if char == self._lb:
            end = self._src.find(self._rb, self._pos)
            if end < 0:
                raise _ParseFailure
            try:
                offset = int(self._src[self._pos + 1:end])
            except ValueError:
                raise _ParseFailure
            self._pos = end + 1
            return True, offset
        digits = 0
        while self._pos + digits < len(self._src) and self._src[self._pos + digits].isdigit():
            digits += 1
        if not digits:
            return True, 0
        value = int(self._src[self._pos:self._pos + digits])
        self._pos += digits
        return False, value

    def _maybe_call(
        self,
        callee: XlA1Reference | XlR1C1Reference | XlDefinedName | str,
    ) -> Expression:
        if self._at_end() or self._peek() != '(':
            return callee if isinstance(callee, Expression) else XlDefinedName(name=callee)
        self._pos += 1
        self._skip_spaces()
        arguments: list[Expression] = []
        if self._peek() == ')':
            self._pos += 1
            self._skip_spaces()
            return XlFunctionCall(callee=callee, arguments=arguments)
        while True:
            if self._peek() in (self._sep, ')'):
                arguments.append(XlMissingArgument())
            else:
                arguments.append(self._parse_comparison())
            if self._peek() == self._sep:
                self._pos += 1
                self._skip_spaces()
                continue
            self._consume(')')
            return XlFunctionCall(callee=callee, arguments=arguments)
