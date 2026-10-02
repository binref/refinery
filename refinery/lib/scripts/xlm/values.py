"""
The value algebra of the XLM macro language: the values the emulator computes, the quoting
the trace spells them with, and the operations the evaluator applies to them.
"""
from __future__ import annotations

import datetime
import operator

from dataclasses import dataclass
from typing import Any, NamedTuple

from refinery.lib.excel.common import column_letters
from refinery.lib.excel.formula.model import XlBinaryOperator
from refinery.lib.scripts.xlm.trace import XlmStatus

_DATETIME_FORMATS = (
    '%Y-%m-%d %H:%M:%S.%f',
    '%H:%M:%S',
)


class XlmReference(NamedTuple):
    """
    The address of one cell: the sheet it sits on — `None` names the sheet the reading
    formula is on — and its one-based row and column.
    """

    sheet: str | None
    row: int
    col: int

    def a1(self) -> str:
        """
        The A1 spelling of the address, qualified by its sheet when it names one.
        """
        cell = F'{column_letters(self.col)}{self.row}'
        if self.sheet is None:
            return cell
        return F'{self.sheet}!{cell}'


def is_number(value: Any) -> bool:
    """
    Whether a value reads as a number, as the macro language reads one: a number is one, and
    so is the text of a number.
    """
    try:
        float(value)
    except (ValueError, TypeError):
        return False
    return True


def unwrap_literal(text: str) -> str:
    """
    The text of a quoted string literal without its quotes; a text that carries no quotes
    keeps its spelling, and a doubled quote inside the literal spells one quote.
    """
    if len(text) > 1 and text.startswith('"') and text.endswith('"'):
        return text[1:-1].replace('""', '"')
    return text


def wrap_literal(data: Any, must_wrap: bool = False) -> str:
    """
    The spelling the trace gives a value: a number and a boolean keep their own text, a text
    that already carries quotes keeps them, and every other text is quoted with its quotes
    doubled — unless the caller insists on quotes around anything, numbers included.
    """
    if is_number(data) or (
        len(data) > 1
        and data.startswith('"')
        and data.endswith('"')
        and not must_wrap
    ):
        return str(data)
    if isinstance(data, float) and data.is_integer():
        return str(int(data))
    if isinstance(data, (int, bool)):
        return str(data)
    return F'"{str(data).replace(chr(34), chr(34) * 2)}"'


def _default_text(value: Any) -> str:
    if value is None:
        return ''
    if isinstance(value, XlmReference):
        return value.a1()
    if isinstance(value, str):
        return wrap_literal(value)
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


def _error(text: str) -> XlmValue:
    return XlmValue(value=text, text=text)


@dataclass(repr=False, eq=False)
class XlmValue:
    """
    One value of the macro language as the emulator computes it: `value` is the Python object
    behind it, `text` the spelling the trace prints, `partial` marks a value whose computation
    the program never finished, `date` marks a value that came from a date cell, `reference`
    names the cell address the value stands for, and `cells` holds the elements of an array or
    the corners of a range.
    """

    value: Any = None
    text: str | None = None
    partial: bool = False
    date: bool = False
    reference: XlmReference | None = None
    cells: tuple[XlmValue, ...] | None = None

    def __post_init__(self):
        if self.text is None:
            self.text = str(self.value) if self.partial else _default_text(self.value)
        elif is_number(self.text):
            number = float(self.text)
            self.text = str(int(number) if number.is_integer() else number)

    def unwrap(self) -> str:
        """
        The text of the value without the quotes of a string literal.
        """
        return unwrap_literal(self.text)

    def unwrap_date(self) -> datetime.datetime | None:
        """
        The moment an ISO-spelled text names, in one of the spellings the macro language
        writes into cells, or `None` for a text that names none.
        """
        for spelling in _DATETIME_FORMATS:
            try:
                return datetime.datetime.strptime(self.unwrap(), spelling)
            except ValueError:
                continue
        return None


_OPERATOR_FUNCTIONS = {
    XlBinaryOperator.ADD: operator.add,
    XlBinaryOperator.SUB: operator.sub,
    XlBinaryOperator.MUL: operator.mul,
    XlBinaryOperator.DIV: operator.truediv,
    XlBinaryOperator.POW: operator.pow,
    XlBinaryOperator.EQ: operator.eq,
    XlBinaryOperator.NE: operator.ne,
    XlBinaryOperator.LT: operator.lt,
    XlBinaryOperator.LE: operator.le,
    XlBinaryOperator.GT: operator.gt,
    XlBinaryOperator.GE: operator.ge,
}

_OPERATOR_SYMBOLS = {
    XlBinaryOperator.ADD: '+',
    XlBinaryOperator.SUB: '-',
    XlBinaryOperator.MUL: '*',
    XlBinaryOperator.DIV: '/',
    XlBinaryOperator.POW: '^',
    XlBinaryOperator.EQ: '=',
    XlBinaryOperator.NE: '<>',
    XlBinaryOperator.LT: '<',
    XlBinaryOperator.LE: '<=',
    XlBinaryOperator.GT: '>',
    XlBinaryOperator.GE: '>=',
}


def _operand(value: XlmValue) -> Any:
    """
    The operand the operator table applies: a boolean is its number, an empty text is zero,
    and the spellings of TRUE and FALSE are theirs.
    """
    if isinstance(value.value, bool):
        return value.value
    if value.unwrap() == '':
        return 0
    if isinstance(value.value, str):
        lowered = value.value.lower()
        if lowered == 'true':
            return 1
        if lowered == 'false':
            return 0
    return value.value


def _numeric_result(result: Any) -> XlmValue:
    if isinstance(result, bool):
        return XlmValue(value=str(result), text=str(result))
    if isinstance(result, float) and result.is_integer():
        return XlmValue(value=int(result))
    if isinstance(result, float):
        return XlmValue(value=round(result, 10))
    return XlmValue(value=result)


def concat(left: XlmValue, right: XlmValue) -> XlmValue:
    """
    The `&` of two values: their joined texts when both are complete, and the two texts joined
    by the operator itself when either side is partial.
    """
    if left.partial or right.partial:
        fragment = F'{left.unwrap()}&{right.unwrap()}'
        return XlmValue(value=fragment, partial=True)
    joined = left.unwrap() + right.unwrap()
    return XlmValue(value=joined)


def apply_binary(operator: XlBinaryOperator, left: XlmValue, right: XlmValue) -> XlmValue:
    """
    The value of a binary operation. A partial operand leaves the operation unevaluated,
    spelled as its two operands around the operator; complete operands apply the operator
    table to numbers, compare the moments an ISO-spelled text names, and compare anything else
    as text. A division by zero degrades to `#DIV/0!` and a coercion that fails to
    `#VALUE!`, the errors Excel displays for them.
    """
    if operator is XlBinaryOperator.CONCAT:
        return concat(left, right)
    if operator is XlBinaryOperator.RANGE:
        return XlmValue(
            value=F'{left.unwrap()}:{right.unwrap()}',
            cells=(left, right),
            partial=left.partial or right.partial,
        )
    if operator is XlBinaryOperator.ISECT or operator is XlBinaryOperator.UNION:
        separator = ' ' if operator is XlBinaryOperator.ISECT else ','
        return XlmValue(
            value=F'{left.unwrap()}{separator}{right.unwrap()}',
            partial=True,
        )
    if left.partial or right.partial:
        fragment = F'{left.unwrap()}{_OPERATOR_SYMBOLS[operator]}{right.unwrap()}'
        return XlmValue(value=fragment, partial=True)
    operand_left = _operand(left)
    operand_right = _operand(right)
    if is_number(operand_left) and is_number(operand_right):
        function = _OPERATOR_FUNCTIONS[operator]
        try:
            return _numeric_result(function(float(operand_left), float(operand_right)))
        except ZeroDivisionError:
            return _error('#DIV/0!')
    moment_left = left.unwrap_date()
    moment_right = right.unwrap_date()
    if moment_left is not None and moment_right is not None:
        function = _OPERATOR_FUNCTIONS[operator]
        try:
            return _numeric_result(function(moment_left, moment_right))
        except TypeError:
            return _error('#VALUE!')
    function = _OPERATOR_FUNCTIONS[operator]
    try:
        return _numeric_result(function(left.unwrap(), right.unwrap()))
    except TypeError:
        return _error('#VALUE!')


class XlmOutcome:
    """
    What one macro command produced: the value it computed, the jump it asks the engine to
    take, and the status that overrides the one its value derives. A handler that neither
    jumps nor overrides a status leaves both empty.
    """

    def __init__(
        self,
        value: XlmValue | None = None,
        jump: XlmReference | None = None,
        status: XlmStatus | None = None,
    ):
        self.value = XlmValue() if value is None else value
        self.jump = jump
        self.status = status
