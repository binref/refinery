"""
The value algebra of the XLM macro language: the values the emulator computes, the quoting
the trace spells them with, and the operations the evaluator applies to them.
"""
from __future__ import annotations

import datetime
import math
import operator

from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any, NamedTuple

from refinery.lib.excel.common import column_letters
from refinery.lib.excel.formula.model import XlBinaryOperator
from refinery.lib.scripts.xlm.trace import XlmStatus

if TYPE_CHECKING:
    from refinery.lib.scripts.xlm.references import XlmArrival, XlmCursor

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
    Whether a value reads as a number, as the macro language reads one: a finite number is one,
    and so is the text of one. The digit separators, the infinities, and the missing number
    that Python reads in a text spell no number of the macro language.
    """
    if isinstance(value, str) and '_' in value:
        return False
    try:
        number = float(value)
    except (ValueError, TypeError, OverflowError):
        return False
    return math.isfinite(number)


def condition(value: XlmValue) -> bool | XlmValue:
    """
    The truth of a value, as every command that reads a condition reads it: the spellings of the
    two truth values are theirs, a number holds when it is not zero — by its type, so the text
    of a number holds nothing — a value that holds nothing answers `FALSE`, and a value that is
    an error value is that error. Any other text is the `#VALUE!` error Excel answers for a
    condition that spells no truth value.
    """
    if value.error:
        return value
    data = value.value
    if data is None or data == '':
        return False
    if isinstance(data, bool):
        return data
    if isinstance(data, (int, float)):
        return data != 0
    if isinstance(data, str):
        lowered = data.lower()
        if lowered == 'true':
            return True
        if lowered == 'false':
            return False
    return error_value('#VALUE!')


def error_outcome(
    truth: XlmValue,
    spelled: str | None = None,
    halts: bool = False,
) -> XlmOutcome:
    """
    The outcome a command that reads a condition answers for one that spells no truth value:
    the error value the condition is, spelled as the command when it names one, and an error
    the macro halts on when its grammar makes the condition fatal.
    """
    if spelled is not None:
        truth = replace(truth, text=spelled)
    return XlmOutcome(value=truth, status=XlmStatus.Error if halts else None)


def unwrap_literal(text: str) -> str:
    """
    The text of a quoted string literal without its quotes; a text that carries no quotes
    keeps its spelling, and a doubled quote inside the literal spells one quote.
    """
    if len(text) > 1 and text.startswith('"') and text.endswith('"'):
        return text[1:-1].replace('""', '"')
    return text


def ansi_bytes(text: str) -> bytes:
    """
    The bytes a text occupies in the ANSI code page the macro language writes: a character
    `CHAR` answers is the byte it was made from, any other character its byte in code page
    1252, and a character that code page cannot spell is the question mark Windows writes
    instead.
    """
    data = bytearray()
    for char in text:
        code = ord(char)
        if code > 0xFF:
            try:
                code = char.encode('cp1252')[0]
            except UnicodeEncodeError:
                code = 0x3F
        data.append(code)
    return bytes(data)


def wrap_literal(data: Any, must_wrap: bool = False) -> str:
    """
    The spelling the trace gives a value: a number, a boolean, and a text that already carries
    quotes keep their own spelling — the quoted text only while the caller does not insist on
    quotes — and every other text is quoted with its quotes doubled.
    """
    if isinstance(data, bool):
        return 'TRUE' if data else 'FALSE'
    if is_number(data) or (
        isinstance(data, str)
        and len(data) > 1
        and data.startswith('"')
        and data.endswith('"')
        and not must_wrap
    ):
        return str(data)
    if isinstance(data, float) and data.is_integer():
        return str(int(data))
    if isinstance(data, int):
        return str(data)
    return F'"{str(data).replace(chr(34), chr(34) * 2)}"'


def _default_text(value: Any) -> str:
    if value is None:
        return ''
    if isinstance(value, XlmReference):
        return value.a1()
    if isinstance(value, bool):
        return 'TRUE' if value else 'FALSE'
    if isinstance(value, str):
        return wrap_literal(value, must_wrap=True)
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


def error_value(text: str) -> XlmValue:
    """
    The error value Excel spells with the given text, such as the `#VALUE!` of a coercion that
    failed.
    """
    return XlmValue(value=text, text=text, error=True)


@dataclass(repr=False, eq=False)
class XlmValue:
    """
    One value of the macro language as the emulator computes it: `value` is the Python object
    behind it, `text` the spelling the trace prints, `partial` marks a value whose computation
    the program never finished, `date` marks a value that came from a date cell, `reference`
    names the cell address the value stands for, `cells` holds the elements of an array or the
    corners of a range, and `error` marks an error value such as the `#DIV/0!` of a division
    by zero. A given spelling of a number is normalized unless the value is a text, whose
    spelling is its content.
    """

    value: Any = None
    text: str | None = None
    partial: bool = False
    date: bool = False
    reference: XlmReference | None = None
    cells: tuple[XlmValue, ...] | None = None
    error: bool = False

    def __post_init__(self):
        if self.text is None:
            if isinstance(self.value, bool):
                self.text = 'TRUE' if self.value else 'FALSE'
            elif self.partial:
                self.text = str(self.value)
            else:
                self.text = _default_text(self.value)
        elif not isinstance(self.value, str) and is_number(self.text):
            number = float(self.text)
            self.text = str(int(number) if number.is_integer() else number)

    def unwrap(self) -> str:
        """
        The content of the value as a text. A text the program finished computing is its own
        content, and any other finished value is spelled as itself, whatever spelling the trace
        gives the command that computed it; a value the program never finished is the spelling
        of what it left unfinished, without the quotes of a string literal.
        """
        if self.partial:
            return unwrap_literal(self.text or '')
        if isinstance(self.value, str):
            return self.value
        return _default_text(self.value)

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


_ARITHMETIC_OPERATORS = frozenset((
    XlBinaryOperator.ADD,
    XlBinaryOperator.SUB,
    XlBinaryOperator.MUL,
    XlBinaryOperator.DIV,
    XlBinaryOperator.POW,
))


def _numeric_result(result: Any) -> XlmValue:
    if isinstance(result, bool):
        return XlmValue(value=result)
    if isinstance(result, complex) or (isinstance(result, float) and not math.isfinite(result)):
        return error_value('#NUM!')
    if isinstance(result, float) and result.is_integer():
        return XlmValue(value=int(result))
    if isinstance(result, float):
        return XlmValue(value=round(result, 10))
    return XlmValue(value=result)


def concat(left: XlmValue, right: XlmValue) -> XlmValue:
    """
    The `&` of two values: their joined texts when both are complete, the two texts joined by
    the operator itself when either side is partial, and the error of the first side that is
    an error value.
    """
    if left.partial or right.partial:
        fragment = F'{left.unwrap()}&{right.unwrap()}'
        return XlmValue(value=fragment, partial=True)
    if left.error:
        return left
    if right.error:
        return right
    joined = left.unwrap() + right.unwrap()
    return XlmValue(value=joined)


def apply_binary(operator: XlBinaryOperator, left: XlmValue, right: XlmValue) -> XlmValue:
    """
    The value of a binary operation. A partial operand leaves the operation unevaluated,
    spelled as its two operands around the operator, and an operand that is an error value is
    the value of the whole operation. Complete operands apply the operator table to numbers,
    compare the moments an ISO-spelled text names, and compare anything else as text. A
    division by zero degrades to `#DIV/0!`, a result no finite number holds to `#NUM!`, and an
    arithmetic operand or a coercion that fails to `#VALUE!`, the errors Excel displays for
    them.
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
    if left.error:
        return left
    if right.error:
        return right
    operand_left = _operand(left)
    operand_right = _operand(right)
    if is_number(operand_left) and is_number(operand_right):
        function = _OPERATOR_FUNCTIONS[operator]
        try:
            return _numeric_result(function(float(operand_left), float(operand_right)))
        except ZeroDivisionError:
            return error_value('#DIV/0!')
        except OverflowError:
            return error_value('#NUM!')
    moment_left = left.unwrap_date()
    moment_right = right.unwrap_date()
    if moment_left is not None and moment_right is not None:
        function = _OPERATOR_FUNCTIONS[operator]
        try:
            return _numeric_result(function(moment_left, moment_right))
        except TypeError:
            return error_value('#VALUE!')
    if operator in _ARITHMETIC_OPERATORS:
        return error_value('#VALUE!')
    function = _OPERATOR_FUNCTIONS[operator]
    try:
        return _numeric_result(function(left.unwrap(), right.unwrap()))
    except TypeError:
        return error_value('#VALUE!')


class XlmOutcome:
    """
    What one macro command produced: the value it computed, the jump it asks the engine to
    take, the status that overrides the one its value derives, whether it halts the program,
    and the arrival the engine lands the jump by, for a jump the command that asks for it
    does not name — the step a macro call jumps to and the cell a return continues at. A
    handler that neither jumps nor overrides a status leaves both empty.
    """

    def __init__(
        self,
        value: XlmValue | None = None,
        jump: XlmCursor | None = None,
        status: XlmStatus | None = None,
        halts: bool = False,
        arrival: XlmArrival | None = None,
    ):
        self.value = XlmValue() if value is None else value
        self.jump = jump
        self.status = status
        self.halts = halts
        self.arrival = arrival
