"""
The numeric and logic commands of the macro language: the arithmetic of numbers, the truth of
conditions, the counting of arguments, and the Roman numerals of `_xlfn.ARABIC`.
"""
from __future__ import annotations

import datetime
import decimal
import math
import random

from typing import TYPE_CHECKING

from refinery.lib.excel import synthesize_formula
from refinery.lib.excel.common import datetime_to_serial
from refinery.lib.excel.formula.model import XlA1Reference, XlMissingArgument, XlR1C1Reference
from refinery.lib.scripts.xlm.evaluate import evaluate_expression
from refinery.lib.scripts.xlm.guess import guess_day
from refinery.lib.scripts.xlm.references import expand_range
from refinery.lib.scripts.xlm.trace import XlmStatus
from refinery.lib.scripts.xlm.values import (
    XlmOutcome,
    XlmValue,
    holds,
    is_number,
    wrap_literal,
)

if TYPE_CHECKING:
    from refinery.lib.excel.formula.model import XlFunctionCall
    from refinery.lib.scripts.xlm.engine import XlmEngine
    from refinery.lib.scripts.xlm.references import XlmCursor

#: How many seconds the answer of `NOW` advances from one call to the next, so that a program
#: which waits for a moment of the day moves on instead of reading the same moment forever.
_NOW_STEP = 2

#: How many times the answer of `ISERROR` may repeat at one cell before the emulator flips it,
#: to free a program stuck oscillating between two cells over a condition that never changes.
_ISERROR_REPEAT_LIMIT = 10

_ROMAN_VALUES = (
    ('M', 1000),
    ('CM', 900),
    ('D', 500),
    ('CD', 400),
    ('C', 100),
    ('XC', 90),
    ('L', 50),
    ('XL', 40),
    ('X', 10),
    ('IX', 9),
    ('V', 5),
    ('IV', 4),
    ('I', 1),
)


def _partial(spelled: str) -> XlmOutcome:
    return XlmOutcome(value=XlmValue(value=spelled, partial=True))


def _from_roman(spelled: str) -> int:
    result = 0
    position = 0
    for numeral, value in _ROMAN_VALUES:
        while spelled[position:position + len(numeral)] == numeral:
            result += value
            position += len(numeral)
    if position != len(spelled):
        raise ValueError(spelled)
    return result


def _numeric(
    engine: XlmEngine,
    call: XlFunctionCall,
    cursor: XlmCursor,
    index: int = 0,
) -> XlmValue | None:
    """
    One numeric operand of a command, or `None` when the command cannot compute: an operand
    the program never finished, or one that spells no number, leaves the command unevaluated.
    """
    argument = evaluate_expression(engine, call.arguments[index], cursor)
    if argument.partial or not is_number(argument.value):
        return None
    return argument


def _rounded(number: float, digits: int, rounding: str) -> float:
    """
    The number rounded to the given count of decimal digits in the direction a rounding mode of
    `decimal` names; a negative count rounds to the left of the decimal point. The rounding
    applies to the shortest decimal spelling of the number, the spelling Excel rounds, so that
    a tie that spelling shows is a tie.
    """
    spelled = decimal.Decimal(repr(number))
    exponent = spelled.as_tuple().exponent
    if isinstance(exponent, int) and exponent >= -digits:
        return number
    return float(spelled.quantize(decimal.Decimal(1).scaleb(-digits), rounding=rounding))


def _round_to_digits(
    engine: XlmEngine,
    call: XlFunctionCall,
    cursor: XlmCursor,
    rounding: str,
) -> XlmOutcome:
    """
    The rounding commands: the number of the first argument rounded to the count of decimal
    digits the second argument names, zero when the call names none.
    """
    spelled = synthesize_formula(call)
    number = _numeric(engine, call, cursor)
    if number is None:
        return _partial(spelled)
    digits = 0
    if len(call.arguments) > 1 and not isinstance(call.arguments[1], XlMissingArgument):
        count = _numeric(engine, call, cursor, 1)
        if count is None:
            return _partial(spelled)
        digits = int(float(count.value))
    try:
        result = _rounded(float(number.value), digits, rounding)
    except decimal.DecimalException:
        return _partial(spelled)
    return XlmOutcome(value=XlmValue(value=result))


def _abs(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    argument = _numeric(engine, call, cursor)
    if argument is None:
        return _partial(synthesize_formula(call))
    if isinstance(argument.value, bool):
        return XlmOutcome(value=XlmValue(value=int(argument.value)))
    return XlmOutcome(value=XlmValue(value=abs(float(argument.value))))


def _int(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    """
    The greatest integer that does not exceed the number, as `INT` rounds down.
    """
    argument = _numeric(engine, call, cursor)
    if argument is None:
        return _partial(synthesize_formula(call))
    return XlmOutcome(value=XlmValue(value=math.floor(float(argument.value))))


def _sqrt(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    argument = _numeric(engine, call, cursor)
    if argument is None:
        return _partial(synthesize_formula(call))
    try:
        result = math.sqrt(float(argument.value))
    except ValueError:
        return _partial(synthesize_formula(call))
    return XlmOutcome(value=XlmValue(value=result))


def _trunc(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    """
    The number cut toward zero to the count of decimal digits the call names.
    """
    return _round_to_digits(engine, call, cursor, decimal.ROUND_DOWN)


def _value(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    spelled = synthesize_formula(call)
    argument = evaluate_expression(engine, call.arguments[0], cursor)
    if not argument.partial and is_number(argument.value):
        number = float(argument.value)
        if number.is_integer():
            return XlmOutcome(value=XlmValue(value=int(number)))
        return XlmOutcome(value=XlmValue(value=number))
    if argument.partial:
        return _partial(spelled)
    return XlmOutcome(value=XlmValue(value=0, text=spelled), status=XlmStatus.Error)


def _pair(
    engine: XlmEngine,
    call: XlFunctionCall,
    cursor: XlmCursor,
) -> tuple[XlmValue, XlmValue] | None:
    """
    The two numeric operands of a command, or `None` when the command cannot compute.
    """
    left = evaluate_expression(engine, call.arguments[0], cursor)
    right = evaluate_expression(engine, call.arguments[1], cursor)
    if (
        left.partial
        or right.partial
        or not is_number(left.value)
        or not is_number(right.value)
    ):
        return None
    return left, right


def _mod(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    spelled = synthesize_formula(call)
    operands = _pair(engine, call, cursor)
    if operands is None:
        return _partial(spelled)
    left, right = operands
    try:
        result = float(left.value) % float(right.value)
    except ZeroDivisionError:
        return _partial(spelled)
    return XlmOutcome(value=XlmValue(value=result))


def _round(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    """
    The number rounded to the count of decimal digits the call names, a tie away from zero.
    """
    return _round_to_digits(engine, call, cursor, decimal.ROUND_HALF_UP)


def _round_up(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    """
    The number rounded away from zero to the count of decimal digits the call names.
    """
    return _round_to_digits(engine, call, cursor, decimal.ROUND_UP)


def _randbetween(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    spelled = synthesize_formula(call)
    operands = _pair(engine, call, cursor)
    if operands is None:
        return _partial(spelled)
    left, right = operands
    try:
        result = random.randint(int(float(left.value)), int(float(right.value)))
    except ValueError:
        return _partial(spelled)
    return XlmOutcome(value=XlmValue(value=result))


def _quotient(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    """
    The integer part of the division of the two operands, the remainder discarded toward zero.
    """
    spelled = synthesize_formula(call)
    operands = _pair(engine, call, cursor)
    if operands is None:
        return _partial(spelled)
    left, right = operands
    try:
        result = math.trunc(float(left.value) / float(right.value))
    except (ZeroDivisionError, OverflowError):
        return _partial(spelled)
    return XlmOutcome(value=XlmValue(value=result))


def _extreme(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor, choose) -> XlmOutcome:
    spelled = synthesize_formula(call)
    numbers: list[float] = []
    for node in call.arguments:
        argument = evaluate_expression(engine, node, cursor)
        if argument.partial or not is_number(argument.value):
            return _partial(spelled)
        numbers.append(float(argument.value))
    if not numbers:
        return _partial(spelled)
    return XlmOutcome(value=XlmValue(value=choose(numbers)))


def _max(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    return _extreme(engine, call, cursor, max)


def _min(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    return _extreme(engine, call, cursor, min)


def _product(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    spelled = synthesize_formula(call)
    total = 1.0
    seen = 0
    for node in call.arguments:
        argument = evaluate_expression(engine, node, cursor)
        if argument.partial or not is_number(argument.value):
            return _partial(spelled)
        total *= float(argument.value)
        seen += 1
    if not seen:
        return _partial(spelled)
    return XlmOutcome(value=XlmValue(value=total))


def _sum(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    spelled = synthesize_formula(call)
    total = 0.0
    for node in call.arguments:
        argument = evaluate_expression(engine, node, cursor)
        if argument.partial or not is_number(argument.value):
            return _partial(spelled)
        total += float(argument.value)
    return XlmOutcome(value=XlmValue(value=total))


def _and(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    value = True
    for node in call.arguments:
        argument = evaluate_expression(engine, node, cursor)
        if argument.partial:
            return XlmOutcome(value=XlmValue(value=False, partial=True))
        if not holds(argument):
            value = False
            break
    return XlmOutcome(value=XlmValue(value=value))


def _or(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    value = False
    for node in call.arguments:
        argument = evaluate_expression(engine, node, cursor)
        if argument.partial:
            return XlmOutcome(value=XlmValue(value=False, partial=True))
        if holds(argument):
            value = True
            break
    return XlmOutcome(value=XlmValue(value=value))


def _not(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    argument = evaluate_expression(engine, call.arguments[0], cursor)
    if argument.partial:
        return XlmOutcome(value=XlmValue(value=True, partial=True))
    return XlmOutcome(value=XlmValue(value=not holds(argument)))


def _isnumber(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    argument = evaluate_expression(engine, call.arguments[0], cursor)
    if argument.partial:
        return XlmOutcome(value=XlmValue(
            value=True,
            text=F'ISNUMBER({argument.text})',
            partial=True,
        ))
    return XlmOutcome(value=XlmValue(value=is_number(argument.text)))


def _iserror(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    """
    Whether the argument is an error value, or a value that computes nothing. The answer flips
    once it repeated at one cell often enough, to free a program stuck waiting on a condition
    that never changes.
    """
    argument = evaluate_expression(engine, call.arguments[0], cursor)
    result = argument.value is None or argument.error
    if engine.iserror_at is None:
        engine.iserror_flag = result
        engine.iserror_at = cursor
        engine.iserror_repeats = 1
    elif engine.iserror_at == cursor:
        if engine.iserror_flag != result:
            engine.iserror_flag = result
            engine.iserror_repeats = 1
        elif engine.iserror_repeats < _ISERROR_REPEAT_LIMIT:
            engine.iserror_repeats += 1
        else:
            result = not result
            engine.iserror_at = None
    return XlmOutcome(value=XlmValue(
        value=result,
        text=F'ISERROR({wrap_literal(argument.unwrap())})',
    ))


def _count(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    """
    How many of the arguments are numbers: a reference or a range counts the cells that hold a
    number, and any other argument counts when it is a number, a truth value, or a text that
    spells a number. A value the program never finished leaves the count unevaluated.
    """
    spelled = synthesize_formula(call)
    count = 0
    for node in call.arguments:
        corners = engine.range_corners(node, cursor)
        if corners is None and isinstance(node, (XlA1Reference, XlR1C1Reference)):
            reference = engine.node_reference(node, cursor)
            if reference is not None:
                corners = (reference, reference)
        if corners is not None:
            for reference in expand_range(*corners):
                value = engine.read_reference(reference, cursor)
                if value.partial:
                    return _partial(spelled)
                if (
                    not value.error
                    and not isinstance(value.value, (str, bool))
                    and is_number(value.value)
                ):
                    count += 1
            continue
        if isinstance(node, XlMissingArgument):
            continue
        argument = evaluate_expression(engine, node, cursor)
        if argument.partial:
            return _partial(spelled)
        if not argument.error and is_number(argument.value):
            count += 1
    return XlmOutcome(value=XlmValue(value=count))


def _day(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    spelled = synthesize_formula(call)
    if engine.day >= 0:
        text = str(engine.day)
        return XlmOutcome(value=XlmValue(value=text, text=text))
    argument = evaluate_expression(engine, call.arguments[0], cursor)
    if argument.partial:
        return _partial(spelled)
    if argument.date:
        day = guess_day(engine)
        engine.day = day
        text = str(day)
        return XlmOutcome(value=XlmValue(value=text, text=text))
    if is_number(argument.value):
        return XlmOutcome(
            value=XlmValue(value=0, text='DAY(Serial Date)'),
            status=XlmStatus.NotImplemented,
        )
    return _partial(spelled)


def _now(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    moment = datetime.datetime.now() + datetime.timedelta(
        seconds=engine.now_count * _NOW_STEP,
    )
    engine.now_count += 1
    return XlmOutcome(value=XlmValue(value=datetime_to_serial(moment, False)))


def _arabic(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    spelled = synthesize_formula(call)
    argument = evaluate_expression(engine, call.arguments[0], cursor)
    if argument.partial:
        return _partial(spelled)
    try:
        result = _from_roman(argument.unwrap().upper())
    except ValueError:
        return _partial(spelled)
    return XlmOutcome(value=XlmValue(value=result))


FUNCTION_HANDLERS = {
    'ABS': _abs,
    'AND': _and,
    'COUNT': _count,
    'DAY': _day,
    'INT': _int,
    'ISERROR': _iserror,
    'ISNUMBER': _isnumber,
    'MAX': _max,
    'MIN': _min,
    'MOD': _mod,
    'NOT': _not,
    'NOW': _now,
    'OR': _or,
    'PRODUCT': _product,
    'QUOTIENT': _quotient,
    'RANDBETWEEN': _randbetween,
    'ROUND': _round,
    'ROUNDUP': _round_up,
    'SQRT': _sqrt,
    'SUM': _sum,
    'TRUNC': _trunc,
    'VALUE': _value,
    '_xlfn.ARABIC': _arabic,
}
