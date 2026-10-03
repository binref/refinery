"""
The text commands of the macro language: the characters, lengths, slices, and searches of the
strings the macro program assembles.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from refinery.lib.excel import synthesize_formula
from refinery.lib.scripts.xlm.evaluate import evaluate_expression
from refinery.lib.scripts.xlm.trace import XlmStatus
from refinery.lib.scripts.xlm.values import XlmOutcome, XlmValue, is_number, wrap_literal

if TYPE_CHECKING:
    from refinery.lib.excel.formula.model import XlFunctionCall
    from refinery.lib.scripts.xlm.engine import XlmEngine
    from refinery.lib.scripts.xlm.references import XlmCursor


def _partial(spelled: str) -> XlmOutcome:
    return XlmOutcome(value=XlmValue(value=spelled, partial=True))


def _char(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    spelled = synthesize_formula(call)
    argument = evaluate_expression(engine, call.arguments[0], cursor)
    if argument.partial:
        return XlmOutcome(value=XlmValue(
            value=F'CHAR({argument.text})',
            partial=True,
        ))
    if not is_number(argument.value):
        return _partial(spelled)
    number = float(argument.value)
    if not 0 <= number <= 255:
        engine.char_errors += 1
        return XlmOutcome(
            value=XlmValue(value=spelled, text=spelled),
            status=XlmStatus.Error,
        )
    character = chr(int(number))
    return XlmOutcome(value=XlmValue(value=character, text=character))


def _code(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    spelled = synthesize_formula(call)
    argument = evaluate_expression(engine, call.arguments[0], cursor)
    if argument.partial:
        return _partial(spelled)
    unwrapped = argument.unwrap()
    if not unwrapped:
        return XlmOutcome(value=XlmValue(value=0))
    code = ord(unwrapped[0])
    if code > 256:
        try:
            code = unwrapped[0].encode('cp1252')[0]
        except UnicodeEncodeError:
            pass
    return XlmOutcome(value=XlmValue(value=code))


def _concatenate(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    joined = ''.join(
        evaluate_expression(engine, node, cursor).unwrap()
        for node in call.arguments
    )
    return XlmOutcome(value=XlmValue(value=joined))


def _len(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    spelled = synthesize_formula(call)
    argument = evaluate_expression(engine, call.arguments[0], cursor)
    if argument.partial:
        return _partial(spelled)
    return XlmOutcome(value=XlmValue(value=len(argument.unwrap())))


def _mid(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    text = evaluate_expression(engine, call.arguments[0], cursor)
    base = evaluate_expression(engine, call.arguments[1], cursor)
    length = evaluate_expression(engine, call.arguments[2], cursor)
    if (
        not text.partial
        and not base.partial
        and not length.partial
        and is_number(base.value)
        and is_number(length.value)
    ):
        start = int(float(base.value)) - 1
        count = int(float(length.value))
        result = text.unwrap()[start:start + count]
        return XlmOutcome(value=XlmValue(value=result, text=str(result)))
    fragments = ','.join(synthesize_formula(node) for node in call.arguments)
    return XlmOutcome(value=XlmValue(value=F'MID({fragments})', partial=True))


def _search(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    needle = evaluate_expression(engine, call.arguments[0], cursor)
    haystack = evaluate_expression(engine, call.arguments[1], cursor)
    if not needle.partial and not haystack.partial:
        try:
            position = haystack.unwrap().lower().index(needle.unwrap().lower())
        except ValueError:
            return XlmOutcome(value=XlmValue(value=None, text=''))
        return XlmOutcome(value=XlmValue(value=position))
    return XlmOutcome(value=XlmValue(
        value=0,
        text=F'SEARCH({needle.text},{haystack.text})',
        partial=True,
    ))


def _t(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    spelled = synthesize_formula(call)
    argument = evaluate_expression(engine, call.arguments[0], cursor)
    if argument.partial:
        return _partial(spelled)
    if isinstance(argument.value, bool) or argument.value is None:
        value = ''
    else:
        value = str(argument.value)
    return XlmOutcome(value=XlmValue(
        value=value,
        text=wrap_literal(value, must_wrap=True),
    ))


def _text(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    spelled = synthesize_formula(call)
    value = evaluate_expression(engine, call.arguments[0], cursor)
    form = evaluate_expression(engine, call.arguments[1], cursor)
    if (
        not value.partial
        and not form.partial
        and is_number(value.value)
        and is_number(form.unwrap())
        and int(float(form.unwrap())) == 0
    ):
        return XlmOutcome(value=XlmValue(value=int(float(value.value))))
    return _partial(spelled)


STRING_HANDLERS = {
    'CHAR': _char,
    'CODE': _code,
    'CONCATENATE': _concatenate,
    'LEN': _len,
    'MID': _mid,
    'SEARCH': _search,
    'T': _t,
    'TEXT': _text,
}
