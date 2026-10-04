"""
The text commands of the macro language: the characters, lengths, slices, and searches of the
strings the macro program assembles.
"""
from __future__ import annotations

import re

from typing import TYPE_CHECKING

from refinery.lib.excel import synthesize_formula
from refinery.lib.excel.formula.model import XlMissingArgument
from refinery.lib.scripts.xlm.evaluate import evaluate_expression
from refinery.lib.scripts.xlm.values import (
    XlmOutcome,
    XlmValue,
    ansi_bytes,
    error_value,
    is_number,
    wrap_literal,
)

if TYPE_CHECKING:
    from refinery.lib.excel.formula.model import XlFunctionCall
    from refinery.lib.scripts.xlm.engine import XlmEngine
    from refinery.lib.scripts.xlm.references import XlmCursor


#: The wildcards of a search pattern, and the tilde that makes the one after it literal.
_WILDCARDS = re.compile(r'~([?*~])|([?*])')


def _partial(spelled: str) -> XlmOutcome:
    return XlmOutcome(value=XlmValue(value=spelled, partial=True))


def _wildcard_pattern(pattern: str) -> str:
    """
    The regular expression a search pattern spells: a question mark matches any one character,
    an asterisk any run of characters, and a tilde makes the wildcard or tilde after it literal.
    """
    parts = []
    position = 0
    for match in _WILDCARDS.finditer(pattern):
        parts.append(re.escape(pattern[position:match.start()]))
        literal, wildcard = match.groups()
        if literal:
            parts.append(re.escape(literal))
        elif wildcard == '?':
            parts.append('.')
        else:
            parts.append('.*')
        position = match.end()
    parts.append(re.escape(pattern[position:]))
    return ''.join(parts)


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
    if not 1 <= number <= 255:
        engine.char_errors += 1
        return XlmOutcome(value=error_value('#VALUE!'))
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
    return XlmOutcome(value=XlmValue(value=ansi_bytes(unwrapped[0])[0]))


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
        if start < 0 or count < 0:
            return XlmOutcome(value=error_value('#VALUE!'))
        result = text.unwrap()[start:start + count]
        return XlmOutcome(value=XlmValue(value=result, text=result))
    fragments = ','.join(synthesize_formula(node) for node in call.arguments)
    return XlmOutcome(value=XlmValue(value=F'MID({fragments})', partial=True))


def _search(engine: XlmEngine, call: XlFunctionCall, cursor: XlmCursor) -> XlmOutcome:
    """
    The position of the first match of a pattern in a text, counted from one and ignoring case,
    from the position the third argument names on. A pattern spells wildcards, and a pattern
    the text does not hold, or a position outside the text, answers `#VALUE!`.
    """
    needle = evaluate_expression(engine, call.arguments[0], cursor)
    haystack = evaluate_expression(engine, call.arguments[1], cursor)
    start = XlmValue(value=1)
    if len(call.arguments) > 2 and not isinstance(call.arguments[2], XlMissingArgument):
        start = evaluate_expression(engine, call.arguments[2], cursor)
    if needle.partial or haystack.partial or start.partial:
        return XlmOutcome(value=XlmValue(
            value=0,
            text=F'SEARCH({needle.text},{haystack.text})',
            partial=True,
        ))
    for argument in (needle, haystack, start):
        if argument.error:
            return XlmOutcome(value=argument)
    within = haystack.unwrap()
    if not is_number(start.value) or not 1 <= float(start.value) <= len(within):
        return XlmOutcome(value=error_value('#VALUE!'))
    pattern = re.compile(_wildcard_pattern(needle.unwrap()), re.IGNORECASE | re.DOTALL)
    match = pattern.search(within, int(float(start.value)) - 1)
    if match is None:
        return XlmOutcome(value=error_value('#VALUE!'))
    return XlmOutcome(value=XlmValue(value=match.start() + 1))


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
