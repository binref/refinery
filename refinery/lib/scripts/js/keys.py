"""
How the analyses read a property key, and what a call that may install an accessor installs.

A key is read as `refinery.lib.scripts.js.model.static_string` reads an expression, and a number,
boolean or `null` key as the text it converts to, so `o['constr' + 'uctor']` reads `constructor`
and `a[0]` reads `0` to every reader. A reader asks one of two questions of a key: its text
(`key_text`), for a reader that records the key itself and is unbounded where there is none, or
whether it may be one of a set of names (`key_may_be`), where a key without a text may be any.
"""
from __future__ import annotations

from typing import Iterator, NamedTuple

from refinery.lib.scripts import Node
from refinery.lib.scripts.js.model import (
    RECEIVER_INSTALL_METHODS,
    JsArrayExpression,
    JsBigIntLiteral,
    JsBinaryExpression,
    JsBooleanLiteral,
    JsCallExpression,
    JsIdentifier,
    JsMemberExpression,
    JsNullLiteral,
    JsNumericLiteral,
    JsObjectExpression,
    JsProperty,
    JsRegExpLiteral,
    JsSpreadElement,
    JsStringLiteral,
    JsTemplateLiteral,
    JsUnaryExpression,
    JsUpdateExpression,
    _primitive_literal_text,
    static_string,
    strip_parens,
)

_PRIMITIVE_FORMS = (
    JsBigIntLiteral,
    JsBinaryExpression,
    JsBooleanLiteral,
    JsNullLiteral,
    JsNumericLiteral,
    JsStringLiteral,
    JsTemplateLiteral,
    JsUnaryExpression,
    JsUpdateExpression,
)
"""
The expressions that evaluate to a primitive whatever their operands are.
"""

_UNCALLABLE_FORMS = _PRIMITIVE_FORMS + (
    JsArrayExpression,
    JsObjectExpression,
    JsRegExpLiteral,
)
"""
The expressions that evaluate to a value no call can run.
"""


def expression_key(node: Node | None) -> str | None:
    """
    The property key the expression *node* certainly converts to: the string `static_string` reads
    it as, or the text of a number, boolean or `null` literal; `None` for any other expression.
    """
    text = static_string(node)
    if text is None:
        text = _primitive_literal_text(node)
    return text


def key_text(owner: JsMemberExpression | JsProperty) -> str | None:
    """
    The key the member access or object literal property *owner* certainly names: the name of a
    dotted access or of a plain property, or the `expression_key` of any other key.
    """
    key = owner.property if isinstance(owner, JsMemberExpression) else owner.key
    if not owner.computed and isinstance(key, JsIdentifier):
        return key.name
    return expression_key(key)


def key_may_be(owner: JsMemberExpression | JsProperty, names: frozenset[str]) -> bool:
    """
    Whether the key *owner* names may be one of *names*: a key without a `key_text` may be any.
    """
    text = key_text(owner)
    return text is None or text in names


class AccessorInstall(NamedTuple):
    """
    An install a call may make: *target* is the expression naming the object it installs on, and
    *key* the property it installs, `None` where the install is not bounded to one key.
    """
    target: Node
    key: str | None


def accessor_installs(call: JsCallExpression) -> Iterator[AccessorInstall]:
    """
    Every install of an accessor or a data descriptor *call* may make. A method key without a text
    may be any installer, so such a call may install on its receiver, where its second argument
    may be a function, and on its first argument, where the second or the third may be an object;
    neither install is bounded to a key. An installer the call names installs where ECMA-262 lets
    it: `__defineGetter__` and `__defineSetter__` throw for an uncallable function (B.2.2.2), and
    `defineProperty` and `defineProperties` for a descriptor that is no object. A spread at or
    before a position may put anything there; a spread target names no object.
    """
    callee = strip_parens(call.callee)
    if not isinstance(callee, JsMemberExpression) or callee.object is None:
        return
    method = key_text(callee)
    if method is None or method in RECEIVER_INSTALL_METHODS:
        if _may_be_callable(_argument(call, 1)):
            yield AccessorInstall(callee.object, None if method is None else _argument_key(call, 0))
    if method is None:
        descriptors = (_argument(call, 1), _argument(call, 2))
        key = None
    elif method == 'defineProperty':
        descriptors = (_argument(call, 2),)
        key = _argument_key(call, 1)
    elif method == 'defineProperties':
        descriptors = (_argument(call, 1),)
        key = None
    else:
        return
    target = _argument(call, 0)
    if target is None or isinstance(target, JsSpreadElement):
        return
    if any(_may_be_object(descriptor) for descriptor in descriptors):
        yield AccessorInstall(target, key)


def _argument(call: JsCallExpression, index: int) -> Node | None:
    """
    The argument *call* passes at *index*: the first spread at or before it, which may put anything
    there, or the argument written there, or `None` where none is.
    """
    for position, argument in enumerate(call.arguments):
        if isinstance(argument, JsSpreadElement) or position == index:
            return argument
    return None


def _argument_key(call: JsCallExpression, index: int) -> str | None:
    """
    The key the argument of *call* at *index* converts to, `None` where it may be any.
    """
    argument = _argument(call, index)
    if isinstance(argument, JsSpreadElement):
        return None
    return expression_key(argument)


def _may_be_callable(argument: Node | None) -> bool:
    """
    Whether the argument *argument* may be a function.
    """
    if argument is None:
        return False
    return isinstance(argument, JsSpreadElement) or not isinstance(strip_parens(argument), _UNCALLABLE_FORMS)


def _may_be_object(argument: Node | None) -> bool:
    """
    Whether the argument *argument* may be an object.
    """
    if argument is None:
        return False
    return isinstance(argument, JsSpreadElement) or not isinstance(strip_parens(argument), _PRIMITIVE_FORMS)
