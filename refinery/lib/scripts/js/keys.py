"""
How the analyses read a property key, and what a call that may install an accessor installs.

A key is read as `refinery.lib.scripts.js.model.static_string` reads an expression, and a number,
boolean or `null` key as the text it converts to, so `o['constr' + 'uctor']` reads `constructor`
and `a[0]` reads `0` to every reader. A reader asks one of three questions of a key:

- its text (`key_text`), for a reader that records the key itself and is unbounded where there is
  none;
- whether it may be one of a set of names (`key_may_be`), where a key without a text may be any;
- whether it is certainly one of them (`key_is`), where a key without a text is none of them and is
  recorded as such in the `KeyAssumptions` of the model asking. A fold that writes one of the names
  into such a key shows that model a fact its answers do not record, and the simplifier renews the
  models it holds where one does
  (`refinery.lib.scripts.js.deobfuscation.simplify.JsSimplifications.visit`).

A reader asks its key question after its other conditions, so a reader whose answer is decided, or
whose other conditions fail, records nothing. The readers of `STRINGS_READ_ANYWHERE` look at every
string, not only at keys.
"""
from __future__ import annotations

from typing import Iterator, NamedTuple

from refinery.lib.scripts import Node
from refinery.lib.scripts.js.model import (
    ACCESSOR_INSTALL_METHODS,
    RECEIVER_INSTALL_METHODS,
    JsArrayExpression,
    JsBigIntLiteral,
    JsBinaryExpression,
    JsBooleanLiteral,
    JsCallExpression,
    JsIdentifier,
    JsMemberExpression,
    JsMethodDefinition,
    JsNullLiteral,
    JsNumericLiteral,
    JsObjectExpression,
    JsParenthesizedExpression,
    JsProperty,
    JsPropertyDefinition,
    JsRegExpLiteral,
    JsSpreadElement,
    JsStringLiteral,
    JsTemplateLiteral,
    JsUnaryExpression,
    JsUpdateExpression,
    _primitive_literal_text,
    static_concatenation,
    static_string,
    strip_parens,
)

Keyed = JsMemberExpression | JsProperty | JsMethodDefinition | JsPropertyDefinition
"""
The nodes that name a property by a key: a member access, and a property of an object literal, an
object pattern or a class.
"""

STRINGS_READ_ANYWHERE = frozenset({'caller', 'constructor'})
"""
The names whose readers look at every string a program spells, keys among them: a string spelling
`constructor` lets a constructor escape
(`refinery.lib.scripts.js.analysis.model.SemanticModel.constructors_may_escape`), and one spelling
`caller` may read the function that called another
(`refinery.lib.scripts.js.analysis.model.SemanticModel.spells_caller`). A fold that spells one of
them anywhere is checked by value against those answers, so their readers record no key
(`string_spells`, `key_spells`, `concatenation_spells`).
"""

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


def _key_of(owner: Keyed) -> Node | None:
    return owner.property if isinstance(owner, JsMemberExpression) else owner.key


def key_text(owner: Keyed) -> str | None:
    """
    The key *owner* certainly names: the name of a dotted access or of a plain property, or the
    `expression_key` of any other key.
    """
    key = _key_of(owner)
    if not owner.computed and isinstance(key, JsIdentifier):
        return key.name
    return expression_key(key)


def key_may_be(owner: Keyed, names: frozenset[str]) -> bool:
    """
    Whether the key *owner* names may be one of *names*: a key without a `key_text` may be any.
    """
    text = key_text(owner)
    return text is None or text in names


class KeyAssumptions:
    """
    The keys the answers of one model assumed are none of the names their readers looked for: each
    key without a `key_text` that `key_is` answered no for, with those names, and each one
    `key_named` read as naming nothing, with any name.
    """

    def __init__(self):
        self._names: dict[Node, frozenset[str] | None] = {}

    def assume(self, key: Node, names: frozenset[str] | None) -> None:
        """
        Record that an answer assumed the key *key* is none of *names*, `None` standing for any.
        """
        if key not in self._names:
            self._names[key] = names
            return
        known = self._names[key]
        if known is not None:
            self._names[key] = None if names is None else known | names

    def revealed_by(self, key: Node, text: str) -> bool:
        """
        Whether *text*, written at the key *key*, is a name an answer assumed it is not.
        """
        if key not in self._names:
            return False
        names = self._names[key]
        return names is None or text in names


class _Unrecorded(KeyAssumptions):
    """
    The assumptions of an answer no fold can make stale: they are not recorded.
    """

    def assume(self, key: Node, names: frozenset[str] | None) -> None:
        pass


SETTLED_TREE: KeyAssumptions = _Unrecorded()
"""
The `KeyAssumptions` of the readers of
`refinery.lib.scripts.js.analysis.conversions.ConversionInstalls`, whose answers are read only on a
tree the run settled.
"""

NO_IS_STRICTER: KeyAssumptions = _Unrecorded()
"""
The `KeyAssumptions` of a reader for which no, the answer `key_is` gives a key it cannot read, is
the stricter answer: a fold that spells one of the names there can only make the answer more
permissive, and a held answer may be stricter than a rebuilt one.
"""

UNHELD: KeyAssumptions = _Unrecorded()
"""
The `KeyAssumptions` of a question asked of the live tree outside any model, whose answer no model
holds: it is asked afresh wherever it is needed.
"""


def key_is(owner: Keyed, names: frozenset[str], assumptions: KeyAssumptions) -> bool:
    """
    Whether the key *owner* names is certainly one of *names*. A key without a `key_text` is none of
    them, and *assumptions* records that it was read so.
    """
    text = key_text(owner)
    if text is None:
        key = _key_of(owner)
        if key is not None:
            assumptions.assume(key, names)
        return False
    return text in names


def key_named(owner: Keyed, assumptions: KeyAssumptions) -> str | None:
    """
    The `key_text` of *owner*, for a reader that reads a key without one as naming nothing it looks
    for: *assumptions* records that it was read so, for any name.
    """
    text = key_text(owner)
    if text is None and (key := _key_of(owner)) is not None:
        assumptions.assume(key, None)
    return text


def accessor_install_method(member: JsMemberExpression, assumptions: KeyAssumptions) -> str | None:
    """
    The accessor installer (`refinery.lib.scripts.js.model.ACCESSOR_INSTALL_METHODS`) the key of
    *member* certainly names, or `None` (`key_is`).
    """
    if not key_is(member, ACCESSOR_INSTALL_METHODS, assumptions):
        return None
    return key_text(member)


def string_spells(node: Node | None, name: str) -> bool:
    """
    Whether *node* certainly evaluates to the string *name*, one of `STRINGS_READ_ANYWHERE`.
    """
    assert name in STRINGS_READ_ANYWHERE
    return static_string(node) == name


def key_spells(owner: Keyed, name: str) -> bool:
    """
    Whether the key *owner* names is certainly *name*, one of `STRINGS_READ_ANYWHERE`.
    """
    assert name in STRINGS_READ_ANYWHERE
    return key_text(owner) == name


def concatenation_spells(concatenations: list[JsBinaryExpression], name: str) -> bool:
    """
    Whether one of the `+` concatenations, each listed before those it holds, or a part of one,
    spells *name*, one of `STRINGS_READ_ANYWHERE`, from constants, as `static_string` reads it. They
    are read from the inside out, each once, and a string longer than *name* is kept only as long
    as it takes to stay longer, so a chain of concatenations costs its length rather than its
    square.
    """
    assert name in STRINGS_READ_ANYWHERE
    limit = len(name) + 1
    spelled: dict[Node, str | None] = {}

    def part(node: Node | None) -> str | None:
        node = strip_parens(node)
        if isinstance(node, JsBinaryExpression) and node.operator == '+':
            return spelled.get(node)
        return static_string(node)

    for concatenation in reversed(concatenations):
        value = static_concatenation(concatenation, part(concatenation.left), part(concatenation.right))
        if value is None:
            spelled[concatenation] = None
            continue
        value = spelled[concatenation] = value[:limit]
        if value == name:
            return True
    return False


def spelled_upward(node: Node, text: str, string: bool) -> Iterator[tuple[Node, str]]:
    """
    *node*, which reads as the key *text*, with *text*, and then each parenthesis around it and
    each `+` concatenation holding it, with the string that one reads as, climbing while the
    concatenation reads as a string. *string* says whether *node* evaluates to a string; a number,
    a boolean or `null` only makes a string with an operand that is one. Each string is built from
    the one below it and the other operand, so the climb costs its length.
    """
    cursor = node
    yield cursor, text
    while True:
        parent = cursor.parent
        while isinstance(parent, JsParenthesizedExpression):
            cursor, parent = parent, parent.parent
            yield cursor, text
        if not isinstance(parent, JsBinaryExpression) or parent.operator != '+':
            return
        if not string and static_string(parent.right if parent.left is cursor else parent.left) is None:
            return
        string = True
        if parent.left is cursor:
            spelled = static_concatenation(parent, text, static_string(parent.right))
        else:
            spelled = static_concatenation(parent, static_string(parent.left), text)
        if spelled is None:
            return
        cursor, text = parent, spelled
        yield cursor, text


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
        if _may_be_callable(call_argument(call, 1)):
            yield AccessorInstall(callee.object, None if method is None else _argument_key(call, 0))
    if method is None:
        descriptors = (call_argument(call, 1), call_argument(call, 2))
        key = None
    elif method == 'defineProperty':
        descriptors = (call_argument(call, 2),)
        key = _argument_key(call, 1)
    elif method == 'defineProperties':
        descriptors = (call_argument(call, 1),)
        key = None
    else:
        return
    target = call_argument(call, 0)
    if target is None or isinstance(target, JsSpreadElement):
        return
    if any(_may_be_object(descriptor) for descriptor in descriptors):
        yield AccessorInstall(target, key)


def call_argument(call: JsCallExpression, index: int) -> Node | None:
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
    argument = call_argument(call, index)
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
