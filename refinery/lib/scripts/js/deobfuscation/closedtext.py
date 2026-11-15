"""
The text a code argument evaluates to where it is built from literals by operators and built-ins
alone, which the trusting model reads before a fold writes it there
(`refinery.lib.scripts.js.analysis.model.FoldedText`).
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Iterable

from refinery.lib.scripts import Node
from refinery.lib.scripts.js.analysis.environment import HostEnvironment
from refinery.lib.scripts.js.analysis.model import FoldedText
from refinery.lib.scripts.js.deobfuscation.helpers import (
    MemberRead,
    access_key,
    binary_value,
    extract_literal_value,
    read_data_property,
    unary_value,
)
from refinery.lib.scripts.js.deobfuscation.interpreter import (
    MAX_STRING_LEN,
    STATIC_OBJECTS,
    folded_call,
    folded_method_call,
    registered_builtin,
    registered_method,
)
from refinery.lib.scripts.js.model import (
    JsArrayExpression,
    JsBinaryExpression,
    JsCallExpression,
    JsIdentifier,
    JsMemberExpression,
    JsSpreadElement,
    JsTemplateLiteral,
    JsUnaryExpression,
    strip_parens,
)
from refinery.lib.scripts.js.values import converts_uninterceptably, to_string

if TYPE_CHECKING:
    from refinery.lib.scripts.js.values import Value


class _Open(Exception):
    pass


class _ClosedText:
    """
    Evaluates an expression the way the folds of `refinery.lib.scripts.js.deobfuscation.simplify`
    compute each of its parts: an operator through
    `refinery.lib.scripts.js.deobfuscation.helpers.binary_value` and
    `refinery.lib.scripts.js.deobfuscation.helpers.unary_value`, a member read through
    `refinery.lib.scripts.js.deobfuscation.helpers.read_data_property`, and a built-in call through
    `refinery.lib.scripts.js.deobfuscation.interpreter.folded_call` and
    `refinery.lib.scripts.js.deobfuscation.interpreter.folded_method_call`, over operands that are
    primitives, so that no conversion runs code a program installed.
    """

    def __init__(self, environment: HostEnvironment):
        self.environment = environment
        self.calls: list[tuple[JsCallExpression, type | None]] = []

    def value(self, node: Node | None) -> Value:
        node = strip_parens(node)
        if node is None:
            raise _Open
        if isinstance(node, JsArrayExpression):
            return [self.primitive(element) for element in node.elements]
        if isinstance(node, JsTemplateLiteral):
            return self.joined(self.template_parts(node))
        if isinstance(node, JsUnaryExpression):
            return self.decided(unary_value(
                node.operator,
                self.primitive(node.operand),
                converts_uninterceptably,
                None,
            ))
        if isinstance(node, JsBinaryExpression):
            return self.bounded(self.decided(binary_value(
                node.operator,
                self.primitive(node.left),
                self.primitive(node.right),
                converts_uninterceptably,
                None,
            )))
        if isinstance(node, JsCallExpression):
            return self.bounded(self.call(node))
        if isinstance(node, JsMemberExpression):
            return self.member(node)
        return self.decided(extract_literal_value(node))

    def primitive(self, node: Node | None) -> Value:
        if node is None or isinstance(node, JsSpreadElement):
            raise _Open
        value = self.value(node)
        if not converts_uninterceptably(value):
            raise _Open
        return value

    @staticmethod
    def decided(answer: tuple[bool, Value]) -> Value:
        known, value = answer
        if not known:
            raise _Open
        return value

    def template_parts(self, node: JsTemplateLiteral):
        quasis = node.quasis
        expressions = node.expressions
        for k, quasi in enumerate(quasis):
            cooked = quasi.value
            if cooked is None:
                raise _Open
            yield cooked
            if k < len(expressions):
                yield expressions[k]

    def joined(self, parts: Iterable[str | Node]) -> str:
        texts: list[str] = []
        size = 0
        for part in parts:
            text = part if isinstance(part, str) else to_string(self.primitive(part))
            size += len(text)
            if size > MAX_STRING_LEN:
                raise _Open
            texts.append(text)
        return ''.join(texts)

    @staticmethod
    def bounded(value: Value) -> Value:
        if isinstance(value, str) and len(value) > MAX_STRING_LEN:
            raise _Open
        return value

    def member(self, node: JsMemberExpression) -> Value:
        if node.optional or node.object is None:
            raise _Open
        receiver = self.value(node.object)
        if node.computed:
            key = to_string(self.primitive(node.property))
        elif (key := access_key(node)) is None:
            raise _Open
        outcome, value = read_data_property(receiver, key)
        if outcome is not MemberRead.FOUND:
            raise _Open
        return value

    def call(self, node: JsCallExpression) -> Value:
        if node.optional:
            raise _Open
        callee = strip_parens(node.callee)
        receiver: Value = None
        receiver_type: type | None = None
        if isinstance(callee, JsIdentifier):
            builtin = registered_builtin((None, callee.name), self.environment)
        elif isinstance(callee, JsMemberExpression) and not callee.optional:
            if (method := access_key(callee)) is None:
                raise _Open
            base = strip_parens(callee.object)
            if isinstance(base, JsIdentifier) and base.name in STATIC_OBJECTS:
                builtin = registered_builtin((base.name, method), self.environment)
            else:
                receiver = self.value(base)
                receiver_type = type(receiver)
                builtin = registered_method(receiver, method, self.environment)
        else:
            raise _Open
        if builtin is None:
            raise _Open
        arguments: list[Value] = [self.primitive(argument) for argument in node.arguments]
        if builtin.reads_strings:
            arguments = [to_string(argument) for argument in arguments]
        if receiver_type is None:
            result = self.decided(folded_call(builtin, arguments))
        else:
            result = self.decided(folded_method_call(builtin, receiver, arguments))
        self.calls.append((node, receiver_type))
        return result


def closed_text(node: Node, environment: HostEnvironment) -> FoldedText | None:
    """
    The text *node* evaluates to where it is built from literals, arrays of primitives, templates,
    operators over primitives, element reads, and calls of the built-ins of
    `refinery.lib.scripts.js.deobfuscation.interpreter.BUILTIN_REGISTRY` the host *environment* has,
    each part computed as a fold computes it (`_ClosedText`) with every built-in taken to be intact;
    with each call made. `None` for any other expression, for a value that is no string, for a
    string longer than the interpreter makes
    (`refinery.lib.scripts.js.deobfuscation.interpreter.MAX_STRING_LEN`), and where a call answers
    no value.
    """
    reader = _ClosedText(environment)
    try:
        value = reader.value(node)
    except (_Open, RecursionError):
        return None
    if not isinstance(value, str):
        return None
    return FoldedText(value, tuple(reader.calls))
