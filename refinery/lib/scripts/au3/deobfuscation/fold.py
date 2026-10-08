"""
Constant folding: replacing an expression whose value every ingredient pins with the literal that
spells it.

Operators and coercions evaluate through `refinery.lib.scripts.au3.analysis.values`, builtin calls
through `refinery.lib.scripts.au3.analysis.builtins`; both refuse the unpinned case, and a
refusal here leaves the expression standing. A call folds only when no script function shares the
callee's name, because a script function shadows the builtin.

`And`/`Or` fold only where consumed as a condition, only when both operands' truth is known and
neither holds a call: their value in expression position is unpinned, and whether AutoIt skips
the right side of a decided `And` is not a fact any probe pinned, so a side that does anything at
all is never dropped.

A fold that lands on an array value installs only where a declaration initializes, because an
array literal is legal AutoIt nowhere else — a `StringSplit` over constants in any other
position stands.

A replacement is installed only when it spells differently from the original: a fold that
rewrote `-5` into `-5`, or `Binary("0x41")` into itself, would report a change the next pass
reports again, and the pipeline would never settle.
"""
from __future__ import annotations

from refinery.lib.scripts import Node, Transformer
from refinery.lib.scripts.au3 import ast
from refinery.lib.scripts.au3.analysis.builtins import BUILTIN_NAMES, evaluate_builtin
from refinery.lib.scripts.au3.analysis.cache import model_cache
from refinery.lib.scripts.au3.analysis.values import (
    Au3Value,
    Kind,
    apply_binary,
    apply_unary,
    compare,
    literal_value,
    of_bool,
    render_literal,
    truthy,
)
from refinery.lib.scripts.au3.model import (
    Au3BinaryExpression,
    Au3Call,
    Au3Macro,
    Au3Script,
    Au3UnaryExpression,
)
from refinery.lib.scripts.au3.synth import Au3Synthesizer


class Au3ConstantFolding(Transformer):
    """
    Replaces a macro, unary, binary, or call expression whose operands are known constants with
    the literal of its value, bottom-up in one pass.
    """

    def __init__(self):
        super().__init__()
        self._functions: frozenset[str] = frozenset()
        self._synthesizer = Au3Synthesizer()

    def visit(self, node: Node) -> Node | None:
        if isinstance(node, Au3Script):
            self._functions = model_cache(self, node).scopes.function_names
        self.generic_visit(node)
        replacement = self._folded(node)
        if replacement is None:
            return None
        if self._synthesizer.convert(replacement) == self._synthesizer.convert(node):
            return None
        return replacement

    def _folded(self, node: Node) -> Node | None:
        if isinstance(node, Au3Macro):
            value = literal_value(node, self._functions)
            return None if value is None else self._rendered(node, value)
        if isinstance(node, Au3UnaryExpression):
            operand = literal_value(node.operand, self._functions)
            if operand is None:
                return None
            return self._rendered(node, apply_unary(node.operator, operand))
        if isinstance(node, Au3BinaryExpression):
            value = self._binary_value(node)
            return None if value is None else self._rendered(node, value)
        if isinstance(node, Au3Call):
            return self._folded_call(node)
        return None

    def _binary_value(self, node: Au3BinaryExpression) -> Au3Value | None:
        if node.operator in ('and', 'or'):
            return self._condition_value(node)
        left = literal_value(node.left, self._functions)
        right = literal_value(node.right, self._functions)
        if left is None or right is None:
            return None
        if node.operator in ('=', '==', '<>', '<', '>', '<=', '>='):
            return compare(node.operator, left, right)
        return apply_binary(node.operator, left, right)

    def _condition_value(self, node: Au3BinaryExpression) -> Au3Value | None:
        """
        The truth of an `And`/`Or` consumed as a condition, when both operands' truth is known
        and neither holds a call: the decided side may not be dropped while the other still does
        something, so a call on either side refuses the fold.
        """
        if not ast.consumed_as_condition(node):
            return None
        if node.left is None or node.right is None:
            return None
        if ast.contains_a_call(node.left) or ast.contains_a_call(node.right):
            return None
        one = literal_value(node.left, self._functions)
        two = literal_value(node.right, self._functions)
        if one is None or two is None:
            return None
        left = truthy(one)
        right = truthy(two)
        if left is None or right is None:
            return None
        if node.operator == 'and':
            return of_bool(left and right)
        return of_bool(left or right)

    def _folded_call(self, node: Au3Call) -> Node | None:
        callee = ast.direct_callee(node)
        if callee is None or callee.name in self._functions:
            return None
        if callee.name not in BUILTIN_NAMES:
            return None
        arguments = []
        for argument in node.arguments:
            value = literal_value(argument, self._functions)
            if value is None:
                return None
            arguments.append(value)
        return self._rendered(node, evaluate_builtin(callee.name, tuple(arguments)))

    def _rendered(self, node: Node, value: Au3Value | None) -> Node | None:
        """
        The literal spelling of *value*, or `None` where none spells it or where the position of
        *node* does not accept the spelling: an array literal is legal AutoIt only where a
        declaration initializes, so an array value folds only there.
        """
        if value is None:
            return None
        if value.kind is Kind.ARRAY and not ast.in_declaration_initializer(node):
            return None
        return render_literal(value, self._functions)
