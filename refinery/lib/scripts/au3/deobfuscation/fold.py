"""
Constant folding: replacing an expression whose value every ingredient pins with the literal that
spells it.

Operators and coercions evaluate through `refinery.lib.scripts.au3.analysis.values`, builtin calls
through `refinery.lib.scripts.au3.analysis.builtins`; both refuse the unpinned case, and a
refusal here leaves the expression standing. A call folds only when no script function shares the
callee's name, because a script function shadows the builtin.

`And`/`Or` fold to their boolean value once both operands' truth is known, and to the decided side
alone when the left operand already decides — AutoIt never runs the right side there (probe4 60,
61), so a call on the skipped side is dropped soundly. A ternary over a literal condition folds to
its chosen branch, the only side AutoIt evaluates (probe4 66, 67).

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
    apply_binary,
    apply_unary,
    compare,
    literal_value,
    of_bool,
    render_at,
    truthy,
)
from refinery.lib.scripts.au3.model import (
    Au3BinaryExpression,
    Au3Call,
    Au3Macro,
    Au3Script,
    Au3Ternary,
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
        if isinstance(node, Au3Ternary):
            return self._ternary_branch(node)
        if isinstance(node, Au3Call):
            return self._folded_call(node)
        return None

    def _binary_value(self, node: Au3BinaryExpression) -> Au3Value | None:
        if node.operator in ('and', 'or'):
            return self._logical_value(node)
        left = literal_value(node.left, self._functions)
        right = literal_value(node.right, self._functions)
        if left is None or right is None:
            return None
        if node.operator in ('=', '==', '<>', '<', '>', '<=', '>='):
            return compare(node.operator, left, right)
        return apply_binary(node.operator, left, right)

    def _logical_value(self, node: Au3BinaryExpression) -> Au3Value | None:
        """
        The boolean an `And`/`Or` answers: the decided left operand alone when it already
        decides — AutoIt never runs the right side there (probe4 60, 61) — and otherwise the
        truth of both operands.
        """
        if node.left is None or node.right is None:
            return None
        left = literal_value(node.left, self._functions)
        if left is None:
            return None
        verdict = truthy(left)
        if verdict is None:
            return None
        if node.operator == 'and' and not verdict:
            return of_bool(False)
        if node.operator == 'or' and verdict:
            return of_bool(True)
        right = literal_value(node.right, self._functions)
        if right is None:
            return None
        return apply_binary(node.operator, left, right)

    def _ternary_branch(self, node: Au3Ternary) -> Node | None:
        """
        The branch a ternary over a literal condition takes, the only side AutoIt evaluates
        (probe4 66, 67). A branch holding an array literal spells only where a declaration
        initializes, so the fold refuses anywhere else.
        """
        condition = literal_value(node.condition, self._functions)
        if condition is None:
            return None
        verdict = truthy(condition)
        if verdict is None:
            return None
        branch = node.consequent if verdict else node.alternate
        if branch is None:
            return None
        if ast.contains_an_array_literal(branch) and not ast.in_declaration_initializer(node):
            return None
        return branch

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
        The literal spelling of *value* where *node* stands, or `None` where none spells it or
        the position does not accept the spelling.
        """
        if value is None:
            return None
        return render_at(node, value, self._functions)
