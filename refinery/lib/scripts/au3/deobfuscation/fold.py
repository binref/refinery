"""
Constant folding: replacing an expression whose value every ingredient pins with the literal that
spells it.

Evaluation is the constant evaluator `refinery.lib.scripts.au3.analysis.constants`, asked
unbounded — what the source already spells is already in the tree — so a fold over string
literals of any size stands. A call folds only when no script function shares the callee's name,
because a script function shadows the builtin; both refusals leave the expression standing. The
render gates own the spelling: a value whose literal runs deeper than the renderer's bound
leaves the expression standing too, because no synthesizer prints such a chain.

`And`/`Or` fold to their boolean value once both operands' truth is known, and to the decided
side alone when the left operand already decides — AutoIt never runs the right side there (probe4
60, 61), so a call on the skipped side is dropped soundly. A ternary over a literal condition
folds to its chosen branch, the only side AutoIt evaluates (probe4 66, 67).

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
from refinery.lib.scripts.au3.analysis.cache import model_cache
from refinery.lib.scripts.au3.analysis.constants import Policy, constant_value
from refinery.lib.scripts.au3.analysis.values import (
    literal_value,
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
        self._policy = Policy(frozenset())
        self._synthesizer = Au3Synthesizer()

    def visit(self, node: Node) -> Node | None:
        if isinstance(node, Au3Script):
            self._policy = Policy(model_cache(self, node).scopes.function_names)
        self.generic_visit(node)
        replacement = self._folded(node)
        if replacement is None:
            return None
        if self._synthesizer.convert(replacement) == self._synthesizer.convert(node):
            return None
        return replacement

    def _folded(self, node: Node) -> Node | None:
        if isinstance(node, Au3Ternary):
            return self._ternary_branch(node)
        if not isinstance(node, (Au3Macro, Au3UnaryExpression, Au3BinaryExpression, Au3Call)):
            return None
        value = constant_value(node, self._policy)
        if value is None:
            return None
        return render_at(node, value, self._policy.functions)

    def _ternary_branch(self, node: Au3Ternary) -> Node | None:
        """
        The branch a ternary over a literal condition takes, the only side AutoIt evaluates
        (probe4 66, 67). A branch holding an array literal spells only where a declaration
        initializes, so the fold refuses anywhere else.
        """
        condition = literal_value(node.condition, self._policy.functions)
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
