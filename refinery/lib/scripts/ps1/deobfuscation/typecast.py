"""
PowerShell type cast simplification transforms.
"""
from __future__ import annotations

from refinery.lib.scripts import Node, Transformer, canonical
from refinery.lib.scripts.ps1.analysis.cache import model_cache
from refinery.lib.scripts.ps1.analysis.dataflow import Ps1VariableFlow
from refinery.lib.scripts.ps1.analysis.separator import coerced_text_at
from refinery.lib.scripts.ps1.analysis.values import (
    Ps1Outcome,
    convert,
    make_string_literal,
    read,
    render,
    text_of,
)
from refinery.lib.scripts.ps1.data import named_type, resolve_type
from refinery.lib.scripts.ps1.deobfuscation.helpers import unwrap_single_paren
from refinery.lib.scripts.ps1.model import (
    Expression,
    Ps1BinaryExpression,
    Ps1CastExpression,
    Ps1Script,
    Ps1TypeExpression,
)

#: The two targets this pass treats as something other than a value conversion: one that names a
#: type rather than producing a value of one, and one whose answer the conversion grid does not
#: carry, because it was captured over scalar targets only. See the arm each belongs to.
_TYPE = named_type('System.Type')
_STRING = named_type('System.String')


class Ps1TypeCasts(Transformer):
    """
    A cast written back as the value it produces, asked of
    `refinery.lib.scripts.ps1.analysis.values` rather than decided here.

    `-as` is **not** rewritten into a cast: the two are different expressions, measured. `'abc' -as
    [int]` is `$null` where `[int] 'abc'` throws, and `300 -as [byte]` is `$null` where `[byte] 300`
    throws. `Ps1Outcome` tells them apart, and a conversion that may throw folds neither, so an `-as`
    this cannot answer is left standing rather than turned into the cast that stops the script.

    `[string]` of a collection is read outside the value grid: its elements 5.1 joins with `$OFS`,
    which `_joined_collection` answers. `[char[]]` of a list of numbers is a `Char[]`, which has no
    literal, so `_spelled` writes none and the cast stands while an operator over it reads its type.

    Every question here is asked of one step: the operand has already been visited, so `read` names
    what it came to and `convert` answers the cast over that; `evaluate` would walk the operand again
    at every node, quadratic over a tree a visitor is already descending.
    """

    def __init__(self):
        super().__init__()
        self._flow: Ps1VariableFlow | None = None
        self._entry = False

    def visit(self, node: Node):
        """
        Captured once rather than per cast: every fold below marks the pass changed, which drops the
        cache, so a per-site lookup would rebuild the control-flow graphs of the whole script once
        per folded cast. This pass replaces an expression with the value it produces and neither
        adds nor removes a statement, so the graphs it would rebuild are the graphs it already has.

        Dropped again when the walk it was captured for ends, so that a second walk over a tree the
        first one rewrote cannot be answered from the first walk's graphs.
        """
        if self._entry or not isinstance(node, Ps1Script):
            return super().visit(node)
        self._entry = True
        try:
            self._flow = model_cache(self, node).variable_flow
            return super().visit(node)
        finally:
            self._entry = False
            self._flow = None

    def visit_Ps1BinaryExpression(self, node: Ps1BinaryExpression):
        self.generic_visit(node)
        if node.operator.lower() != '-as' or node.left is None:
            return None
        if not isinstance(node.right, Ps1TypeExpression):
            return None
        target = resolve_type(node.right.name)
        if target is None:
            return None
        return _spelled(node, convert(read(node.left), target))

    def visit_Ps1CastExpression(self, node: Ps1CastExpression):
        self.generic_visit(node)
        target = resolve_type(node.type_name)
        if target is None:
            return None
        return (
            self._named_type(node, target)
            or _spelled(node, convert(read(node.operand), target))
            or self._joined_collection(node, target)
        )

    @staticmethod
    def _named_type(node: Ps1CastExpression, target) -> Expression | None:
        """
        `[type] 'X'`, the one arm here that names a type rather than producing a value of one. What
        the expression evaluates to is a `System.RuntimeType`, which the domain deliberately carries
        no element for, so what this reads out of the operand is a name and what it writes is the
        type literal naming the same thing.
        """
        if target != _TYPE:
            return None
        named = text_of(read(node.operand))
        return None if named is None else Ps1TypeExpression(offset=node.offset, name=named)

    def _joined_collection(self, node: Ps1CastExpression, target) -> Expression | None:
        """
        The conversion grid was captured over scalar targets only, so the domain has no cell for a
        `[string]` of a collection, and the separator is not a property of the value in any case:
        `refinery.lib.scripts.ps1.analysis.separator` answers it, at the point the cast stands, and
        refuses wherever a run could have written the name something else.
        """
        if target != _STRING or node.operand is None or self._flow is None:
            return None
        text = coerced_text_at(unwrap_single_paren(node.operand), node, self._flow)
        return None if text is None else make_string_literal(text)


def _spelled(node: Expression, outcome: Ps1Outcome) -> Expression | None:
    """
    The expression an outcome is written as, or `None` where nothing is written.

    An outcome that may throw is never folded, because the script's throw is part of what it does
    and replacing it with the value the operation would have had deletes that. A fact that names no
    value has no spelling. And a value the node *already* spells is left alone: replacing a tree
    with an equal one is a rewrite that never converges, and `refinery.lib.scripts.canonical` is the
    model's own answer to whether two trees spell the same program.
    """
    if outcome.may_throw:
        return None
    spelled = render(outcome.value)
    if spelled is None or canonical(spelled) == canonical(node):
        return None
    return spelled
