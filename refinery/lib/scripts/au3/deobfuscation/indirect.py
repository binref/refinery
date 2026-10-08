"""
Alias and indirection rewriting: replacing the callee of a call through an alias variable with the
function that variable provably names.

The alias map in `refinery.lib.scripts.au3.analysis.aliases` holds, per scope, every variable that
is the target of exactly one write — the alias initializer — with every other occurrence of it the
callee of a call. This pass reads that map and rewrites those callees: a variable holding the bare
`Execute` builtin names `Execute`, one initialized from `Execute("name")` names `name`. The
rewrite is structural — what `Execute` evaluates to as a value is never assumed — and the alias
declaration stays behind as dead code, whose removal is Phase 4's question.

The map is read once per pass and held: rewriting a callee only ever removes a read occurrence,
which cannot disqualify an alias, so the pass's own edits cannot make its snapshot wrong.
Rewriting can *qualify* further aliases — `$e("x")` becomes `Execute("x")`, which is the
initializer shape a `$b = Execute("BinaryToString")` declaration needs — and that is the next
pass's model, so the group iterates until no callee changes.
"""
from __future__ import annotations

from refinery.lib.scripts import Node, Transformer, set_child
from refinery.lib.scripts.au3 import ast
from refinery.lib.scripts.au3.analysis.aliases import Au3AliasModel
from refinery.lib.scripts.au3.analysis.cache import model_cache
from refinery.lib.scripts.au3.model import (
    Au3Call,
    Au3Identifier,
    Au3Script,
    Au3Variable,
)


class Au3IndirectCallRewrite(Transformer):
    """
    Replaces the callee of a call through an alias variable with the function the alias map says
    that variable names.
    """

    def __init__(self):
        super().__init__()
        self._aliases = Au3AliasModel({})

    def visit(self, node: Node) -> Node | None:
        if isinstance(node, Au3Script):
            self._aliases = model_cache(self, node).aliases
        self.generic_visit(node)
        if not isinstance(node, Au3Call):
            return None
        callee = ast.unwrap_parens(node.callee)
        if not isinstance(callee, Au3Variable):
            return None
        alias = self._aliases.alias(ast.enclosing_function(node), callee.name)
        if alias is None:
            return None
        set_child(node, 'callee', Au3Identifier(name=alias.name, raw=alias.raw))
        self.mark_changed()
        return None
