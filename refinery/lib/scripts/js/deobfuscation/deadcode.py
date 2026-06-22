"""
Eliminate dead code branches guarded by constant conditions.

This transformer prunes unreachable branches from `if`/`else` statements when the test is a
literal whose truthiness can be determined statically. When the discarded test is not provably
free of side effects, it is kept as a leading expression statement so that pruning never changes
observable behavior. Purity of a call inside the test is resolved through the script's effect
model, so a test that only invokes proven-pure functions or intrinsics is dropped with the branch.
"""
from __future__ import annotations

from refinery.lib.scripts import Node, Statement
from refinery.lib.scripts.js.analysis.cache import model_cache
from refinery.lib.scripts.js.analysis.effects import (
    EffectModel,
    side_effect_free,
)
from refinery.lib.scripts.js.deobfuscation.helpers import (
    BodyProcessingTransformer,
    is_statically_evaluable,
    is_truthy,
)
from refinery.lib.scripts.js.model import (
    JsBlockStatement,
    JsExpressionStatement,
    JsIfStatement,
    JsScript,
    JsVariableDeclaration,
    JsVarKind,
)


class JsDeadCodeElimination(BodyProcessingTransformer):
    """
    Remove unreachable code guarded by constant conditions.
    """

    def __init__(self):
        super().__init__()
        self._root: JsScript | None = None
        self._effects: EffectModel | None = None

    @property
    def effects(self) -> EffectModel | None:
        """
        The effect model for the current script, built on first demand. It is `None` until a script
        has been visited, and is built only when a prunable test is not already conservatively free
        of side effects, so a run that never reaches that check pays nothing.
        """
        if self._root is None:
            return None
        if self._effects is None:
            self._effects = model_cache(self, self._root).effects
        return self._effects

    def visit_JsScript(self, node: JsScript):
        self._root = node
        self._effects = None
        return super().visit_JsScript(node)

    def _process_body(self, parent: Node, body: list[Statement]):
        result: list[Statement] = []
        changed = False
        for stmt in body:
            replacement = self._try_prune(stmt)
            if replacement is not None:
                result.extend(replacement)
                changed = True
            else:
                result.append(stmt)
        if changed:
            self._replace_body(parent, body, result)

    def _try_prune(self, stmt: Statement) -> list[Statement] | None:
        if not isinstance(stmt, JsIfStatement):
            return None
        if stmt.test is None:
            return None
        if not is_statically_evaluable(stmt.test):
            return None
        truthy = is_truthy(stmt.test)
        if truthy is None:
            return None
        taken = stmt.consequent if truthy else stmt.alternate
        result = self._unwrap_branch(taken)
        if not self._test_is_side_effect_free(stmt.test):
            result.insert(0, JsExpressionStatement(expression=stmt.test))
        return result

    def _test_is_side_effect_free(self, test: Node) -> bool:
        """
        Whether the discarded test can be dropped. The conservative structural check is tried first;
        only when it fails is the effect model consulted, so a call to a proven-pure function or
        intrinsic in the test no longer forces it to be kept.
        """
        if side_effect_free(test):
            return True
        effects = self.effects
        return effects is not None and effects.is_side_effect_free(test)

    @staticmethod
    def _unwrap_branch(branch: Statement | None) -> list[Statement]:
        """
        Extract the statements from a branch. If the branch is a block, return its body list
        contents; if it is a bare statement, wrap it in a single-element list. Blocks containing
        `let` or `const` declarations are kept as-is to preserve block scoping.
        """
        if branch is None:
            return []
        if isinstance(branch, JsBlockStatement):
            for stmt in branch.body:
                if isinstance(stmt, JsVariableDeclaration) and stmt.kind in (
                    JsVarKind.LET,
                    JsVarKind.CONST,
                ):
                    return [branch]
            return list(branch.body)
        return [branch]
