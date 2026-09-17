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
from refinery.lib.scripts.js.analysis.model import (
    SemanticModel,
    _walk_skipping_functions,
    annex_b_var_home,
    pattern_identifiers,
)
from refinery.lib.scripts.js.deobfuscation.helpers import (
    BodyProcessingTransformer,
    is_truthy,
)
from refinery.lib.scripts.js.model import (
    JsBlockStatement,
    JsClassDeclaration,
    JsExpressionStatement,
    JsFunctionDeclaration,
    JsIdentifier,
    JsIfStatement,
    JsLabeledStatement,
    JsScript,
    JsVariableDeclaration,
    JsVariableDeclarator,
    JsVarKind,
)


def _is_scoped_to_the_block_holding_it(stmt: Statement | None) -> bool:
    """
    Whether *stmt*, standing directly in a block, binds a name that block is the scope of, so that
    lifting it into the list around the block would give the name a different scope or a different
    moment to start holding its value. Read through the labels a declaration may be written under.

    A `let`, a `const` and a class are scoped to the block. So is a function declaration, whichever
    way its mode reads it: strict code and each of the conditions §B.3.3.1 names bind it in the
    block alone, and where Annex B does create a `var` outside the block, the name holds the
    function only from the point the declaration runs, while one written in the list around the
    block holds it from the entry of the scope.
    """
    while isinstance(stmt, JsLabeledStatement):
        stmt = stmt.body
    if isinstance(stmt, JsVariableDeclaration):
        return stmt.kind in (JsVarKind.LET, JsVarKind.CONST)
    return isinstance(stmt, (JsClassDeclaration, JsFunctionDeclaration))


def _the_names_a_dropped_branch_still_declares(branch: Statement | None) -> list[Statement]:
    """
    A `var` statement declaring every name *branch* binds outside itself, or nothing where it binds
    none.

    Removing a branch removes the statements it would have run, and a declaration is more than a
    statement it runs: a `var`, and in sloppy code a function declaration Annex B gives a `var` half
    to, name something from the entry of the enclosing scope onwards, whether or not the branch is
    ever reached. Reading such a name answers `undefined` in a program that keeps the branch and
    throws in one that does not, so the names have to be left behind even where nothing else is.

    What the branch binds lexically is not among them, and neither is a `var` inside a function it
    holds: the first goes with the block it was scoped to, and the second belongs to that function.
    """
    if branch is None:
        return []
    names: list[str] = []
    seen: set[str] = set()
    for node in _walk_skipping_functions([branch]):
        if isinstance(node, JsVariableDeclaration) and node.kind is JsVarKind.VAR:
            found = [
                ident.name
                for declarator in node.declarations
                if isinstance(declarator, JsVariableDeclarator)
                for ident in pattern_identifiers(declarator.id)
            ]
        elif isinstance(node, JsFunctionDeclaration) and node.id is not None:
            found = [node.id.name] if annex_b_var_home(node) is not None else []
        else:
            continue
        for name in found:
            if name not in seen:
                seen.add(name)
                names.append(name)
    if not names:
        return []
    return [JsVariableDeclaration(
        kind=JsVarKind.VAR,
        declarations=[
            JsVariableDeclarator(id=JsIdentifier(name=name)) for name in names
        ],
    )]


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

    @property
    def model(self) -> SemanticModel | None:
        """
        The semantic model for the current script. Whether a test denotes a value at all is a scope
        question — `undefined` is a value only where nothing has bound that name — so no branch can be
        pruned without one. It is reached through the cache rather than through `effects`, which holds
        a model but is built lazily and costs far more than this pass needs to spend on an `if`.
        """
        if self._root is None:
            return None
        return model_cache(self, self._root).model

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
            self._replace_body(parent, result)

    def _try_prune(self, stmt: Statement) -> list[Statement] | None:
        if not isinstance(stmt, JsIfStatement):
            return None
        if stmt.test is None:
            return None
        model = self.model
        if model is None:
            return None
        assert self._root is not None
        truthy = is_truthy(stmt.test, model_cache(self, self._root))
        if truthy is None:
            return None
        taken = stmt.consequent if truthy else stmt.alternate
        dropped = stmt.alternate if truthy else stmt.consequent
        result = self._unwrap_branch(taken)
        result[0:0] = _the_names_a_dropped_branch_still_declares(dropped)
        if not self._test_is_side_effect_free(stmt.test):
            result.insert(0, JsExpressionStatement(expression=stmt.test))
        return result

    def _test_is_side_effect_free(self, test: Node) -> bool:
        """
        Whether the discarded test can be dropped. The model-aware effect check is authoritative when a
        model is available: it certifies a proven-pure call the model-free check would keep, and rejects
        a read through a `with` body's dynamic scope the model-free check would wrongly call pure (that
        read may fire the `with` object's getter or throw). Dropping the test discards its whole
        value, so the throw a read of a name nothing binds would raise is kept unless the shared
        establishment proof vouches a creating write for it. The structural check is only a fallback
        for a pass constructed without a model.
        """
        effects = self.effects
        if effects is not None:
            assert self._root is not None
            established = model_cache(self, self._root).read_established
            return effects.is_side_effect_free(
                test, reads_may_throw=True, read_established=established)
        return side_effect_free(test)

    @staticmethod
    def _unwrap_branch(branch: Statement | None) -> list[Statement]:
        """
        Extract the statements from a branch. If the branch is a block, return its body list
        contents; if it is a bare statement, wrap it in a single-element list. A block is kept whole
        wherever it declares something that is scoped to it, since lifting the statements out would
        move that declaration into the scope around it or give it a different moment to start
        holding its value, which `_is_scoped_to_the_block_holding_it` answers.

        A bare function declaration is the same branch written without the block §B.3.4 reads it as,
        so it is given one rather than being lifted: a declaration standing in the list around the
        `if` holds its function from the entry of the scope, where the clause holds it from the
        point the clause runs.
        """
        if branch is None:
            return []
        if isinstance(branch, JsBlockStatement):
            if any(_is_scoped_to_the_block_holding_it(stmt) for stmt in branch.body):
                return [branch]
            return list(branch.body)
        if _is_scoped_to_the_block_holding_it(branch):
            return [JsBlockStatement(body=[branch])]
        return [branch]
