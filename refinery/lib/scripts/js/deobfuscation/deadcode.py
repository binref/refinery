"""
Eliminate dead code branches guarded by constant conditions, and statements that never run.

This transformer prunes unreachable branches from `if`/`else` statements when the test is a
literal whose truthiness can be determined statically. When the discarded test is not provably
free of side effects, it is kept as a leading expression statement so that pruning never changes
observable behavior. Purity of a call inside the test is resolved through the script's effect
model, so a test that only invokes proven-pure functions or intrinsics is dropped with the branch.
It also removes the statements control never reaches, such as code behind a `return`.
"""
from __future__ import annotations

from typing import NamedTuple

from refinery.lib.scripts import Node, Statement
from refinery.lib.scripts.js.analysis.cache import ModelCache, model_cache
from refinery.lib.scripts.js.analysis.model import (
    SemanticModel,
    _walk_skipping_functions,
    annex_b_var_home,
    is_unread_source,
    pattern_identifiers,
)
from refinery.lib.scripts.js.deobfuscation.helpers import (
    BatchedTransformer,
    BodyProcessingTransformer,
    is_truthy,
)
from refinery.lib.scripts.js.model import (
    JsBlockStatement,
    JsClassDeclaration,
    JsExportAllDeclaration,
    JsExportDefaultDeclaration,
    JsExportNamedDeclaration,
    JsExpressionStatement,
    JsFunctionDeclaration,
    JsIdentifier,
    JsIfStatement,
    JsImportDeclaration,
    JsLabeledStatement,
    JsScript,
    JsSwitchCase,
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


def _the_names_a_dropped_branch_still_declares(
    branch: Statement | None,
    model: SemanticModel,
) -> tuple[str, ...] | None:
    """
    Every name *branch* binds outside itself, which a `var` left in its place declares, or `None`
    where the branch cannot go.

    Removing a branch removes the statements it would have run, and a declaration is more than a
    statement it runs: a `var`, and in sloppy code a function declaration Annex B gives a `var` half
    to, name something from the entry of the enclosing scope onwards, whether or not the branch is
    ever reached. Reading such a name answers `undefined` in a program that keeps the branch and
    throws in one that does not, so the names have to be left behind even where nothing else is.

    What the branch binds lexically is not among them, and neither is a `var` inside a function it
    holds: the first goes with the block it was scoped to, and the second belongs to that function.
    Source the model never read (`refinery.lib.scripts.js.analysis.model.is_unread_source`) may
    declare anything, so a branch holding some stays.

    Where the file may be an ES module, the `var` half of a function declared in a block exists in
    the CommonJS reading only, so a `var` left behind would be wrong in one reading and its absence
    in the other. The branch then stays where anything reads, writes or otherwise observes that half
    (`refinery.lib.scripts.js.analysis.model.SemanticModel.annex_b_copy_observed`), and its function
    leaves no name behind where nothing does.
    """
    if branch is None:
        return ()
    names: list[str] = []
    seen: set[str] = set()
    for node in _walk_skipping_functions([branch]):
        if is_unread_source(node):
            return None
        if isinstance(node, JsVariableDeclaration) and node.kind is JsVarKind.VAR:
            found = [
                ident.name
                for declarator in node.declarations
                if isinstance(declarator, JsVariableDeclarator)
                for ident in pattern_identifiers(declarator.id)
            ]
        elif isinstance(node, JsFunctionDeclaration) and node.id is not None:
            if annex_b_var_home(node, model.file_kind) is None:
                continue
            if model.file_kind.may_be_an_es_module:
                if model.annex_b_copy_observed(node):
                    return None
                continue
            found = [node.id.name]
        else:
            continue
        for name in found:
            if name not in seen:
                seen.add(name)
                names.append(name)
    return tuple(names)


def _declaring(names: tuple[str, ...]) -> JsVariableDeclaration:
    """
    The `var` left where code went that declared *names*
    (`_the_names_a_dropped_branch_still_declares`), which declares them and stores nothing.
    """
    return JsVariableDeclaration(
        kind=JsVarKind.VAR,
        declarations=[JsVariableDeclarator(id=JsIdentifier(name=name)) for name in names],
    )


_STATEMENT_LISTS = (JsScript, JsBlockStatement, JsSwitchCase)

_MODULE_DECLARATIONS = (
    JsImportDeclaration,
    JsExportNamedDeclaration,
    JsExportDefaultDeclaration,
    JsExportAllDeclaration,
)


def _stays_where_it_never_runs(stmt: Statement) -> bool:
    """
    Whether *stmt* stays in its list although it never runs: a declaration scoped to the list
    (`_is_scoped_to_the_block_holding_it`), whose name means it in the whole list whether or not it
    runs, an `import` or `export` declaration, which links the module before any of its code runs,
    and a `var` that stores nothing, which is what a statement that goes leaves behind.
    """
    if _is_scoped_to_the_block_holding_it(stmt) or isinstance(stmt, _MODULE_DECLARATIONS):
        return True
    return (
        isinstance(stmt, JsVariableDeclaration)
        and stmt.kind is JsVarKind.VAR
        and all(
            isinstance(declarator, JsVariableDeclarator) and declarator.init is None
            for declarator in stmt.declarations
        )
    )


class _Removal(NamedTuple):
    """
    The statements of one list that never run and go, and the names a `var` written where the
    first of them stood declares (`_the_names_a_dropped_branch_still_declares`).
    """
    gone: frozenset[Statement]
    still_declared: tuple[str, ...]


def _statements_that_never_run(body: list[Statement], cache: ModelCache) -> _Removal | None:
    """
    The statements of *body* that never run and can go, or `None` where there are none. Which
    statements can run is the shared control-flow model's answer
    (`refinery.lib.scripts.analysis.dominance.DominatorModel.never_runs`). What stays although it
    never runs stays (`_stays_where_it_never_runs`), and so does a statement where it cannot be said
    which names it still declares (`_the_names_a_dropped_branch_still_declares`).
    """
    gone: set[Statement] = set()
    names: list[str] = []
    for stmt in body:
        if _stays_where_it_never_runs(stmt) or not cache.dominance.never_runs(stmt):
            continue
        if (declared := _the_names_a_dropped_branch_still_declares(stmt, cache.model)) is None:
            continue
        gone.add(stmt)
        names.extend(name for name in declared if name not in names)
    if not gone:
        return None
    return _Removal(frozenset(gone), tuple(names))


class _Decision(NamedTuple):
    """
    What an `if` statement's test evaluates to, whether the test may go with the dropped branch or
    has to stay behind as a statement, and the names a `var` left behind for the dropped branch
    declares (`_the_names_a_dropped_branch_still_declares`).
    """
    test_is_truthy: bool
    test_may_go: bool
    still_declared: tuple[str, ...]


class JsDeadCodeElimination(BatchedTransformer, BodyProcessingTransformer):
    """
    Remove unreachable code guarded by constant conditions, and statements that never run.

    The pass runs in the batched regime of
    `refinery.lib.scripts.js.deobfuscation.helpers.BatchedTransformer`. One walk over the tree the
    run entered on decides every `if` standing in a statement list, and the pass's usual walk then
    makes the edits, innermost list first, each list replaced once. That walk reaches only the lists
    the tree still holds, so every edit lands on an attached list.

    A decision reads the value the test evaluates to and whether the test has an effect, and both
    survive every other edit of the run, because each edit keeps every surviving statement's
    evaluations and their order: a dropped branch never ran; a lifted branch ran exactly where it
    now stands, carrying the edits made inside it; a test that may have an effect stays behind and
    runs once in its place; a test without one goes, and nothing observed it; and the `var`
    declarations left behind for a dropped branch carry no value. A block that holds a declaration
    scoped to it is kept whole rather than lifted. The values every other test reads are therefore
    the ones they read on the entry tree.

    The same walk decides, for every statement list, which statements never run: those the
    control-flow graph of the entry tree does not reach. No edit of the run gives control a way it
    did not have: a statement that never runs makes no jump, a dropped branch takes its ways with
    it, a lifted branch keeps the jumps it makes and their targets, and a test kept behind runs
    where the `if` ran. A statement unreached on the entry tree is therefore unreached on the tree
    the run leaves, and one an edit leaves unreached only now goes in the next run.
    """

    def __init__(self):
        super().__init__()
        self._root: JsScript | None = None
        self._decisions: dict[JsIfStatement, _Decision] | None = None
        self._removals: dict[Node, _Removal] | None = None

    def visit_JsScript(self, node: JsScript):
        self._root = node
        self._decisions = None
        self._removals = None
        if self.batching:
            cache = model_cache(self, node)
            lists = [holder for holder in node.walk() if isinstance(holder, _STATEMENT_LISTS)]
            self._decisions = {
                stmt: decision for holder in lists for stmt in holder.body
                if isinstance(stmt, JsIfStatement)
                and (decision := self._decide(stmt)) is not None
            }
            self._removals = {
                holder: removal for holder in lists
                if (removal := _statements_that_never_run(holder.body, cache)) is not None
            }
        try:
            return super().visit_JsScript(node)
        finally:
            self._decisions = None
            self._removals = None

    def visit_JsSwitchCase(self, node: JsSwitchCase):
        self.generic_visit(node)
        self._process_body(node, node.body)
        return None

    def _process_body(self, parent: Node, body: list[Statement]):
        result: list[Statement] = []
        changed = False
        removal = self._removal(parent, body)
        declared = False
        for stmt in body:
            if removal is not None and stmt in removal.gone:
                if not declared and removal.still_declared:
                    declared = True
                    result.append(_declaring(removal.still_declared))
                changed = True
                continue
            replacement = self._try_prune(stmt)
            if replacement is not None:
                result.extend(replacement)
                changed = True
            else:
                result.append(stmt)
        if changed:
            self._replace_body(parent, result)

    def _removal(self, parent: Node, body: list[Statement]) -> _Removal | None:
        """
        The statements of *body*, the list of *parent*, that never run and go. No statement goes in
        a run that entered on no script: there is no control-flow graph to ask.
        """
        if self._removals is not None:
            return self._removals.get(parent)
        if self._root is None:
            return None
        return _statements_that_never_run(body, model_cache(self, self._root))

    def _try_prune(self, stmt: Statement) -> list[Statement] | None:
        if not isinstance(stmt, JsIfStatement):
            return None
        if self._decisions is None:
            decision = self._decide(stmt)
        else:
            decision = self._decisions.get(stmt)
        if decision is None:
            return None
        taken = stmt.consequent if decision.test_is_truthy else stmt.alternate
        result = self._unwrap_branch(taken)
        if decision.still_declared:
            result.insert(0, _declaring(decision.still_declared))
        if not decision.test_may_go:
            result.insert(0, JsExpressionStatement(expression=stmt.test))
        return result

    def _decide(self, stmt: JsIfStatement) -> _Decision | None:
        """
        The decision for *stmt*, or `None` where the value of its test is not known. Whether a test
        denotes a value at all is a scope question — `undefined` is a value only where nothing has
        bound that name — so no branch is pruned in a run that entered on no script.
        """
        if stmt.test is None or self._root is None:
            return None
        cache = model_cache(self, self._root)
        truthy = is_truthy(stmt.test, cache)
        if truthy is None:
            return None
        dropped = stmt.alternate if truthy else stmt.consequent
        declared = _the_names_a_dropped_branch_still_declares(dropped, cache.model)
        if declared is None:
            return None
        return _Decision(truthy, self._test_is_side_effect_free(stmt.test, cache), declared)

    @staticmethod
    def _test_is_side_effect_free(test: Node, cache: ModelCache) -> bool:
        """
        Whether the discarded test can be dropped, by the model-aware effect check: it certifies a
        proven-pure call a structural check would keep, and rejects a read through a `with` body's
        dynamic scope a structural check would wrongly call pure (that read may fire the `with`
        object's getter or throw). Dropping the test discards its whole value, so the throw a read
        of a name nothing binds would raise is kept unless the shared establishment proof vouches a
        creating write for it.
        """
        return cache.effects.is_side_effect_free(
            test, reads_may_throw=True, read_established=cache.read_established
        )

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
