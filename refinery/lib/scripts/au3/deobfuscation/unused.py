"""
The write-only store sweep: a plain assignment whose target nothing reads leaves the tree. The
read census of `refinery.lib.scripts.au3.analysis.usage` answers the headline question — how often
each storage is read, the variables of unread text among its readers — and every other fact the
rules ask is owned by the module that pinned it: which storage a write targets, whether it may
reach a caller's storage, and which names are declared constants by
`refinery.lib.scripts.au3.analysis.scopes`, whether a write may target a global and whether an
implicit write is fatal by `refinery.lib.scripts.au3.analysis.existence`, and whether the
script's entry is open by `refinery.lib.scripts.au3.analysis.cache.Au3ModelCache.entry_is_open`.

A store leaves in one of two shapes. An effect-free right-hand side is dropped whole: building
a discarded value writes nothing observable. Any other right-hand side is spliced — it becomes the
statement's whole expression — because its evaluation, and the termination it may cause, are what
the program does; only a right-hand side holding an array literal is never spliced, a bare array
literal being legal only where a declaration initializes. A pure array-literal right-hand side
takes the drop: building a discarded array writes nothing observable either.

Dropping a store removes the reads of its right-hand side — within an expression every variable
occurrence is a read; assignments exist only in statement position — so the sweep runs as one
cascade: counters seeded from the census, every name one of whose counters reaches zero admitted
with its own stores, and all decisions made before the first edit runs. The census counts reads
per storage — one function's local, or the global — through the one classifier that resolves
which storages a read may reach, so a read of one function's `Local $x` keeps no store to another
function's own. The recall limits that survive: position within a storage is ignored — a read
before the store keeps it — a read whose claim shares its statement protects both storages, and
a `Local` claim that follows an implicit write still counts as protecting it.

The guards beside the read counts: a name declared constant — its write is a fatal the removal
would hide — one of the command-line constants every script starts with, whose write is fatal
the same way — a `ByRef` parameter of the enclosing scope, whose write reaches the caller's
storage — and a name some string or directive spells: a computed name is built from string data,
so a spelled name is one no removal may take away. The counts protect per the storage the write
targets: a provable local waits on the reads that may reach its own function's local, a store at
script level on the reads that may reach the global from any scope, an implicit write that may
target a global on both, and an implicit write that creates a local only on every read standing
in its function — the implicit local is invisible outside it, and a name missing in another
scope is missing whether or not the store leaves. The binding rules gate on the same storage:
a local keeps its store unless its own scope holds a reading channel, because a dynamic payload
runs in the scope it stands in and can name a local of it; a global store needs an open entry,
no reading channel anywhere, and implicit writes that are not fatal; and an implicit write
inside a function adds the question whether a global of the name may exist — when one may, the
write could target it and the anywhere gate applies, and when none may, the write creates a
local only and the in-scope gate answers.
"""
from __future__ import annotations

from dataclasses import dataclass

from refinery.lib.scripts import Node, Statement, Transformer, set_child
from refinery.lib.scripts.au3 import ast
from refinery.lib.scripts.au3.analysis.cache import model_cache
from refinery.lib.scripts.au3.analysis.existence import Au3ExistenceModel
from refinery.lib.scripts.au3.analysis.scopes import Au3ScopeModel, Binding
from refinery.lib.scripts.au3.analysis.usage import Au3UsageModel
from refinery.lib.scripts.au3.deobfuscation.helpers import rebuild_statements
from refinery.lib.scripts.au3.model import (
    Au3Assignment,
    Au3ExpressionStatement,
    Au3FunctionDeclaration,
    Au3Script,
    Au3Variable,
    Expression,
)

_Store = tuple[Au3ExpressionStatement, Au3Assignment, Au3FunctionDeclaration | None]


@dataclass
class _ReadCensus:
    """
    The sweep's mutable copy of the per-storage read counts: the reads that may reach one
    function's local, the reads standing in one scope that may reach the global, and the
    per-name sum of the global arm. A dropped store releases its right-hand side's reads through
    the same classifier that seeded them, and a counter reaching zero re-admits its name.
    """
    local_reads: dict[tuple[Au3FunctionDeclaration, str], int]
    global_reads: dict[tuple[Au3FunctionDeclaration | None, str], int]
    global_totals: dict[str, int]


class Au3UnusedVariableRemoval(Transformer):
    """
    Removes a plain assignment whose target no read reaches, one sweep per visit.
    """

    def __init__(self):
        super().__init__()
        self._scopes: Au3ScopeModel | None = None
        self._usage: Au3UsageModel | None = None
        self._existence: Au3ExistenceModel | None = None
        self._entry_open: bool = False
        self._reading_scopes: frozenset[Au3FunctionDeclaration] = frozenset()
        self._dropped: frozenset[Statement] = frozenset()
        self._spliced: dict[Statement, Au3Assignment] = {}

    def visit(self, node: Node) -> Node | None:
        if isinstance(node, Au3Script):
            self._sweep(node)
        return None

    def _sweep(self, script: Au3Script) -> None:
        cache = model_cache(self, script)
        self._scopes = cache.scopes
        self._usage = cache.usage
        self._existence = cache.existence
        self._entry_open = cache.entry_is_open
        assert self._usage is not None
        self._reading_scopes = frozenset(filter(None, (
            ast.enclosing_function(channel) for channel in self._usage.reading_channels
        )))
        stores: dict[str, list[_Store]] = {}
        self._collect(script, stores)
        assert self._scopes is not None
        assert self._existence is not None
        census = _ReadCensus(
            local_reads={
                (scope, name): count
                for scope, counts in self._usage.local_read_counts.items()
                for name, count in counts.items()
            },
            global_reads={
                (scope, name): count
                for scope, counts in self._usage.global_read_counts.items()
                for name, count in counts.items()
            },
            global_totals={},
        )
        for (_, name), count in census.global_reads.items():
            census.global_totals[name] = census.global_totals.get(name, 0) + count
        dropped: set[Statement] = set()
        spliced: dict[Statement, Au3Assignment] = {}
        worklist = list(stores)
        while worklist:
            name = worklist.pop()
            editable = [
                (statement, assignment, scope)
                for statement, assignment, scope in stores[name]
                if statement not in dropped
                and statement not in spliced
                and self._store_is_unread(statement, scope, name, census)
                and self._store_is_removable(statement, scope, name)
            ]
            if not editable:
                continue
            if (
                name in self._scopes.constant_names
                or self._existence.write_is_fatal(name)
                or self._usage.spells(name)
            ):
                continue
            for statement, assignment, scope in editable:
                value = assignment.value
                assert value is not None
                if self._usage.effect_free(value):
                    dropped.add(statement)
                    self._release_reads(scope, value, census, stores, worklist)
                elif not ast.contains_an_array_literal(value):
                    spliced[statement] = assignment
        if not dropped and not spliced:
            return
        self._dropped = frozenset(dropped)
        self._spliced = spliced
        if rebuild_statements(script, 'body', None, self._replacement):
            self.mark_changed()

    def _collect(self, script: Au3Script, stores: dict[str, list[_Store]]) -> None:
        """
        Every plain assignment the tree holds, with the scope it stands in: an expression
        statement whose expression is an assignment with a plain variable target. Assignments exist
        only in statement position, so no other shape is a candidate.
        """
        for scope, body in ast.scope_bodies(script):
            for statement in ast.scope_nodes(body):
                if not isinstance(statement, Au3ExpressionStatement):
                    continue
                assignment = ast.unwrap_parens(statement.expression)
                if isinstance(assignment, Au3Assignment) and assignment.operator == '=':
                    target = ast.unwrap_parens(assignment.target)
                    if isinstance(target, Au3Variable) and assignment.value is not None:
                        stores.setdefault(target.name, []).append((statement, assignment, scope))

    def _store_is_unread(
        self,
        statement: Au3ExpressionStatement,
        scope: Au3FunctionDeclaration | None,
        name: str,
        census: _ReadCensus,
    ) -> bool:
        """
        Whether no read may still observe the store on *name* in *scope*: every counter
        protecting the storage the write targets has reached zero. A provable local is protected
        by the reads that may reach its own function's local, a store at script level by the
        reads that may reach the global from any scope, an implicit write that may target a
        global by both, and an implicit write that creates a local only by every read standing
        in its function.
        """
        assert self._scopes is not None
        assert self._existence is not None
        binding = self._scopes.binding(scope, statement, name)
        if binding is Binding.GLOBAL:
            return census.global_totals.get(name, 0) == 0
        assert scope is not None
        if binding is Binding.LOCAL:
            return census.local_reads.get((scope, name), 0) == 0
        if self._existence.write_may_target_global(binding, name, True):
            return (
                census.global_totals.get(name, 0) == 0
                and census.local_reads.get((scope, name), 0) == 0
            )
        return (
            census.local_reads.get((scope, name), 0) == 0
            and census.global_reads.get((scope, name), 0) == 0
        )

    def _store_is_removable(
        self,
        statement: Au3ExpressionStatement,
        scope: Au3FunctionDeclaration | None,
        name: str,
    ) -> bool:
        """
        Whether the store *statement* performs on *name* may leave: a write that may reach a
        caller's storage never does, and the binding rules gate on the storage the scope model
        resolves the write to.
        """
        assert self._scopes is not None
        assert self._usage is not None
        assert self._existence is not None
        if self._scopes.writes_caller_storage(scope, name):
            return False
        binding = self._scopes.binding(scope, statement, name)
        if binding is Binding.LOCAL:
            return scope not in self._reading_scopes
        if not self._entry_open or self._existence.implicit_writes_are_fatal:
            return False
        if self._existence.write_may_target_global(binding, name, True):
            return not self._usage.reading_channels
        return scope not in self._reading_scopes

    def _release_reads(
        self,
        scope: Au3FunctionDeclaration | None,
        value: Expression,
        census: _ReadCensus,
        stores: dict[str, list[_Store]],
        worklist: list[str],
    ) -> None:
        """
        The reads of a dropped right-hand side leave with it: every variable occurrence in an
        expression is a read, so each one decrements the counters of the storages it may reach —
        resolved by the same classifier that seeded them — and a counter reaching zero re-admits
        its name with its stores.
        """
        assert self._scopes is not None
        for node in value.walk():
            if not isinstance(node, Au3Variable):
                continue
            for storage in self._scopes.read_storages(scope, node, node.name):
                if storage is Binding.GLOBAL:
                    census.global_reads[(scope, node.name)] -= 1
                    census.global_totals[node.name] -= 1
                    empty = census.global_reads[(scope, node.name)] == 0
                else:
                    assert scope is not None
                    census.local_reads[(scope, node.name)] -= 1
                    empty = census.local_reads[(scope, node.name)] == 0
                if empty and node.name in stores:
                    worklist.append(node.name)

    def _replacement(
        self,
        statement: Statement,
        scope: Au3FunctionDeclaration | None,
    ) -> list[Statement] | None:
        """
        The planned edit of *statement*: a dropped store leaves, a spliced one stands with its
        right-hand side as its whole expression, and any other statement stands as it is.
        """
        if statement in self._dropped:
            return []
        assignment = self._spliced.get(statement)
        if assignment is None:
            return None
        set_child(statement, 'expression', assignment.value)
        return [statement]
