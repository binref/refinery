"""
The Phase 4 transform: what no live code reaches leaves the tree. A function no call names and
no string spells, a declarator no occurrence binds or may bind, and an expression statement
whose evaluation writes nothing and cannot terminate the script are removed — each only when
no dynamic-name channel could observe the removal. What answers every question the rules ask is
the usage model of `refinery.lib.scripts.au3.analysis.usage`, which this transform reads and
never re-derives.

One sweep per visit: the census reads the usage model once, then a single tree edit runs over
every scope. The group's run loop is what reaches the fixpoint — a function whose only callers
this sweep removed keeps its call sites until the next sweep re-census — so the iteration a
deeply nested obfuscator needs happens inside one execution of the cleanup group.

Three gates close parts of the sweep. The entry gate: a script with no executable top-level
statement, and any script holding an include, is a fragment whose functions and globals can be
reached from outside the tree, so only its dead locals and effect-free statements leave. The
channel gate: a computed-name channel outside the functions this sweep removes blocks function
and global removal for the whole visit, because the name it computes may reach anything, and a
channel inside a function blocks that function's local removal, because a dynamic payload runs
in the scope it stands in and can name a local of it. The error-node gate: a tree that failed to
parse anywhere blocks the whole pass, because the raw error text is live source the real AutoIt
runs and no model here reads.

What a removal may not hide: an initializer or dimension that could terminate the script — a
division, an exponentiation, an array subscript, a call of the wrong arity — keeps its
declarator, and an `Exit` or an impure expression keeps a function out of the pure set the
statement rule reads.
"""
from __future__ import annotations

from refinery.lib.scripts import Node, Statement, Transformer, set_child_list
from refinery.lib.scripts.au3 import ast
from refinery.lib.scripts.au3.analysis.cache import model_cache
from refinery.lib.scripts.au3.analysis.scopes import Au3ScopeModel, Binding
from refinery.lib.scripts.au3.analysis.usage import Au3UsageModel
from refinery.lib.scripts.au3.model import (
    Au3Directive,
    Au3EnumDeclaration,
    Au3EnumDeclarator,
    Au3ErrorNode,
    Au3ExpressionStatement,
    Au3FunctionDeclaration,
    Au3Include,
    Au3IncludeOnce,
    Au3Script,
    Au3VariableDeclaration,
    Au3VariableDeclarator,
)


class Au3DeadCodeElimination(Transformer):
    """
    Removes a function no live call reaches, a declarator no occurrence binds, and an
    expression statement that is effect-free, one sweep per visit.
    """

    def __init__(self):
        super().__init__()
        self._scopes: Au3ScopeModel | None = None
        self._usage: Au3UsageModel | None = None
        self._removable: frozenset[str] = frozenset()
        self._globals_may_leave: bool = False
        self._channel_scopes: frozenset[Au3FunctionDeclaration] = frozenset()

    def visit(self, node: Node) -> Node | None:
        if isinstance(node, Au3Script):
            self._sweep(node)
        return None

    def _sweep(self, script: Au3Script) -> None:
        if script.errors or any(isinstance(node, Au3ErrorNode) for node in script.walk()):
            return
        cache = model_cache(self, script)
        self._scopes = cache.scopes
        self._usage = cache.usage
        self._channel_scopes = frozenset(filter(None, (
            ast.enclosing_function(channel) for channel in self._usage.channels
        )))
        entry_open = self._entry_is_open(script)
        removable = self._uncalled() if entry_open else set()
        removable = self._without_nested_survivors(removable)
        blocked = self._channels_block(removable)
        if blocked:
            removable = set()
        self._removable = frozenset(removable)
        self._globals_may_leave = entry_open and not blocked
        if self._prune(script, 'body', None):
            self.mark_changed()

    def _entry_is_open(self, script: Au3Script) -> bool:
        """
        Whether the script runs from its own top-level statements: it holds a statement that is
        neither a declaration, a function definition nor a directive, and no include anywhere —
        an included file's contents are called from outside the tree.
        """
        for node in script.walk():
            if isinstance(node, (Au3Include, Au3IncludeOnce)):
                return False
        for statement in script.body:
            if not isinstance(statement, (
                Au3VariableDeclaration,
                Au3EnumDeclaration,
                Au3FunctionDeclaration,
                Au3Directive,
            )):
                return True
        return False

    def _uncalled(self) -> set[str]:
        """
        Every function no direct-identifier call in the tree names and no string or directive
        spells.
        """
        usage = self._usage
        assert usage is not None
        return {
            name
            for name in usage.functions
            if usage.call_counts.get(name, 0) == 0
            and not usage.spells(name)
        }

    def _without_nested_survivors(self, removable: set[str]) -> set[str]:
        """
        *removable* minus every function whose subtree holds a function declaration that is not
        itself removable, shrunk until stable: a candidate that would take a surviving nested
        function with it is not removable this sweep.
        """
        usage = self._usage
        assert usage is not None
        while True:
            survivors = {
                name
                for name in removable
                if all(
                    nested.name is None or nested.name.name in removable
                    for nested in usage.functions[name].walk()
                    if isinstance(nested, Au3FunctionDeclaration)
                )
            }
            if survivors == removable:
                return survivors
            removable = survivors

    def _channels_block(self, removable: set[str]) -> bool:
        """
        Whether a computed-name channel stands outside the functions *removable* names: its
        consumer survives the sweep, so the name it computes may reach anything.
        """
        usage = self._usage
        assert usage is not None
        for channel in usage.channels:
            scope = ast.enclosing_function(channel)
            if scope is None or scope.name is None or scope.name.name not in removable:
                return True
        return False

    def _prune(self, parent: Node, attr: str, scope: Au3FunctionDeclaration | None) -> bool:
        """
        One statement list of one scope: every dead statement dropped, every declaration pruned
        per declarator, and the same done to every nested list and every kept function body.
        """
        assert self._usage is not None
        surviving: list[Statement] = []
        changed = False
        for statement in getattr(parent, attr):
            if self._statement_is_dead(statement, scope):
                changed = True
                continue
            if isinstance(statement, Au3VariableDeclaration):
                alive = [
                    declarator
                    for declarator in statement.declarations
                    if not self._declarator_is_dead(statement, declarator, scope)
                ]
                if len(alive) != len(statement.declarations):
                    changed = True
                    if not alive:
                        continue
                    set_child_list(statement, 'declarations', alive)
            surviving.append(statement)
            for owner, nested in ast.statement_lists(statement):
                if self._prune(owner, nested, scope):
                    changed = True
            if isinstance(statement, Au3FunctionDeclaration):
                if self._prune(statement, 'body', statement):
                    changed = True
        if changed:
            set_child_list(parent, attr, surviving)
        return changed

    def _statement_is_dead(
        self,
        statement: Statement,
        scope: Au3FunctionDeclaration | None,
    ) -> bool:
        """
        Whether *statement* leaves as a whole: a function this sweep removes, an enum whose every
        entry is dead, or an expression statement that is effect-free. A variable declaration
        leaves per declarator instead, so `_prune` answers it.
        """
        assert self._usage is not None
        if isinstance(statement, Au3FunctionDeclaration):
            return statement.name is not None and statement.name.name in self._removable
        if isinstance(statement, Au3EnumDeclaration):
            return bool(statement.declarations) and all(
                self._declarator_is_dead(statement, declarator, scope)
                for declarator in statement.declarations
            )
        if isinstance(statement, Au3ExpressionStatement):
            return self._usage.effect_free(statement.expression)
        return False

    def _declarator_is_dead(
        self,
        statement: Statement,
        declarator: Au3VariableDeclarator | Au3EnumDeclarator,
        scope: Au3FunctionDeclaration | None,
    ) -> bool:
        """
        Whether *declarator* leaves: no occurrence binds or may bind the storage its statement's
        keyword forces — `Binding.NONE` never leaves, its write proving nothing — its name is
        spelled in no string, and its initializer and every dimension are effect-free. A local
        leaves only when its own scope holds no channel: a dynamic `Execute` payload runs in the
        scope it stands in and can name the local.
        """
        assert self._scopes is not None
        assert self._usage is not None
        variable = declarator.variable
        if variable is None:
            return False
        name = variable.name
        binding = self._scopes.binding(scope, statement, name)
        if binding is Binding.LOCAL:
            assert scope is not None
            if scope in self._channel_scopes:
                return False
            if name in self._usage.local_bindings.get(scope, frozenset()):
                return False
        elif binding is Binding.GLOBAL:
            if not self._globals_may_leave:
                return False
            readers = self._usage.global_bindings.get(name, frozenset())
            if any(
                reader is None or reader.name is None or reader.name.name not in self._removable
                for reader in readers
            ):
                return False
        else:
            return False
        if self._usage.spells(name):
            return False
        if not self._usage.effect_free(declarator.initializer):
            return False
        dimensions = declarator.dimensions if isinstance(declarator, Au3VariableDeclarator) else ()
        return all(self._usage.effect_free(dimension) for dimension in dimensions)
