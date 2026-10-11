"""
AutoIt3 scoping: the documented rules that decide which storage a write or a read targets and
which storage an occurrence may reach, and the script's declared functions. This module is the
single owner of that question — the constant-binding walk in
`refinery.lib.scripts.au3.analysis.propagation` consults it and never re-derives the answer.

The rules, per the AutoIt3 documentation:

- at script level, any declaration or assignment writes the global of that name regardless of
  keyword — an unseen `#include` cannot change what a script-level write targets;
- inside a function, `Local`, `Global`, and `Static` force their storage, and a bare `Const`
  introduces a constant of function scope;
- a bare assignment, `Dim`, or `ReDim` inside a function writes the global when a same-named
  global exists and a local otherwise — but a same-named global in an unseen `#include` is
  indistinguishable from no global at all, so such a write proves nothing and is reported as
  `Binding.NONE`. It proves a local instead when the written name is a parameter of the function,
  or a `Local`, `Static`, or local `Const`/`Enum` statement declaring it stands directly in the
  function body before the statement holding the write: a top-level statement before the write
  runs on every path that reaches it, because AutoIt has no jumps, and an existing local takes
  the write (probe4 23). A `For`/`For…In` loop claiming the name stands the same way — the loop
  creates its variable local before its first test, a zero trip included (probe4 31), so a write
  in its body or after it finds the local. A `Global` declaration of the name anywhere in the
  function still proves the global and keeps the write `NONE`.

The model also holds the tree's constant names — a `Const` or `Enum` declaration or a `Const`
parameter claims one — because no scope placement softens that fact: writing a constant is an
interpreter refusal, so a caller that flattens a dynamic write over a name asks the model first.
It answers whether the tree holds an include the same way — the node, or the directive an
include line with trailing text becomes — because an unseen included file may declare storage
and constants no tree declaration covers, so every caller that rewrites around the tree's own
declarations asks the model first.
"""
from __future__ import annotations

import enum
import re

from dataclasses import dataclass, field
from typing import TypeGuard, cast

from refinery.lib.scripts import Node, Statement
from refinery.lib.scripts.au3 import ast
from refinery.lib.scripts.au3.model import (
    Au3Directive,
    Au3EnumDeclaration,
    Au3ForInStatement,
    Au3ForStatement,
    Au3FunctionDeclaration,
    Au3Include,
    Au3IncludeOnce,
    Au3Parameter,
    Au3ScopeKind,
    Au3Script,
    Au3VariableDeclaration,
)


class Binding(enum.Enum):
    """
    The storage a write provably targets: the one global of that name, one function's local, or
    nothing at all.
    """
    GLOBAL = enum.auto()
    LOCAL = enum.auto()
    NONE = enum.auto()


#: An include spelled as a directive: the parser reads an include line only as the include node
#: when the line ends after the path, so one with trailing text — the comment form the official
#: documentation's own examples write — stays a directive that names the same unseen file.
_INCLUDE_SPELLING = re.compile(r'\s*#\s*include', re.IGNORECASE)


@dataclass(frozen=True)
class Au3LocalFacts:
    """
    What one function body proves about a name: whether it is a parameter, whether any `Global`
    declaration in the function claims it, the body position where it first takes a declaration
    that forces the local storage, and the body positions of every statement holding such a
    declaration or claim at any depth.
    """
    parameters: frozenset[str]
    global_names: frozenset[str]
    first_local: dict[str, int]
    local_positions: dict[str, frozenset[int]]


def _declared_names(declaration: Au3VariableDeclaration | Au3EnumDeclaration) -> set[str]:
    names = set()
    for declarator in declaration.declarations:
        if declarator.variable is not None:
            names.add(declarator.variable.name)
    return names


def _declares_local(
    statement: Statement,
) -> TypeGuard[Au3VariableDeclaration | Au3EnumDeclaration]:
    """
    Whether *statement* declares its names into the local storage: `Local`, `Static`, a local
    `Const`, or an `Enum` no `Global` keyword leads — an enum's entries are constants of the scope
    the declaration stands in. A `Dim` forces nothing.
    """
    if isinstance(statement, Au3VariableDeclaration):
        if statement.scope is Au3ScopeKind.GLOBAL:
            return False
        return (
            statement.scope is Au3ScopeKind.LOCAL
            or statement.is_static
            or statement.is_const
        )
    if isinstance(statement, Au3EnumDeclaration):
        return statement.scope is not Au3ScopeKind.GLOBAL
    return False


def _local_claim_names(node: Node) -> set[str] | None:
    """
    The names *node* claims into the local storage — a local-forcing declaration's declared names
    or a `For`/`For…In` loop's variable — or `None` when it claims none.
    """
    if isinstance(node, (Au3VariableDeclaration, Au3EnumDeclaration)):
        return _declared_names(node) if _declares_local(node) else None
    if isinstance(node, (Au3ForStatement, Au3ForInStatement)):
        return None if node.variable is None else {node.variable.name}
    return None


def _local_facts(function: Au3FunctionDeclaration) -> Au3LocalFacts:
    """
    The local facts of *function*'s body: parameter names, the names any `Global` declaration in
    it claims — at any depth, but not inside a nested function, which is a scope of its own —
    the first body position at which each name takes a local-forcing declaration or becomes the
    variable of a `For`/`For…In` loop, and the body positions of every statement holding such a
    declaration or claim at any depth.
    """
    parameters = {
        parameter.variable.name
        for parameter in function.params
        if parameter.variable is not None
    }
    global_names = set()
    for node in ast.scope_nodes(function.body):
        if (
            isinstance(node, (Au3VariableDeclaration, Au3EnumDeclaration))
            and node.scope is Au3ScopeKind.GLOBAL
        ):
            global_names |= _declared_names(node)
    first_local: dict[str, int] = {}
    for index, statement in enumerate(function.body):
        names = _local_claim_names(statement)
        if names is None:
            continue
        for name in names:
            first_local.setdefault(name, index)
    local_positions: dict[str, set[int]] = {}
    for node in ast.scope_nodes(function.body):
        names = _local_claim_names(node)
        if names is None:
            continue
        index = _top_level_index(function, node)
        for name in names:
            local_positions.setdefault(name, set()).add(index)
    return Au3LocalFacts(
        frozenset(parameters),
        frozenset(global_names),
        first_local,
        {name: frozenset(indices) for name, indices in local_positions.items()},
    )


def _top_level_index(scope: Au3FunctionDeclaration, write: Node) -> int:
    """
    The position in *scope*'s body of the top-level statement that holds *write*, or `-1` when
    the chain leaves the body: the write stands in no statement the body owns — a parameter
    default, the function's own name — so no declaration before it is pinned.
    """
    cursor = write
    while cursor.parent is not None and cursor.parent is not scope:
        cursor = cursor.parent
    if cursor.parent is not scope or not isinstance(cursor, Statement):
        return -1
    return scope.body.index(cast(Statement, cursor))


@dataclass(frozen=True)
class Au3ScopeModel:
    """
    The script's declared functions, the answers to which storage a write or a read targets and
    which storage an occurrence may reach, the names the tree declares constants, and whether the
    tree holds an include. Built once per tree version by `build_scope_model`.
    """
    functions: dict[str, Au3FunctionDeclaration]
    local_facts: dict[Au3FunctionDeclaration, Au3LocalFacts] = field(default_factory=dict)
    constant_names: frozenset[str] = frozenset()
    holds_an_include: bool = False

    @property
    def function_names(self) -> frozenset[str]:
        return frozenset(self.functions)

    def binding(
        self,
        scope: Au3FunctionDeclaration | None,
        write: Node,
        name: str,
    ) -> Binding:
        """
        The storage the write *write* performs on *name* targets when it stands in *scope*: the
        whole script when `None`, one function's body otherwise. The write is the declaration,
        assignment, loop, or ReDim statement that performs it —
        `refinery.lib.scripts.au3.ast.owning_statement` names it from any node inside. A bare,
        compound, `Dim`, or `ReDim` write whose name is a parameter of the function, whose name a
        local-forcing declaration in the body precedes, or whose name a `For`/`For…In` loop in
        the body claims at or before it, targets that local — unless a `Global` declaration of
        the name anywhere in the function claims the global.
        """
        if scope is None:
            return Binding.GLOBAL
        if isinstance(write, (Au3ForStatement, Au3ForInStatement)):
            return Binding.LOCAL
        if isinstance(write, (Au3VariableDeclaration, Au3EnumDeclaration)):
            if write.scope is Au3ScopeKind.GLOBAL:
                return Binding.GLOBAL
            if write.scope is Au3ScopeKind.LOCAL:
                return Binding.LOCAL
            if isinstance(write, Au3VariableDeclaration) and write.is_static:
                return Binding.LOCAL
            if write.is_const:
                return Binding.LOCAL
        facts = self.local_facts.get(scope)
        if facts is None or name in facts.global_names:
            return Binding.NONE
        if name in facts.parameters:
            return Binding.LOCAL
        first = facts.first_local.get(name)
        if first is None:
            return Binding.NONE
        if first <= _top_level_index(scope, write):
            return Binding.LOCAL
        return Binding.NONE

    def read_binding(
        self,
        scope: Au3FunctionDeclaration | None,
        read: Node,
        name: str,
    ) -> Binding:
        """
        The storage the read *read* of *name* targets when it stands in *scope*: the whole script
        when `None`, one function's body otherwise. A read before a same-named local-forcing
        declaration in the body sees the global and a read after it the local (probe4 22-23), and
        a function that declares the name `Global` reads the global throughout. A name a `Dim`
        in the function declares forces no storage, so a read of it keeps the global: the
        function created no local the read could see. A parameter read inside the body targets
        the local, but a read inside a parameter default runs before any parameter is bound, so
        it keeps the global — the only storage that could exist where it stands.
        """
        if scope is None:
            return Binding.GLOBAL
        facts = self.local_facts.get(scope)
        if facts is None or name in facts.global_names:
            return Binding.GLOBAL
        if name in facts.parameters:
            if _top_level_index(scope, read) < 0:
                return Binding.GLOBAL
            return Binding.LOCAL
        first = facts.first_local.get(name)
        if first is None:
            return Binding.GLOBAL
        if first <= _top_level_index(scope, read):
            return Binding.LOCAL
        return Binding.GLOBAL

    def local_precedes_read(
        self,
        scope: Au3FunctionDeclaration | None,
        read: Node,
        name: str,
    ) -> bool:
        """
        Whether the read *read* of *name* in *scope* targets a local that exists when the read
        runs and whose claim strictly precedes it. `read_binding` counts the statement that
        claims a local as covering a read inside it, but the local does not exist while that
        statement's own initializer runs — `Local $x = $x` is an interpreter refusal (probe9g)
        where the dynamic read of the same name answers `""` — so a caller that replaces a
        dynamic read with the plain one asks this instead. A parameter needs no claim: it exists
        once the function's parameters are bound, and the defaults that fill them run before any
        is, so a read inside a parameter default — of the very parameter being defaulted no less
        — targets nothing the plain read may name and counts only inside the body.
        """
        if scope is None:
            return False
        facts = self.local_facts.get(scope)
        if facts is None or name in facts.global_names:
            return False
        if name in facts.parameters:
            return _top_level_index(scope, read) >= 0
        first = facts.first_local.get(name)
        if first is None:
            return False
        return first < _top_level_index(scope, read)

    def may_bind_local(
        self,
        scope: Au3FunctionDeclaration | None,
        occurrence: Node,
        name: str,
    ) -> bool:
        """
        Whether the occurrence *occurrence* of *name* may bind a local of *scope*: the name is a
        parameter of the function, or a local-forcing declaration or `For`/`For…In` claim of it
        stands in a top-level statement at or before the occurrence's. A declaration inside a
        branch creates its local the moment the branch runs it, and a loop's second iteration
        sees one an earlier iteration created, so the occurrence and the claim sharing their
        top-level statement counts as preceding it. A read that provably precedes every claim —
        `read_binding` answering `Binding.GLOBAL` with no claim behind it — is one no local can
        reach. An occurrence inside a parameter default may bind no local at all: no parameter
        is bound and no body statement has run where it stands.
        """
        if scope is None:
            return False
        facts = self.local_facts.get(scope)
        if facts is None or name in facts.global_names:
            return False
        if name in facts.parameters:
            return _top_level_index(scope, occurrence) >= 0
        index = _top_level_index(scope, occurrence)
        return any(position <= index for position in facts.local_positions.get(name, ()))


def _constant_names(root: Au3Script) -> frozenset[str]:
    """
    Every name the tree declares a constant: the names of a `Const` declaration, of any `Enum` —
    an enum's entries are constants of the scope it stands in — and of a `Const` parameter.
    """
    names: set[str] = set()
    for node in root.walk():
        if isinstance(node, Au3VariableDeclaration):
            if node.is_const:
                names |= _declared_names(node)
        elif isinstance(node, Au3EnumDeclaration):
            names |= _declared_names(node)
        elif isinstance(node, Au3Parameter):
            if node.is_const and node.variable is not None:
                names.add(node.variable.name)
    return frozenset(names)


def build_scope_model(root: Au3Script) -> Au3ScopeModel:
    """
    Collect the function declarations of *root*, the local facts of each body, the names the tree
    declares constants, and whether the tree holds an include — the node the parser reads an
    include line without trailing text into, or the directive one with trailing text becomes.
    Two functions of one name never coexist in a script AutoIt runs, so the mapping keeps the
    last of them without comment.
    """
    functions: dict[str, Au3FunctionDeclaration] = {}
    holds_an_include = False
    for node in root.walk():
        if isinstance(node, Au3FunctionDeclaration):
            if node.name is not None:
                functions[node.name.name] = node
        elif isinstance(node, (Au3Include, Au3IncludeOnce)):
            holds_an_include = True
        elif isinstance(node, Au3Directive) and _INCLUDE_SPELLING.match(node.text):
            holds_an_include = True
    local_facts = {function: _local_facts(function) for function in functions.values()}
    return Au3ScopeModel(
        functions,
        local_facts,
        _constant_names(root),
        holds_an_include,
    )
