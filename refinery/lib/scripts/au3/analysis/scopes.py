"""
AutoIt3 scoping: the documented rules that decide which storage a write targets, and the script's
declared functions. This module is the single owner of that question — the
constant-binding walk in `refinery.lib.scripts.au3.analysis.propagation` consults it and never
re-derives the answer.

The rules, per the AutoIt3 documentation:

- at script level, any declaration or assignment writes the global of that name regardless of
  keyword — an unseen `#include` cannot change what a script-level write targets;
- inside a function, `Local`, `Global`, and `Static` force their storage, and a bare `Const`
  introduces a constant of function scope;
- a bare assignment or `Dim` inside a function writes the global when a same-named global exists
  and a local otherwise — but a same-named global in an unseen `#include` is indistinguishable
  from no global at all, so such a write proves nothing and is reported as `Binding.NONE`.
"""
from __future__ import annotations

import enum

from dataclasses import dataclass

from refinery.lib.scripts import Node
from refinery.lib.scripts.au3.model import (
    Au3EnumDeclaration,
    Au3ForInStatement,
    Au3ForStatement,
    Au3FunctionDeclaration,
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


@dataclass(frozen=True)
class Au3ScopeModel:
    """
    The script's declared functions, and the answer to which storage a write targets. Built once
    per tree version by `build_scope_model`.
    """
    functions: dict[str, Au3FunctionDeclaration]

    @property
    def function_names(self) -> frozenset[str]:
        return frozenset(self.functions)

    def binding(self, scope: Au3FunctionDeclaration | None, write: Node) -> Binding:
        """
        The storage *write* targets when it stands in *scope*: the whole script when `None`, one
        function's body otherwise. The write is the declaration, assignment, loop, or ReDim
        statement that performs it — `refinery.lib.scripts.au3.ast.owning_statement` names it from
        any node inside.
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
        return Binding.NONE


def build_scope_model(root: Au3Script) -> Au3ScopeModel:
    """
    Collect the function declarations of *root*. Two functions of one name never coexist in a
    script AutoIt runs, so the mapping keeps the last of them without comment.
    """
    functions: dict[str, Au3FunctionDeclaration] = {}
    for node in root.walk():
        if isinstance(node, Au3FunctionDeclaration):
            if node.name is not None:
                functions[node.name.name] = node
    return Au3ScopeModel(functions)
