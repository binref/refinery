"""
VBA dead code removal: removes assignments to unread variables and empty uncalled procedures.
"""
from __future__ import annotations

from refinery.lib.scripts import Statement, Transformer
from refinery.lib.scripts.vba.deobfuscation._helpers import (
    _SINGLE_ARG_BUILTINS,
    _STRING_BUILTINS,
    _body_lists,
)
from refinery.lib.scripts.vba.model import (
    VbaCallExpression,
    VbaIdentifier,
    VbaLetStatement,
    VbaModule,
    VbaProcedureDeclaration,
)

_PURE_BUT_UNEVALUABLE = frozenset({
    'atn',
    'ccur',
    'cdate',
    'cdec',
    'clnglng',
    'clngptr',
    'cos',
    'csng',
    'cvar',
    'exp',
    'log',
    'sin',
    'sqr',
    'str',
    'str$',
    'tan',
    'val',
})

_PURE_BUILTINS = frozenset(_SINGLE_ARG_BUILTINS) | _STRING_BUILTINS | _PURE_BUT_UNEVALUABLE


def _has_side_effects(node) -> bool:
    """
    Return whether an expression tree might have side effects. Calls to known
    pure VBA builtins are treated as side-effect-free.
    """
    for child in node.walk():
        if not isinstance(child, VbaCallExpression):
            continue
        if not isinstance(child.callee, VbaIdentifier):
            return True
        if child.callee.name.lower() not in _PURE_BUILTINS:
            return True
    return False


class VbaDeadVariableRemoval(Transformer):

    def visit(self, node):
        if isinstance(node, VbaModule):
            if self._remove_dead_variables(node):
                self.mark_changed()
        return None

    def _remove_dead_variables(self, module: VbaModule) -> bool:
        assignments: dict[str, list[tuple[VbaLetStatement, list[Statement], int]]] = {}
        for body in _body_lists(module):
            if body is module.body:
                continue
            for idx, stmt in enumerate(body):
                if (
                    isinstance(stmt, VbaLetStatement)
                    and isinstance(stmt.target, VbaIdentifier)
                    and stmt.value is not None
                ):
                    if not _has_side_effects(stmt.value):
                        key = stmt.target.name.lower()
                        assignments.setdefault(key, []).append((stmt, body, idx))
        read_names: set[str] = set()
        for node in module.walk():
            if not isinstance(node, VbaIdentifier):
                continue
            if isinstance(node.parent, VbaLetStatement) and node.parent.target is node:
                continue
            read_names.add(node.name.lower())
        removals: list[tuple[list[Statement], int]] = []
        for key, entries in assignments.items():
            if key not in read_names:
                for _, body, idx in entries:
                    removals.append((body, idx))
        for body, idx in sorted(removals, key=lambda t: t[1], reverse=True):
            del body[idx]
        return bool(removals)


class VbaEmptyProcedureRemoval(Transformer):

    def visit(self, node):
        if isinstance(node, VbaModule):
            if self._remove_empty_procedures(node):
                self.mark_changed()
        return None

    def _remove_empty_procedures(self, module: VbaModule) -> bool:
        empty: dict[str, list[int]] = {}
        for idx, stmt in enumerate(module.body):
            if isinstance(stmt, VbaProcedureDeclaration) and not stmt.body:
                empty.setdefault(stmt.name.lower(), []).append(idx)
        if not empty:
            return False
        referenced: set[str] = set()
        for node in module.walk():
            if isinstance(node, VbaIdentifier):
                key = node.name.lower()
                if key in empty:
                    referenced.add(key)
        indices: list[int] = []
        for key, positions in empty.items():
            if key not in referenced:
                indices.extend(positions)
        for idx in sorted(indices, reverse=True):
            del module.body[idx]
        return bool(indices)
