"""
VBA dead variable removal: removes assignments to variables that are never read, provided the
right-hand side has no side effects.
"""
from __future__ import annotations

from refinery.lib.scripts import Statement, Transformer
from refinery.lib.scripts.vba.deobfuscation._helpers import _body_lists
from refinery.lib.scripts.vba.model import (
    VbaCallExpression,
    VbaIdentifier,
    VbaLetStatement,
    VbaModule,
)


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
                    has_call = False
                    for child in stmt.value.walk():
                        if isinstance(child, VbaCallExpression):
                            has_call = True
                            break
                    if not has_call:
                        key = stmt.target.name.lower()
                        assignments.setdefault(key, []).append((stmt, body, idx))
        read_names: set[str] = set()
        for node in module.walk():
            if not isinstance(node, VbaIdentifier):
                continue
            parent = node.parent
            if isinstance(parent, VbaLetStatement) and parent.target is node:
                continue
            read_names.add(node.name.lower())
        removals: list[tuple[list[Statement], int]] = []
        for key, entries in assignments.items():
            if key not in read_names:
                for _stmt, body, idx in entries:
                    removals.append((body, idx))
        for body, idx in sorted(removals, key=lambda t: t[1], reverse=True):
            del body[idx]
        return bool(removals)
