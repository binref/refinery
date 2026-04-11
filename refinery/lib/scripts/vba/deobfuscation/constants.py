"""
VBA constant inlining: substitutes single-assignment constant variableswith their literal values.
"""
from __future__ import annotations

from refinery.lib.scripts import Expression, Statement, Transformer
from refinery.lib.scripts.vba.deobfuscation._helpers import (
    _body_lists,
    _clone_expression,
    _is_constant_expr,
)
from refinery.lib.scripts.vba.model import (
    VbaCallExpression,
    VbaConstDeclaration,
    VbaConstDeclarator,
    VbaExpressionStatement,
    VbaForEachStatement,
    VbaForStatement,
    VbaIdentifier,
    VbaLetStatement,
    VbaModule,
)


class VbaConstantInlining(Transformer):

    def visit(self, node):
        if isinstance(node, VbaModule):
            if self._inline_constants(node):
                self.mark_changed()
        return None

    def _inline_constants(self, module: VbaModule) -> bool:
        candidates: dict[str, list[tuple[Expression, list[Statement], int]]] = {}
        assignment_counts: dict[str, int] = {}
        for body in _body_lists(module):
            for idx, stmt in enumerate(body):
                if isinstance(stmt, VbaConstDeclaration):
                    for d in stmt.declarators:
                        if d.value is not None and _is_constant_expr(d.value):
                            key = d.name.lower()
                            candidates.setdefault(key, []).append((d.value, body, idx))
                            assignment_counts[key] = assignment_counts.get(key, 0) + 1
                elif (
                    isinstance(stmt, VbaLetStatement)
                    and isinstance(stmt.target, VbaIdentifier)
                    and stmt.value is not None
                ):
                    key = stmt.target.name.lower()
                    assignment_counts[key] = assignment_counts.get(key, 0) + 1
                    if _is_constant_expr(stmt.value):
                        candidates.setdefault(key, []).append((stmt.value, body, idx))
        loop_variables: set[str] = set()
        for node in module.walk():
            if isinstance(node, (VbaForStatement, VbaForEachStatement)):
                if isinstance(node.variable, VbaIdentifier):
                    loop_variables.add(node.variable.name.lower())
        candidates = {
            k: v for k, v in candidates.items()
            if len(v) == 1
            and k not in loop_variables
            and assignment_counts.get(k, 0) == 1
        }
        if not candidates:
            return False
        reads: dict[str, list[VbaIdentifier]] = {}
        for node in module.walk():
            if not isinstance(node, VbaIdentifier):
                continue
            parent = node.parent
            if isinstance(parent, VbaLetStatement) and parent.target is node:
                continue
            if isinstance(parent, (VbaConstDeclaration, VbaConstDeclarator)):
                continue
            if isinstance(parent, VbaCallExpression) and parent.callee is node:
                continue
            if isinstance(parent, VbaExpressionStatement) and parent.expression is node:
                continue
            if (
                isinstance(parent, (VbaForStatement, VbaForEachStatement))
                and parent.variable is node
            ):
                continue
            key = node.name.lower()
            if key in candidates:
                reads.setdefault(key, []).append(node)
        removals: list[tuple[list[Statement], int]] = []
        for key, refs in reads.items():
            literal_node, body, idx = candidates[key][0]
            for ref in refs:
                replacement = _clone_expression(literal_node)
                replacement.parent = ref.parent
                parent = ref.parent
                for attr_name in vars(parent):
                    if attr_name in ('parent', 'offset'):
                        continue
                    value = getattr(parent, attr_name)
                    if value is ref:
                        setattr(parent, attr_name, replacement)
                    elif isinstance(value, list):
                        for i, item in enumerate(value):
                            if item is ref:
                                value[i] = replacement
            removals.append((body, idx))
        for body, idx in sorted(removals, key=lambda t: t[1], reverse=True):
            del body[idx]
        return bool(removals)
