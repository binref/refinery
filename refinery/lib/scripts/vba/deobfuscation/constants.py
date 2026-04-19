"""
VBA constant inlining: substitutes single-assignment constant variables with their literal values.
"""
from __future__ import annotations

from typing import NamedTuple

from refinery.lib.scripts import Expression, Statement, Transformer, _clone_node, _replace_in_parent
from refinery.lib.scripts.vba.deobfuscation.helpers import (
    body_lists,
    is_constant_expr,
    is_identifier_read,
)
from refinery.lib.scripts.vba.model import (
    VbaConstDeclaration,
    VbaForEachStatement,
    VbaForStatement,
    VbaIdentifier,
    VbaLetStatement,
    VbaModule,
)


class InlineCandidate(NamedTuple):
    value: Expression
    body: list[Statement]
    position: int


class VbaConstantInlining(Transformer):

    def visit(self, node):
        if isinstance(node, VbaModule):
            if self._inline_constants(node):
                self.mark_changed()
        return None

    def _inline_constants(self, module: VbaModule) -> bool:
        candidates = self._collect_inline_candidates(module)
        if not candidates:
            return False
        reads = self._find_constant_reads(module, candidates)
        return self._apply_constant_replacements(reads, candidates)

    @staticmethod
    def _collect_inline_candidates(
        module: VbaModule,
    ) -> dict[str, list[InlineCandidate]]:
        candidates: dict[str, list[InlineCandidate]] = {}
        assignment_counts: dict[str, int] = {}
        for body in body_lists(module):
            for pos, stmt in enumerate(body):
                if isinstance(stmt, VbaConstDeclaration):
                    for d in stmt.declarators:
                        if d.value is not None and is_constant_expr(d.value):
                            key = d.name.lower()
                            candidates.setdefault(key, []).append(InlineCandidate(d.value, body, pos))
                            assignment_counts[key] = assignment_counts.get(key, 0) + 1
                elif (
                    isinstance(stmt, VbaLetStatement)
                    and isinstance(stmt.target, VbaIdentifier)
                    and stmt.value is not None
                ):
                    key = stmt.target.name.lower()
                    assignment_counts[key] = assignment_counts.get(key, 0) + 1
                    if is_constant_expr(stmt.value):
                        candidates.setdefault(key, []).append(InlineCandidate(stmt.value, body, pos))
        loop_variables: set[str] = set()
        for node in module.walk():
            if isinstance(node, (VbaForStatement, VbaForEachStatement)):
                if isinstance(node.variable, VbaIdentifier):
                    loop_variables.add(node.variable.name.lower())
        return {
            k: v for k, v in candidates.items()
            if len(v) == 1
            and k not in loop_variables
            and assignment_counts.get(k, 0) == 1
        }

    @staticmethod
    def _find_constant_reads(
        module: VbaModule,
        candidates: dict[str, list[InlineCandidate]],
    ) -> dict[str, list[VbaIdentifier]]:
        reads: dict[str, list[VbaIdentifier]] = {}
        for node in module.walk():
            if not isinstance(node, VbaIdentifier):
                continue
            if not is_identifier_read(node):
                continue
            key = node.name.lower()
            if key in candidates:
                reads.setdefault(key, []).append(node)
        return reads

    @staticmethod
    def _apply_constant_replacements(
        reads: dict[str, list[VbaIdentifier]],
        candidates: dict[str, list[InlineCandidate]],
    ) -> bool:
        removals: list[tuple[list[Statement], int]] = []
        for key, refs in reads.items():
            candidate = candidates[key][0]
            for ref in refs:
                replacement = _clone_node(candidate.value)
                _replace_in_parent(ref, replacement)
            removals.append((candidate.body, candidate.position))
        for body, pos in sorted(removals, key=lambda t: t[1], reverse=True):
            del body[pos]
        return bool(removals)
