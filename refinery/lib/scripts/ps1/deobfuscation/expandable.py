"""
Hoist void subexpressions out of expandable strings, replacing the expandable
string with a plain string literal of its text parts. The hoisted statements
are inserted around the parent statement preserving their side effects. Only
operates on expandable strings where ALL subexpressions are void-producing
(command invocations, assignments).

Safety constraint: subexpressions from leftmost expandable strings are
inserted BEFORE the parent statement (they were going to run first anyway).
Subexpressions from other expandable strings are inserted AFTER the parent
statement to preserve execution order.
"""
from __future__ import annotations

from refinery.lib.scripts import Block, Transformer, _replace_in_parent
from refinery.lib.scripts.ps1.deobfuscation._helpers import (
    _get_body,
    _make_string_literal,
)
from refinery.lib.scripts.ps1.model import (
    Ps1AssignmentExpression,
    Ps1BinaryExpression,
    Ps1CommandInvocation,
    Ps1ExpandableString,
    Ps1ExpressionStatement,
    Ps1StringLiteral,
    Ps1SubExpression,
    _Ps1Code,
)


class Ps1ExpandableStringHoist(Transformer):
    """
    Extract void subexpressions from expandable strings into preceding or
    following statements, then replace the expandable string with a plain
    string literal.
    """

    def visit(self, node):
        for container in list(node.walk()):
            body = _get_body(container)
            if body is None:
                continue
            i = 0
            while i < len(body):
                before, after = self._extract_void_subexpressions(body[i])
                if before or after:
                    for stmt in before:
                        stmt.parent = container
                    for stmt in after:
                        stmt.parent = container
                    body[i + 1:i + 1] = after
                    body[i:i] = before
                    self.mark_changed()
                    i += len(before) + len(after)
                i += 1
        return None

    @staticmethod
    def _is_void_statement(stmt) -> bool:
        """
        A statement is void when it produces no output value.
        """
        if not isinstance(stmt, Ps1ExpressionStatement):
            return False
        expr = stmt.expression
        return isinstance(expr, (Ps1CommandInvocation, Ps1AssignmentExpression))

    @staticmethod
    def _is_leftmost(node) -> bool:
        """
        Check whether *node* sits in the leftmost evaluation position of its
        enclosing expression tree. An expandable string is leftmost when every
        ancestor `Ps1BinaryExpression` has it (or the subtree containing it)
        as its `left` operand. This guarantees the subexpressions would have
        been the first thing evaluated, so hoisting them before the statement
        does not change execution order.
        """
        child = node
        parent = node.parent
        while parent is not None:
            if isinstance(parent, Ps1BinaryExpression):
                if parent.left is not child:
                    return False
            if isinstance(parent, (Ps1ExpressionStatement, _Ps1Code, Block)):
                break
            child = parent
            parent = parent.parent
        return True

    def _extract_void_subexpressions(self, stmt) -> tuple[list, list]:
        """
        Walk the statement tree, find expandable strings where all
        subexpressions are void, replace them with string literals, and
        return `(before_stmts, after_stmts)`.
        """
        before: list = []
        after: list = []
        for node in list(stmt.walk()):
            if not isinstance(node, Ps1ExpandableString):
                continue
            subs = [p for p in node.parts if isinstance(p, Ps1SubExpression)]
            if not subs:
                continue
            if not all(
                all(self._is_void_statement(s) for s in sub.body)
                for sub in subs
            ):
                continue
            text_parts: list[str] = []
            for part in node.parts:
                if isinstance(part, Ps1StringLiteral):
                    text_parts.append(part.value)
            collected: list = []
            for sub in subs:
                collected.extend(sub.body)
            if self._is_leftmost(node):
                before.extend(collected)
            else:
                after.extend(collected)
            replacement = _make_string_literal(''.join(text_parts))
            _replace_in_parent(node, replacement)
        return before, after
