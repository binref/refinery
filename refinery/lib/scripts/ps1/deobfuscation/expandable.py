"""
Hoist void subexpressions out of expandable strings, replacing the expandable
string with a plain string literal of its text parts. The hoisted statements
are inserted around the parent statement preserving their side effects. Only
operates on expandable strings where ALL subexpressions are void-producing
(assignments only — a command inside `$( ... )` contributes its output to the
string, so it is never hoisted).

Safety constraint: only a string that its statement evaluates exactly once
whenever the statement runs is hoisted; one in a script block, a body, a
condition of a compound statement or an operand a `-and` or `-or` may skip is
left alone. Subexpressions from an expandable string that nothing but constants
is evaluated before are inserted BEFORE the parent statement (they were going to
run first anyway). Subexpressions from other expandable strings are inserted
AFTER the parent statement to preserve execution order.
"""
from __future__ import annotations

from refinery.lib.scripts import Block, Node, Statement, Transformer
from refinery.lib.scripts.ps1.analysis.values import UNKNOWN, evaluate, make_string_literal
from refinery.lib.scripts.ps1.ast import (
    get_body,
    in_evaluation_order,
    may_be_skipped_by_a_short_circuit,
)
from refinery.lib.scripts.ps1.deobfuscation.substitution import substitute, substitute_statement
from refinery.lib.scripts.ps1.model import (
    Ps1AssignmentExpression,
    Ps1Code,
    Ps1CommandArgument,
    Ps1ExpandableString,
    Ps1ExpressionStatement,
    Ps1Pipeline,
    Ps1StringLiteral,
    Ps1SubExpression,
)

#: The statements that evaluate each of their parts once, in order, whenever they run. Every other
#: statement holds a body or a condition that runs conditionally, repeatedly, or not at all.
_STATEMENTS_EVALUATED_ONCE = (
    Ps1ExpressionStatement,
    Ps1Pipeline,
)


def _is_constant(node) -> bool:
    """
    Whether evaluating *node* reads no variable, runs nothing and cannot throw, which is what a
    value the domain pins without any environment is.
    """
    outcome = evaluate(node)
    return not outcome.may_throw and outcome.value is not UNKNOWN


def _runs_once_with(node: Node, stmt: Node) -> bool:
    """
    Whether *node* is evaluated exactly once whenever the statement *stmt* runs: *stmt* and every
    statement between the two evaluate their parts once, no script block or body stands between
    them, and no `-and` or `-or` may skip *node*.
    """
    if not isinstance(stmt, _STATEMENTS_EVALUATED_ONCE):
        return False
    cursor = node.parent
    while cursor is not stmt:
        if cursor is None or isinstance(cursor, (Ps1Code, Block)):
            return False
        if isinstance(cursor, Statement) and not isinstance(cursor, _STATEMENTS_EVALUATED_ONCE):
            return False
        cursor = cursor.parent
    return not may_be_skipped_by_a_short_circuit(node)


class Ps1ExpandableStringHoist(Transformer):

    def visit(self, node):
        for container in list(node.walk()):
            body = get_body(container)
            if body is None:
                continue
            i = 0
            while i < len(body):
                before, after, replaced = self._extract_void_subexpressions(body[i])
                if before or after:
                    hoisted = [*before, body[i], *after]
                    if substitute_statement(container, body[i], hoisted):
                        i += len(before) + len(after)
                if replaced:
                    self.mark_changed()
                i += 1
        return None

    @staticmethod
    def _is_void_statement(stmt) -> bool:
        """
        A statement is void when it contributes nothing to an interpolating string, which only an
        assignment does.
        """
        if not isinstance(stmt, Ps1ExpressionStatement):
            return False
        return isinstance(stmt.expression, Ps1AssignmentExpression)

    @staticmethod
    def _runs_first(node: Node, stmt: Node) -> bool:
        """
        Check whether nothing but constants is evaluated before *node* when the statement *stmt*
        runs, reading its parts in the order `refinery.lib.scripts.ps1.ast.in_evaluation_order`
        gives: an operand, an argument, an element or a receiver that is evaluated ahead of the
        part holding *node* has to be a constant that cannot throw, and the name of an argument
        evaluates nothing. A constant reads no variable and runs nothing, so evaluating it later
        leaves every other effect where it was, and hoisting the subexpressions before the
        statement does not change what anything observes. That is the one place they may go when the
        statement is a pipeline: its commands run after the whole of its input is evaluated, and
        read what the input assigned.
        """
        holding: set[int] = set()
        cursor = node.parent
        while cursor is not None:
            holding.add(id(cursor))
            if cursor is stmt:
                break
            cursor = cursor.parent
        for evaluated in in_evaluation_order(stmt):
            if evaluated is node:
                return True
            parent = evaluated.parent
            if id(evaluated) in holding or parent is None or id(parent) not in holding:
                continue
            if isinstance(evaluated, Ps1CommandArgument):
                holding.add(id(evaluated))
                continue
            if not _is_constant(evaluated):
                return False
        return True

    def _extract_void_subexpressions(self, stmt) -> tuple[list, list, bool]:
        """
        Walk the statement tree, find expandable strings whose every part is literal text or a void
        subexpression, replace them with string literals, and return `(before, after, replaced)`.

        Every part has to be accounted for: a part that is neither — the `$env:APPDATA` in
        `"$env:APPDATA$($z=1)\\dropper.exe"` — has no text this can write down, so rewriting the
        string around it would silently delete what it interpolated. `replaced` is reported apart
        from the two lists because a subexpression with an empty body rewrites the string while
        hoisting no statement; and hoisting is done only after the replace, so a string nested inside
        one already rewritten is not reached and run twice. A string whose subexpressions hoist a
        statement is rewritten only where `_runs_once_with` places it: hoisted out of a body, a
        condition or a skipped operand, an assignment would run where the string never did.
        """
        before: list = []
        after: list = []
        replaced = False
        for node in list(stmt.walk_in_order()):
            if not isinstance(node, Ps1ExpandableString):
                continue
            if not all(
                isinstance(part, (Ps1StringLiteral, Ps1SubExpression))
                for part in node.parts
            ):
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
            if collected and not _runs_once_with(node, stmt):
                continue
            first = self._runs_first(node, stmt)
            literal = make_string_literal(''.join(text_parts))
            if not substitute(node, literal, moved=collected):
                continue
            if first:
                before.extend(collected)
            else:
                after.extend(collected)
            replaced = True
        return before, after, replaced
