"""
Write each statement that is a comma sequence as one statement per part.

The statement `a = x, b = y;` runs `a = x` and then `b = y`, and its completion value is that of
its last part, which is also what `a = x; b = y;` leaves behind. Every pass that removes or moves
code reads a store, a call or a discarded value as the statement it stands in, so a store joined
to another one by a comma is a part of an expression to all of them: two dead stores written in
one sequence stay where the same two written as statements go. Minifiers and obfuscators join
statements this way throughout.
"""
from __future__ import annotations

from refinery.lib.scripts import Node, Transformer, set_child_list
from refinery.lib.scripts.js.model import (
    Expression,
    JsBlockStatement,
    JsExpressionStatement,
    JsScript,
    JsSequenceExpression,
    JsStaticBlock,
    JsSwitchCase,
    Statement,
    strip_parens,
)

_STATEMENT_LISTS = (
    JsScript,
    JsBlockStatement,
    JsStaticBlock,
    JsSwitchCase,
)


def _parts(statement: Node) -> list[Statement] | None:
    """
    The statements the parts of *statement* make, or `None` where it is not a comma sequence. A part
    that is itself a sequence in parentheses gives its own parts, in the order they run. The
    comments around the statement go with its first and its last part.
    """
    if (
        not isinstance(statement, JsExpressionStatement)
        or not isinstance(strip_parens(statement.expression), JsSequenceExpression)
    ):
        return None
    expressions: list[Expression] = []
    pending = [statement.expression]
    while pending:
        expression = pending.pop()
        if isinstance(sequence := strip_parens(expression), JsSequenceExpression):
            pending.extend(reversed(sequence.expressions))
        elif expression is not None:
            expressions.append(expression)
    if not expressions:
        return None
    parts: list[Statement] = [
        JsExpressionStatement(expression=expression, offset=expression.offset)
        for expression in expressions
    ]
    parts[0].leading_comments = list(statement.leading_comments)
    parts[-1].trailing_comments = list(statement.trailing_comments)
    return parts


class JsSequenceStatementSplitting(Transformer):
    """
    Replace each statement that is a comma sequence by the statements its parts make. Where the
    statement stands in a list, its parts take its place in that list; where it is the whole body of
    a branch, a loop or a label, they make a block, which declares nothing and so changes no scope.
    """

    self_converging = True

    def generic_visit(self, node: Node):
        super().generic_visit(node)
        if isinstance(node, _STATEMENT_LISTS):
            self._split_in_place(node)
        return None

    def visit_JsExpressionStatement(self, node: JsExpressionStatement):
        self.generic_visit(node)
        if isinstance(node.parent, _STATEMENT_LISTS):
            return None
        if (parts := _parts(node)) is None:
            return None
        return JsBlockStatement(body=parts, offset=node.offset)

    def _split_in_place(self, holder: JsScript | JsBlockStatement | JsStaticBlock | JsSwitchCase):
        statements: list[Statement] = []
        split = False
        for statement in holder.body:
            if (parts := _parts(statement)) is None:
                statements.append(statement)
                continue
            statements.extend(parts)
            split = True
        if split:
            set_child_list(holder, 'body', statements)
            self.mark_changed()
