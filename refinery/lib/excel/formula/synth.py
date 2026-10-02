"""
The synthesizer that prints the formula model back as one line of formula text, without the
leading `=`. Parentheses are emitted only where the precedence table demands them, so that a
cleaned tree prints as the shortest text that reads back as the same tree. A union is the one
operator that is never spelled bare: outside parentheses a comma is an argument separator, so
every union is wrapped, the formula root included.
"""
from __future__ import annotations

import re

from refinery.lib.excel.formula.model import (
    Expression,
    XlA1Reference,
    XlArrayConstant,
    XlBinaryExpression,
    XlBinaryOperator,
    XlBoolean,
    XlDefinedName,
    XlError,
    XlFunctionCall,
    XlMissingArgument,
    XlNumber,
    XlParenExpression,
    XlR1C1Reference,
    XlString,
    XlUnaryExpression,
    XlUnaryOperator,
    XlUnparsedFormula,
)
from refinery.lib.excel.formula.parse import International
from refinery.lib.scripts import Node, Synthesizer

_PRECEDENCE = {
    XlBinaryOperator.EQ: 1,
    XlBinaryOperator.NE: 1,
    XlBinaryOperator.LT: 1,
    XlBinaryOperator.LE: 1,
    XlBinaryOperator.GT: 1,
    XlBinaryOperator.GE: 1,
    XlBinaryOperator.CONCAT: 2,
    XlBinaryOperator.ADD: 3,
    XlBinaryOperator.SUB: 3,
    XlBinaryOperator.MUL: 4,
    XlBinaryOperator.DIV: 4,
    XlBinaryOperator.POW: 5,
    XlBinaryOperator.UNION: 8,
    XlBinaryOperator.ISECT: 9,
    XlBinaryOperator.RANGE: 10,
    XlUnaryOperator.NEG: 7,
    XlUnaryOperator.POS: 7,
    XlUnaryOperator.PERCENT: 6,
}

_RE_BARE_SHEET = re.compile(R'[A-Za-z_\\][A-Za-z0-9_.\\?]*')


def _sheet_token(name: str) -> str:
    if _RE_BARE_SHEET.fullmatch(name):
        return name
    escaped = name.replace("'", "''")
    return F"'{escaped}'"


def _qualify(sheets: tuple[str, ...]) -> str:
    return F"{':'.join(_sheet_token(s) for s in sheets)}!"


def _column_letters(col: int) -> str:
    letters = ''
    while col:
        col, letter = divmod(col - 1, 26)
        letters = chr(0x41 + letter) + letters
    return letters


class FormulaSynthesizer(Synthesizer):
    """
    Print a formula `Expression` as formula text. The list separator of the output follows the
    `International` it is given, so a workbook stored under another locale round-trips too.
    """

    def __init__(self, international: International | None = None):
        international = international or International()
        super().__init__()
        self._sep = international.list_separator
        self._lb = international.left_bracket
        self._rb = international.right_bracket

    def convert(self, node: Node) -> str:
        if isinstance(node, XlBinaryExpression) and node.operator is XlBinaryOperator.UNION:
            node = XlParenExpression(operand=node)
        return super().convert(node)

    def _emit_operand(self, operand: Expression | None, parent: int, left: bool):
        if operand is None:
            return
        if isinstance(operand, XlBinaryExpression):
            if operand.operator is XlBinaryOperator.UNION:
                self._write('(')
                self.visit(operand)
                self._write(')')
                return
            precedence = _PRECEDENCE[operand.operator]
            if precedence < parent or (precedence == parent and not left):
                self._write('(')
                self.visit(operand)
                self._write(')')
                return
        elif isinstance(operand, XlUnaryExpression):
            if _PRECEDENCE[operand.operator] < parent:
                self._write('(')
                self.visit(operand)
                self._write(')')
                return
        self.visit(operand)

    def visit_XlNumber(self, node: XlNumber):
        self._write(self._format_number(node))

    def visit_XlString(self, node: XlString):
        escaped = node.value.replace('"', '""')
        self._write(F'"{escaped}"')

    def visit_XlBoolean(self, node: XlBoolean):
        self._write('TRUE' if node.value else 'FALSE')

    def visit_XlError(self, node: XlError):
        self._write(node.value)

    def visit_XlBinaryExpression(self, node: XlBinaryExpression):
        precedence = _PRECEDENCE[node.operator]
        text = ' ' if node.operator is XlBinaryOperator.ISECT else node.operator.value
        self._emit_operand(node.left, precedence, left=True)
        self._write(text)
        self._emit_operand(node.right, precedence, left=False)

    def visit_XlUnaryExpression(self, node: XlUnaryExpression):
        if node.operator is XlUnaryOperator.PERCENT:
            self._emit_operand(node.operand, _PRECEDENCE[node.operator], left=False)
            self._write(node.operator.value)
            return
        self._write(node.operator.value)
        self._emit_operand(node.operand, _PRECEDENCE[node.operator], left=True)

    def visit_XlParenExpression(self, node: XlParenExpression):
        self._write('(')
        if node.operand is not None:
            self.visit(node.operand)
        self._write(')')

    def visit_XlMissingArgument(self, node: XlMissingArgument):
        pass

    def visit_XlUnparsedFormula(self, node: XlUnparsedFormula):
        self._write(node.text)

    def visit_XlA1Reference(self, node: XlA1Reference):
        if node.sheets is not None:
            self._write(_qualify(node.sheets))
        column = _column_letters(node.col)
        row = F'${node.row}' if not node.relative_row else str(node.row)
        col = F'${column}' if not node.relative_col else column
        self._write(F'{col}{row}')

    def visit_XlR1C1Reference(self, node: XlR1C1Reference):
        if node.sheets is not None:
            self._write(_qualify(node.sheets))
        self._write(
            F'{self._axis("R", node.row, node.relative_row)}'
            F'{self._axis("C", node.col, node.relative_col)}'
        )

    def visit_XlDefinedName(self, node: XlDefinedName):
        if node.sheet is not None:
            self._write(_qualify((node.sheet,)))
        self._write(node.name)

    def visit_XlFunctionCall(self, node: XlFunctionCall):
        if isinstance(node.callee, str):
            self._write(node.callee)
        else:
            self.visit(node.callee)
        self._write('(')
        for index, argument in enumerate(node.arguments):
            if index:
                self._write(self._sep)
            self.visit(argument)
        self._write(')')

    def visit_XlArrayConstant(self, node: XlArrayConstant):
        self._write('{')
        for rindex, row in enumerate(node.rows):
            if rindex:
                self._write(';')
            for cindex, item in enumerate(row):
                if cindex:
                    self._write(self._sep)
                self.visit(item)
        self._write('}')

    def _axis(self, letter: str, value: int, relative: bool) -> str:
        if not relative:
            return F'{letter}{value}'
        if value:
            return F'{letter}{self._lb}{value}{self._rb}'
        return letter

    def _format_number(self, node: XlNumber) -> str:
        try:
            if float(node.raw) == node.value:
                return node.raw
        except (TypeError, ValueError):
            pass
        if isinstance(node.value, int):
            return str(node.value)
        return repr(node.value)


def synthesize_formula(
    expression: Expression,
    international: International | None = None,
) -> str:
    """
    Print a formula `Expression` as one line of formula text without the leading `=`.
    """
    return FormulaSynthesizer(international).convert(expression)
