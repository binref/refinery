"""
Synthesize AutoIt3 source from an `Au3Script` AST. Every statement starts on a line of its own,
nested statements are indented by four spaces, and keywords are written in their canonical
spellings from the token table. A single-line `If` prints in block form, since it parses to the
same tree as one. Correctness of expression nesting is provided by `precedence.needs_parens`
rather than by the presence of `Au3ParenExpression` nodes, so a tree a deobfuscation pass
produced that dropped explicit parentheses still prints correctly.

A statement that outgrows one line is continued: the token that would not fit is written behind
a continuation marker on a new line at column zero, and the breaks fall only where the
interpreter accepts one — behind a separator, an opening bracket, or the keyword that leads an
expression — never inside a literal.

Text the parser could not read is written exactly as it stood in the input: an error node holds
the slice from the start of its statement to the end of its line, so the synthesizer ends that
line and the next statement begins on a fresh one.
"""
from __future__ import annotations

from typing import TypeVar

from refinery.lib.scripts import Node, Statement, Synthesizer, UnspellableNode
from refinery.lib.scripts.au3.lexer import encode_au3_string
from refinery.lib.scripts.au3.limits import MAX_LINESIZE
from refinery.lib.scripts.au3.model import (
    Au3ArrayAccess,
    Au3ArrayLiteral,
    Au3Assignment,
    Au3BinaryExpression,
    Au3BooleanLiteral,
    Au3Call,
    Au3CaseRange,
    Au3ContinueCaseStatement,
    Au3ContinueLoopStatement,
    Au3DefaultLiteral,
    Au3Directive,
    Au3DoUntilStatement,
    Au3ElseIf,
    Au3EnumDeclaration,
    Au3EnumDeclarator,
    Au3ErrorNode,
    Au3ExitLoopStatement,
    Au3ExitStatement,
    Au3ExpressionStatement,
    Au3FloatLiteral,
    Au3ForInStatement,
    Au3ForStatement,
    Au3FunctionDeclaration,
    Au3Identifier,
    Au3IfStatement,
    Au3Include,
    Au3IncludeOnce,
    Au3IntLiteral,
    Au3Macro,
    Au3MemberAccess,
    Au3NullLiteral,
    Au3Parameter,
    Au3ParenExpression,
    Au3ReDimStatement,
    Au3ReDimTarget,
    Au3ReturnStatement,
    Au3Script,
    Au3SelectCase,
    Au3SelectStatement,
    Au3StringLiteral,
    Au3SwitchCase,
    Au3SwitchStatement,
    Au3Ternary,
    Au3UnaryExpression,
    Au3Variable,
    Au3VariableDeclaration,
    Au3VariableDeclarator,
    Au3WhileStatement,
    Au3WithMember,
    Au3WithStatement,
)
from refinery.lib.scripts.au3.precedence import needs_parens, statement_needs_parens
from refinery.lib.scripts.au3.token import KEYWORD_SPELLINGS, Au3TokenKind

_SPELL = KEYWORD_SPELLINGS
_K = Au3TokenKind
_RequiredChild = TypeVar('_RequiredChild', bound=Node)

#: The room an atom written on a line leaves behind itself: the longest separator that may
#: follow it and the continuation marker that would end the line there.
_BREAK_RESERVE = len(' _') + len(' Step ')


class Au3Synthesizer(Synthesizer):
    """
    Synthesizes AutoIt3 source; see the module docstring for the output contract.
    """

    def __init__(self, indent: str = '    ', line_length: int = MAX_LINESIZE):
        super().__init__(indent, line_length)
        self._break_pending = False

    def convert(self, node: Node) -> str:
        self._break_pending = False
        return super().convert(node)

    def _write_separator(self, text: str):
        """
        Write a token a continuation may legally follow — a separator between operands, an
        opening bracket, the keyword that leads an expression — so the atom written next may
        break the line in front of itself where it would not fit behind one.
        """
        self._write(text)
        self._break_pending = True

    def _write_atom(self, text: str):
        """
        Write one token, breaking the line in front of it where it would not fit: the break
        ends the line at the current column with the continuation marker, so an atom that
        cannot fit with that room behind it starts the next line at column zero. A continued
        line carries no indent, so the atom keeps the whole line to itself.
        """
        if (
            self._break_pending
            and self._col + len(text) + _BREAK_RESERVE > self._line_length
        ):
            self._write(' _')
            self._write('\n')
        self._break_pending = False
        self._write(text)

    def _newline(self):
        self._break_pending = False
        if self._parts.tell() == 0:
            return
        super()._newline()

    def _emit_leading_comments(self, node: Node):
        for comment in node.leading_comments:
            self._newline()
            self._write(comment)

    def _emit_trailing_comments(self, node: Node):
        for comment in node.trailing_comments:
            self._write(F' {comment}')

    def _emit_statement(self, stmt: Statement):
        self._emit_leading_comments(stmt)
        self._newline()
        self.visit(stmt)
        self._emit_trailing_comments(stmt)

    def _emit_statements(self, body: list[Statement]):
        self._depth += 1
        for stmt in body:
            self._emit_statement(stmt)
        self._depth -= 1

    def _emit_child(self, child: Node | None, parent: Node):
        if child is None:
            return
        if needs_parens(child, parent):
            self._write_separator('(')
            self.visit(child)
            self._write(')')
        else:
            self.visit(child)

    def _required(self, child: _RequiredChild | None, parent: Node) -> _RequiredChild:
        """
        A child the grammar requires although the model types it as optional. A tree that reaches
        this method without one is a shape no text spells, and printing an approximation of it is
        the corruption the `UnspellableNode` refusal exists to prevent.
        """
        if child is None:
            raise UnspellableNode(parent)
        return child

    def _emit_binary(self, node: Au3BinaryExpression):
        """
        The left spine is emitted by a loop, not recursion: a concatenation chain hundreds of
        pieces deep is a shape obfuscated scripts spell and the renders install, and one
        recursion frame per level would exhaust the interpreter stack before the chain was
        printed. The walk stops at any left child that needs brackets, which `_emit_child`
        then prints with them.
        """
        spine: list[Au3BinaryExpression] = [node]
        current: Node | None = node.left
        while (
            isinstance(current, Au3BinaryExpression)
            and not needs_parens(current, spine[-1])
        ):
            spine.append(current)
            current = current.left
        self._emit_child(current, spine[-1])
        for parent in reversed(spine):
            self._write_separator(F' {parent.operator} ')
            self._emit_child(parent.right, parent)

    visit_Au3BinaryExpression = _emit_binary

    def visit_Au3Script(self, node: Au3Script):
        for stmt in node.body:
            self._emit_statement(stmt)
        for comment in node.trailing_comments:
            self._newline()
            self._write(comment)
        if self._parts.tell():
            self._write('\n')

    def visit_Au3ErrorNode(self, node: Au3ErrorNode):
        self._write(node.text)

    def visit_Au3Directive(self, node: Au3Directive):
        self._write(node.text)

    def visit_Au3Include(self, node: Au3Include):
        if node.library:
            self._write(F'#include <{node.path}>')
        else:
            self._write(F'#include "{node.path}"')

    def visit_Au3IncludeOnce(self, node: Au3IncludeOnce):
        self._write('#include-once')

    def visit_Au3IntLiteral(self, node: Au3IntLiteral):
        self._write_atom(node.raw)

    def visit_Au3FloatLiteral(self, node: Au3FloatLiteral):
        self._write_atom(node.raw)

    def visit_Au3StringLiteral(self, node: Au3StringLiteral):
        self._write_atom(node.raw or encode_au3_string(node.value))

    def visit_Au3BooleanLiteral(self, node: Au3BooleanLiteral):
        self._write_atom(_SPELL[_K.TRUE if node.value else _K.FALSE])

    def visit_Au3NullLiteral(self, node: Au3NullLiteral):
        self._write_atom(_SPELL[_K.NULL])

    def visit_Au3DefaultLiteral(self, node: Au3DefaultLiteral):
        self._write_atom(_SPELL[_K.DEFAULT])

    def visit_Au3Variable(self, node: Au3Variable):
        self._write_atom(node.raw)

    def visit_Au3Macro(self, node: Au3Macro):
        self._write_atom(node.raw)

    def visit_Au3Identifier(self, node: Au3Identifier):
        self._write_atom(node.raw)

    def visit_Au3UnaryExpression(self, node: Au3UnaryExpression):
        if node.operator == 'not':
            self._write_separator(F'{_SPELL[_K.NOT]} ')
        else:
            self._write_separator(node.operator)
        self._emit_child(node.operand, node)

    def visit_Au3Assignment(self, node: Au3Assignment):
        self._emit_child(node.target, node)
        self._write_separator(F' {node.operator} ')
        self._emit_child(node.value, node)

    def visit_Au3Ternary(self, node: Au3Ternary):
        self._emit_child(node.condition, node)
        self._write_separator(' ? ')
        self._emit_child(node.consequent, node)
        self._write_separator(' : ')
        self._emit_child(node.alternate, node)

    def visit_Au3ParenExpression(self, node: Au3ParenExpression):
        self._write_separator('(')
        self._emit_child(node.expression, node)
        self._write(')')

    def visit_Au3Call(self, node: Au3Call):
        self._emit_child(node.callee, node)
        self._write_separator('(')
        for i, argument in enumerate(node.arguments):
            if i > 0:
                self._write_separator(', ')
            self.visit(argument)
        self._write(')')

    def visit_Au3ArrayAccess(self, node: Au3ArrayAccess):
        self._emit_child(node.array, node)
        self._write_separator('[')
        if node.index is not None:
            self.visit(node.index)
        self._write(']')

    def visit_Au3MemberAccess(self, node: Au3MemberAccess):
        self._emit_child(node.object, node)
        self._write(F'.{node.raw or node.member}')

    def visit_Au3WithMember(self, node: Au3WithMember):
        self._write(F'.{node.raw or node.member}')

    def visit_Au3ArrayLiteral(self, node: Au3ArrayLiteral):
        self._write_separator('[')
        for i, element in enumerate(node.elements):
            if i > 0:
                self._write_separator(', ')
            self.visit(element)
        self._write(']')

    def visit_Au3ExpressionStatement(self, node: Au3ExpressionStatement):
        if node.expression is not None:
            if statement_needs_parens(node.expression):
                self._write_separator('(')
                self.visit(node.expression)
                self._write(')')
            else:
                self.visit(node.expression)

    def visit_Au3IfStatement(self, node: Au3IfStatement):
        self._write_separator(F'{_SPELL[_K.IF]} ')
        self._emit_child(node.test, node)
        self._write(F' {_SPELL[_K.THEN]}')
        self._emit_statements(node.body)
        for elseif in node.elseifs:
            self._visit_elseif(elseif)
        if node.else_body is not None:
            self._newline()
            self._write(_SPELL[_K.ELSE])
            self._emit_statements(node.else_body)
        self._newline()
        self._write(_SPELL[_K.ENDIF])

    def _visit_elseif(self, node: Au3ElseIf):
        self._newline()
        self._write_separator(F'{_SPELL[_K.ELSEIF]} ')
        self._emit_child(node.test, node)
        self._write(F' {_SPELL[_K.THEN]}')
        self._emit_statements(node.body)
        self._emit_trailing_comments(node)

    def visit_Au3WhileStatement(self, node: Au3WhileStatement):
        self._write_separator(F'{_SPELL[_K.WHILE]} ')
        self._emit_child(node.test, node)
        self._emit_statements(node.body)
        self._newline()
        self._write(_SPELL[_K.WEND])

    def visit_Au3DoUntilStatement(self, node: Au3DoUntilStatement):
        self._write(_SPELL[_K.DO])
        self._emit_statements(node.body)
        self._newline()
        self._write_separator(F'{_SPELL[_K.UNTIL]} ')
        self._emit_child(node.test, node)

    def visit_Au3ForStatement(self, node: Au3ForStatement):
        self._write_separator(F'{_SPELL[_K.FOR]} ')
        self.visit(self._required(node.variable, node))
        self._write_separator(' = ')
        self._emit_child(node.start, node)
        self._write_separator(F' {_SPELL[_K.TO]} ')
        self._emit_child(node.limit, node)
        if node.step is not None:
            self._write_separator(F' {_SPELL[_K.STEP]} ')
            self._emit_child(node.step, node)
        self._emit_statements(node.body)
        self._newline()
        self._write(_SPELL[_K.NEXT])

    def visit_Au3ForInStatement(self, node: Au3ForInStatement):
        self._write_separator(F'{_SPELL[_K.FOR]} ')
        self.visit(self._required(node.variable, node))
        self._write_separator(F' {_SPELL[_K.IN]} ')
        self._emit_child(node.iterable, node)
        self._emit_statements(node.body)
        self._newline()
        self._write(_SPELL[_K.NEXT])

    def visit_Au3SelectStatement(self, node: Au3SelectStatement):
        self._write(_SPELL[_K.SELECT])
        for case in node.cases:
            self._visit_select_case(case)
        self._newline()
        self._write(_SPELL[_K.ENDSELECT])

    def _visit_select_case(self, node: Au3SelectCase):
        self._emit_leading_comments(node)
        self._newline()
        if node.test is None:
            self._write(F'{_SPELL[_K.CASE]} {_SPELL[_K.ELSE]}')
        else:
            self._write_separator(F'{_SPELL[_K.CASE]} ')
            self._emit_child(node.test, node)
        self._emit_statements(node.body)
        self._emit_trailing_comments(node)

    def visit_Au3SwitchStatement(self, node: Au3SwitchStatement):
        self._write_separator(F'{_SPELL[_K.SWITCH]} ')
        self._emit_child(node.discriminant, node)
        for case in node.cases:
            self._visit_switch_case(case)
        self._newline()
        self._write(_SPELL[_K.ENDSWITCH])

    def _visit_switch_case(self, node: Au3SwitchCase):
        self._emit_leading_comments(node)
        self._newline()
        if node.values is None:
            self._write(F'{_SPELL[_K.CASE]} {_SPELL[_K.ELSE]}')
            self._emit_statements(node.body)
            self._emit_trailing_comments(node)
            return
        self._write_separator(F'{_SPELL[_K.CASE]} ')
        for i, value in enumerate(node.values):
            if i > 0:
                self._write_separator(', ')
            self._visit_switch_value(value)
        self._emit_statements(node.body)
        self._emit_trailing_comments(node)

    def _visit_switch_value(self, node: Node):
        if isinstance(node, Au3CaseRange):
            self._emit_child(node.start, node)
            self._write_separator(F' {_SPELL[_K.TO]} ')
            self._emit_child(node.end, node)
        else:
            self.visit(node)

    def visit_Au3WithStatement(self, node: Au3WithStatement):
        self._write_separator(F'{_SPELL[_K.WITH]} ')
        self._emit_child(node.object, node)
        self._emit_statements(node.body)
        self._newline()
        self._write(_SPELL[_K.ENDWITH])

    def visit_Au3VariableDeclaration(self, node: Au3VariableDeclaration):
        if node.scope is not None:
            self._write_separator(F'{node.scope.value} ')
        if node.is_const:
            self._write_separator(F'{_SPELL[_K.CONST]} ')
        if node.is_static:
            self._write_separator(F'{_SPELL[_K.STATIC]} ')
        for i, declarator in enumerate(node.declarations):
            if i > 0:
                self._write_separator(', ')
            self.visit(declarator)

    def visit_Au3VariableDeclarator(self, node: Au3VariableDeclarator):
        self.visit(self._required(node.variable, node))
        for dimension in node.dimensions:
            self._write_separator('[')
            if dimension is not None:
                self.visit(dimension)
            self._write(']')
        if node.initializer is not None:
            self._write_separator(' = ')
            self._emit_child(node.initializer, node)

    def visit_Au3EnumDeclaration(self, node: Au3EnumDeclaration):
        if node.scope is not None:
            self._write_separator(F'{node.scope.value} ')
        if node.is_const:
            self._write_separator(F'{_SPELL[_K.CONST]} ')
        self._write(_SPELL[_K.ENUM])
        if (node.step_operator, node.step_value) != ('+', 1):
            self._write(F' {_SPELL[_K.STEP]} {node.step_operator}{node.step_value}')
        self._write_separator(' ')
        for i, declarator in enumerate(node.declarations):
            if i > 0:
                self._write_separator(', ')
            self.visit(declarator)

    def visit_Au3EnumDeclarator(self, node: Au3EnumDeclarator):
        self.visit(self._required(node.variable, node))
        if node.initializer is not None:
            self._write_separator(' = ')
            self._emit_child(node.initializer, node)

    def visit_Au3ReDimStatement(self, node: Au3ReDimStatement):
        self._write(F'{_SPELL[_K.REDIM]} ')
        for i, target in enumerate(node.targets):
            if i > 0:
                self._write_separator(', ')
            self.visit(target)

    def visit_Au3ReDimTarget(self, node: Au3ReDimTarget):
        self.visit(self._required(node.variable, node))
        for dimension in node.dimensions:
            self._write_separator('[')
            self.visit(dimension)
            self._write(']')

    def visit_Au3FunctionDeclaration(self, node: Au3FunctionDeclaration):
        if node.is_volatile:
            self._write(F'{_SPELL[_K.VOLATILE]} ')
        name = self._required(node.name, node)
        self._write_separator(F'{_SPELL[_K.FUNC]} {name.raw}(')
        for i, param in enumerate(node.params):
            if i > 0:
                self._write_separator(', ')
            self.visit(param)
        self._write(')')
        self._emit_statements(node.body)
        self._newline()
        self._write(_SPELL[_K.ENDFUNC])

    def visit_Au3Parameter(self, node: Au3Parameter):
        if node.is_const:
            self._write(F'{_SPELL[_K.CONST]} ')
        if node.by_ref:
            self._write(F'{_SPELL[_K.BYREF]} ')
        self.visit(self._required(node.variable, node))
        if node.default is not None:
            self._write_separator(' = ')
            self._emit_child(node.default, node)

    def visit_Au3ReturnStatement(self, node: Au3ReturnStatement):
        self._write(_SPELL[_K.RETURN])
        if node.value is not None:
            self._write_separator(' ')
            self._emit_child(node.value, node)

    def visit_Au3ExitStatement(self, node: Au3ExitStatement):
        self._write(_SPELL[_K.EXIT])
        if node.code is not None:
            self._write_separator(' ')
            self._emit_child(node.code, node)

    def visit_Au3ExitLoopStatement(self, node: Au3ExitLoopStatement):
        self._write(_SPELL[_K.EXITLOOP])
        if node.level is not None:
            self._write_separator(' ')
            self._emit_child(node.level, node)

    def visit_Au3ContinueLoopStatement(self, node: Au3ContinueLoopStatement):
        self._write(_SPELL[_K.CONTINUELOOP])
        if node.level is not None:
            self._write_separator(' ')
            self._emit_child(node.level, node)

    def visit_Au3ContinueCaseStatement(self, node: Au3ContinueCaseStatement):
        self._write(_SPELL[_K.CONTINUECASE])
