from __future__ import annotations

from refinery.lib.scripts import Node, Visitor
from refinery.lib.scripts.vba.model import (
    Statement,
    VbaBangAccess,
    VbaBinaryExpression,
    VbaBooleanLiteral,
    VbaCallExpression,
    VbaCallStatement,
    VbaCaseClause,
    VbaConstDeclaration,
    VbaDateLiteral,
    VbaDebugPrintStatement,
    VbaDeclareStatement,
    VbaDoLoopStatement,
    VbaElseIfClause,
    VbaEmptyLiteral,
    VbaEndStatement,
    VbaEnumDefinition,
    VbaEnumMember,
    VbaEraseStatement,
    VbaErrorNode,
    VbaEventDeclaration,
    VbaExitStatement,
    VbaExpressionStatement,
    VbaFloatLiteral,
    VbaForEachStatement,
    VbaForStatement,
    VbaFunctionDeclaration,
    VbaGosubStatement,
    VbaGotoStatement,
    VbaIdentifier,
    VbaIfStatement,
    VbaImplementsStatement,
    VbaIndexExpression,
    VbaIntegerLiteral,
    VbaLabelStatement,
    VbaLetStatement,
    VbaMeExpression,
    VbaMemberAccess,
    VbaModule,
    VbaNewExpression,
    VbaNothingLiteral,
    VbaNullLiteral,
    VbaOnErrorStatement,
    VbaOptionStatement,
    VbaParameter,
    VbaParenExpression,
    VbaPropertyDeclaration,
    VbaRaiseEventStatement,
    VbaRedimStatement,
    VbaResumeStatement,
    VbaReturnStatement,
    VbaSelectCaseStatement,
    VbaSetStatement,
    VbaStopStatement,
    VbaStringLiteral,
    VbaSubDeclaration,
    VbaTypeDefinition,
    VbaTypeOfIsExpression,
    VbaTypedIdentifier,
    VbaUnaryExpression,
    VbaVariableDeclaration,
    VbaVariableDeclarator,
    VbaWhileStatement,
    VbaWithStatement,
)


class VbaSynthesizer(Visitor):

    def __init__(self, indent: str = '  '):
        self._indent = indent
        self._depth = 0
        self._parts: list[str] = []

    def convert(self, node: Node) -> str:
        self._parts.clear()
        self._depth = 0
        self.visit(node)
        return ''.join(self._parts)

    def _write(self, text: str):
        self._parts.append(text)

    def _newline(self):
        self._parts.append('\n')
        self._parts.append(self._indent * self._depth)

    def _emit_body(self, body: list[Statement]):
        self._depth += 1
        for stmt in body:
            self._newline()
            self.visit(stmt)
        self._depth -= 1

    def _comma_separated(self, nodes: list):
        for i, node in enumerate(nodes):
            if i > 0:
                self._write(', ')
            if node is None:
                continue
            self.visit(node)

    def _emit_params(self, params: list[VbaParameter]):
        self._write('(')
        for i, p in enumerate(params):
            if i > 0:
                self._write(', ')
            self.visit(p)
        self._write(')')

    def generic_visit(self, node: Node):
        self._write(F'<{type(node).__name__}>')

    def visit_VbaIntegerLiteral(self, node: VbaIntegerLiteral):
        self._write(node.raw)

    def visit_VbaFloatLiteral(self, node: VbaFloatLiteral):
        self._write(node.raw)

    def visit_VbaStringLiteral(self, node: VbaStringLiteral):
        self._write(node.raw)

    def visit_VbaDateLiteral(self, node: VbaDateLiteral):
        self._write(node.raw)

    def visit_VbaBooleanLiteral(self, node: VbaBooleanLiteral):
        self._write('True' if node.value else 'False')

    def visit_VbaNothingLiteral(self, node: VbaNothingLiteral):
        self._write('Nothing')

    def visit_VbaNullLiteral(self, node: VbaNullLiteral):
        self._write('Null')

    def visit_VbaEmptyLiteral(self, node: VbaEmptyLiteral):
        self._write('Empty')

    def visit_VbaMeExpression(self, node: VbaMeExpression):
        self._write('Me')

    def visit_VbaIdentifier(self, node: VbaIdentifier):
        self._write(node.name)

    def visit_VbaTypedIdentifier(self, node: VbaTypedIdentifier):
        self._write(F'{node.name}{node.suffix}')

    def visit_VbaErrorNode(self, node: VbaErrorNode):
        self._write(node.text)

    def visit_VbaBinaryExpression(self, node: VbaBinaryExpression):
        if node.left:
            self.visit(node.left)
        self._write(F' {node.operator} ')
        if node.right:
            self.visit(node.right)

    def visit_VbaUnaryExpression(self, node: VbaUnaryExpression):
        op = node.operator
        self._write(op)
        if op.isalpha():
            self._write(' ')
        if node.operand:
            self.visit(node.operand)

    def visit_VbaCallExpression(self, node: VbaCallExpression):
        if node.callee:
            self.visit(node.callee)
        self._write('(')
        self._comma_separated(node.arguments)
        self._write(')')

    def visit_VbaMemberAccess(self, node: VbaMemberAccess):
        if node.object:
            self.visit(node.object)
        self._write(F'.{node.member}')

    def visit_VbaBangAccess(self, node: VbaBangAccess):
        if node.object:
            self.visit(node.object)
        self._write(F'!{node.member}')

    def visit_VbaIndexExpression(self, node: VbaIndexExpression):
        if node.object:
            self.visit(node.object)
        self._write('(')
        self._comma_separated(node.arguments)
        self._write(')')

    def visit_VbaNewExpression(self, node: VbaNewExpression):
        self._write('New ')
        if node.class_name:
            self.visit(node.class_name)

    def visit_VbaTypeOfIsExpression(self, node: VbaTypeOfIsExpression):
        self._write('TypeOf ')
        if node.operand:
            self.visit(node.operand)
        self._write(' Is ')
        if node.type_name:
            self.visit(node.type_name)

    def visit_VbaParenExpression(self, node: VbaParenExpression):
        self._write('(')
        if node.expression:
            self.visit(node.expression)
        self._write(')')

    def visit_VbaModule(self, node: VbaModule):
        for i, stmt in enumerate(node.body):
            if i > 0:
                self._newline()
            self.visit(stmt)

    def visit_VbaOptionStatement(self, node: VbaOptionStatement):
        self._write(F'Option {node.keyword}')
        if node.value:
            self._write(F' {node.value}')

    def visit_VbaDeclareStatement(self, node: VbaDeclareStatement):
        if node.scope:
            self._write(F'{node.scope} ')
        kind = 'Function' if node.is_function else 'Sub'
        self._write(F'Declare {kind} {node.name}')
        if node.lib:
            self._write(F' Lib {node.lib}')
        if node.alias:
            self._write(F' Alias {node.alias}')
        self._emit_params(node.params)
        if node.return_type:
            self._write(F' As {node.return_type}')

    def visit_VbaTypeDefinition(self, node: VbaTypeDefinition):
        if node.scope:
            self._write(F'{node.scope} ')
        self._write(F'Type {node.name}')
        self._depth += 1
        for m in node.members:
            self._newline()
            self._write(m.name)
            if m.bounds:
                self._write('(')
                self._comma_separated(m.bounds)
                self._write(')')
            if m.type_name:
                self._write(F' As {m.type_name}')
        self._depth -= 1
        self._newline()
        self._write('End Type')

    def visit_VbaEnumDefinition(self, node: VbaEnumDefinition):
        if node.scope:
            self._write(F'{node.scope} ')
        self._write(F'Enum {node.name}')
        self._depth += 1
        for m in node.members:
            self._newline()
            self.visit(m)
        self._depth -= 1
        self._newline()
        self._write('End Enum')

    def visit_VbaEnumMember(self, node: VbaEnumMember):
        self._write(node.name)
        if node.value is not None:
            self._write(' = ')
            self.visit(node.value)

    def visit_VbaConstDeclaration(self, node: VbaConstDeclaration):
        if node.scope:
            self._write(F'{node.scope} ')
        self._write(F'Const {node.name}')
        if node.type_name:
            self._write(F' As {node.type_name}')
        self._write(' = ')
        if node.value:
            self.visit(node.value)

    def visit_VbaVariableDeclaration(self, node: VbaVariableDeclaration):
        self._write(F'{node.scope} ')
        for i, d in enumerate(node.declarators):
            if i > 0:
                self._write(', ')
            self.visit(d)

    def visit_VbaVariableDeclarator(self, node: VbaVariableDeclarator):
        self._write(node.name)
        if node.is_array or node.bounds:
            self._write('(')
            self._comma_separated(node.bounds)
            self._write(')')
        if node.type_name:
            if node.is_new:
                self._write(F' As New {node.type_name}')
            else:
                self._write(F' As {node.type_name}')

    def visit_VbaEventDeclaration(self, node: VbaEventDeclaration):
        if node.scope:
            self._write(F'{node.scope} ')
        self._write(F'Event {node.name}')
        self._emit_params(node.params)

    def visit_VbaParameter(self, node: VbaParameter):
        if node.is_optional:
            self._write('Optional ')
        if node.passing:
            self._write(F'{node.passing} ')
        if node.is_paramarray:
            self._write('ParamArray ')
        self._write(node.name)
        if node.is_array:
            self._write('()')
        if node.type_name:
            self._write(F' As {node.type_name}')
        if node.default is not None:
            self._write(' = ')
            self.visit(node.default)

    def visit_VbaSubDeclaration(self, node: VbaSubDeclaration):
        if node.scope:
            self._write(F'{node.scope} ')
        if node.is_static:
            self._write('Static ')
        self._write(F'Sub {node.name}')
        self._emit_params(node.params)
        self._emit_body(node.body)
        self._newline()
        self._write('End Sub')

    def visit_VbaFunctionDeclaration(self, node: VbaFunctionDeclaration):
        if node.scope:
            self._write(F'{node.scope} ')
        if node.is_static:
            self._write('Static ')
        self._write(F'Function {node.name}')
        self._emit_params(node.params)
        if node.return_type:
            self._write(F' As {node.return_type}')
        self._emit_body(node.body)
        self._newline()
        self._write('End Function')

    def visit_VbaPropertyDeclaration(self, node: VbaPropertyDeclaration):
        if node.scope:
            self._write(F'{node.scope} ')
        if node.is_static:
            self._write('Static ')
        self._write(F'Property {node.kind} {node.name}')
        self._emit_params(node.params)
        if node.return_type:
            self._write(F' As {node.return_type}')
        self._emit_body(node.body)
        self._newline()
        self._write('End Property')

    def visit_VbaExpressionStatement(self, node: VbaExpressionStatement):
        if node.expression:
            self.visit(node.expression)
        if node.arguments:
            self._write(' ')
            self._comma_separated(node.arguments)

    def visit_VbaCallStatement(self, node: VbaCallStatement):
        self._write('Call ')
        if node.callee:
            self.visit(node.callee)
        if node.arguments:
            self._write('(')
            self._comma_separated(node.arguments)
            self._write(')')

    def visit_VbaLetStatement(self, node: VbaLetStatement):
        if node.explicit:
            self._write('Let ')
        if node.target:
            self.visit(node.target)
        self._write(' = ')
        if node.value:
            self.visit(node.value)

    def visit_VbaSetStatement(self, node: VbaSetStatement):
        self._write('Set ')
        if node.target:
            self.visit(node.target)
        self._write(' = ')
        if node.value:
            self.visit(node.value)

    def visit_VbaIfStatement(self, node: VbaIfStatement):
        if node.single_line:
            self._write('If ')
            if node.condition:
                self.visit(node.condition)
            self._write(' Then ')
            for i, stmt in enumerate(node.body):
                if i > 0:
                    self._write(': ')
                self.visit(stmt)
            if node.else_body:
                self._write(' Else ')
                for i, stmt in enumerate(node.else_body):
                    if i > 0:
                        self._write(': ')
                    self.visit(stmt)
            return
        self._write('If ')
        if node.condition:
            self.visit(node.condition)
        self._write(' Then')
        self._emit_body(node.body)
        for clause in node.elseif_clauses:
            self._newline()
            self.visit(clause)
        if node.else_body:
            self._newline()
            self._write('Else')
            self._emit_body(node.else_body)
        self._newline()
        self._write('End If')

    def visit_VbaElseIfClause(self, node: VbaElseIfClause):
        self._write('ElseIf ')
        if node.condition:
            self.visit(node.condition)
        self._write(' Then')
        self._emit_body(node.body)

    def visit_VbaForStatement(self, node: VbaForStatement):
        self._write('For ')
        if node.variable:
            self.visit(node.variable)
        self._write(' = ')
        if node.start:
            self.visit(node.start)
        self._write(' To ')
        if node.end:
            self.visit(node.end)
        if node.step:
            self._write(' Step ')
            self.visit(node.step)
        self._emit_body(node.body)
        self._newline()
        self._write('Next')

    def visit_VbaForEachStatement(self, node: VbaForEachStatement):
        self._write('For Each ')
        if node.variable:
            self.visit(node.variable)
        self._write(' In ')
        if node.collection:
            self.visit(node.collection)
        self._emit_body(node.body)
        self._newline()
        self._write('Next')

    def visit_VbaDoLoopStatement(self, node: VbaDoLoopStatement):
        self._write('Do')
        if node.condition_position == 'pre' and node.condition:
            self._write(F' {node.condition_type} ')
            self.visit(node.condition)
        self._emit_body(node.body)
        self._newline()
        self._write('Loop')
        if node.condition_position == 'post' and node.condition:
            self._write(F' {node.condition_type} ')
            self.visit(node.condition)

    def visit_VbaWhileStatement(self, node: VbaWhileStatement):
        self._write('While ')
        if node.condition:
            self.visit(node.condition)
        self._emit_body(node.body)
        self._newline()
        self._write('Wend')

    def visit_VbaSelectCaseStatement(self, node: VbaSelectCaseStatement):
        self._write('Select Case ')
        if node.expression:
            self.visit(node.expression)
        self._depth += 1
        for c in node.cases:
            self._newline()
            self.visit(c)
        self._depth -= 1
        self._newline()
        self._write('End Select')

    def visit_VbaCaseClause(self, node: VbaCaseClause):
        if node.is_else:
            self._write('Case Else')
        else:
            self._write('Case ')
            self._comma_separated(node.tests)
        self._emit_body(node.body)

    def visit_VbaWithStatement(self, node: VbaWithStatement):
        self._write('With ')
        if node.object:
            self.visit(node.object)
        self._emit_body(node.body)
        self._newline()
        self._write('End With')

    def visit_VbaGotoStatement(self, node: VbaGotoStatement):
        self._write(F'GoTo {node.label}')

    def visit_VbaGosubStatement(self, node: VbaGosubStatement):
        self._write(F'GoSub {node.label}')

    def visit_VbaOnErrorStatement(self, node: VbaOnErrorStatement):
        if node.action == 'ResumeNext':
            self._write('On Error Resume Next')
        elif node.action == 'GoTo':
            self._write(F'On Error GoTo {node.label}')
        else:
            self._write('On Error')

    def visit_VbaExitStatement(self, node: VbaExitStatement):
        self._write(F'Exit {node.kind}')

    def visit_VbaReturnStatement(self, node: VbaReturnStatement):
        self._write('Return')

    def visit_VbaRedimStatement(self, node: VbaRedimStatement):
        self._write('ReDim ')
        if node.preserve:
            self._write('Preserve ')
        for i, d in enumerate(node.declarators):
            if i > 0:
                self._write(', ')
            self.visit(d)

    def visit_VbaEraseStatement(self, node: VbaEraseStatement):
        self._write('Erase ')
        self._comma_separated(node.targets)

    def visit_VbaRaiseEventStatement(self, node: VbaRaiseEventStatement):
        self._write(F'RaiseEvent {node.name}')
        if node.arguments:
            self._write('(')
            self._comma_separated(node.arguments)
            self._write(')')

    def visit_VbaLabelStatement(self, node: VbaLabelStatement):
        self._write(F'{node.label}:')

    def visit_VbaStopStatement(self, node: VbaStopStatement):
        self._write('Stop')

    def visit_VbaEndStatement(self, node: VbaEndStatement):
        self._write('End')

    def visit_VbaDebugPrintStatement(self, node: VbaDebugPrintStatement):
        self._write('Debug.Print')
        if node.arguments:
            self._write(' ')
            for i, arg in enumerate(node.arguments):
                if i > 0:
                    self._write('; ')
                self.visit(arg)

    def visit_VbaResumeStatement(self, node: VbaResumeStatement):
        self._write('Resume')
        if node.label:
            self._write(F' {node.label}')

    def visit_VbaImplementsStatement(self, node: VbaImplementsStatement):
        self._write(F'Implements {node.name}')
