"""
AST-to-source synthesizer for PowerShell.
"""
from __future__ import annotations

from refinery.lib.scripts import Block, Node, Visitor
from refinery.lib.scripts.ps1.model import (
    Expression,
    Ps1AccessKind,
    Ps1ArrayExpression,
    Ps1ArrayLiteral,
    Ps1AssignmentExpression,
    Ps1Attribute,
    Ps1BinaryExpression,
    Ps1BreakStatement,
    Ps1CastExpression,
    Ps1CatchClause,
    Ps1CommandArgument,
    Ps1CommandArgumentKind,
    Ps1CommandInvocation,
    Ps1ContinueStatement,
    Ps1DataSection,
    Ps1DoUntilLoop,
    Ps1DoWhileLoop,
    Ps1ErrorNode,
    Ps1ExitStatement,
    Ps1ExpandableHereString,
    Ps1ExpandableString,
    Ps1ExpressionStatement,
    Ps1ForEachLoop,
    Ps1ForLoop,
    Ps1FunctionDefinition,
    Ps1HashLiteral,
    Ps1HereString,
    Ps1IfStatement,
    Ps1IndexExpression,
    Ps1IntegerLiteral,
    Ps1InvokeMember,
    Ps1MemberAccess,
    Ps1ParamBlock,
    Ps1ParameterDeclaration,
    Ps1ParenExpression,
    Ps1Pipeline,
    Ps1PipelineElement,
    Ps1RangeExpression,
    Ps1RealLiteral,
    Ps1Redirection,
    Ps1ReturnStatement,
    Ps1ScopeModifier,
    Ps1Script,
    Ps1ScriptBlock,
    Ps1StringLiteral,
    Ps1SubExpression,
    Ps1SwitchStatement,
    Ps1ThrowStatement,
    Ps1TrapStatement,
    Ps1TryCatchFinally,
    Ps1TypeExpression,
    Ps1UnaryExpression,
    Ps1Variable,
    Ps1WhileLoop,
)


class Ps1Synthesizer(Visitor):

    def __init__(self, indent: str = '    '):
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

    def _emit_block(self, block: Block):
        self._write('{')
        self._depth += 1
        for stmt in block.body:
            self._newline()
            self.visit(stmt)
        self._depth -= 1
        if block.body:
            self._newline()
        self._write('}')

    def _emit_statement_list(self, stmts: list):
        for i, stmt in enumerate(stmts):
            if i > 0:
                self._newline()
            self.visit(stmt)

    def generic_visit(self, node: Node):
        self._write(F'<{type(node).__name__}>')

    def visit_Ps1Variable(self, node: Ps1Variable):
        prefix = '@' if node.splatted else '$'
        scope_str = ''
        if node.scope != Ps1ScopeModifier.NONE:
            scope_str = F'{node.scope.value}:'
        name = F'{{{node.name}}}' if node.braced else node.name
        self._write(F'{prefix}{scope_str}{name}')

    def visit_Ps1IntegerLiteral(self, node: Ps1IntegerLiteral):
        self._write(node.raw)

    def visit_Ps1RealLiteral(self, node: Ps1RealLiteral):
        self._write(node.raw)

    def visit_Ps1StringLiteral(self, node: Ps1StringLiteral):
        self._write(node.raw)

    def visit_Ps1ExpandableString(self, node: Ps1ExpandableString):
        self._write(node.raw)

    def visit_Ps1HereString(self, node: Ps1HereString):
        self._write(node.raw)

    def visit_Ps1ExpandableHereString(self, node: Ps1ExpandableHereString):
        self._write(node.raw)

    def visit_Ps1BinaryExpression(self, node: Ps1BinaryExpression):
        if node.left:
            self.visit(node.left)
        self._write(F' {node.operator} ')
        if node.right:
            self.visit(node.right)

    def visit_Ps1UnaryExpression(self, node: Ps1UnaryExpression):
        if node.prefix:
            self._write(node.operator)
            if node.operator.startswith('-'):
                self._write(' ')
            if node.operand:
                self.visit(node.operand)
        else:
            if node.operand:
                self.visit(node.operand)
            self._write(node.operator)

    def visit_Ps1TypeExpression(self, node: Ps1TypeExpression):
        self._write(F'[{node.name}]')

    def visit_Ps1CastExpression(self, node: Ps1CastExpression):
        self._write(F'[{node.type_name}]')
        if node.operand:
            self.visit(node.operand)

    def visit_Ps1MemberAccess(self, node: Ps1MemberAccess):
        if node.object:
            self.visit(node.object)
        self._write(node.access.value)
        if isinstance(node.member, Expression):
            self.visit(node.member)
        else:
            self._write(str(node.member))

    def visit_Ps1IndexExpression(self, node: Ps1IndexExpression):
        if node.object:
            self.visit(node.object)
        self._write('[')
        if node.index:
            self.visit(node.index)
        self._write(']')

    def visit_Ps1InvokeMember(self, node: Ps1InvokeMember):
        if node.object:
            self.visit(node.object)
        self._write(node.access.value)
        if isinstance(node.member, Expression):
            self.visit(node.member)
        else:
            self._write(str(node.member))
        self._write('(')
        for i, arg in enumerate(node.arguments):
            if i > 0:
                self._write(', ')
            self.visit(arg)
        self._write(')')

    def visit_Ps1CommandInvocation(self, node: Ps1CommandInvocation):
        if node.invocation_operator:
            self._write(node.invocation_operator)
            self._write(' ')
        if node.name:
            self.visit(node.name)
        for arg in node.arguments:
            self._write(' ')
            self.visit(arg)

    def visit_Ps1CommandArgument(self, node: Ps1CommandArgument):
        if node.kind == Ps1CommandArgumentKind.SWITCH:
            self._write(node.name)
        elif node.kind == Ps1CommandArgumentKind.NAMED:
            self._write(F'{node.name}:')
            if node.value:
                self.visit(node.value)
        elif node.kind == Ps1CommandArgumentKind.POSITIONAL:
            if node.value:
                self.visit(node.value)

    def visit_Ps1CallExpression(self, node):
        if node.callee:
            self.visit(node.callee)
        self._write('(')
        for i, arg in enumerate(node.arguments):
            if i > 0:
                self._write(', ')
            self.visit(arg)
        self._write(')')

    def visit_Ps1AssignmentExpression(self, node: Ps1AssignmentExpression):
        if node.target:
            self.visit(node.target)
        self._write(F' {node.operator} ')
        if node.value:
            self.visit(node.value)

    def visit_Ps1ArrayLiteral(self, node: Ps1ArrayLiteral):
        for i, elem in enumerate(node.elements):
            if i > 0:
                self._write(', ')
            self.visit(elem)

    def visit_Ps1ArrayExpression(self, node: Ps1ArrayExpression):
        self._write('@(')
        self._emit_statement_list(node.body)
        self._write(')')

    def visit_Ps1HashLiteral(self, node: Ps1HashLiteral):
        self._write('@{')
        if node.pairs:
            self._depth += 1
            for key, value in node.pairs:
                self._newline()
                self.visit(key)
                self._write(' = ')
                self.visit(value)
            self._depth -= 1
            self._newline()
        self._write('}')

    def visit_Ps1SubExpression(self, node: Ps1SubExpression):
        self._write('$(')
        self._emit_statement_list(node.body)
        self._write(')')

    def visit_Ps1ParenExpression(self, node: Ps1ParenExpression):
        self._write('(')
        if node.expression:
            self.visit(node.expression)
        self._write(')')

    def visit_Ps1ScriptBlock(self, node: Ps1ScriptBlock):
        self._write('{')
        self._depth += 1
        if node.param_block:
            self._newline()
            self.visit(node.param_block)
        has_named = (
            node.begin_block or node.process_block
            or node.end_block or node.dynamicparam_block
        )
        if has_named:
            if node.begin_block:
                self._newline()
                self._write('begin ')
                self._emit_block(node.begin_block)
            if node.process_block:
                self._newline()
                self._write('process ')
                self._emit_block(node.process_block)
            if node.end_block:
                self._newline()
                self._write('end ')
                self._emit_block(node.end_block)
            if node.dynamicparam_block:
                self._newline()
                self._write('dynamicparam ')
                self._emit_block(node.dynamicparam_block)
        else:
            for stmt in node.body:
                self._newline()
                self.visit(stmt)
        self._depth -= 1
        if node.body or has_named or node.param_block:
            self._newline()
        self._write('}')

    def visit_Ps1RangeExpression(self, node: Ps1RangeExpression):
        if node.start:
            self.visit(node.start)
        self._write('..')
        if node.end:
            self.visit(node.end)

    def visit_Ps1Attribute(self, node: Ps1Attribute):
        self._write(F'[{node.name}')
        if node.positional_args or node.named_args:
            self._write('(')
            items: list[str] = []
            for arg in node.positional_args:
                old_parts = self._parts
                self._parts = []
                self.visit(arg)
                items.append(''.join(self._parts))
                self._parts = old_parts
            for key, val in node.named_args:
                old_parts = self._parts
                self._parts = []
                self.visit(val)
                v = ''.join(self._parts)
                self._parts = old_parts
                items.append(F'{key}={v}')
            self._write(', '.join(items))
            self._write(')')
        self._write(']')

    def visit_Ps1ParameterDeclaration(self, node: Ps1ParameterDeclaration):
        for attr in node.attributes:
            self.visit(attr)
        if node.variable:
            self.visit(node.variable)
        if node.default_value:
            self._write(' = ')
            self.visit(node.default_value)

    def visit_Ps1ParamBlock(self, node: Ps1ParamBlock):
        for attr in node.attributes:
            self.visit(attr)
            self._newline()
        self._write('param(')
        for i, param in enumerate(node.parameters):
            if i > 0:
                self._write(', ')
            self.visit(param)
        self._write(')')

    def visit_Ps1Redirection(self, node: Ps1Redirection):
        self._write(node.operator)
        self._write(' ')
        if node.target:
            self.visit(node.target)

    def visit_Ps1PipelineElement(self, node: Ps1PipelineElement):
        if node.expression:
            self.visit(node.expression)
        for redir in node.redirections:
            self._write(' ')
            self.visit(redir)

    def visit_Ps1Pipeline(self, node: Ps1Pipeline):
        for i, elem in enumerate(node.elements):
            if i > 0:
                self._write(' | ')
            self.visit(elem)

    def visit_Ps1ExpressionStatement(self, node: Ps1ExpressionStatement):
        if node.expression:
            self.visit(node.expression)

    def visit_Ps1IfStatement(self, node: Ps1IfStatement):
        for i, (cond, body) in enumerate(node.clauses):
            if i == 0:
                self._write('if (')
            else:
                self._write(' elseif (')
            if cond:
                self.visit(cond)
            self._write(') ')
            self._emit_block(body)
        if node.else_block:
            self._write(' else ')
            self._emit_block(node.else_block)

    def visit_Ps1WhileLoop(self, node: Ps1WhileLoop):
        self._write('while (')
        if node.condition:
            self.visit(node.condition)
        self._write(') ')
        if node.body:
            self._emit_block(node.body)

    def visit_Ps1DoWhileLoop(self, node: Ps1DoWhileLoop):
        self._write('do ')
        if node.body:
            self._emit_block(node.body)
        self._write(' while (')
        if node.condition:
            self.visit(node.condition)
        self._write(')')

    def visit_Ps1DoUntilLoop(self, node: Ps1DoUntilLoop):
        self._write('do ')
        if node.body:
            self._emit_block(node.body)
        self._write(' until (')
        if node.condition:
            self.visit(node.condition)
        self._write(')')

    def visit_Ps1ForLoop(self, node: Ps1ForLoop):
        self._write('for (')
        if node.initializer:
            self.visit(node.initializer)
        self._write('; ')
        if node.condition:
            self.visit(node.condition)
        self._write('; ')
        if node.iterator:
            self.visit(node.iterator)
        self._write(') ')
        if node.body:
            self._emit_block(node.body)

    def visit_Ps1ForEachLoop(self, node: Ps1ForEachLoop):
        self._write('foreach ')
        if node.parallel:
            self._write('-Parallel ')
        self._write('(')
        if node.variable:
            self.visit(node.variable)
        self._write(' in ')
        if node.iterable:
            self.visit(node.iterable)
        self._write(') ')
        if node.body:
            self._emit_block(node.body)

    def visit_Ps1SwitchStatement(self, node: Ps1SwitchStatement):
        self._write('switch ')
        if node.regex:
            self._write('-Regex ')
        if node.wildcard:
            self._write('-Wildcard ')
        if node.exact:
            self._write('-Exact ')
        if node.case_sensitive:
            self._write('-CaseSensitive ')
        if node.file:
            self._write('-File ')
        self._write('(')
        if node.value:
            self.visit(node.value)
        self._write(') {')
        self._depth += 1
        for cond, body in node.clauses:
            self._newline()
            if cond is None:
                self._write('default ')
            else:
                self.visit(cond)
                self._write(' ')
            self._emit_block(body)
        self._depth -= 1
        self._newline()
        self._write('}')

    def visit_Ps1TryCatchFinally(self, node: Ps1TryCatchFinally):
        self._write('try ')
        if node.try_block:
            self._emit_block(node.try_block)
        for clause in node.catch_clauses:
            self._write(' catch')
            if clause.types:
                self._write(' ')
                self._write(' '.join(F'[{t}]' for t in clause.types))
            self._write(' ')
            if clause.body:
                self._emit_block(clause.body)
        if node.finally_block:
            self._write(' finally ')
            self._emit_block(node.finally_block)

    def visit_Ps1CatchClause(self, node: Ps1CatchClause):
        pass

    def visit_Ps1TrapStatement(self, node: Ps1TrapStatement):
        self._write('trap ')
        if node.type_name:
            self._write(F'[{node.type_name}] ')
        if node.body:
            self._emit_block(node.body)

    def visit_Ps1FunctionDefinition(self, node: Ps1FunctionDefinition):
        kw = 'filter' if node.is_filter else 'function'
        self._write(F'{kw} {node.name} ')
        if node.body:
            self.visit(node.body)

    def visit_Ps1ReturnStatement(self, node: Ps1ReturnStatement):
        self._write('return')
        if node.pipeline:
            self._write(' ')
            self.visit(node.pipeline)

    def visit_Ps1ThrowStatement(self, node: Ps1ThrowStatement):
        self._write('throw')
        if node.pipeline:
            self._write(' ')
            self.visit(node.pipeline)

    def visit_Ps1BreakStatement(self, node: Ps1BreakStatement):
        self._write('break')
        if node.label:
            self._write(' ')
            self.visit(node.label)

    def visit_Ps1ContinueStatement(self, node: Ps1ContinueStatement):
        self._write('continue')
        if node.label:
            self._write(' ')
            self.visit(node.label)

    def visit_Ps1ExitStatement(self, node: Ps1ExitStatement):
        self._write('exit')
        if node.pipeline:
            self._write(' ')
            self.visit(node.pipeline)

    def visit_Ps1DataSection(self, node: Ps1DataSection):
        self._write('data ')
        if node.name:
            self._write(F'{node.name} ')
        if node.body:
            self._emit_block(node.body)

    def visit_Ps1ErrorNode(self, node: Ps1ErrorNode):
        self._write(node.text)

    def visit_Ps1Script(self, node: Ps1Script):
        if node.param_block:
            self.visit(node.param_block)
            self._newline()
        has_named = (
            node.begin_block or node.process_block
            or node.end_block or node.dynamicparam_block
        )
        if has_named:
            if node.begin_block:
                self._write('begin ')
                self._emit_block(node.begin_block)
                self._newline()
            if node.process_block:
                self._write('process ')
                self._emit_block(node.process_block)
                self._newline()
            if node.end_block:
                self._write('end ')
                self._emit_block(node.end_block)
                self._newline()
            if node.dynamicparam_block:
                self._write('dynamicparam ')
                self._emit_block(node.dynamicparam_block)
                self._newline()
        else:
            self._emit_statement_list(node.body)

    def visit_Block(self, node: Block):
        self._emit_block(node)
