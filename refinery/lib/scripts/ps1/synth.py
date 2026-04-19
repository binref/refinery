"""
AST-to-source synthesizer for PowerShell.
"""
from __future__ import annotations

import io

from refinery.lib.scripts import Block, Node, Synthesizer
from refinery.lib.scripts.ps1.model import (
    Expression,
    Ps1ArrayExpression,
    Ps1ArrayLiteral,
    Ps1AssignmentExpression,
    Ps1Attribute,
    Ps1BinaryExpression,
    Ps1BreakStatement,
    Ps1CastExpression,
    Ps1Code,
    Ps1CommandArgument,
    Ps1CommandArgumentKind,
    Ps1CommandInvocation,
    Ps1ContinueStatement,
    Ps1DataSection,
    Ps1DoLoop,
    Ps1ErrorNode,
    Ps1Exit,
    Ps1ExitStatement,
    Ps1ExpandableHereString,
    Ps1ExpandableString,
    Ps1ExpressionStatement,
    Ps1FileRedirection,
    Ps1ForEachLoop,
    Ps1ForLoop,
    Ps1FunctionDefinition,
    Ps1HashLiteral,
    Ps1HereString,
    Ps1IfStatement,
    Ps1IndexExpression,
    Ps1IntegerLiteral,
    Ps1InvokeMember,
    Ps1Jump,
    Ps1MemberAccess,
    Ps1MergingRedirection,
    Ps1ParamBlock,
    Ps1ParameterDeclaration,
    Ps1ParenExpression,
    Ps1Pipeline,
    Ps1PipelineElement,
    Ps1RangeExpression,
    Ps1RealLiteral,
    Ps1RedirectionStream,
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
from refinery.lib.scripts.ps1.token import KEYWORD_SPELLING


class Ps1Synthesizer(Synthesizer):

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
        self._write('"')
        for part in node.parts:
            if isinstance(part, Ps1StringLiteral):
                self._write(self._escape_for_dq(part.value))
            elif isinstance(part, Ps1Variable):
                self._emit_variable_in_dq(part)
            else:
                self.visit(part)
        self._write('"')

    def _emit_variable_in_dq(self, node: Ps1Variable):
        prefix = '@' if node.splatted else '$'
        scope_str = ''
        if node.scope != Ps1ScopeModifier.NONE:
            scope_str = F'{node.scope.value}:'
        self._write(F'{prefix}{{{scope_str}{node.name}}}')

    @staticmethod
    def _escape_for_dq(value: str) -> str:
        return value.replace('`', '``').replace('"', '""').replace('$', '`$')

    def visit_Ps1HereString(self, node: Ps1HereString):
        self._write(node.raw)

    def visit_Ps1ExpandableHereString(self, node: Ps1ExpandableHereString):
        self._write(node.raw)

    def visit_Ps1BinaryExpression(self, node: Ps1BinaryExpression):
        spine: list[tuple[str, Expression | None]] = []
        current: Expression | None = node
        while isinstance(current, Ps1BinaryExpression):
            spine.append((current.operator, current.right))
            current = current.left
        if current:
            self.visit(current)
        for operator, right in reversed(spine):
            self._write(F' {operator} ')
            if right:
                self.visit(right)

    def visit_Ps1UnaryExpression(self, node: Ps1UnaryExpression):
        if node.prefix:
            self._write(node.operator)
            if node.operator.startswith('-') and len(node.operator) > 1:
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

    def _emit_member_prefix(self, node: Ps1MemberAccess | Ps1InvokeMember):
        if node.object:
            self.visit(node.object)
        self._write(node.access.value)
        if isinstance(node.member, Expression):
            self.visit(node.member)
        else:
            self._write(str(node.member))

    def visit_Ps1MemberAccess(self, node: Ps1MemberAccess):
        self._emit_member_prefix(node)

    def visit_Ps1IndexExpression(self, node: Ps1IndexExpression):
        if node.object:
            self.visit(node.object)
        self._write('[')
        if node.index:
            self.visit(node.index)
        self._write(']')

    def visit_Ps1InvokeMember(self, node: Ps1InvokeMember):
        self._emit_member_prefix(node)
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
        for redir in node.redirections:
            self._write(' ')
            self.visit(redir)

    def visit_Ps1CommandArgument(self, node: Ps1CommandArgument):
        if node.kind == Ps1CommandArgumentKind.SWITCH:
            self._write(node.name)
        elif node.kind == Ps1CommandArgumentKind.NAMED:
            self._write(F'{node.name}:')
            if node.value:
                self._emit_argument_value(node.value)
        elif node.kind == Ps1CommandArgumentKind.POSITIONAL:
            if node.value:
                self._emit_argument_value(node.value)

    def _emit_argument_value(self, value: Expression):
        if isinstance(value, Ps1BinaryExpression):
            self._write('(')
            self.visit(value)
            self._write(')')
        else:
            self.visit(value)

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

    def _emit_script_body(self, node: Ps1Code, *, newline_after: bool):
        has_named = (
            node.begin_block or node.process_block
            or node.end_block or node.dynamicparam_block
        )
        if has_named:
            for keyword, block in (
                ('begin', node.begin_block),
                ('process', node.process_block),
                ('end', node.end_block),
                ('dynamicparam', node.dynamicparam_block),
            ):
                if block:
                    if not newline_after:
                        self._newline()
                    self._write(F'{keyword} ')
                    self._emit_block(block)
                    if newline_after:
                        self._newline()
        else:
            if newline_after:
                self._emit_statement_list(node.body)
            else:
                for stmt in node.body:
                    self._newline()
                    self.visit(stmt)

    def visit_Ps1ScriptBlock(self, node: Ps1ScriptBlock):
        self._write('{')
        self._depth += 1
        if node.param_block:
            self._newline()
            self.visit(node.param_block)
        self._emit_script_body(node, newline_after=False)
        self._depth -= 1
        has_content = (
            node.body or node.param_block
            or node.begin_block or node.process_block
            or node.end_block or node.dynamicparam_block
        )
        if has_content:
            self._newline()
        self._write('}')

    def visit_Ps1RangeExpression(self, node: Ps1RangeExpression):
        if node.start:
            self.visit(node.start)
        self._write('..')
        if node.end:
            self.visit(node.end)

    def _render_to_string(self, node: Node) -> str:
        saved = self._parts
        self._parts = io.StringIO()
        try:
            self.visit(node)
            return self._parts.getvalue()
        finally:
            self._parts = saved

    def visit_Ps1Attribute(self, node: Ps1Attribute):
        self._write(F'[{node.name}')
        if node.positional_args or node.named_args:
            self._write('(')
            items: list[str] = []
            for arg in node.positional_args:
                items.append(self._render_to_string(arg))
            for key, val in node.named_args:
                items.append(F'{key}={self._render_to_string(val)}')
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
        self._write(KEYWORD_SPELLING.get('param', 'param'))
        self._write('(')
        for i, param in enumerate(node.parameters):
            if i > 0:
                self._write(', ')
            self.visit(param)
        self._write(')')

    def _emit_redirection_stream(self, stream: Ps1RedirectionStream) -> str:
        if stream == Ps1RedirectionStream.OUTPUT:
            return ''
        if stream == Ps1RedirectionStream.ALL:
            return '*'
        return str(stream.value)

    def visit_Ps1FileRedirection(self, node: Ps1FileRedirection):
        prefix = self._emit_redirection_stream(node.stream)
        op = '>>' if node.append else '>'
        self._write(F'{prefix}{op}')
        if node.target:
            self._write(' ')
            self.visit(node.target)

    def visit_Ps1MergingRedirection(self, node: Ps1MergingRedirection):
        prefix = self._emit_redirection_stream(node.from_stream)
        self._write(F'{prefix}>&{node.to_stream.value}')

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
        if node.label:
            self._write(F'{node.label} ')
        self._write('while (')
        if node.condition:
            self.visit(node.condition)
        self._write(') ')
        if node.body:
            self._emit_block(node.body)

    def visit_Ps1DoLoop(self, node: Ps1DoLoop):
        if node.label:
            self._write(F'{node.label} ')
        self._write('do ')
        if node.body:
            self._emit_block(node.body)
        keyword = 'until' if node.is_until else 'while'
        self._write(F' {keyword} (')
        if node.condition:
            self.visit(node.condition)
        self._write(')')

    def visit_Ps1ForLoop(self, node: Ps1ForLoop):
        if node.label:
            self._write(F'{node.label} ')
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
        if node.label:
            self._write(F'{node.label} ')
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
        if node.label:
            self._write(F'{node.label} ')
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
            if node.value:
                self.visit(node.value)
            self._write(' {')
        else:
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

    def _visit_jump(self, node: Ps1Jump, name: str):
        self._write(name)
        if suffix := node.label:
            self._write(' ')
            self.visit(suffix)

    def _visit_exit(self, node: Ps1Exit, name: str):
        self._write(name)
        if suffix := node.pipeline:
            self._write(' ')
            self.visit(suffix)

    def visit_Ps1ReturnStatement(self, node: Ps1ReturnStatement):
        self._visit_exit(node, 'return')

    def visit_Ps1ExitStatement(self, node: Ps1ExitStatement):
        self._visit_exit(node, 'exit')

    def visit_Ps1ThrowStatement(self, node: Ps1ThrowStatement):
        self._visit_exit(node, 'throw')

    def visit_Ps1BreakStatement(self, node: Ps1BreakStatement):
        self._visit_jump(node, 'break')

    def visit_Ps1ContinueStatement(self, node: Ps1ContinueStatement):
        self._visit_jump(node, 'continue')

    def visit_Ps1DataSection(self, node: Ps1DataSection):
        self._write('data ')
        if node.name:
            self._write(F'{node.name} ')
        if node.commands:
            self._write('-SupportedCommand ')
            for i, cmd in enumerate(node.commands):
                if i > 0:
                    self._write(', ')
                self.visit(cmd)
            self._write(' ')
        if node.body:
            self._emit_block(node.body)

    def visit_Ps1ErrorNode(self, node: Ps1ErrorNode):
        self._write(node.text)

    def visit_Ps1Script(self, node: Ps1Script):
        if node.param_block:
            self.visit(node.param_block)
            self._newline()
        self._emit_script_body(node, newline_after=True)

    def visit_Block(self, node: Block):
        self._emit_block(node)
