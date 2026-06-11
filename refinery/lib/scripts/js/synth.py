from __future__ import annotations

from refinery.lib.scripts import Node, Synthesizer
from refinery.lib.scripts.js.deobfuscation.helpers import escape_js_string
from refinery.lib.scripts.js.model import (
    JsArrowFunctionExpression,
    JsAssignmentPattern,
    JsAwaitExpression,
    JsBigIntLiteral,
    JsBlockStatement,
    JsBooleanLiteral,
    JsBreakStatement,
    JsCallExpression,
    JsCatchClause,
    JsClassBody,
    JsClassDeclaration,
    JsClassExpression,
    JsConditionalExpression,
    JsContinueStatement,
    JsDebuggerStatement,
    JsDoWhileStatement,
    JsEmptyStatement,
    JsErrorNode,
    JsExportAllDeclaration,
    JsExportDefaultDeclaration,
    JsExportNamedDeclaration,
    JsExportSpecifier,
    JsExpressionStatement,
    JsForInStatement,
    JsForOfStatement,
    JsForStatement,
    JsFunctionDeclaration,
    JsFunctionExpression,
    JsIdentifier,
    JsIfStatement,
    JsImportDeclaration,
    JsImportDefaultSpecifier,
    JsImportNamespaceSpecifier,
    JsImportSpecifier,
    JsLabeledStatement,
    JsMemberExpression,
    JsMethodDefinition,
    JsMethodKind,
    JsNewExpression,
    JsNullLiteral,
    JsNumericLiteral,
    JsObjectExpression,
    JsObjectPattern,
    JsParenthesizedExpression,
    JsProperty,
    JsPropertyDefinition,
    JsPropertyKind,
    JsRegExpLiteral,
    JsReturnStatement,
    JsScript,
    JsSequenceExpression,
    JsStringLiteral,
    JsSwitchCase,
    JsSwitchStatement,
    JsTaggedTemplateExpression,
    JsTemplateElement,
    JsTemplateLiteral,
    JsThisExpression,
    JsThrowStatement,
    JsTryStatement,
    JsUnaryExpression,
    JsUpdateExpression,
    JsVariableDeclaration,
    JsVariableDeclarator,
    JsWhileStatement,
    JsWithStatement,
    JsYieldExpression,
    Statement,
)
from refinery.lib.scripts.js.precedence import needs_parens, statement_needs_parens

_WORD_UNARY_OPS = frozenset({'typeof', 'void', 'delete'})


class JsSynthesizer(Synthesizer):

    def __init__(
        self,
        indent: str = '  ',
        line_length: int = 140,
        unescape_strings: bool = False,
        strip_comments: bool = False,
    ):
        super().__init__(indent, line_length)
        self._unescape_strings = unescape_strings
        self._strip_comments = strip_comments

    def _emit_leading_comments(self, node: Node):
        if self._strip_comments or not node.leading_comments:
            return
        for comment in node.leading_comments:
            self._write(comment)
            self._newline()

    def _emit_block(self, body: list[Statement]):
        self._write('{')
        self._depth += 1
        for stmt in body:
            self._newline()
            self._emit_leading_comments(stmt)
            self.visit(stmt)
        self._depth -= 1
        if body:
            self._newline()
        self._write('}')

    def _emit_child(self, child: Node | None, parent: Node):
        """
        Emit *child* in the context of *parent*, wrapping it in parentheses when operator precedence
        requires it. This makes the printed output correct regardless of whether the tree carries
        an explicit `JsParenthesizedExpression` node in that position.
        """
        if child is None:
            return
        if needs_parens(child, parent):
            self._write('(')
            self.visit(child)
            self._write(')')
        else:
            self.visit(child)

    def _emit_element(self, node, wrap_sequences: bool):
        if node is None:
            return
        if wrap_sequences and isinstance(node, JsSequenceExpression):
            self._write('(')
            self.visit(node)
            self._write(')')
        else:
            self.visit(node)

    def _comma_separated(
        self,
        nodes: list,
        lead_newline: bool = True,
        wrap_sequences: bool = False,
    ) -> bool:
        if not nodes:
            return False
        save_pos = self._parts.tell()
        save_col = self._col
        overflow = False
        for i, node in enumerate(nodes):
            if i > 0:
                self._write(', ')
            self._emit_element(node, wrap_sequences)
            if self._col > self._line_length:
                overflow = True
                break
        if not overflow:
            return False
        self._parts.seek(save_pos)
        self._parts.truncate()
        self._col = save_col
        self._depth += 1
        for i, node in enumerate(nodes):
            if i > 0 or lead_newline:
                self._newline()
            self._emit_element(node, wrap_sequences)
            if i < len(nodes) - 1:
                self._write(',')
        self._depth -= 1
        return True

    def _emit_params(self, params: list):
        self._write('(')
        if self._comma_separated(params):
            self._newline()
        self._write(')')

    def _emit_function_prefix(self, is_async: bool, generator: bool):
        if is_async:
            self._write('async ')
        self._write('function')
        if generator:
            self._write('*')

    def _emit_key(self, key: Node | None, computed: bool):
        if computed:
            self._write('[')
            if key:
                self.visit(key)
            self._write(']')
        elif key:
            self.visit(key)

    def visit_JsNumericLiteral(self, node: JsNumericLiteral):
        self._write(node.raw)

    def visit_JsBigIntLiteral(self, node: JsBigIntLiteral):
        self._write(node.raw)

    def visit_JsStringLiteral(self, node: JsStringLiteral):
        if self._unescape_strings:
            self._write(self._encode_string(node.value, node.raw))
        else:
            self._write(node.raw)

    @staticmethod
    def _encode_string(value: str, raw: str) -> str:
        quote = raw[0] if raw and raw[0] in ('"', "'") else "'"
        return F'{quote}{escape_js_string(value, quote)}{quote}'

    def visit_JsRegExpLiteral(self, node: JsRegExpLiteral):
        self._write(node.raw)

    def visit_JsBooleanLiteral(self, node: JsBooleanLiteral):
        self._write('true' if node.value else 'false')

    def visit_JsNullLiteral(self, node: JsNullLiteral):
        self._write('null')

    def visit_JsThisExpression(self, node: JsThisExpression):
        self._write('this')

    def visit_JsIdentifier(self, node: JsIdentifier):
        self._write(node.name)

    def visit_JsErrorNode(self, node: JsErrorNode):
        self._write(node.text)

    def visit_JsTemplateLiteral(self, node: JsTemplateLiteral):
        self._write('`')
        qi = iter(node.quasis)
        ei = iter(node.expressions)
        for q in qi:
            self._write(q.value)
            e = next(ei, None)
            if e is not None:
                self._write('${')
                self.visit(e)
                self._write('}')
        self._write('`')

    def visit_JsTemplateElement(self, node: JsTemplateElement):
        self._write(node.value)

    def _emit_array_like(self, node):
        self._write('[')
        if self._comma_separated(node.elements, wrap_sequences=True):
            self._newline()
        self._write(']')

    visit_JsArrayExpression = _emit_array_like
    visit_JsArrayPattern = _emit_array_like

    def visit_JsObjectExpression(self, node: JsObjectExpression):
        if not node.properties:
            self._write('{}')
            return
        self._write('{')
        breaking = False
        for i, prop in enumerate(node.properties):
            if i > 0:
                self._write(',')
            if not breaking and self._col >= self._line_length:
                breaking = True
                self._depth += 1
            if breaking:
                self._newline()
            else:
                self._write(' ')
            self.visit(prop)
        if breaking:
            self._depth -= 1
            self._newline()
            self._write('}')
        else:
            self._write(' }')

    def visit_JsProperty(self, node: JsProperty):
        if node.kind in (JsPropertyKind.GET, JsPropertyKind.SET):
            self._write(F'{node.kind.value} ')
        if node.method and node.value and isinstance(node.value, JsFunctionExpression):
            if node.value.is_async:
                self._write('async ')
            if node.value.generator:
                self._write('*')
        self._emit_key(node.key, node.computed)
        if node.method:
            if node.value and isinstance(node.value, JsFunctionExpression):
                self._emit_params(node.value.params)
                self._write(' ')
                if node.value.body:
                    self._emit_block(node.value.body.body)
            return
        if node.shorthand:
            return
        self._write(': ')
        self._emit_element(node.value, True)

    def _emit_spread_like(self, node):
        self._write('...')
        self._emit_element(node.argument, True)

    visit_JsSpreadElement = _emit_spread_like
    visit_JsRestElement = _emit_spread_like

    def visit_JsUnaryExpression(self, node: JsUnaryExpression):
        if node.prefix:
            self._write(node.operator)
            if node.operator in _WORD_UNARY_OPS:
                self._write(' ')
            self._emit_child(node.operand, node)
        else:
            self._emit_child(node.operand, node)
            self._write(node.operator)

    def visit_JsUpdateExpression(self, node: JsUpdateExpression):
        if node.prefix:
            self._write(node.operator)
            self._emit_child(node.argument, node)
        else:
            self._emit_child(node.argument, node)
            self._write(node.operator)

    def _emit_binary_like(self, node):
        self._emit_child(node.left, node)
        self._write(F' {node.operator} ')
        self._emit_child(node.right, node)

    visit_JsBinaryExpression = _emit_binary_like
    visit_JsLogicalExpression = _emit_binary_like
    visit_JsAssignmentExpression = _emit_binary_like

    def visit_JsConditionalExpression(self, node: JsConditionalExpression):
        self._emit_child(node.test, node)
        self._write(' ? ')
        self._emit_child(node.consequent, node)
        self._write(' : ')
        self._emit_child(node.alternate, node)

    def visit_JsMemberExpression(self, node: JsMemberExpression):
        self._emit_child(node.object, node)
        if node.computed:
            if node.optional:
                self._write('?.')
            self._write('[')
            if node.property:
                self.visit(node.property)
            self._write(']')
        elif node.optional:
            self._write('?.')
            if node.property:
                self.visit(node.property)
        else:
            self._write('.')
            if node.property:
                self.visit(node.property)

    def visit_JsCallExpression(self, node: JsCallExpression):
        self._emit_child(node.callee, node)
        if node.optional:
            self._write('?.')
        self._write('(')
        if self._comma_separated(node.arguments, wrap_sequences=True):
            self._newline()
        self._write(')')

    def visit_JsNewExpression(self, node: JsNewExpression):
        self._write('new ')
        self._emit_child(node.callee, node)
        self._write('(')
        if self._comma_separated(node.arguments, wrap_sequences=True):
            self._newline()
        self._write(')')

    def visit_JsSequenceExpression(self, node: JsSequenceExpression):
        self._comma_separated(node.expressions, lead_newline=False)

    def visit_JsYieldExpression(self, node: JsYieldExpression):
        self._write('yield')
        if node.delegate:
            self._write('*')
        if node.argument:
            self._write(' ')
            self._emit_element(node.argument, True)

    def visit_JsAwaitExpression(self, node: JsAwaitExpression):
        self._write('await ')
        self._emit_child(node.argument, node)

    def visit_JsTaggedTemplateExpression(self, node: JsTaggedTemplateExpression):
        self._emit_child(node.tag, node)
        if node.quasi:
            self.visit(node.quasi)

    def visit_JsParenthesizedExpression(self, node: JsParenthesizedExpression):
        self._write('(')
        if node.expression:
            self.visit(node.expression)
        self._write(')')

    def _emit_function(self, node):
        self._emit_function_prefix(node.is_async, node.generator)
        if node.id:
            self._write(' ')
            self.visit(node.id)
        self._emit_params(node.params)
        self._write(' ')
        if node.body:
            self._emit_block(node.body.body)

    visit_JsFunctionExpression = _emit_function

    def visit_JsArrowFunctionExpression(self, node: JsArrowFunctionExpression):
        if node.is_async:
            self._write('async ')
        if len(node.params) == 1 and isinstance(node.params[0], JsIdentifier):
            self.visit(node.params[0])
        else:
            self._emit_params(node.params)
        self._write(' => ')
        if node.body:
            if isinstance(node.body, JsBlockStatement):
                self._emit_block(node.body.body)
            elif isinstance(node.body, JsSequenceExpression) or statement_needs_parens(node.body):
                self._write('(')
                self.visit(node.body)
                self._write(')')
            else:
                self.visit(node.body)

    def _emit_class(self, node: JsClassDeclaration | JsClassExpression):
        self._write('class')
        if node.id:
            self._write(' ')
            self.visit(node.id)
        if node.super_class:
            self._write(' extends ')
            self._emit_child(node.super_class, node)
        self._write(' ')
        if node.body:
            self.visit(node.body)

    def visit_JsClassExpression(self, node: JsClassExpression):
        self._emit_class(node)

    def visit_JsObjectPattern(self, node: JsObjectPattern):
        self._write('{')
        for i, prop in enumerate(node.properties):
            if i > 0:
                self._write(', ')
            else:
                self._write(' ')
            self.visit(prop)
        if node.properties:
            self._write(' ')
        self._write('}')

    def visit_JsAssignmentPattern(self, node: JsAssignmentPattern):
        if node.left:
            self.visit(node.left)
        self._write(' = ')
        self._emit_element(node.right, True)

    def visit_JsClassBody(self, node: JsClassBody):
        self._write('{')
        self._depth += 1
        for member in node.body:
            self._newline()
            self.visit(member)
        self._depth -= 1
        if node.body:
            self._newline()
        self._write('}')

    def visit_JsMethodDefinition(self, node: JsMethodDefinition):
        if node.is_static:
            self._write('static ')
        if node.kind in (JsMethodKind.GET, JsMethodKind.SET):
            self._write(F'{node.kind.value} ')
        if node.value and isinstance(node.value, JsFunctionExpression):
            if node.value.is_async:
                self._write('async ')
            if node.value.generator:
                self._write('*')
        self._emit_key(node.key, node.computed)
        if node.value and isinstance(node.value, JsFunctionExpression):
            self._emit_params(node.value.params)
            self._write(' ')
            if node.value.body:
                self._emit_block(node.value.body.body)

    def visit_JsPropertyDefinition(self, node: JsPropertyDefinition):
        if node.is_static:
            self._write('static ')
        self._emit_key(node.key, node.computed)
        if node.value:
            self._write(' = ')
            self._emit_element(node.value, True)
        self._write(';')

    def visit_JsExpressionStatement(self, node: JsExpressionStatement):
        expr = node.expression
        if expr is not None:
            if statement_needs_parens(expr):
                self._write('(')
                self.visit(expr)
                self._write(')')
            else:
                self.visit(expr)
        self._write(';')

    def visit_JsBlockStatement(self, node: JsBlockStatement):
        self._emit_block(node.body)

    def visit_JsEmptyStatement(self, node: JsEmptyStatement):
        self._write(';')

    def visit_JsVariableDeclaration(self, node: JsVariableDeclaration):
        self._write(F'{node.kind.value} ')
        self._comma_separated(node.declarations)
        self._write(';')

    def visit_JsVariableDeclarator(self, node: JsVariableDeclarator):
        if node.id:
            self.visit(node.id)
        if node.init:
            self._write(' = ')
            self._emit_element(node.init, True)

    def visit_JsIfStatement(self, node: JsIfStatement):
        self._write('if (')
        if node.test:
            self.visit(node.test)
        self._write(') ')
        if node.consequent:
            self._emit_statement_body(node.consequent)
        if node.alternate:
            self._write(' else ')
            self._emit_statement_body(node.alternate)

    def _emit_statement_body(self, stmt: Statement):
        if isinstance(stmt, JsBlockStatement):
            self._emit_block(stmt.body)
        else:
            self._emit_block([stmt])

    def visit_JsWhileStatement(self, node: JsWhileStatement):
        self._write('while (')
        if node.test:
            self.visit(node.test)
        self._write(') ')
        if node.body:
            self._emit_statement_body(node.body)

    def visit_JsDoWhileStatement(self, node: JsDoWhileStatement):
        self._write('do ')
        if node.body:
            self._emit_statement_body(node.body)
        self._write(' while (')
        if node.test:
            self.visit(node.test)
        self._write(');')

    def _emit_for_binding(self, node: Statement | Node):
        if isinstance(node, JsVariableDeclaration):
            self._write(F'{node.kind.value} ')
            for i, decl in enumerate(node.declarations):
                if i > 0:
                    self._write(', ')
                self.visit(decl)
        else:
            self.visit(node)

    def visit_JsForStatement(self, node: JsForStatement):
        self._write('for (')
        if node.init:
            self._emit_for_binding(node.init)
        self._write('; ')
        if node.test:
            self.visit(node.test)
        self._write('; ')
        if node.update:
            self.visit(node.update)
        self._write(') ')
        if node.body:
            self._emit_statement_body(node.body)

    def visit_JsForInStatement(self, node: JsForInStatement):
        self._write('for (')
        if node.left:
            self._emit_for_binding(node.left)
        self._write(' in ')
        if node.right:
            self.visit(node.right)
        self._write(') ')
        if node.body:
            self._emit_statement_body(node.body)

    def visit_JsForOfStatement(self, node: JsForOfStatement):
        self._write('for ')
        if node.is_await:
            self._write('await ')
        self._write('(')
        if node.left:
            self._emit_for_binding(node.left)
        self._write(' of ')
        if node.right:
            self.visit(node.right)
        self._write(') ')
        if node.body:
            self._emit_statement_body(node.body)

    def visit_JsSwitchStatement(self, node: JsSwitchStatement):
        self._write('switch (')
        if node.discriminant:
            self.visit(node.discriminant)
        self._write(') {')
        self._depth += 1
        for case in node.cases:
            self._newline()
            self.visit(case)
        self._depth -= 1
        if node.cases:
            self._newline()
        self._write('}')

    def visit_JsSwitchCase(self, node: JsSwitchCase):
        if node.test:
            self._write('case ')
            self.visit(node.test)
            self._write(':')
        else:
            self._write('default:')
        self._depth += 1
        for stmt in node.body:
            self._newline()
            self.visit(stmt)
        self._depth -= 1

    def visit_JsTryStatement(self, node: JsTryStatement):
        self._write('try ')
        if node.block:
            self._emit_block(node.block.body)
        if node.handler:
            self._write(' ')
            self.visit(node.handler)
        if node.finalizer:
            self._write(' finally ')
            self._emit_block(node.finalizer.body)

    def visit_JsCatchClause(self, node: JsCatchClause):
        self._write('catch')
        if node.param:
            self._write(' (')
            self.visit(node.param)
            self._write(')')
        self._write(' ')
        if node.body:
            self._emit_block(node.body.body)

    def visit_JsThrowStatement(self, node: JsThrowStatement):
        self._write('throw ')
        if node.argument:
            self.visit(node.argument)
        self._write(';')

    def visit_JsReturnStatement(self, node: JsReturnStatement):
        self._write('return')
        if node.argument:
            self._write(' ')
            self.visit(node.argument)
        self._write(';')

    def visit_JsBreakStatement(self, node: JsBreakStatement):
        self._write('break')
        if node.label:
            self._write(' ')
            self.visit(node.label)
        self._write(';')

    def visit_JsContinueStatement(self, node: JsContinueStatement):
        self._write('continue')
        if node.label:
            self._write(' ')
            self.visit(node.label)
        self._write(';')

    def visit_JsLabeledStatement(self, node: JsLabeledStatement):
        if node.label:
            self.visit(node.label)
        self._write(': ')
        if node.body:
            self.visit(node.body)

    def visit_JsWithStatement(self, node: JsWithStatement):
        self._write('with (')
        if node.object:
            self.visit(node.object)
        self._write(') ')
        if node.body:
            self._emit_statement_body(node.body)

    def visit_JsDebuggerStatement(self, node: JsDebuggerStatement):
        self._write('debugger;')

    visit_JsFunctionDeclaration = _emit_function

    def visit_JsClassDeclaration(self, node: JsClassDeclaration):
        self._emit_class(node)

    def visit_JsImportDeclaration(self, node: JsImportDeclaration):
        self._write('import ')
        if not node.specifiers:
            if node.source:
                self.visit(node.source)
            self._write(';')
            return
        default_spec = None
        namespace_spec = None
        named_specs: list = []
        for spec in node.specifiers:
            if isinstance(spec, JsImportDefaultSpecifier):
                default_spec = spec
            elif isinstance(spec, JsImportNamespaceSpecifier):
                namespace_spec = spec
            elif isinstance(spec, JsImportSpecifier):
                named_specs.append(spec)
        if default_spec:
            if default_spec.local:
                self.visit(default_spec.local)
            if namespace_spec or named_specs:
                self._write(', ')
        if namespace_spec:
            self._write('* as ')
            if namespace_spec.local:
                self.visit(namespace_spec.local)
        if named_specs:
            self._write('{ ')
            for i, spec in enumerate(named_specs):
                if i > 0:
                    self._write(', ')
                self.visit(spec)
            self._write(' }')
        self._write(' from ')
        if node.source:
            self.visit(node.source)
        self._write(';')

    def visit_JsImportSpecifier(self, node: JsImportSpecifier):
        if node.imported:
            self.visit(node.imported)
        if (
            node.local and node.imported
            and isinstance(node.local, JsIdentifier)
            and isinstance(node.imported, JsIdentifier)
            and node.local.name != node.imported.name
        ):
            self._write(' as ')
            self.visit(node.local)

    def visit_JsImportDefaultSpecifier(self, node: JsImportDefaultSpecifier):
        if node.local:
            self.visit(node.local)

    def visit_JsImportNamespaceSpecifier(self, node: JsImportNamespaceSpecifier):
        self._write('* as ')
        if node.local:
            self.visit(node.local)

    def visit_JsExportNamedDeclaration(self, node: JsExportNamedDeclaration):
        self._write('export ')
        if node.declaration:
            self.visit(node.declaration)
            return
        self._write('{ ')
        for i, spec in enumerate(node.specifiers):
            if i > 0:
                self._write(', ')
            self.visit(spec)
        self._write(' }')
        if node.source:
            self._write(' from ')
            self.visit(node.source)
        self._write(';')

    def visit_JsExportDefaultDeclaration(self, node: JsExportDefaultDeclaration):
        self._write('export default ')
        if node.declaration:
            self.visit(node.declaration)
            if not isinstance(node.declaration, (
                JsFunctionDeclaration, JsClassDeclaration,
            )):
                self._write(';')

    def visit_JsExportAllDeclaration(self, node: JsExportAllDeclaration):
        self._write('export *')
        if node.exported:
            self._write(' as ')
            self.visit(node.exported)
        self._write(' from ')
        if node.source:
            self.visit(node.source)
        self._write(';')

    def visit_JsExportSpecifier(self, node: JsExportSpecifier):
        if node.local:
            self.visit(node.local)
        if (
            node.exported and node.local
            and isinstance(node.exported, JsIdentifier)
            and isinstance(node.local, JsIdentifier)
            and node.exported.name != node.local.name
        ):
            self._write(' as ')
            self.visit(node.exported)

    def visit_JsScript(self, node: JsScript):
        for i, stmt in enumerate(node.body):
            if i > 0:
                self._newline()
            self._emit_leading_comments(stmt)
            self.visit(stmt)
