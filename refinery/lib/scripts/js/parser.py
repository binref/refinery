from __future__ import annotations

from refinery.lib.scripts.js.lexer import JsLexer, _ESCAPE_MAP
from refinery.lib.scripts.js.model import (
    Expression,
    JsArrayExpression,
    JsArrayPattern,
    JsArrowFunctionExpression,
    JsAssignmentExpression,
    JsAssignmentPattern,
    JsAwaitExpression,
    JsBigIntLiteral,
    JsBinaryExpression,
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
    JsLogicalExpression,
    JsMemberExpression,
    JsMethodDefinition,
    JsNewExpression,
    JsNullLiteral,
    JsNumericLiteral,
    JsObjectExpression,
    JsObjectPattern,
    JsParenthesizedExpression,
    JsProperty,
    JsPropertyDefinition,
    JsRegExpLiteral,
    JsRestElement,
    JsReturnStatement,
    JsScript,
    JsSequenceExpression,
    JsSpreadElement,
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
from refinery.lib.scripts.js.token import JsToken, JsTokenKind


class JsParser:

    def __init__(self, source: str):
        self._lexer = JsLexer(source)
        self._source = source
        self._tokens = self._lexer.tokenize()
        self._current: JsToken = JsToken(JsTokenKind.EOF, '', 0)
        self._preceded_by_newline: bool = False
        self._no_in: bool = False
        self._pending_comments: list[str] = []
        self._advance()

    def _advance(self) -> JsToken:
        prev = self._current
        had_newline = False
        while True:
            tok = next(self._tokens, JsToken(JsTokenKind.EOF, '', len(self._source)))
            if tok.kind == JsTokenKind.NEWLINE:
                had_newline = True
                continue
            if tok.kind == JsTokenKind.COMMENT:
                self._pending_comments.append(tok.value)
                continue
            break
        self._current = tok
        self._preceded_by_newline = had_newline
        return prev

    def _drain_comments(self, node):
        if self._pending_comments:
            node.leading_comments.extend(self._pending_comments)
            self._pending_comments.clear()

    def _peek(self) -> JsToken:
        return self._current

    def _at(self, *kinds: JsTokenKind) -> bool:
        return self._current.kind in kinds

    def _eat(self, kind: JsTokenKind) -> JsToken | None:
        if self._current.kind == kind:
            return self._advance()
        return None

    def _expect(self, kind: JsTokenKind) -> JsToken:
        if self._current.kind == kind:
            return self._advance()
        tok = self._current
        self._advance()
        return JsToken(kind, tok.value, tok.offset)

    def _eat_semicolon(self) -> bool:
        if self._eat(JsTokenKind.SEMICOLON):
            return True
        if self._at(JsTokenKind.RBRACE, JsTokenKind.EOF):
            return True
        if self._preceded_by_newline:
            return True
        return False

    def parse(self) -> JsScript:
        return self._parse_program()

    def _parse_program(self) -> JsScript:
        offset = self._current.offset
        body: list[Statement] = []
        while not self._at(JsTokenKind.EOF):
            mark = self._current.offset
            comments = list(self._pending_comments)
            self._pending_comments.clear()
            try:
                stmt = self._parse_statement()
            except Exception:
                stmt = None
            if stmt is not None:
                stmt.leading_comments.extend(comments)
                body.append(stmt)
            elif self._current.offset == mark:
                tok = self._advance()
                error = JsExpressionStatement(
                    offset=tok.offset,
                    expression=JsErrorNode(offset=tok.offset, text=tok.value),
                )
                error.leading_comments.extend(comments)
                body.append(error)
        return JsScript(body=body, offset=offset)

    def _parse_statement(self) -> Statement | None:
        offset = self._current.offset
        kind = self._current.kind

        if kind == JsTokenKind.LBRACE:
            return self._parse_block_statement()
        if kind == JsTokenKind.SEMICOLON:
            self._advance()
            return JsEmptyStatement(offset=offset)
        if kind in (JsTokenKind.VAR, JsTokenKind.LET, JsTokenKind.CONST):
            return self._parse_variable_declaration()
        if kind == JsTokenKind.IF:
            return self._parse_if_statement()
        if kind == JsTokenKind.WHILE:
            return self._parse_while_statement()
        if kind == JsTokenKind.DO:
            return self._parse_do_while_statement()
        if kind == JsTokenKind.FOR:
            return self._parse_for_statement()
        if kind == JsTokenKind.SWITCH:
            return self._parse_switch_statement()
        if kind == JsTokenKind.TRY:
            return self._parse_try_statement()
        if kind == JsTokenKind.WITH:
            return self._parse_with_statement()
        if kind == JsTokenKind.RETURN:
            return self._parse_return_statement()
        if kind == JsTokenKind.THROW:
            return self._parse_throw_statement()
        if kind == JsTokenKind.BREAK:
            return self._parse_break_statement()
        if kind == JsTokenKind.CONTINUE:
            return self._parse_continue_statement()
        if kind == JsTokenKind.FUNCTION:
            return self._parse_function_declaration()
        if kind == JsTokenKind.CLASS:
            return self._parse_class_declaration()
        if kind == JsTokenKind.DEBUGGER:
            self._advance()
            self._eat_semicolon()
            return JsDebuggerStatement(offset=offset)
        if kind == JsTokenKind.IMPORT:
            return self._parse_import_declaration()
        if kind == JsTokenKind.EXPORT:
            return self._parse_export_declaration()
        if kind == JsTokenKind.ASYNC:
            return self._parse_async_statement()

        expr = self._parse_expression()

        if (
            isinstance(expr, JsIdentifier)
            and self._eat(JsTokenKind.COLON)
        ):
            body = self._parse_statement()
            return JsLabeledStatement(label=expr, body=body, offset=offset)

        self._eat_semicolon()
        return JsExpressionStatement(expression=expr, offset=offset)

    def _parse_block_statement(self) -> JsBlockStatement:
        offset = self._current.offset
        self._expect(JsTokenKind.LBRACE)
        body: list[Statement] = []
        while not self._at(JsTokenKind.RBRACE, JsTokenKind.EOF):
            mark = self._current.offset
            comments = list(self._pending_comments)
            self._pending_comments.clear()
            try:
                stmt = self._parse_statement()
            except Exception:
                stmt = None
            if stmt is not None:
                stmt.leading_comments.extend(comments)
                body.append(stmt)
            elif self._current.offset == mark:
                tok = self._advance()
                error = JsExpressionStatement(
                    offset=tok.offset,
                    expression=JsErrorNode(offset=tok.offset, text=tok.value),
                )
                error.leading_comments.extend(comments)
                body.append(error)
        self._expect(JsTokenKind.RBRACE)
        return JsBlockStatement(body=body, offset=offset)

    def _parse_variable_declaration(self) -> JsVariableDeclaration:
        offset = self._current.offset
        kind_tok = self._advance()
        kind = kind_tok.value
        declarations: list[JsVariableDeclarator] = []
        declarations.append(self._parse_variable_declarator())
        while self._eat(JsTokenKind.COMMA):
            declarations.append(self._parse_variable_declarator())
        self._eat_semicolon()
        return JsVariableDeclaration(declarations=declarations, kind=kind, offset=offset)

    def _parse_variable_declarator(self) -> JsVariableDeclarator:
        offset = self._current.offset
        id_node = self._parse_binding_pattern()
        init = None
        if self._eat(JsTokenKind.EQUALS):
            init = self._parse_assignment_expression()
        return JsVariableDeclarator(id=id_node, init=init, offset=offset)

    def _parse_binding_pattern(self) -> Expression:
        if self._at(JsTokenKind.LBRACKET):
            return self._parse_array_pattern()
        if self._at(JsTokenKind.LBRACE):
            return self._parse_object_pattern()
        return self._parse_binding_identifier()

    def _parse_binding_identifier(self) -> Expression:
        offset = self._current.offset
        tok = self._expect(JsTokenKind.IDENTIFIER)
        return JsIdentifier(name=tok.value, offset=offset)

    def _parse_array_pattern(self) -> JsArrayPattern:
        offset = self._current.offset
        self._expect(JsTokenKind.LBRACKET)
        elements: list[Expression | None] = []
        while not self._at(JsTokenKind.RBRACKET, JsTokenKind.EOF):
            if self._at(JsTokenKind.COMMA):
                elements.append(None)
                self._advance()
                continue
            if self._at(JsTokenKind.ELLIPSIS):
                elements.append(self._parse_rest_element())
                break
            elem = self._parse_binding_pattern()
            if self._eat(JsTokenKind.EQUALS):
                right = self._parse_assignment_expression()
                elem = JsAssignmentPattern(left=elem, right=right, offset=elem.offset)
            elements.append(elem)
            if not self._at(JsTokenKind.RBRACKET):
                self._expect(JsTokenKind.COMMA)
        self._expect(JsTokenKind.RBRACKET)
        return JsArrayPattern(elements=elements, offset=offset)

    def _parse_object_pattern(self) -> JsObjectPattern:
        offset = self._current.offset
        self._expect(JsTokenKind.LBRACE)
        properties: list[JsProperty | JsRestElement] = []
        while not self._at(JsTokenKind.RBRACE, JsTokenKind.EOF):
            if self._at(JsTokenKind.ELLIPSIS):
                properties.append(self._parse_rest_element())
                break
            prop = self._parse_object_pattern_property()
            properties.append(prop)
            if not self._at(JsTokenKind.RBRACE):
                self._expect(JsTokenKind.COMMA)
        self._expect(JsTokenKind.RBRACE)
        return JsObjectPattern(properties=properties, offset=offset)

    def _parse_object_pattern_property(self) -> JsProperty:
        offset = self._current.offset
        if self._at(JsTokenKind.LBRACKET):
            self._advance()
            key = self._parse_assignment_expression()
            self._expect(JsTokenKind.RBRACKET)
            self._expect(JsTokenKind.COLON)
            value = self._parse_binding_pattern()
            if self._eat(JsTokenKind.EQUALS):
                right = self._parse_assignment_expression()
                value = JsAssignmentPattern(left=value, right=right, offset=value.offset)
            return JsProperty(
                key=key, value=value, computed=True, shorthand=False, offset=offset)

        key = self._parse_property_name()
        if self._eat(JsTokenKind.COLON):
            value = self._parse_binding_pattern()
            if self._eat(JsTokenKind.EQUALS):
                right = self._parse_assignment_expression()
                value = JsAssignmentPattern(left=value, right=right, offset=value.offset)
            return JsProperty(
                key=key, value=value, computed=False, shorthand=False, offset=offset)

        value = key
        if self._eat(JsTokenKind.EQUALS):
            right = self._parse_assignment_expression()
            value = JsAssignmentPattern(left=key, right=right, offset=key.offset)
        return JsProperty(key=key, value=value, computed=False, shorthand=True, offset=offset)

    def _parse_rest_element(self) -> JsRestElement:
        offset = self._current.offset
        self._expect(JsTokenKind.ELLIPSIS)
        argument = self._parse_binding_pattern()
        return JsRestElement(argument=argument, offset=offset)

    def _parse_if_statement(self) -> JsIfStatement:
        offset = self._current.offset
        self._expect(JsTokenKind.IF)
        self._expect(JsTokenKind.LPAREN)
        test = self._parse_expression()
        self._expect(JsTokenKind.RPAREN)
        consequent = self._parse_statement()
        alternate = None
        if self._eat(JsTokenKind.ELSE):
            alternate = self._parse_statement()
        return JsIfStatement(
            test=test, consequent=consequent, alternate=alternate, offset=offset)

    def _parse_while_statement(self) -> JsWhileStatement:
        offset = self._current.offset
        self._expect(JsTokenKind.WHILE)
        self._expect(JsTokenKind.LPAREN)
        test = self._parse_expression()
        self._expect(JsTokenKind.RPAREN)
        body = self._parse_statement()
        return JsWhileStatement(test=test, body=body, offset=offset)

    def _parse_do_while_statement(self) -> JsDoWhileStatement:
        offset = self._current.offset
        self._expect(JsTokenKind.DO)
        body = self._parse_statement()
        self._expect(JsTokenKind.WHILE)
        self._expect(JsTokenKind.LPAREN)
        test = self._parse_expression()
        self._expect(JsTokenKind.RPAREN)
        self._eat_semicolon()
        return JsDoWhileStatement(test=test, body=body, offset=offset)

    def _parse_for_statement(self) -> Statement:
        offset = self._current.offset
        self._expect(JsTokenKind.FOR)

        is_await = False
        if self._eat(JsTokenKind.AWAIT):
            is_await = True

        self._expect(JsTokenKind.LPAREN)

        if self._at(JsTokenKind.SEMICOLON):
            self._advance()
            return self._parse_for_rest(None, offset)

        if self._at(JsTokenKind.VAR, JsTokenKind.LET, JsTokenKind.CONST):
            decl_offset = self._current.offset
            kind_tok = self._advance()
            kind = kind_tok.value
            declarator = self._parse_variable_declarator()
            decl = JsVariableDeclaration(
                declarations=[declarator], kind=kind, offset=decl_offset)
            if self._eat(JsTokenKind.IN):
                right = self._parse_expression()
                self._expect(JsTokenKind.RPAREN)
                body = self._parse_statement()
                return JsForInStatement(
                    left=decl, right=right, body=body, offset=offset)
            if self._at(JsTokenKind.OF) or (
                self._at(JsTokenKind.IDENTIFIER) and self._current.value == 'of'
            ):
                self._advance()
                right = self._parse_assignment_expression()
                self._expect(JsTokenKind.RPAREN)
                body = self._parse_statement()
                return JsForOfStatement(
                    left=decl, right=right, body=body, is_await=is_await, offset=offset)
            while self._eat(JsTokenKind.COMMA):
                decl.declarations.append(self._parse_variable_declarator())
            self._expect(JsTokenKind.SEMICOLON)
            return self._parse_for_rest(decl, offset)

        saved_no_in = self._no_in
        self._no_in = True
        init_expr = self._parse_expression()
        self._no_in = saved_no_in
        if self._eat(JsTokenKind.IN):
            right = self._parse_expression()
            self._expect(JsTokenKind.RPAREN)
            body = self._parse_statement()
            return JsForInStatement(
                left=init_expr, right=right, body=body, offset=offset)
        if self._at(JsTokenKind.OF) or (
            self._at(JsTokenKind.IDENTIFIER) and self._current.value == 'of'
        ):
            self._advance()
            right = self._parse_assignment_expression()
            self._expect(JsTokenKind.RPAREN)
            body = self._parse_statement()
            return JsForOfStatement(
                left=init_expr, right=right, body=body, is_await=is_await, offset=offset)
        self._expect(JsTokenKind.SEMICOLON)
        return self._parse_for_rest(init_expr, offset)

    def _parse_for_rest(
        self,
        init: Expression | Statement | None,
        offset: int,
    ) -> JsForStatement:
        test = None
        if not self._at(JsTokenKind.SEMICOLON):
            test = self._parse_expression()
        self._expect(JsTokenKind.SEMICOLON)
        update = None
        if not self._at(JsTokenKind.RPAREN):
            update = self._parse_expression()
        self._expect(JsTokenKind.RPAREN)
        body = self._parse_statement()
        return JsForStatement(
            init=init, test=test, update=update, body=body, offset=offset)

    def _parse_switch_statement(self) -> JsSwitchStatement:
        offset = self._current.offset
        self._expect(JsTokenKind.SWITCH)
        self._expect(JsTokenKind.LPAREN)
        discriminant = self._parse_expression()
        self._expect(JsTokenKind.RPAREN)
        self._expect(JsTokenKind.LBRACE)
        cases: list[JsSwitchCase] = []
        while not self._at(JsTokenKind.RBRACE, JsTokenKind.EOF):
            cases.append(self._parse_switch_case())
        self._expect(JsTokenKind.RBRACE)
        return JsSwitchStatement(
            discriminant=discriminant, cases=cases, offset=offset)

    def _parse_switch_case(self) -> JsSwitchCase:
        offset = self._current.offset
        test = None
        if self._eat(JsTokenKind.CASE):
            test = self._parse_expression()
            self._expect(JsTokenKind.COLON)
        elif self._eat(JsTokenKind.DEFAULT):
            self._expect(JsTokenKind.COLON)
        else:
            self._advance()
        consequent: list[Statement] = []
        while not self._at(
            JsTokenKind.CASE, JsTokenKind.DEFAULT,
            JsTokenKind.RBRACE, JsTokenKind.EOF,
        ):
            stmt = self._parse_statement()
            if stmt is not None:
                consequent.append(stmt)
        return JsSwitchCase(test=test, consequent=consequent, offset=offset)

    def _parse_try_statement(self) -> JsTryStatement:
        offset = self._current.offset
        self._expect(JsTokenKind.TRY)
        block = self._parse_block_statement()
        handler = None
        finalizer = None
        if self._eat(JsTokenKind.CATCH):
            handler = self._parse_catch_clause()
        if self._eat(JsTokenKind.FINALLY):
            finalizer = self._parse_block_statement()
        return JsTryStatement(
            block=block, handler=handler, finalizer=finalizer, offset=offset)

    def _parse_catch_clause(self) -> JsCatchClause:
        offset = self._current.offset
        param = None
        if self._eat(JsTokenKind.LPAREN):
            param = self._parse_binding_pattern()
            self._expect(JsTokenKind.RPAREN)
        body = self._parse_block_statement()
        return JsCatchClause(param=param, body=body, offset=offset)

    def _parse_with_statement(self) -> JsWithStatement:
        offset = self._current.offset
        self._expect(JsTokenKind.WITH)
        self._expect(JsTokenKind.LPAREN)
        obj = self._parse_expression()
        self._expect(JsTokenKind.RPAREN)
        body = self._parse_statement()
        return JsWithStatement(object=obj, body=body, offset=offset)

    def _parse_return_statement(self) -> JsReturnStatement:
        offset = self._current.offset
        self._expect(JsTokenKind.RETURN)
        argument = None
        if not self._preceded_by_newline and not self._at(
            JsTokenKind.SEMICOLON, JsTokenKind.RBRACE, JsTokenKind.EOF,
        ):
            argument = self._parse_expression()
        self._eat_semicolon()
        return JsReturnStatement(argument=argument, offset=offset)

    def _parse_throw_statement(self) -> JsThrowStatement:
        offset = self._current.offset
        self._expect(JsTokenKind.THROW)
        argument = None
        if not self._preceded_by_newline:
            argument = self._parse_expression()
        self._eat_semicolon()
        return JsThrowStatement(argument=argument, offset=offset)

    def _parse_break_statement(self) -> JsBreakStatement:
        offset = self._current.offset
        self._expect(JsTokenKind.BREAK)
        label = None
        if not self._preceded_by_newline and self._at(JsTokenKind.IDENTIFIER):
            tok = self._advance()
            label = JsIdentifier(name=tok.value, offset=tok.offset)
        self._eat_semicolon()
        return JsBreakStatement(label=label, offset=offset)

    def _parse_continue_statement(self) -> JsContinueStatement:
        offset = self._current.offset
        self._expect(JsTokenKind.CONTINUE)
        label = None
        if not self._preceded_by_newline and self._at(JsTokenKind.IDENTIFIER):
            tok = self._advance()
            label = JsIdentifier(name=tok.value, offset=tok.offset)
        self._eat_semicolon()
        return JsContinueStatement(label=label, offset=offset)

    def _parse_function_declaration(
        self,
        is_async: bool = False,
    ) -> JsFunctionDeclaration:
        offset = self._current.offset
        self._expect(JsTokenKind.FUNCTION)
        generator = bool(self._eat(JsTokenKind.STAR))
        id_node = None
        if self._at(JsTokenKind.IDENTIFIER):
            tok = self._advance()
            id_node = JsIdentifier(name=tok.value, offset=tok.offset)
        params = self._parse_formal_parameters()
        body = self._parse_block_statement()
        return JsFunctionDeclaration(
            id=id_node,
            params=params,
            body=body,
            generator=generator,
            is_async=is_async,
            offset=offset,
        )

    def _parse_formal_parameters(self) -> list[Expression]:
        self._expect(JsTokenKind.LPAREN)
        params: list[Expression] = []
        while not self._at(JsTokenKind.RPAREN, JsTokenKind.EOF):
            if self._at(JsTokenKind.ELLIPSIS):
                params.append(self._parse_rest_element())
                break
            param = self._parse_binding_pattern()
            if self._eat(JsTokenKind.EQUALS):
                default = self._parse_assignment_expression()
                param = JsAssignmentPattern(
                    left=param, right=default, offset=param.offset)
            params.append(param)
            if not self._at(JsTokenKind.RPAREN):
                self._expect(JsTokenKind.COMMA)
        self._expect(JsTokenKind.RPAREN)
        return params

    def _parse_class_declaration(self) -> JsClassDeclaration:
        offset = self._current.offset
        self._expect(JsTokenKind.CLASS)
        id_node = None
        if self._at(JsTokenKind.IDENTIFIER):
            tok = self._advance()
            id_node = JsIdentifier(name=tok.value, offset=tok.offset)
        super_class = None
        if self._eat(JsTokenKind.EXTENDS):
            super_class = self._parse_assignment_expression()
        body = self._parse_class_body()
        return JsClassDeclaration(
            id=id_node, super_class=super_class, body=body, offset=offset)

    def _parse_class_body(self) -> JsClassBody:
        offset = self._current.offset
        self._expect(JsTokenKind.LBRACE)
        members: list[JsMethodDefinition | JsPropertyDefinition] = []
        while not self._at(JsTokenKind.RBRACE, JsTokenKind.EOF):
            if self._eat(JsTokenKind.SEMICOLON):
                continue
            members.append(self._parse_class_member())
        self._expect(JsTokenKind.RBRACE)
        return JsClassBody(body=members, offset=offset)

    def _parse_class_member(self) -> JsMethodDefinition | JsPropertyDefinition:
        offset = self._current.offset
        is_static = False
        if (
            self._at(JsTokenKind.IDENTIFIER) and self._current.value == 'static'
        ):
            saved_pos = self._current
            self._advance()
            if self._at(
                JsTokenKind.LBRACE, JsTokenKind.RBRACE, JsTokenKind.EOF,
                JsTokenKind.SEMICOLON,
            ):
                key = JsIdentifier(name='static', offset=saved_pos.offset)
                return self._finish_class_member(key, False, False, offset)
            is_static = True

        kind = 'method'
        is_generator = False

        if self._eat(JsTokenKind.STAR):
            is_generator = True

        if self._at(JsTokenKind.IDENTIFIER) and self._current.value == 'get':
            saved = self._current
            self._advance()
            if self._at(JsTokenKind.LPAREN):
                key = JsIdentifier(name='get', offset=saved.offset)
                return self._finish_class_member(key, is_static, is_generator, offset)
            kind = 'get'
        elif self._at(JsTokenKind.IDENTIFIER) and self._current.value == 'set':
            saved = self._current
            self._advance()
            if self._at(JsTokenKind.LPAREN):
                key = JsIdentifier(name='set', offset=saved.offset)
                return self._finish_class_member(key, is_static, is_generator, offset)
            kind = 'set'
        elif self._at(JsTokenKind.ASYNC):
            saved = self._current
            self._advance()
            if self._at(JsTokenKind.LPAREN):
                key = JsIdentifier(name='async', offset=saved.offset)
                return self._finish_class_member(key, is_static, is_generator, offset)

        computed = False
        if self._at(JsTokenKind.LBRACKET):
            computed = True
            self._advance()
            key = self._parse_assignment_expression()
            self._expect(JsTokenKind.RBRACKET)
        else:
            key = self._parse_property_name()

        if kind == 'method' and not is_generator and not self._at(JsTokenKind.LPAREN):
            value = None
            if self._eat(JsTokenKind.EQUALS):
                value = self._parse_assignment_expression()
            self._eat_semicolon()
            return JsPropertyDefinition(
                key=key, value=value, computed=computed,
                is_static=is_static, offset=offset)

        return self._finish_class_member(key, is_static, is_generator, offset, kind, computed)

    def _finish_class_member(
        self,
        key: Expression,
        is_static: bool,
        is_generator: bool,
        offset: int,
        kind: str = 'method',
        computed: bool = False,
    ) -> JsMethodDefinition:
        func_offset = self._current.offset
        params = self._parse_formal_parameters()
        body = self._parse_block_statement()
        value = JsFunctionExpression(
            params=params,
            body=body,
            generator=is_generator,
            offset=func_offset,
        )
        if isinstance(key, JsIdentifier) and key.name == 'constructor' and kind == 'method':
            kind = 'constructor'
        return JsMethodDefinition(
            key=key, value=value, kind=kind, computed=computed,
            is_static=is_static, offset=offset)

    def _parse_import_declaration(self) -> JsImportDeclaration:
        offset = self._current.offset
        self._expect(JsTokenKind.IMPORT)

        if self._at(JsTokenKind.STRING_SINGLE, JsTokenKind.STRING_DOUBLE):
            source = self._parse_string_literal()
            self._eat_semicolon()
            return JsImportDeclaration(source=source, offset=offset)

        specifiers: list[
            JsImportSpecifier | JsImportDefaultSpecifier | JsImportNamespaceSpecifier
        ] = []

        if self._at(JsTokenKind.IDENTIFIER):
            tok = self._advance()
            specifiers.append(JsImportDefaultSpecifier(
                local=JsIdentifier(name=tok.value, offset=tok.offset),
                offset=tok.offset,
            ))
            if self._eat(JsTokenKind.COMMA):
                if self._at(JsTokenKind.STAR):
                    specifiers.append(self._parse_namespace_import())
                elif self._at(JsTokenKind.LBRACE):
                    specifiers.extend(self._parse_named_imports())

        elif self._at(JsTokenKind.STAR):
            specifiers.append(self._parse_namespace_import())

        elif self._at(JsTokenKind.LBRACE):
            specifiers.extend(self._parse_named_imports())

        self._expect_contextual('from')
        source = self._parse_string_literal()
        self._eat_semicolon()
        return JsImportDeclaration(
            specifiers=specifiers, source=source, offset=offset)

    def _parse_namespace_import(self) -> JsImportNamespaceSpecifier:
        offset = self._current.offset
        self._expect(JsTokenKind.STAR)
        self._expect_contextual('as')
        tok = self._expect(JsTokenKind.IDENTIFIER)
        return JsImportNamespaceSpecifier(
            local=JsIdentifier(name=tok.value, offset=tok.offset),
            offset=offset,
        )

    def _parse_named_imports(self) -> list[JsImportSpecifier]:
        self._expect(JsTokenKind.LBRACE)
        specs: list[JsImportSpecifier] = []
        while not self._at(JsTokenKind.RBRACE, JsTokenKind.EOF):
            spec_offset = self._current.offset
            tok = self._advance()
            imported = JsIdentifier(name=tok.value, offset=tok.offset)
            local = imported
            if self._at(JsTokenKind.AS) or (
                self._at(JsTokenKind.IDENTIFIER) and self._current.value == 'as'
            ):
                self._advance()
                ltok = self._expect(JsTokenKind.IDENTIFIER)
                local = JsIdentifier(name=ltok.value, offset=ltok.offset)
            specs.append(JsImportSpecifier(
                imported=imported, local=local, offset=spec_offset))
            if not self._at(JsTokenKind.RBRACE):
                self._expect(JsTokenKind.COMMA)
        self._expect(JsTokenKind.RBRACE)
        return specs

    def _parse_export_declaration(self) -> Statement:
        offset = self._current.offset
        self._expect(JsTokenKind.EXPORT)

        if self._eat(JsTokenKind.DEFAULT):
            if self._at(JsTokenKind.FUNCTION):
                decl = self._parse_function_declaration()
                return JsExportDefaultDeclaration(declaration=decl, offset=offset)
            if self._at(JsTokenKind.CLASS):
                decl = self._parse_class_declaration()
                return JsExportDefaultDeclaration(declaration=decl, offset=offset)
            if self._at(JsTokenKind.ASYNC):
                decl = self._parse_async_statement()
                return JsExportDefaultDeclaration(declaration=decl, offset=offset)
            expr = self._parse_assignment_expression()
            self._eat_semicolon()
            return JsExportDefaultDeclaration(declaration=expr, offset=offset)

        if self._at(JsTokenKind.STAR):
            self._advance()
            exported = None
            if self._at(JsTokenKind.AS) or (
                self._at(JsTokenKind.IDENTIFIER) and self._current.value == 'as'
            ):
                self._advance()
                tok = self._expect(JsTokenKind.IDENTIFIER)
                exported = JsIdentifier(name=tok.value, offset=tok.offset)
            self._expect_contextual('from')
            source = self._parse_string_literal()
            self._eat_semicolon()
            return JsExportAllDeclaration(
                source=source, exported=exported, offset=offset)

        if self._at(JsTokenKind.LBRACE):
            return self._parse_export_named(offset)

        if self._at(JsTokenKind.VAR, JsTokenKind.LET, JsTokenKind.CONST):
            decl = self._parse_variable_declaration()
            return JsExportNamedDeclaration(declaration=decl, offset=offset)
        if self._at(JsTokenKind.FUNCTION):
            decl = self._parse_function_declaration()
            return JsExportNamedDeclaration(declaration=decl, offset=offset)
        if self._at(JsTokenKind.CLASS):
            decl = self._parse_class_declaration()
            return JsExportNamedDeclaration(declaration=decl, offset=offset)
        if self._at(JsTokenKind.ASYNC):
            decl = self._parse_async_statement()
            return JsExportNamedDeclaration(declaration=decl, offset=offset)

        self._advance()
        return JsExportNamedDeclaration(offset=offset)

    def _parse_export_named(self, offset: int) -> JsExportNamedDeclaration:
        self._expect(JsTokenKind.LBRACE)
        specifiers: list[JsExportSpecifier] = []
        while not self._at(JsTokenKind.RBRACE, JsTokenKind.EOF):
            spec_offset = self._current.offset
            tok = self._advance()
            local = JsIdentifier(name=tok.value, offset=tok.offset)
            exported = local
            if self._at(JsTokenKind.AS) or (
                self._at(JsTokenKind.IDENTIFIER) and self._current.value == 'as'
            ):
                self._advance()
                etok = self._advance()
                exported = JsIdentifier(name=etok.value, offset=etok.offset)
            specifiers.append(JsExportSpecifier(
                local=local, exported=exported, offset=spec_offset))
            if not self._at(JsTokenKind.RBRACE):
                self._expect(JsTokenKind.COMMA)
        self._expect(JsTokenKind.RBRACE)
        source = None
        if self._at(JsTokenKind.FROM) or (
            self._at(JsTokenKind.IDENTIFIER) and self._current.value == 'from'
        ):
            self._advance()
            source = self._parse_string_literal()
        self._eat_semicolon()
        return JsExportNamedDeclaration(
            specifiers=specifiers, source=source, offset=offset)

    def _parse_async_statement(self) -> Statement:
        offset = self._current.offset
        self._expect(JsTokenKind.ASYNC)
        if self._at(JsTokenKind.FUNCTION) and not self._preceded_by_newline:
            return self._parse_function_declaration(is_async=True)
        expr = self._parse_expression_starting_with_async(offset)
        self._eat_semicolon()
        return JsExpressionStatement(expression=expr, offset=offset)

    def _expect_contextual(self, keyword: str):
        if self._at(JsTokenKind.FROM) and keyword == 'from':
            self._advance()
            return
        if self._at(JsTokenKind.AS) and keyword == 'as':
            self._advance()
            return
        if self._at(JsTokenKind.IDENTIFIER) and self._current.value == keyword:
            self._advance()
            return
        self._advance()

    def _parse_expression(self) -> Expression:
        expr = self._parse_assignment_expression()
        if self._at(JsTokenKind.COMMA):
            exprs = [expr]
            while self._eat(JsTokenKind.COMMA):
                exprs.append(self._parse_assignment_expression())
            return JsSequenceExpression(expressions=exprs, offset=expr.offset)
        return expr

    def _parse_assignment_expression(self) -> Expression:
        left = self._parse_conditional_expression()
        if self._current.kind.is_assignment:
            op = self._advance().value
            right = self._parse_assignment_expression()
            left = self._to_pattern(left) if op == '=' else left
            return JsAssignmentExpression(
                left=left, operator=op, right=right, offset=left.offset)
        return left

    def _parse_conditional_expression(self) -> Expression:
        expr = self._parse_nullish_coalescing_expression()
        if self._eat(JsTokenKind.QUESTION):
            consequent = self._parse_assignment_expression()
            self._expect(JsTokenKind.COLON)
            alternate = self._parse_assignment_expression()
            return JsConditionalExpression(
                test=expr, consequent=consequent, alternate=alternate,
                offset=expr.offset)
        return expr

    def _parse_nullish_coalescing_expression(self) -> Expression:
        left = self._parse_logical_or_expression()
        while self._eat(JsTokenKind.QQ):
            right = self._parse_logical_or_expression()
            left = JsLogicalExpression(
                left=left, operator='??', right=right, offset=left.offset)
        return left

    def _parse_logical_or_expression(self) -> Expression:
        left = self._parse_logical_and_expression()
        while self._eat(JsTokenKind.OR):
            right = self._parse_logical_and_expression()
            left = JsLogicalExpression(
                left=left, operator='||', right=right, offset=left.offset)
        return left

    def _parse_logical_and_expression(self) -> Expression:
        left = self._parse_bitwise_or_expression()
        while self._eat(JsTokenKind.AND):
            right = self._parse_bitwise_or_expression()
            left = JsLogicalExpression(
                left=left, operator='&&', right=right, offset=left.offset)
        return left

    def _parse_bitwise_or_expression(self) -> Expression:
        left = self._parse_bitwise_xor_expression()
        while self._eat(JsTokenKind.PIPE):
            right = self._parse_bitwise_xor_expression()
            left = JsBinaryExpression(
                left=left, operator='|', right=right, offset=left.offset)
        return left

    def _parse_bitwise_xor_expression(self) -> Expression:
        left = self._parse_bitwise_and_expression()
        while self._eat(JsTokenKind.CARET):
            right = self._parse_bitwise_and_expression()
            left = JsBinaryExpression(
                left=left, operator='^', right=right, offset=left.offset)
        return left

    def _parse_bitwise_and_expression(self) -> Expression:
        left = self._parse_equality_expression()
        while self._eat(JsTokenKind.AMP):
            right = self._parse_equality_expression()
            left = JsBinaryExpression(
                left=left, operator='&', right=right, offset=left.offset)
        return left

    def _parse_equality_expression(self) -> Expression:
        left = self._parse_relational_expression()
        while self._at(
            JsTokenKind.EQ2, JsTokenKind.BANG_EQ,
            JsTokenKind.EQ3, JsTokenKind.BANG_EQ2,
        ):
            op = self._advance().value
            right = self._parse_relational_expression()
            left = JsBinaryExpression(
                left=left, operator=op, right=right, offset=left.offset)
        return left

    def _parse_relational_expression(self) -> Expression:
        left = self._parse_shift_expression()
        while self._at(
            JsTokenKind.LT, JsTokenKind.GT,
            JsTokenKind.LT_EQ, JsTokenKind.GT_EQ,
            JsTokenKind.INSTANCEOF, JsTokenKind.IN,
        ):
            if self._no_in and self._at(JsTokenKind.IN):
                break
            op = self._advance().value
            right = self._parse_shift_expression()
            left = JsBinaryExpression(
                left=left, operator=op, right=right, offset=left.offset)
        return left

    def _parse_shift_expression(self) -> Expression:
        left = self._parse_additive_expression()
        while self._at(
            JsTokenKind.LT2, JsTokenKind.GT2, JsTokenKind.GT3,
        ):
            op = self._advance().value
            right = self._parse_additive_expression()
            left = JsBinaryExpression(
                left=left, operator=op, right=right, offset=left.offset)
        return left

    def _parse_additive_expression(self) -> Expression:
        left = self._parse_multiplicative_expression()
        while self._at(JsTokenKind.PLUS, JsTokenKind.MINUS):
            op = self._advance().value
            right = self._parse_multiplicative_expression()
            left = JsBinaryExpression(
                left=left, operator=op, right=right, offset=left.offset)
        return left

    def _parse_multiplicative_expression(self) -> Expression:
        left = self._parse_exponentiation_expression()
        while self._at(JsTokenKind.STAR, JsTokenKind.SLASH, JsTokenKind.PERCENT):
            op = self._advance().value
            right = self._parse_exponentiation_expression()
            left = JsBinaryExpression(
                left=left, operator=op, right=right, offset=left.offset)
        return left

    def _parse_exponentiation_expression(self) -> Expression:
        expr = self._parse_unary_expression()
        if self._eat(JsTokenKind.STAR2):
            right = self._parse_exponentiation_expression()
            return JsBinaryExpression(
                left=expr, operator='**', right=right, offset=expr.offset)
        return expr

    def _parse_unary_expression(self) -> Expression:
        if self._at(
            JsTokenKind.BANG, JsTokenKind.TILDE,
            JsTokenKind.TYPEOF, JsTokenKind.VOID, JsTokenKind.DELETE,
        ):
            tok = self._advance()
            operand = self._parse_unary_expression()
            return JsUnaryExpression(
                operator=tok.value, operand=operand, prefix=True, offset=tok.offset)
        if self._at(JsTokenKind.PLUS) and not self._preceded_by_newline:
            tok = self._advance()
            operand = self._parse_unary_expression()
            return JsUnaryExpression(
                operator='+', operand=operand, prefix=True, offset=tok.offset)
        if self._at(JsTokenKind.MINUS) and not self._preceded_by_newline:
            tok = self._advance()
            operand = self._parse_unary_expression()
            return JsUnaryExpression(
                operator='-', operand=operand, prefix=True, offset=tok.offset)
        if self._at(JsTokenKind.AWAIT):
            tok = self._advance()
            operand = self._parse_unary_expression()
            return JsAwaitExpression(argument=operand, offset=tok.offset)
        return self._parse_update_expression()

    def _parse_update_expression(self) -> Expression:
        if self._at(JsTokenKind.INC, JsTokenKind.DEC):
            tok = self._advance()
            argument = self._parse_call_expression()
            return JsUpdateExpression(
                operator=tok.value, argument=argument, prefix=True, offset=tok.offset)
        expr = self._parse_call_expression()
        if not self._preceded_by_newline and self._at(
            JsTokenKind.INC, JsTokenKind.DEC,
        ):
            tok = self._advance()
            return JsUpdateExpression(
                operator=tok.value, argument=expr, prefix=False, offset=expr.offset)
        return expr

    def _parse_call_expression(self) -> Expression:
        expr = self._parse_new_expression()
        while True:
            if self._at(JsTokenKind.LPAREN):
                expr = self._parse_call_arguments(expr, optional=False)
            elif self._eat(JsTokenKind.DOT):
                prop_tok = self._advance()
                prop = JsIdentifier(name=prop_tok.value, offset=prop_tok.offset)
                expr = JsMemberExpression(
                    object=expr, property=prop,
                    computed=False, optional=False, offset=expr.offset)
            elif self._at(JsTokenKind.LBRACKET):
                self._advance()
                prop = self._parse_expression()
                self._expect(JsTokenKind.RBRACKET)
                expr = JsMemberExpression(
                    object=expr, property=prop,
                    computed=True, optional=False, offset=expr.offset)
            elif self._eat(JsTokenKind.QUESTION_DOT):
                if self._at(JsTokenKind.LPAREN):
                    expr = self._parse_call_arguments(expr, optional=True)
                elif self._at(JsTokenKind.LBRACKET):
                    self._advance()
                    prop = self._parse_expression()
                    self._expect(JsTokenKind.RBRACKET)
                    expr = JsMemberExpression(
                        object=expr, property=prop,
                        computed=True, optional=True, offset=expr.offset)
                else:
                    prop_tok = self._advance()
                    prop = JsIdentifier(name=prop_tok.value, offset=prop_tok.offset)
                    expr = JsMemberExpression(
                        object=expr, property=prop,
                        computed=False, optional=True, offset=expr.offset)
            elif self._at(
                JsTokenKind.TEMPLATE_FULL, JsTokenKind.TEMPLATE_HEAD,
            ):
                quasi = self._parse_template_literal()
                expr = JsTaggedTemplateExpression(
                    tag=expr, quasi=quasi, offset=expr.offset)
            else:
                break
        return expr

    def _parse_call_arguments(
        self,
        callee: Expression,
        optional: bool,
    ) -> JsCallExpression:
        saved_no_in = self._no_in
        self._no_in = False
        self._expect(JsTokenKind.LPAREN)
        args: list[Expression] = []
        while not self._at(JsTokenKind.RPAREN, JsTokenKind.EOF):
            if self._at(JsTokenKind.ELLIPSIS):
                offset = self._current.offset
                self._advance()
                arg = self._parse_assignment_expression()
                args.append(JsSpreadElement(argument=arg, offset=offset))
            else:
                args.append(self._parse_assignment_expression())
            if not self._at(JsTokenKind.RPAREN):
                self._expect(JsTokenKind.COMMA)
        self._expect(JsTokenKind.RPAREN)
        self._no_in = saved_no_in
        return JsCallExpression(
            callee=callee, arguments=args, optional=optional, offset=callee.offset)

    def _parse_new_expression(self) -> Expression:
        if self._at(JsTokenKind.NEW):
            offset = self._current.offset
            self._advance()
            if self._at(JsTokenKind.DOT):
                self._advance()
                tok = self._advance()
                return JsMemberExpression(
                    object=JsIdentifier(name='new', offset=offset),
                    property=JsIdentifier(name=tok.value, offset=tok.offset),
                    computed=False,
                    offset=offset,
                )
            callee = self._parse_new_expression()
            args: list[Expression] = []
            if self._at(JsTokenKind.LPAREN):
                self._advance()
                while not self._at(JsTokenKind.RPAREN, JsTokenKind.EOF):
                    if self._at(JsTokenKind.ELLIPSIS):
                        so = self._current.offset
                        self._advance()
                        arg = self._parse_assignment_expression()
                        args.append(JsSpreadElement(argument=arg, offset=so))
                    else:
                        args.append(self._parse_assignment_expression())
                    if not self._at(JsTokenKind.RPAREN):
                        self._expect(JsTokenKind.COMMA)
                self._expect(JsTokenKind.RPAREN)
            return JsNewExpression(callee=callee, arguments=args, offset=offset)
        return self._parse_primary_expression()

    def _parse_primary_expression(self) -> Expression:
        tok = self._current
        offset = tok.offset

        if self._at(JsTokenKind.IDENTIFIER):
            self._advance()
            if self._at(JsTokenKind.ARROW) and not self._preceded_by_newline:
                self._advance()
                param = JsIdentifier(name=tok.value, offset=offset)
                body = self._parse_arrow_body()
                return JsArrowFunctionExpression(
                    params=[param], body=body, offset=offset)
            return JsIdentifier(name=tok.value, offset=offset)

        if self._at(JsTokenKind.INTEGER):
            self._advance()
            raw = tok.value
            text = raw.replace('_', '')
            if text.startswith(('0x', '0X')):
                value = int(text, 16)
            elif text.startswith(('0o', '0O')):
                value = int(text, 8)
            elif text.startswith(('0b', '0B')):
                value = int(text, 2)
            else:
                value = int(text)
            return JsNumericLiteral(value=value, raw=raw, offset=offset)

        if self._at(JsTokenKind.FLOAT):
            self._advance()
            raw = tok.value
            value = float(raw.replace('_', ''))
            return JsNumericLiteral(value=value, raw=raw, offset=offset)

        if self._at(JsTokenKind.BIGINT):
            self._advance()
            raw = tok.value
            text = raw.replace('_', '').rstrip('n')
            if text.startswith(('0x', '0X')):
                value = int(text, 16)
            elif text.startswith(('0o', '0O')):
                value = int(text, 8)
            elif text.startswith(('0b', '0B')):
                value = int(text, 2)
            else:
                value = int(text)
            return JsBigIntLiteral(value=value, raw=raw, offset=offset)

        if self._at(JsTokenKind.STRING_SINGLE, JsTokenKind.STRING_DOUBLE):
            return self._parse_string_literal()

        if self._at(JsTokenKind.REGEXP):
            self._advance()
            raw = tok.value
            last_slash = raw.rfind('/')
            pattern = raw[1:last_slash]
            flags = raw[last_slash + 1:]
            return JsRegExpLiteral(
                pattern=pattern, flags=flags, raw=raw, offset=offset)

        if self._at(JsTokenKind.TEMPLATE_FULL, JsTokenKind.TEMPLATE_HEAD):
            return self._parse_template_literal()

        if self._at(JsTokenKind.TRUE):
            self._advance()
            return JsBooleanLiteral(value=True, offset=offset)
        if self._at(JsTokenKind.FALSE):
            self._advance()
            return JsBooleanLiteral(value=False, offset=offset)
        if self._at(JsTokenKind.NULL):
            self._advance()
            return JsNullLiteral(offset=offset)
        if self._at(JsTokenKind.THIS):
            self._advance()
            return JsThisExpression(offset=offset)
        if self._at(JsTokenKind.SUPER):
            self._advance()
            return JsIdentifier(name='super', offset=offset)

        if self._at(JsTokenKind.LBRACKET):
            return self._parse_array_literal()
        if self._at(JsTokenKind.LBRACE):
            return self._parse_object_literal()

        if self._at(JsTokenKind.LPAREN):
            return self._parse_paren_or_arrow()

        if self._at(JsTokenKind.FUNCTION):
            return self._parse_function_expression()
        if self._at(JsTokenKind.CLASS):
            return self._parse_class_expression()

        if self._at(JsTokenKind.ASYNC):
            return self._parse_async_expression()

        if self._at(JsTokenKind.YIELD):
            return self._parse_yield_expression()

        self._advance()
        return JsErrorNode(text=tok.value, message='unexpected token', offset=offset)

    def _parse_string_literal(self) -> JsStringLiteral:
        tok = self._advance()
        raw = tok.value
        if len(raw) >= 2:
            value = self._decode_string_value(raw[1:-1])
        else:
            value = raw
        return JsStringLiteral(value=value, raw=raw, offset=tok.offset)

    @staticmethod
    def _decode_string_value(text: str) -> str:
        parts: list[str] = []
        i = 0
        length = len(text)
        while i < length:
            c = text[i]
            if c != '\\' or i + 1 >= length:
                parts.append(c)
                i += 1
                continue
            i += 1
            c = text[i]
            i += 1
            mapped = _ESCAPE_MAP.get(c)
            if mapped is not None:
                parts.append(mapped)
                continue
            if c == 'x' and i + 1 < length:
                hexstr = text[i:i + 2]
                if len(hexstr) == 2 and all(
                    h in '0123456789abcdefABCDEF' for h in hexstr
                ):
                    parts.append(chr(int(hexstr, 16)))
                    i += 2
                    continue
                parts.append('x')
                continue
            if c == 'u':
                if i < length and text[i] == '{':
                    end = text.find('}', i + 1)
                    if end != -1:
                        hexstr = text[i + 1:end]
                        if hexstr and all(
                            h in '0123456789abcdefABCDEF' for h in hexstr
                        ):
                            parts.append(chr(int(hexstr, 16)))
                            i = end + 1
                            continue
                        i = end + 1
                        parts.append('u')
                        continue
                elif i + 3 < length:
                    hexstr = text[i:i + 4]
                    if len(hexstr) == 4 and all(
                        h in '0123456789abcdefABCDEF' for h in hexstr
                    ):
                        parts.append(chr(int(hexstr, 16)))
                        i += 4
                        continue
                parts.append('u')
                continue
            if c in '\r\n':
                if c == '\r' and i < length and text[i] == '\n':
                    i += 1
                continue
            parts.append(c)
        return ''.join(parts)

    def _parse_template_literal(self) -> JsTemplateLiteral:
        offset = self._current.offset
        quasis: list[JsTemplateElement] = []
        expressions: list[Expression] = []

        if self._at(JsTokenKind.TEMPLATE_FULL):
            tok = self._advance()
            raw = tok.value
            value = raw[1:-1]
            quasis.append(JsTemplateElement(
                value=value, raw=raw, tail=True, offset=tok.offset))
            return JsTemplateLiteral(
                quasis=quasis, expressions=expressions, offset=offset)

        tok = self._advance()
        raw = tok.value
        value = raw[1:-2]
        quasis.append(JsTemplateElement(
            value=value, raw=raw, tail=False, offset=tok.offset))

        while True:
            expr = self._parse_expression()
            expressions.append(expr)
            if self._at(JsTokenKind.TEMPLATE_TAIL):
                tok = self._advance()
                raw = tok.value
                value = raw[1:-1]
                quasis.append(JsTemplateElement(
                    value=value, raw=raw, tail=True, offset=tok.offset))
                break
            elif self._at(JsTokenKind.TEMPLATE_MIDDLE):
                tok = self._advance()
                raw = tok.value
                value = raw[1:-2]
                quasis.append(JsTemplateElement(
                    value=value, raw=raw, tail=False, offset=tok.offset))
            else:
                quasis.append(JsTemplateElement(
                    value='', raw='', tail=True, offset=self._current.offset))
                break

        return JsTemplateLiteral(
            quasis=quasis, expressions=expressions, offset=offset)

    def _parse_array_literal(self) -> JsArrayExpression:
        saved_no_in = self._no_in
        self._no_in = False
        offset = self._current.offset
        self._expect(JsTokenKind.LBRACKET)
        elements: list[Expression | None] = []
        while not self._at(JsTokenKind.RBRACKET, JsTokenKind.EOF):
            if self._at(JsTokenKind.COMMA):
                elements.append(None)
                self._advance()
                continue
            if self._at(JsTokenKind.ELLIPSIS):
                so = self._current.offset
                self._advance()
                arg = self._parse_assignment_expression()
                elements.append(JsSpreadElement(argument=arg, offset=so))
            else:
                elements.append(self._parse_assignment_expression())
            if not self._at(JsTokenKind.RBRACKET):
                self._eat(JsTokenKind.COMMA)
        self._expect(JsTokenKind.RBRACKET)
        self._no_in = saved_no_in
        return JsArrayExpression(elements=elements, offset=offset)

    def _parse_object_literal(self) -> JsObjectExpression:
        saved_no_in = self._no_in
        self._no_in = False
        offset = self._current.offset
        self._expect(JsTokenKind.LBRACE)
        properties: list[JsProperty | JsSpreadElement] = []
        while not self._at(JsTokenKind.RBRACE, JsTokenKind.EOF):
            if self._at(JsTokenKind.ELLIPSIS):
                so = self._current.offset
                self._advance()
                arg = self._parse_assignment_expression()
                properties.append(JsSpreadElement(argument=arg, offset=so))
            else:
                properties.append(self._parse_object_property())
            if not self._at(JsTokenKind.RBRACE):
                self._eat(JsTokenKind.COMMA)
        self._expect(JsTokenKind.RBRACE)
        self._no_in = saved_no_in
        return JsObjectExpression(properties=properties, offset=offset)

    def _parse_object_property(self) -> JsProperty:
        offset = self._current.offset
        is_generator = bool(self._eat(JsTokenKind.STAR))

        if self._at(JsTokenKind.IDENTIFIER) and self._current.value in ('get', 'set'):
            kind_val = self._current.value
            saved = self._current
            self._advance()
            if self._at(
                JsTokenKind.LPAREN,
                JsTokenKind.COLON,
                JsTokenKind.COMMA,
                JsTokenKind.RBRACE,
                JsTokenKind.EQUALS
            ):
                key = JsIdentifier(name=kind_val, offset=saved.offset)
                return self._finish_property_value(key, False, False, offset)
            key = self._parse_property_name_from_current()
            return self._make_method_property(key, kind_val, False, offset)

        if self._at(JsTokenKind.ASYNC) and not is_generator:
            saved = self._current
            self._advance()
            if self._preceded_by_newline or self._at(
                JsTokenKind.COLON, JsTokenKind.COMMA,
                JsTokenKind.RBRACE, JsTokenKind.EQUALS,
                JsTokenKind.LPAREN,
            ):
                if self._at(JsTokenKind.LPAREN):
                    key = JsIdentifier(name='async', offset=saved.offset)
                    return self._make_method_property(key, 'init', False, offset)
                key = JsIdentifier(name='async', offset=saved.offset)
                return self._finish_property_value(key, False, False, offset)
            gen = bool(self._eat(JsTokenKind.STAR))
            key = self._parse_property_name_from_current()
            return self._make_method_property(key, 'init', gen, offset, is_async=True)

        computed = False
        if self._at(JsTokenKind.LBRACKET):
            computed = True
            self._advance()
            key = self._parse_assignment_expression()
            self._expect(JsTokenKind.RBRACKET)
        else:
            key = self._parse_property_name()

        if is_generator or self._at(JsTokenKind.LPAREN):
            return self._make_method_property(key, 'init', is_generator, offset, computed=computed)

        return self._finish_property_value(key, computed, False, offset)

    def _finish_property_value(
        self,
        key: Expression,
        computed: bool,
        is_generator: bool,
        offset: int,
    ) -> JsProperty:
        if self._eat(JsTokenKind.COLON):
            value = self._parse_assignment_expression()
            return JsProperty(
                key=key, value=value, computed=computed,
                shorthand=False, offset=offset)
        return JsProperty(
            key=key, value=key, computed=computed,
            shorthand=True, offset=offset)

    def _make_method_property(
        self,
        key: Expression,
        kind: str,
        is_generator: bool,
        offset: int,
        computed: bool = False,
        is_async: bool = False,
    ) -> JsProperty:
        func_offset = self._current.offset
        params = self._parse_formal_parameters()
        body = self._parse_block_statement()
        value = JsFunctionExpression(
            params=params, body=body, generator=is_generator,
            is_async=is_async, offset=func_offset)
        return JsProperty(
            key=key, value=value, computed=computed,
            shorthand=False, method=True, kind=kind, offset=offset)

    def _parse_property_name(self) -> Expression:
        tok = self._current
        if self._at(JsTokenKind.INTEGER, JsTokenKind.FLOAT):
            self._advance()
            raw = tok.value
            text = raw.replace('_', '')
            return JsNumericLiteral(
                value=float(text) if tok.kind == JsTokenKind.FLOAT else int(text),
                raw=raw,
                offset=tok.offset,
            )
        if self._at(JsTokenKind.STRING_SINGLE, JsTokenKind.STRING_DOUBLE):
            return self._parse_string_literal()
        self._advance()
        return JsIdentifier(name=tok.value, offset=tok.offset)

    def _parse_property_name_from_current(self) -> Expression:
        return self._parse_property_name()

    def _parse_paren_or_arrow(self) -> Expression:
        saved_no_in = self._no_in
        self._no_in = False
        try:
            offset = self._current.offset
            self._expect(JsTokenKind.LPAREN)

            if self._at(JsTokenKind.RPAREN):
                self._advance()
                self._expect(JsTokenKind.ARROW)
                body = self._parse_arrow_body()
                return JsArrowFunctionExpression(params=[], body=body, offset=offset)

            if self._at(JsTokenKind.ELLIPSIS):
                params = self._parse_arrow_params_rest()
                self._expect(JsTokenKind.RPAREN)
                self._expect(JsTokenKind.ARROW)
                body = self._parse_arrow_body()
                return JsArrowFunctionExpression(params=params, body=body, offset=offset)

            expr = self._parse_expression()

            if self._at(JsTokenKind.RPAREN):
                self._advance()
                if self._at(JsTokenKind.ARROW) and not self._preceded_by_newline:
                    self._advance()
                    params = self._expr_to_params(expr)
                    body = self._parse_arrow_body()
                    return JsArrowFunctionExpression(
                        params=params, body=body, offset=offset)
                return JsParenthesizedExpression(expression=expr, offset=offset)

            self._expect(JsTokenKind.RPAREN)
            return JsParenthesizedExpression(expression=expr, offset=offset)
        finally:
            self._no_in = saved_no_in

    def _parse_arrow_params_rest(self) -> list[Expression]:
        params: list[Expression] = []
        while self._at(JsTokenKind.ELLIPSIS):
            params.append(self._parse_rest_element())
            if self._at(JsTokenKind.COMMA):
                self._advance()
        return params

    def _parse_arrow_body(self) -> Expression | JsBlockStatement:
        if self._at(JsTokenKind.LBRACE):
            return self._parse_block_statement()
        return self._parse_assignment_expression()

    def _expr_to_params(self, expr: Expression) -> list[Expression]:
        if isinstance(expr, JsSequenceExpression):
            return [self._to_param(e) for e in expr.expressions]
        return [self._to_param(expr)]

    def _to_param(self, expr: Expression) -> Expression:
        if isinstance(expr, JsIdentifier):
            return expr
        if isinstance(expr, JsAssignmentExpression) and expr.operator == '=':
            return JsAssignmentPattern(
                left=self._to_param(expr.left),
                right=expr.right,
                offset=expr.offset,
            )
        if isinstance(expr, JsSpreadElement):
            return JsRestElement(argument=self._to_param(expr.argument), offset=expr.offset)
        if isinstance(expr, JsArrayExpression):
            elements = [
                self._to_param(e) if e is not None else None
                for e in expr.elements
            ]
            return JsArrayPattern(elements=elements, offset=expr.offset)
        if isinstance(expr, JsObjectExpression):
            props: list[JsProperty | JsRestElement] = []
            for p in expr.properties:
                if isinstance(p, JsSpreadElement):
                    props.append(JsRestElement(
                        argument=self._to_param(p.argument), offset=p.offset))
                else:
                    props.append(p)
            return JsObjectPattern(properties=props, offset=expr.offset)
        return expr

    def _to_pattern(self, expr: Expression) -> Expression:
        if isinstance(expr, JsArrayExpression):
            elements = [
                self._to_pattern(e) if e is not None else None
                for e in expr.elements
            ]
            return JsArrayPattern(elements=elements, offset=expr.offset)
        if isinstance(expr, JsObjectExpression):
            props: list[JsProperty | JsRestElement] = []
            for p in expr.properties:
                if isinstance(p, JsSpreadElement):
                    props.append(JsRestElement(
                        argument=self._to_pattern(p.argument), offset=p.offset))
                else:
                    props.append(p)
            return JsObjectPattern(properties=props, offset=expr.offset)
        return expr

    def _parse_function_expression(self) -> JsFunctionExpression:
        offset = self._current.offset
        self._expect(JsTokenKind.FUNCTION)
        generator = bool(self._eat(JsTokenKind.STAR))
        id_node = None
        if self._at(JsTokenKind.IDENTIFIER):
            tok = self._advance()
            id_node = JsIdentifier(name=tok.value, offset=tok.offset)
        params = self._parse_formal_parameters()
        body = self._parse_block_statement()
        return JsFunctionExpression(
            id=id_node, params=params, body=body,
            generator=generator, offset=offset)

    def _parse_class_expression(self) -> JsClassExpression:
        offset = self._current.offset
        self._expect(JsTokenKind.CLASS)
        id_node = None
        if self._at(JsTokenKind.IDENTIFIER):
            tok = self._advance()
            id_node = JsIdentifier(name=tok.value, offset=tok.offset)
        super_class = None
        if self._eat(JsTokenKind.EXTENDS):
            super_class = self._parse_assignment_expression()
        body = self._parse_class_body()
        return JsClassExpression(
            id=id_node, super_class=super_class, body=body, offset=offset)

    def _parse_async_expression(self) -> Expression:
        offset = self._current.offset
        self._advance()
        return self._parse_expression_starting_with_async(offset)

    def _parse_expression_starting_with_async(self, offset: int) -> Expression:
        if self._at(JsTokenKind.FUNCTION) and not self._preceded_by_newline:
            self._advance()
            generator = bool(self._eat(JsTokenKind.STAR))
            id_node = None
            if self._at(JsTokenKind.IDENTIFIER):
                tok = self._advance()
                id_node = JsIdentifier(name=tok.value, offset=tok.offset)
            params = self._parse_formal_parameters()
            body = self._parse_block_statement()
            return JsFunctionExpression(
                id=id_node, params=params, body=body,
                generator=generator, is_async=True, offset=offset)

        if self._at(JsTokenKind.IDENTIFIER) and not self._preceded_by_newline:
            tok = self._advance()
            if self._at(JsTokenKind.ARROW) and not self._preceded_by_newline:
                self._advance()
                param = JsIdentifier(name=tok.value, offset=tok.offset)
                body = self._parse_arrow_body()
                return JsArrowFunctionExpression(
                    params=[param], body=body, is_async=True, offset=offset)
            return JsIdentifier(name=tok.value, offset=tok.offset)

        if self._at(JsTokenKind.LPAREN) and not self._preceded_by_newline:
            paren_result = self._parse_paren_or_arrow()
            if isinstance(paren_result, JsArrowFunctionExpression):
                paren_result.is_async = True
                paren_result.offset = offset
            return paren_result

        return JsIdentifier(name='async', offset=offset)

    def _parse_yield_expression(self) -> JsYieldExpression:
        offset = self._current.offset
        self._advance()
        delegate = False
        if self._eat(JsTokenKind.STAR):
            delegate = True
        argument = None
        if not self._preceded_by_newline and not self._at(
            JsTokenKind.SEMICOLON, JsTokenKind.RBRACE,
            JsTokenKind.RPAREN, JsTokenKind.RBRACKET,
            JsTokenKind.COMMA, JsTokenKind.COLON, JsTokenKind.EOF,
        ):
            argument = self._parse_assignment_expression()
        return JsYieldExpression(
            argument=argument, delegate=delegate, offset=offset)
