from __future__ import annotations

from refinery.lib.scripts.vba.lexer import VbaLexer
from refinery.lib.scripts.vba.model import (
    Expression,
    Statement,
    VbaBangAccess,
    VbaBinaryExpression,
    VbaBooleanLiteral,
    VbaByValArgument,
    VbaCallExpression,
    VbaCallStatement,
    VbaCaseClause,
    VbaConstDeclaration,
    VbaConstDeclarator,
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
    VbaExitKind,
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
    VbaIntegerLiteral,
    VbaLabelStatement,
    VbaLetStatement,
    VbaLoopConditionPosition,
    VbaLoopConditionType,
    VbaMeExpression,
    VbaMemberAccess,
    VbaModule,
    VbaNamedArgument,
    VbaNewExpression,
    VbaNothingLiteral,
    VbaNullLiteral,
    VbaOnBranchKind,
    VbaOnBranchStatement,
    VbaOnErrorAction,
    VbaOnErrorStatement,
    VbaOptionStatement,
    VbaParameter,
    VbaParameterPassing,
    VbaParenExpression,
    VbaPropertyDeclaration,
    VbaPropertyKind,
    VbaRaiseEventStatement,
    VbaRangeExpression,
    VbaRedimStatement,
    VbaResumeStatement,
    VbaReturnStatement,
    VbaScopeModifier,
    VbaSelectCaseStatement,
    VbaSetStatement,
    VbaStopStatement,
    VbaStringLiteral,
    VbaSubDeclaration,
    VbaTypeDefinition,
    VbaTypeOfIsExpression,
    VbaUnaryExpression,
    VbaVariableDeclaration,
    VbaVariableDeclarator,
    VbaWhileStatement,
    VbaWithStatement,
)
from refinery.lib.scripts.vba.token import VbaToken, VbaTokenKind


class VbaParser:

    _PAREN_ARG_STOP = frozenset({VbaTokenKind.RPAREN})

    def __init__(self, source: str):
        self._lexer = VbaLexer(source)
        self._source = source
        self._tokens = self._lexer.tokenize()
        self._current: VbaToken = VbaToken(VbaTokenKind.EOF, '', 0)
        self._in_single_line_if = False
        self._pending_next: int = 0
        self._advance()

    def _advance(self) -> VbaToken:
        prev = self._current
        while True:
            tok = next(self._tokens, VbaToken(VbaTokenKind.EOF, '', len(self._source)))
            if tok.kind == VbaTokenKind.COMMENT:
                continue
            break
        self._current = tok
        return prev

    def _at(self, *kinds: VbaTokenKind) -> bool:
        return self._current.kind in kinds

    def _at_keyword(self, *words: str) -> bool:
        if self._current.kind == VbaTokenKind.IDENTIFIER:
            return self._current.value.lower() in words
        if self._current.kind.is_keyword:
            return self._current.value.lower() in words
        return False

    def _eat(self, kind: VbaTokenKind) -> VbaToken | None:
        if self._current.kind == kind:
            return self._advance()
        return None

    def _eat_keyword(self, *words: str) -> VbaToken | None:
        if self._at_keyword(*words):
            return self._advance()
        return None

    def _expect(self, kind: VbaTokenKind) -> VbaToken:
        if self._current.kind == kind:
            return self._advance()
        tok = self._current
        self._advance()
        return VbaToken(kind, tok.value, tok.offset)

    def _eat_eos(self):
        while self._at(VbaTokenKind.NEWLINE, VbaTokenKind.COLON):
            self._advance()

    def _expect_eos(self):
        if self._at(VbaTokenKind.NEWLINE, VbaTokenKind.COLON, VbaTokenKind.EOF):
            self._eat_eos()
        else:
            self._advance()
            self._eat_eos()

    def _eat_end(self, keyword: str) -> bool:
        if self._at(VbaTokenKind.END):
            saved = self._current
            self._advance()
            if self._at_keyword(keyword):
                self._advance()
                return True
            self._current = saved
        if self._at_keyword(F'end{keyword}'):
            self._advance()
            return True
        return False

    def _eat_go_keyword(self) -> str:
        if self._at(VbaTokenKind.GOTO):
            self._advance()
            return 'goto'
        if self._at(VbaTokenKind.GOSUB):
            self._advance()
            return 'gosub'
        if self._at_keyword('go'):
            self._advance()
            if self._at(VbaTokenKind.TO):
                self._advance()
                return 'goto'
            if self._at(VbaTokenKind.SUB):
                self._advance()
                return 'gosub'
        return ''

    def _peek_after_current(self) -> str:
        return self._source[self._current.offset + len(self._current.value):].lstrip(' \t')

    def _comma_list(self, parse_element) -> list:
        items = [parse_element()]
        while self._eat(VbaTokenKind.COMMA):
            items.append(parse_element())
        return items

    def parse(self) -> VbaModule:
        return self._parse_module()

    def _parse_module(self) -> VbaModule:
        offset = self._current.offset
        body: list[Statement] = []
        self._eat_eos()
        while not self._at(VbaTokenKind.EOF):
            stmt = self._parse_module_element()
            if stmt is not None:
                body.append(stmt)
            self._eat_eos()
        return VbaModule(body=body, offset=offset)

    def _parse_module_element(self) -> Statement | None:
        if self._at_keyword('option'):
            return self._parse_option_statement()

        scope = VbaScopeModifier.NONE
        is_static = False
        if self._at_keyword('public', 'private', 'friend'):
            scope = VbaScopeModifier(self._current.value.capitalize())
            self._advance()
        if self._at_keyword('static'):
            is_static = True
            self._advance()

        if self._at_keyword('sub'):
            return self._parse_sub_declaration(scope, is_static)
        if self._at_keyword('function'):
            return self._parse_function_declaration(scope, is_static)
        if self._at_keyword('property'):
            return self._parse_property_declaration(scope, is_static)
        if self._at_keyword('declare'):
            return self._parse_declare_statement(scope)
        if self._at_keyword('type'):
            return self._parse_type_definition(scope)
        if self._at_keyword('enum'):
            return self._parse_enum_definition(scope)
        if self._at_keyword('const'):
            return self._parse_const_declaration(scope)
        if self._at_keyword('dim', 'global'):
            dim_scope = scope if scope is not VbaScopeModifier.NONE else VbaScopeModifier(
                self._current.value.capitalize())
            return self._parse_variable_declaration(dim_scope)
        if self._at_keyword('event'):
            return self._parse_event_declaration(scope)
        if self._at_keyword('implements'):
            return self._parse_implements_statement()
        if scope is not VbaScopeModifier.NONE and not is_static:
            return self._parse_variable_declaration(scope)
        if self._at_keyword('withevents'):
            we_scope = scope if scope is not VbaScopeModifier.NONE else VbaScopeModifier.PRIVATE
            return self._parse_variable_declaration(we_scope)

        if self._at_keyword('attribute'):
            return self._skip_to_eos()

        return self._parse_statement()

    def _parse_option_statement(self) -> VbaOptionStatement:
        offset = self._current.offset
        self._advance()
        keyword = self._current.value
        self._advance()
        value = ''
        if not self._at(VbaTokenKind.NEWLINE, VbaTokenKind.COLON, VbaTokenKind.EOF):
            value = self._current.value
            self._advance()
        self._eat_eos()
        return VbaOptionStatement(keyword=keyword, value=value, offset=offset)

    def _parse_declare_statement(self, scope: VbaScopeModifier) -> VbaDeclareStatement:
        offset = self._current.offset
        self._advance()
        self._eat_keyword('ptrsafe')
        is_function = self._at_keyword('function')
        self._advance()
        name = self._current.value
        self._advance()
        lib = ''
        if self._at_keyword('lib'):
            self._advance()
            lib = self._current.value
            self._advance()
        alias = ''
        if self._at_keyword('alias'):
            self._advance()
            alias = self._current.value
            self._advance()
        params: list[VbaParameter] = []
        if self._at(VbaTokenKind.LPAREN):
            params = self._parse_parameter_list()
        return_type = ''
        if self._eat(VbaTokenKind.AS):
            return_type = self._parse_type_name()
        self._eat_eos()
        return VbaDeclareStatement(
            scope=scope, name=name, lib=lib, alias=alias,
            is_function=is_function, params=params,
            return_type=return_type, offset=offset,
        )

    def _parse_type_definition(self, scope: VbaScopeModifier) -> VbaTypeDefinition:
        offset = self._current.offset
        self._advance()
        name = self._current.value
        self._advance()
        self._eat_eos()
        members: list[VbaVariableDeclarator] = []
        while not self._at(VbaTokenKind.EOF):
            if self._eat_end('type'):
                break
            m_offset = self._current.offset
            m_name = self._current.value
            self._advance()
            bounds: list[Expression] = []
            if self._at(VbaTokenKind.LPAREN):
                self._advance()
                if not self._at(VbaTokenKind.RPAREN):
                    bounds = self._parse_bounds_list()
                self._expect(VbaTokenKind.RPAREN)
            type_name = ''
            if self._eat(VbaTokenKind.AS):
                type_name = self._parse_type_name()
            members.append(VbaVariableDeclarator(
                name=m_name, type_name=type_name, bounds=bounds, offset=m_offset))
            self._eat_eos()
        self._eat_eos()
        return VbaTypeDefinition(scope=scope, name=name, members=members, offset=offset)

    def _parse_enum_definition(self, scope: VbaScopeModifier) -> VbaEnumDefinition:
        offset = self._current.offset
        self._advance()
        name = self._current.value
        self._advance()
        self._eat_eos()
        members: list[VbaEnumMember] = []
        while not self._at(VbaTokenKind.EOF):
            if self._eat_end('enum'):
                break
            m_offset = self._current.offset
            m_name = self._current.value
            self._advance()
            value: Expression | None = None
            if self._eat(VbaTokenKind.EQ):
                value = self._parse_expression()
            members.append(VbaEnumMember(name=m_name, value=value, offset=m_offset))
            self._eat_eos()
        self._eat_eos()
        return VbaEnumDefinition(scope=scope, name=name, members=members, offset=offset)

    def _parse_const_declarator(self) -> VbaConstDeclarator:
        offset = self._current.offset
        name = self._current.value
        self._advance()
        type_name = ''
        if self._eat(VbaTokenKind.AS):
            type_name = self._parse_type_name()
        self._expect(VbaTokenKind.EQ)
        value = self._parse_expression()
        return VbaConstDeclarator(name=name, type_name=type_name, value=value, offset=offset)

    def _parse_const_declaration(self, scope: VbaScopeModifier) -> VbaConstDeclaration:
        offset = self._current.offset
        self._advance()
        declarators = self._comma_list(self._parse_const_declarator)
        self._eat_eos()
        return VbaConstDeclaration(scope=scope, declarators=declarators, offset=offset)

    def _parse_variable_declaration(self, scope: VbaScopeModifier) -> VbaVariableDeclaration:
        offset = self._current.offset
        self._eat_keyword('dim', 'global', 'static')
        self._eat_keyword('shared')
        declarators = self._comma_list(self._parse_variable_declarator)
        self._eat_eos()
        return VbaVariableDeclaration(
            scope=scope, declarators=declarators, offset=offset)

    def _parse_declarator_suffix(self, allow_new: bool = False) -> tuple[bool, list[Expression], str, bool]:
        bounds: list[Expression] = []
        is_array = False
        if self._at(VbaTokenKind.LPAREN):
            is_array = True
            self._advance()
            if not self._at(VbaTokenKind.RPAREN):
                bounds = self._parse_bounds_list()
            self._expect(VbaTokenKind.RPAREN)
        type_name = ''
        is_new = False
        if self._eat(VbaTokenKind.AS):
            if allow_new and self._eat(VbaTokenKind.NEW):
                is_new = True
            type_name = self._parse_type_name()
        return is_array, bounds, type_name, is_new

    def _parse_variable_declarator(self) -> VbaVariableDeclarator:
        offset = self._current.offset
        with_events = bool(self._eat(VbaTokenKind.WITHEVENTS))
        name = self._current.value
        self._advance()
        is_array, bounds, type_name, is_new = self._parse_declarator_suffix(allow_new=True)
        return VbaVariableDeclarator(
            name=name, type_name=type_name, is_array=is_array,
            bounds=bounds, is_new=is_new, with_events=with_events, offset=offset,
        )

    def _parse_event_declaration(self, scope: VbaScopeModifier) -> VbaEventDeclaration:
        offset = self._current.offset
        self._advance()
        name = self._current.value
        self._advance()
        params: list[VbaParameter] = []
        if self._at(VbaTokenKind.LPAREN):
            params = self._parse_parameter_list()
        self._eat_eos()
        return VbaEventDeclaration(scope=scope, name=name, params=params, offset=offset)

    def _parse_implements_statement(self) -> VbaImplementsStatement:
        offset = self._current.offset
        self._advance()
        name = self._parse_type_name()
        self._eat_eos()
        return VbaImplementsStatement(name=name, offset=offset)

    def _parse_procedure_body(
        self, end_keyword: str, has_return_type: bool,
    ) -> tuple[str, list[VbaParameter], str, list[Statement]]:
        name = self._current.value
        self._advance()
        params: list[VbaParameter] = []
        if self._at(VbaTokenKind.LPAREN):
            params = self._parse_parameter_list()
        return_type = ''
        if has_return_type and self._eat(VbaTokenKind.AS):
            return_type = self._parse_type_name()
        self._eat_eos()
        body = self._parse_block_until(end_keyword)
        return name, params, return_type, body

    def _parse_sub_declaration(
        self, scope: VbaScopeModifier, is_static: bool,
    ) -> VbaSubDeclaration:
        offset = self._current.offset
        self._advance()
        name, params, _, body = self._parse_procedure_body('sub', has_return_type=False)
        return VbaSubDeclaration(
            scope=scope, name=name, params=params,
            body=body, is_static=is_static, offset=offset,
        )

    def _parse_function_declaration(
        self, scope: VbaScopeModifier, is_static: bool,
    ) -> VbaFunctionDeclaration:
        offset = self._current.offset
        self._advance()
        name, params, return_type, body = self._parse_procedure_body(
            'function', has_return_type=True)
        return VbaFunctionDeclaration(
            scope=scope, name=name, params=params,
            return_type=return_type, body=body,
            is_static=is_static, offset=offset,
        )

    def _parse_property_declaration(
        self, scope: VbaScopeModifier, is_static: bool,
    ) -> VbaPropertyDeclaration:
        offset = self._current.offset
        self._advance()
        kind = VbaPropertyKind(self._current.value.capitalize())
        self._advance()
        name, params, return_type, body = self._parse_procedure_body(
            'property', has_return_type=True)
        return VbaPropertyDeclaration(
            scope=scope, kind=kind, name=name, params=params,
            return_type=return_type, body=body,
            is_static=is_static, offset=offset,
        )

    def _parse_parameter_list(self) -> list[VbaParameter]:
        self._expect(VbaTokenKind.LPAREN)
        params: list[VbaParameter] = []
        while not self._at(VbaTokenKind.RPAREN, VbaTokenKind.EOF):
            params.append(self._parse_parameter())
            if not self._at(VbaTokenKind.RPAREN):
                self._expect(VbaTokenKind.COMMA)
        self._expect(VbaTokenKind.RPAREN)
        return params

    def _parse_parameter(self) -> VbaParameter:
        offset = self._current.offset
        is_optional = False
        is_paramarray = False
        passing = VbaParameterPassing.NONE

        while True:
            if self._at_keyword('optional'):
                is_optional = True
                self._advance()
            elif self._at(VbaTokenKind.BYVAL):
                passing = VbaParameterPassing.BY_VAL
                self._advance()
            elif self._at(VbaTokenKind.BYREF):
                passing = VbaParameterPassing.BY_REF
                self._advance()
            else:
                break
        is_paramarray = bool(self._eat_keyword('paramarray'))

        name = self._current.value
        self._advance()

        is_array = False
        if self._at(VbaTokenKind.LPAREN):
            self._advance()
            self._expect(VbaTokenKind.RPAREN)
            is_array = True

        type_name = ''
        if self._eat(VbaTokenKind.AS):
            type_name = self._parse_type_name()

        default: Expression | None = None
        if self._eat(VbaTokenKind.EQ):
            default = self._parse_expression()

        return VbaParameter(
            name=name, passing=passing, type_name=type_name,
            is_optional=is_optional, is_paramarray=is_paramarray,
            default=default, is_array=is_array, offset=offset,
        )

    def _parse_type_name(self) -> str:
        parts = [self._current.value]
        self._advance()
        while self._eat(VbaTokenKind.DOT):
            parts.append(self._current.value)
            self._advance()
        name = '.'.join(parts)
        if name.lower() == 'string' and self._eat(VbaTokenKind.STAR):
            length = self._current.value
            self._advance()
            return F'{name} * {length}'
        return name

    def _parse_block_until(self, end_keyword: str) -> list[Statement]:
        merged = F'end{end_keyword}'
        body: list[Statement] = []
        while not self._at(VbaTokenKind.EOF):
            self._eat_eos()
            if self._at(VbaTokenKind.EOF):
                break
            if self._at(VbaTokenKind.END):
                saved = self._current
                self._advance()
                if self._at_keyword(end_keyword):
                    self._advance()
                    return body
                self._current = saved
            elif self._at_keyword(merged):
                self._advance()
                return body
            stmt = self._parse_statement()
            if stmt is not None:
                body.append(stmt)
        return body

    def _parse_statement(self) -> Statement | None:
        offset = self._current.offset
        kind = self._current.kind

        if kind.is_end_of_statement:
            self._advance()
            return None

        if kind == VbaTokenKind.INTEGER:
            label_val = self._current.value
            self._advance()
            if self._in_single_line_if:
                return VbaGotoStatement(label=label_val, offset=offset)
            return VbaLabelStatement(label=label_val, offset=offset)

        if kind == VbaTokenKind.IDENTIFIER and not kind.is_keyword:
            next_peek = self._peek_after_current()
            if next_peek.startswith(':') and not next_peek.startswith(':='):
                label_val = self._current.value
                self._advance()
                self._eat(VbaTokenKind.COLON)
                return VbaLabelStatement(label=label_val, offset=offset)

        if self._at_keyword('if'):
            return self._parse_if_statement()
        if self._at_keyword('for'):
            return self._parse_for_statement()
        if self._at_keyword('do'):
            return self._parse_do_loop_statement()
        if self._at_keyword('while'):
            return self._parse_while_statement()
        if self._at_keyword('select'):
            return self._parse_select_case_statement()
        if self._at_keyword('with'):
            return self._parse_with_statement()
        if self._at_keyword('set'):
            return self._parse_set_statement()
        if self._at_keyword('let'):
            return self._parse_let_statement()
        if self._at_keyword('call'):
            return self._parse_call_statement()
        if self._at_keyword('dim', 'static'):
            return self._parse_variable_declaration(
                VbaScopeModifier(self._current.value.capitalize()))
        if self._at_keyword('redim'):
            return self._parse_redim_statement()
        if self._at_keyword('const'):
            return self._parse_const_declaration(VbaScopeModifier.NONE)
        if self._at_keyword('goto'):
            return self._parse_go_statement(is_goto=True)
        if self._at_keyword('gosub'):
            return self._parse_go_statement(is_goto=False)
        if self._at_keyword('on'):
            return self._parse_on_statement()
        if self._at_keyword('exit'):
            return self._parse_exit_statement()
        if self._at_keyword('return'):
            self._advance()
            return VbaReturnStatement(offset=offset)
        if self._at_keyword('resume'):
            return self._parse_resume_statement()
        if self._at_keyword('stop'):
            self._advance()
            return VbaStopStatement(offset=offset)
        if self._at_keyword('end'):
            return self._parse_end_statement()
        if self._at_keyword('erase'):
            return self._parse_erase_statement()
        if self._at_keyword('raiseevent'):
            return self._parse_raiseevent_statement()
        if self._at_keyword('debug'):
            return self._parse_debug_print_statement()

        if self._at_keyword('lset', 'rset'):
            return self._parse_let_statement()

        if self._at_keyword('go'):
            after = self._peek_after_current()
            word = after.split()[0].lower() if after.split() else ''
            if word in ('to', 'sub'):
                branch = self._eat_go_keyword()
                if branch == 'goto':
                    label = self._current.value
                    self._advance()
                    return VbaGotoStatement(label=label, offset=offset)
                if branch == 'gosub':
                    label = self._current.value
                    self._advance()
                    return VbaGosubStatement(label=label, offset=offset)

        if self._at_keyword('open'):
            return self._skip_to_eos()

        if self._at_keyword('line'):
            peek = self._peek_after_current()
            if peek.lower().startswith('input'):
                return self._skip_to_eos()

        return self._parse_implicit_call_or_assignment()

    def _skip_to_eos(self) -> VbaExpressionStatement:
        offset = self._current.offset
        start = offset
        while not self._at(VbaTokenKind.NEWLINE, VbaTokenKind.COLON, VbaTokenKind.EOF):
            self._advance()
        raw = self._source[start:self._current.offset]
        return VbaExpressionStatement(
            expression=VbaIdentifier(name=raw.strip(), offset=offset),
            offset=offset,
        )

    def _parse_if_statement(self) -> VbaIfStatement:
        offset = self._current.offset
        self._advance()
        condition = self._parse_expression()
        self._expect(VbaTokenKind.THEN)

        while self._at(VbaTokenKind.COLON):
            self._advance()

        if not self._at(VbaTokenKind.NEWLINE, VbaTokenKind.EOF):
            return self._parse_single_line_if(condition, offset)

        self._eat_eos()
        body: list[Statement] = []
        elseif_clauses: list[VbaElseIfClause] = []
        else_body: list[Statement] = []
        found_else = False

        while not self._at(VbaTokenKind.EOF):
            if self._eat_end('if'):
                break
            if self._at(VbaTokenKind.ELSEIF):
                ei_offset = self._current.offset
                self._advance()
                ei_cond = self._parse_expression()
                self._expect(VbaTokenKind.THEN)
                self._eat_eos()
                elseif_clauses.append(VbaElseIfClause(
                    condition=ei_cond, body=[], offset=ei_offset))
                continue
            if self._at(VbaTokenKind.ELSE):
                ei_offset = self._current.offset
                self._advance()
                if self._at(VbaTokenKind.IF):
                    self._advance()
                    ei_cond = self._parse_expression()
                    self._expect(VbaTokenKind.THEN)
                    self._eat_eos()
                    elseif_clauses.append(VbaElseIfClause(
                        condition=ei_cond, body=[], offset=ei_offset))
                    continue
                self._eat_eos()
                found_else = True
                break
            stmt = self._parse_statement()
            if stmt is not None:
                if elseif_clauses:
                    elseif_clauses[-1].body.append(stmt)
                else:
                    body.append(stmt)
            self._eat_eos()

        if found_else:
            else_body = self._collect_body(lambda: self._eat_end('if'))

        return VbaIfStatement(
            condition=condition,
            body=body,
            elseif_clauses=elseif_clauses,
            else_body=else_body,
            offset=offset,
        )

    def _parse_single_line_if(
        self, condition: Expression, offset: int,
    ) -> VbaIfStatement:
        saved = self._in_single_line_if
        self._in_single_line_if = True
        try:
            body = self._collect_single_line_body()
            if self._eat(VbaTokenKind.ELSE):
                else_body = self._collect_single_line_body()
            else:
                else_body = []
            return VbaIfStatement(
                condition=condition,
                body=body,
                else_body=else_body,
                single_line=True,
                offset=offset,
            )
        finally:
            self._in_single_line_if = saved

    def _collect_single_line_body(self) -> list[Statement]:
        body: list[Statement] = []
        while not self._at(
            VbaTokenKind.ELSE,
            VbaTokenKind.EOF,
            VbaTokenKind.NEWLINE,
        ):
            if self._at(VbaTokenKind.COLON):
                self._advance()
                continue
            stmt = self._parse_statement()
            if stmt is not None:
                body.append(stmt)
        return body

    def _consume_next_variable(self):
        if not self._at(
            VbaTokenKind.NEWLINE, VbaTokenKind.COLON, VbaTokenKind.EOF,
        ):
            self._parse_expression()
        while self._eat(VbaTokenKind.COMMA):
            self._pending_next += 1

    def _parse_for_body(self) -> list[Statement]:
        self._eat_eos()

        def _at_next():
            if self._pending_next > 0:
                self._pending_next -= 1
                self._consume_next_variable()
                return True
            if self._at(VbaTokenKind.NEXT):
                self._advance()
                self._consume_next_variable()
                return True
            return False

        return self._collect_body(_at_next)

    def _parse_for_statement(self) -> Statement:
        offset = self._current.offset
        self._advance()

        if self._eat(VbaTokenKind.EACH):
            variable = self._parse_postfix_expression()
            self._expect(VbaTokenKind.IN)
            collection = self._parse_expression()
            body = self._parse_for_body()
            return VbaForEachStatement(
                variable=variable, collection=collection,
                body=body, offset=offset,
            )

        variable = self._parse_postfix_expression()
        self._expect(VbaTokenKind.EQ)
        start = self._parse_expression()
        self._expect(VbaTokenKind.TO)
        end = self._parse_expression()
        step: Expression | None = None
        if self._eat(VbaTokenKind.STEP):
            step = self._parse_expression()
        body = self._parse_for_body()
        return VbaForStatement(
            variable=variable, start=start, end=end,
            step=step, body=body, offset=offset,
        )

    def _collect_body(self, is_done) -> list[Statement]:
        body: list[Statement] = []
        while not self._at(VbaTokenKind.EOF):
            self._eat_eos()
            if self._at(VbaTokenKind.EOF) or is_done():
                break
            stmt = self._parse_statement()
            if stmt is not None:
                body.append(stmt)
        return body

    def _parse_loop_condition(self, position):
        if self._at(VbaTokenKind.WHILE):
            kind = VbaLoopConditionType.WHILE
        elif self._at(VbaTokenKind.UNTIL):
            kind = VbaLoopConditionType.UNTIL
        else:
            return None
        self._advance()
        return kind, position, self._parse_expression()

    def _parse_do_loop_statement(self) -> VbaDoLoopStatement:
        offset = self._current.offset
        self._advance()

        condition: Expression | None = None
        condition_type: VbaLoopConditionType | None = None
        condition_position: VbaLoopConditionPosition | None = None

        parsed = self._parse_loop_condition(VbaLoopConditionPosition.PRE)
        if parsed is not None:
            condition_type, condition_position, condition = parsed

        self._eat_eos()

        def _at_loop():
            nonlocal condition_type, condition_position, condition
            if self._at(VbaTokenKind.LOOP):
                self._advance()
                parsed = self._parse_loop_condition(VbaLoopConditionPosition.POST)
                if parsed is not None:
                    condition_type, condition_position, condition = parsed
                return True
            return False

        body = self._collect_body(_at_loop)

        return VbaDoLoopStatement(
            condition=condition, condition_type=condition_type,
            condition_position=condition_position,
            body=body, offset=offset,
        )

    def _parse_while_statement(self) -> VbaWhileStatement:
        offset = self._current.offset
        self._advance()
        condition = self._parse_expression()
        self._eat_eos()

        def _at_wend():
            if self._at(VbaTokenKind.WEND):
                self._advance()
                return True
            return False

        body = self._collect_body(_at_wend)
        return VbaWhileStatement(
            condition=condition, body=body, offset=offset)

    def _parse_select_case_statement(self) -> VbaSelectCaseStatement:
        offset = self._current.offset
        self._advance()
        self._expect(VbaTokenKind.CASE)
        expr = self._parse_expression()
        self._eat_eos()
        cases: list[VbaCaseClause] = []
        while not self._at(VbaTokenKind.EOF):
            self._eat_eos()
            if self._eat_end('select'):
                break
            if self._at(VbaTokenKind.CASE):
                cases.append(self._parse_case_clause())
            elif self._at(VbaTokenKind.EOF):
                break
            else:
                if cases:
                    stmt = self._parse_statement()
                    if stmt is not None:
                        cases[-1].body.append(stmt)
                else:
                    self._advance()
        return VbaSelectCaseStatement(
            expression=expr, cases=cases, offset=offset)

    def _parse_case_body(self) -> list[Statement]:
        def _at_case_end():
            if self._at(VbaTokenKind.CASE):
                return True
            if self._at(VbaTokenKind.END):
                after = self._peek_after_current()
                if after[:6].lower() == 'select' and not after[6:7].isalnum():
                    return True
            return self._at_keyword('endselect')

        return self._collect_body(_at_case_end)

    def _parse_case_clause(self) -> VbaCaseClause:
        offset = self._current.offset
        self._advance()
        if self._eat_keyword('else'):
            self._eat_eos()
            body = self._parse_case_body()
            return VbaCaseClause(is_else=True, body=body, offset=offset)

        tests = [self._parse_case_test()]
        while self._eat(VbaTokenKind.COMMA):
            tests.append(self._parse_case_test())
        self._eat_eos()
        body = self._parse_case_body()
        return VbaCaseClause(tests=tests, body=body, offset=offset)

    def _parse_with_statement(self) -> VbaWithStatement:
        offset = self._current.offset
        self._advance()
        obj = self._parse_expression()
        self._eat_eos()
        body = self._parse_block_until('with')
        return VbaWithStatement(object=obj, body=body, offset=offset)

    def _parse_set_statement(self) -> VbaSetStatement:
        offset = self._current.offset
        self._advance()
        target = self._parse_postfix_expression()
        self._expect(VbaTokenKind.EQ)
        value = self._parse_expression()
        return VbaSetStatement(target=target, value=value, offset=offset)

    def _parse_let_statement(self) -> VbaLetStatement:
        offset = self._current.offset
        keyword = self._current.value
        self._advance()
        target = self._parse_postfix_expression()
        self._expect(VbaTokenKind.EQ)
        value = self._parse_expression()
        return VbaLetStatement(
            target=target, value=value, explicit=True, keyword=keyword, offset=offset)

    def _parse_call_statement(self) -> VbaCallStatement:
        offset = self._current.offset
        self._advance()
        callee = self._parse_postfix_expression()
        args: list[Expression | None] = []
        if self._at(VbaTokenKind.LPAREN):
            self._advance()
            if not self._at(VbaTokenKind.RPAREN):
                args = self._parse_argument_list()
            self._expect(VbaTokenKind.RPAREN)
        return VbaCallStatement(callee=callee, arguments=args, offset=offset)

    def _parse_redim_statement(self) -> VbaRedimStatement:
        offset = self._current.offset
        self._advance()
        preserve = bool(self._eat_keyword('preserve'))
        declarators = self._comma_list(self._parse_redim_declarator)
        return VbaRedimStatement(
            preserve=preserve, declarators=declarators, offset=offset)

    def _parse_redim_declarator(self) -> VbaVariableDeclarator:
        offset = self._current.offset
        parts: list[str] = []
        if self._at(VbaTokenKind.DOT):
            parts.append('')
            self._advance()
            parts.append(self._current.value)
            self._advance()
        else:
            parts.append(self._current.value)
            self._advance()
        while self._eat(VbaTokenKind.DOT):
            parts.append(self._current.value)
            self._advance()
        name = '.'.join(parts)
        is_array, bounds, type_name, _ = self._parse_declarator_suffix()
        return VbaVariableDeclarator(
            name=name, type_name=type_name, is_array=is_array,
            bounds=bounds, offset=offset,
        )

    def _parse_erase_statement(self) -> VbaEraseStatement:
        offset = self._current.offset
        self._advance()
        targets = self._comma_list(self._parse_expression)
        return VbaEraseStatement(targets=targets, offset=offset)

    def _parse_raiseevent_statement(self) -> VbaRaiseEventStatement:
        offset = self._current.offset
        self._advance()
        name = self._current.value
        self._advance()
        arguments: list[Expression] = []
        if self._at(VbaTokenKind.LPAREN):
            self._advance()
            if not self._at(VbaTokenKind.RPAREN):
                arguments = self._parse_expression_list()
            self._expect(VbaTokenKind.RPAREN)
        return VbaRaiseEventStatement(
            name=name, arguments=arguments, offset=offset)

    def _parse_go_statement(self, is_goto: bool) -> VbaGotoStatement | VbaGosubStatement:
        offset = self._current.offset
        self._advance()
        label = self._current.value
        self._advance()
        if is_goto:
            return VbaGotoStatement(label=label, offset=offset)
        return VbaGosubStatement(label=label, offset=offset)

    def _parse_on_statement(self) -> Statement:
        offset = self._current.offset
        self._advance()
        if self._at(VbaTokenKind.ERROR):
            self._advance()
            if self._at_keyword('resume'):
                self._advance()
                if self._at_keyword('next'):
                    self._advance()
                    return VbaOnErrorStatement(
                        action=VbaOnErrorAction.RESUME_NEXT, offset=offset)
                return VbaOnErrorStatement(
                    action=VbaOnErrorAction.RESUME, offset=offset)
            if self._eat_go_keyword() == 'goto':
                if self._at(VbaTokenKind.MINUS):
                    self._advance()
                    label = F'-{self._current.value}'
                else:
                    label = self._current.value
                self._advance()
                return VbaOnErrorStatement(
                    action=VbaOnErrorAction.GOTO, label=label, offset=offset)
            return VbaOnErrorStatement(action=VbaOnErrorAction.NONE, offset=offset)
        expr = self._parse_expression()
        branch = self._eat_go_keyword()
        if branch == 'goto':
            kind = VbaOnBranchKind.GOTO
        elif branch == 'gosub':
            kind = VbaOnBranchKind.GOSUB
        else:
            return VbaOnErrorStatement(action=VbaOnErrorAction.NONE, offset=offset)
        labels = [self._current.value]
        self._advance()
        while self._eat(VbaTokenKind.COMMA):
            labels.append(self._current.value)
            self._advance()
        return VbaOnBranchStatement(
            expression=expr, kind=kind, labels=labels, offset=offset)

    def _parse_exit_statement(self) -> Statement:
        offset = self._current.offset
        self._advance()
        try:
            kind = VbaExitKind(self._current.value.capitalize())
        except ValueError:
            self._advance()
            return VbaErrorNode(offset=offset)
        self._advance()
        return VbaExitStatement(kind=kind, offset=offset)

    def _parse_resume_statement(self) -> VbaResumeStatement:
        offset = self._current.offset
        self._advance()
        label = ''
        if self._at_keyword('next'):
            label = 'Next'
            self._advance()
        elif not self._at(VbaTokenKind.NEWLINE, VbaTokenKind.COLON, VbaTokenKind.EOF):
            label = self._current.value
            self._advance()
        return VbaResumeStatement(label=label, offset=offset)

    def _parse_end_statement(self) -> Statement:
        offset = self._current.offset
        self._advance()
        return VbaEndStatement(offset=offset)

    def _parse_debug_print_statement(self) -> VbaDebugPrintStatement:
        offset = self._current.offset
        self._advance()
        self._eat(VbaTokenKind.DOT)
        method = self._current.value
        self._advance()
        arguments: list[Expression] = []
        separators: list[str] = []
        if not self._at(VbaTokenKind.NEWLINE, VbaTokenKind.COLON, VbaTokenKind.EOF):
            arguments, separators = self._parse_print_argument_list()
        return VbaDebugPrintStatement(
            method=method, arguments=arguments, separators=separators, offset=offset)

    def _parse_print_argument_list(self) -> tuple[list[Expression], list[str]]:
        args = [self._parse_expression()]
        separators: list[str] = []
        while self._at(VbaTokenKind.SEMICOLON, VbaTokenKind.COMMA):
            sep = ';' if self._at(VbaTokenKind.SEMICOLON) else ','
            separators.append(sep)
            self._advance()
            if self._at(VbaTokenKind.NEWLINE, VbaTokenKind.COLON, VbaTokenKind.EOF):
                break
            args.append(self._parse_expression())
        return args, separators

    def _parse_implicit_call_or_assignment(self) -> Statement:
        offset = self._current.offset
        expr = self._parse_postfix_expression()

        if self._eat(VbaTokenKind.EQ):
            value = self._parse_expression()
            return VbaLetStatement(
                target=expr, value=value, explicit=False, offset=offset)

        if not self._at(
            VbaTokenKind.NEWLINE, VbaTokenKind.COLON, VbaTokenKind.EOF,
            VbaTokenKind.ELSE,
        ):
            args = self._parse_argument_list()
            return VbaExpressionStatement(
                expression=expr, arguments=args, offset=offset)

        return VbaExpressionStatement(expression=expr, offset=offset)

    def _parse_argument_list(
        self,
        stop: frozenset[VbaTokenKind] = frozenset({
            VbaTokenKind.NEWLINE, VbaTokenKind.COLON,
            VbaTokenKind.EOF, VbaTokenKind.RPAREN,
            VbaTokenKind.ELSE,
        }),
    ) -> list[Expression | None]:
        args: list[Expression | None] = []
        while True:
            if self._current.kind in stop:
                break
            if self._at(VbaTokenKind.COMMA):
                args.append(None)
                self._advance()
                continue
            args.append(self._parse_argument_expression())
            if not self._eat(VbaTokenKind.COMMA):
                break
        return args

    def _parse_argument_expression(self) -> Expression:
        if self._at(VbaTokenKind.BYVAL):
            offset = self._current.offset
            self._advance()
            return VbaByValArgument(
                expression=self._parse_expression(), offset=offset)
        expr = self._parse_expression()
        if self._at(VbaTokenKind.ASSIGN):
            self._advance()
            name = expr.name if isinstance(expr, VbaIdentifier) else ''
            value = self._parse_expression()
            return VbaNamedArgument(
                name=name, expression=value, offset=expr.offset)
        return expr

    def _parse_expression_list(self) -> list[Expression]:
        return self._comma_list(self._parse_expression)

    def _parse_bounds_list(self) -> list[Expression]:
        return self._comma_list(self._parse_bound_expression)

    _COMPARISON_OPS = frozenset({
        VbaTokenKind.EQ,
        VbaTokenKind.NEQ,
        VbaTokenKind.LT,
        VbaTokenKind.GT,
        VbaTokenKind.LTE,
        VbaTokenKind.GTE,
    })

    def _parse_case_test(self) -> Expression:
        offset = self._current.offset
        if self._at(VbaTokenKind.IS):
            self._advance()
            if self._at(*self._COMPARISON_OPS):
                op = self._advance().value
                right = self._parse_expression()
                return VbaBinaryExpression(
                    left=VbaIdentifier(name='Is', offset=offset),
                    operator=op, right=right, offset=offset,
                )
            return self._reparse_is_as_expression(offset)
        if self._at(*self._COMPARISON_OPS):
            op = self._advance().value
            right = self._parse_expression()
            return VbaBinaryExpression(
                left=VbaIdentifier(name='Is', offset=offset),
                operator=op, right=right, offset=offset,
            )
        return self._parse_bound_expression()

    def _reparse_is_as_expression(self, offset: int) -> Expression:
        expr = self._parse_postfix_chain(VbaIdentifier(name='Is', offset=offset))
        if self._eat(VbaTokenKind.TO):
            upper = self._parse_expression()
            return VbaRangeExpression(start=expr, end=upper, offset=offset)
        return expr

    def _parse_bound_expression(self) -> Expression:
        expr = self._parse_expression()
        if self._eat(VbaTokenKind.TO):
            upper = self._parse_expression()
            expr = VbaRangeExpression(start=expr, end=upper, offset=expr.offset)
        return expr

    def _parse_expression(self) -> Expression:
        return self._parse_imp_expression()

    def _binary_left(self, next_parser, *ops) -> Expression:
        left = next_parser()
        while True:
            for kind, op_str in ops:
                if self._eat(kind):
                    right = next_parser()
                    left = VbaBinaryExpression(
                        left=left, operator=op_str, right=right, offset=left.offset)
                    break
            else:
                break
        return left

    def _parse_imp_expression(self) -> Expression:
        return self._binary_left(self._parse_eqv_expression, (VbaTokenKind.IMP, 'Imp'))

    def _parse_eqv_expression(self) -> Expression:
        return self._binary_left(self._parse_xor_expression, (VbaTokenKind.EQV, 'Eqv'))

    def _parse_xor_expression(self) -> Expression:
        return self._binary_left(self._parse_or_expression, (VbaTokenKind.XOR, 'Xor'))

    def _parse_or_expression(self) -> Expression:
        return self._binary_left(self._parse_and_expression, (VbaTokenKind.OR, 'Or'))

    def _parse_and_expression(self) -> Expression:
        return self._binary_left(self._parse_not_expression, (VbaTokenKind.AND, 'And'))

    def _parse_not_expression(self) -> Expression:
        tok = self._eat(VbaTokenKind.NOT)
        if tok:
            operand = self._parse_not_expression()
            return VbaUnaryExpression(
                operator='Not', operand=operand, offset=tok.offset)
        return self._parse_comparison_expression()

    def _parse_comparison_expression(self) -> Expression:
        left = self._parse_concat_expression()
        while self._at(
            VbaTokenKind.EQ, VbaTokenKind.NEQ,
            VbaTokenKind.LT, VbaTokenKind.GT,
            VbaTokenKind.LTE, VbaTokenKind.GTE,
            VbaTokenKind.IS, VbaTokenKind.LIKE,
        ):
            op_tok = self._advance()
            right = self._parse_concat_expression()
            left = VbaBinaryExpression(
                left=left, operator=op_tok.value, right=right, offset=left.offset)
        return left

    def _parse_concat_expression(self) -> Expression:
        return self._binary_left(self._parse_additive_expression, (VbaTokenKind.AMPERSAND, '&'))

    def _parse_additive_expression(self) -> Expression:
        return self._binary_left(
            self._parse_mod_expression, (VbaTokenKind.PLUS, '+'), (VbaTokenKind.MINUS, '-'))

    def _parse_mod_expression(self) -> Expression:
        return self._binary_left(self._parse_integer_div_expression, (VbaTokenKind.MOD, 'Mod'))

    def _parse_integer_div_expression(self) -> Expression:
        return self._binary_left(
            self._parse_multiplicative_expression, (VbaTokenKind.BACKSLASH, '\\'))

    def _parse_multiplicative_expression(self) -> Expression:
        return self._binary_left(
            self._parse_unary_expression, (VbaTokenKind.STAR, '*'), (VbaTokenKind.SLASH, '/'))

    def _parse_exponentiation_expression(self) -> Expression:
        left = self._parse_postfix_expression()
        while self._eat(VbaTokenKind.CARET):
            right = self._parse_exponentiation_rhs()
            left = VbaBinaryExpression(
                left=left, operator='^', right=right, offset=left.offset)
        return left

    def _parse_exponentiation_rhs(self) -> Expression:
        if self._at(VbaTokenKind.MINUS):
            tok = self._advance()
            operand = self._parse_exponentiation_rhs()
            return VbaUnaryExpression(
                operator='-', operand=operand, offset=tok.offset)
        if self._at(VbaTokenKind.PLUS):
            self._advance()
            return self._parse_exponentiation_rhs()
        return self._parse_postfix_expression()

    def _parse_unary_expression(self) -> Expression:
        if self._at(VbaTokenKind.MINUS):
            tok = self._advance()
            operand = self._parse_unary_expression()
            return VbaUnaryExpression(
                operator='-', operand=operand, offset=tok.offset)
        if self._at(VbaTokenKind.PLUS):
            self._advance()
            return self._parse_unary_expression()
        return self._parse_exponentiation_expression()

    def _parse_postfix_chain(self, expr: Expression) -> Expression:
        while True:
            if self._eat(VbaTokenKind.DOT):
                member = self._current.value
                self._advance()
                expr = VbaMemberAccess(
                    object=expr, member=member, offset=expr.offset)
            elif self._eat(VbaTokenKind.BANG):
                member = self._current.value
                self._advance()
                expr = VbaBangAccess(
                    object=expr, member=member, offset=expr.offset)
            elif self._at(VbaTokenKind.LPAREN):
                self._advance()
                args: list[Expression | None] = []
                if not self._at(VbaTokenKind.RPAREN):
                    args = self._parse_argument_list(self._PAREN_ARG_STOP)
                self._expect(VbaTokenKind.RPAREN)
                expr = VbaCallExpression(
                    callee=expr, arguments=args, offset=expr.offset)
            else:
                break
        return expr

    def _parse_postfix_expression(self) -> Expression:
        return self._parse_postfix_chain(self._parse_primary_expression())

    def _parse_primary_expression(self) -> Expression:
        tok = self._current
        offset = tok.offset

        if self._at(VbaTokenKind.INTEGER):
            self._advance()
            raw = tok.value
            text = raw.rstrip('%&!#@')
            if text.lower().startswith('&h'):
                value = int(text[2:], 16)
            elif text.lower().startswith('&o'):
                value = int(text[2:], 8)
            else:
                value = int(text)
            return VbaIntegerLiteral(value=value, raw=raw, offset=offset)

        if self._at(VbaTokenKind.FLOAT):
            self._advance()
            raw = tok.value
            text = raw.rstrip('%&!#@').replace('d', 'e').replace('D', 'E')
            value = float(text)
            return VbaFloatLiteral(value=value, raw=raw, offset=offset)

        if self._at(VbaTokenKind.STRING):
            self._advance()
            raw = tok.value
            if len(raw) >= 2:
                value = raw[1:-1].replace('""', '"')
            else:
                value = raw
            return VbaStringLiteral(value=value, raw=raw, offset=offset)

        if self._at(VbaTokenKind.DATE_LITERAL):
            self._advance()
            return VbaDateLiteral(raw=tok.value, offset=offset)

        if self._at(VbaTokenKind.BOOLEAN_TRUE):
            self._advance()
            return VbaBooleanLiteral(value=True, offset=offset)

        if self._at(VbaTokenKind.BOOLEAN_FALSE):
            self._advance()
            return VbaBooleanLiteral(value=False, offset=offset)

        if self._at(VbaTokenKind.NOTHING):
            self._advance()
            return VbaNothingLiteral(offset=offset)

        if self._at(VbaTokenKind.NULL):
            self._advance()
            return VbaNullLiteral(offset=offset)

        if self._at(VbaTokenKind.EMPTY):
            self._advance()
            return VbaEmptyLiteral(offset=offset)

        if self._at(VbaTokenKind.ME):
            self._advance()
            return VbaMeExpression(offset=offset)

        if self._at(VbaTokenKind.NEW):
            self._advance()
            class_name = self._parse_postfix_expression()
            return VbaNewExpression(class_name=class_name, offset=offset)

        if self._at(VbaTokenKind.TYPEOF):
            self._advance()
            operand = self._parse_postfix_expression()
            self._expect(VbaTokenKind.IS)
            type_name = self._parse_postfix_expression()
            return VbaTypeOfIsExpression(
                operand=operand, type_name=type_name, offset=offset)

        if self._at(VbaTokenKind.LPAREN):
            self._advance()
            inner = self._parse_expression()
            self._expect(VbaTokenKind.RPAREN)
            return VbaParenExpression(expression=inner, offset=offset)

        if self._at(VbaTokenKind.DOT):
            self._advance()
            member = self._current.value
            self._advance()
            return VbaMemberAccess(object=None, member=member, offset=offset)

        if self._at(VbaTokenKind.IDENTIFIER) or self._current.kind.is_keyword:
            name = tok.value
            self._advance()
            return VbaIdentifier(name=name, offset=offset)

        self._advance()
        return VbaErrorNode(text=tok.value, message='unexpected token', offset=offset)
