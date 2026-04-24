"""
Recursive-descent parser for PowerShell based on the PowerShell Language Specification 3.0.
"""
from __future__ import annotations

import re

from contextlib import contextmanager

from refinery.lib.scripts import Block
from refinery.lib.scripts.ps1.lexer import (
    _DASH_OPERATORS,
    Ps1Lexer,
    Ps1LexerMode,
)
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
    Ps1ClassDefinition,
    Ps1CommandArgument,
    Ps1CommandArgumentKind,
    Ps1CommandInvocation,
    Ps1ContinueStatement,
    Ps1DataSection,
    Ps1DoLoop,
    Ps1EnumDefinition,
    Ps1EnumMember,
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
    Ps1MemberModifier,
    Ps1MergingRedirection,
    Ps1MethodMember,
    Ps1ParamBlock,
    Ps1ParameterDeclaration,
    Ps1ParenExpression,
    Ps1Pipeline,
    Ps1PipelineElement,
    Ps1PropertyMember,
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
    Statement,
)
from refinery.lib.scripts.ps1.token import (
    _VARIABLE_PATTERN_CORE,
    BACKTICK_ESCAPE,
    DOUBLE_QUOTES,
    NORMALIZE_QUOTES,
    SINGLE_QUOTES,
    WHITESPACE,
    Ps1Token,
    Ps1TokenKind,
    _strip_backtick_noop,
)

_NON_COMPARISON_DASH_OPS = frozenset({
    '-and',
    '-band',
    '-bnot',
    '-bor',
    '-bxor',
    '-f',
    '-not',
    '-or',
    '-xor',
})
_COMPARISON_OPERATORS = frozenset(_DASH_OPERATORS.values()) - _NON_COMPARISON_DASH_OPS

_BINARY_PRECEDENCE: dict[str, int] = {}
_BINARY_PRECEDENCE.update(dict.fromkeys(('-and', '-or', '-xor'), 10))
_BINARY_PRECEDENCE.update(dict.fromkeys(('-band', '-bor', '-bxor'), 20))
_BINARY_PRECEDENCE.update(dict.fromkeys(_COMPARISON_OPERATORS, 30))

_EXPRESSION_START_KINDS = frozenset({
    Ps1TokenKind.INTEGER,
    Ps1TokenKind.REAL,
    Ps1TokenKind.STRING_VERBATIM,
    Ps1TokenKind.STRING_EXPAND,
    Ps1TokenKind.HSTRING_VERBATIM,
    Ps1TokenKind.HSTRING_EXPAND,
    Ps1TokenKind.VARIABLE,
    Ps1TokenKind.SPLAT_VARIABLE,
    Ps1TokenKind.LPAREN,
    Ps1TokenKind.AT_LPAREN,
    Ps1TokenKind.AT_LBRACE,
    Ps1TokenKind.DOLLAR_LPAREN,
    Ps1TokenKind.LBRACE,
    Ps1TokenKind.LBRACKET,
    Ps1TokenKind.PLUS,
    Ps1TokenKind.DASH,
    Ps1TokenKind.EXCLAIM,
    Ps1TokenKind.INCREMENT,
    Ps1TokenKind.DECREMENT,
    Ps1TokenKind.COMMA,
})

_STATEMENT_TERMINATORS = frozenset({
    Ps1TokenKind.NEWLINE,
    Ps1TokenKind.SEMICOLON,
    Ps1TokenKind.RBRACE,
    Ps1TokenKind.RPAREN,
    Ps1TokenKind.EOF,
    Ps1TokenKind.PIPE,
})

_PIPELINE_TERMINATORS = _STATEMENT_TERMINATORS | {
    Ps1TokenKind.DOUBLE_AMPERSAND,
    Ps1TokenKind.DOUBLE_PIPE,
}

_VARIABLE_FRAG = re.compile(
    r'\$(?:' + _VARIABLE_PATTERN_CORE + r')',
    re.IGNORECASE,
)

_MERGING_PATTERN = re.compile(r'(\d|\*)?>&(\d)')

_ASSIGNMENT_RHS_STATEMENT_KINDS = frozenset({
    Ps1TokenKind.IF,
    Ps1TokenKind.WHILE,
    Ps1TokenKind.DO,
    Ps1TokenKind.FOR,
    Ps1TokenKind.FOREACH,
    Ps1TokenKind.SWITCH,
    Ps1TokenKind.TRY,
})

_MULTIPLIER_SUFFIXES = {
    'kb': 1024,
    'mb': 1024 ** 2,
    'gb': 1024 ** 3,
    'tb': 1024 ** 4,
    'pb': 1024 ** 5,
}


class Ps1Parser:

    def __init__(self, source: str):
        self.source = source
        self._lexer = Ps1Lexer(source)
        self._gen = self._lexer.tokenize()
        self._current: Ps1Token = Ps1Token(Ps1TokenKind.EOF, '', 0)
        self._disable_comma = False
        self._advance()

    def _advance(self, mode_hint: Ps1LexerMode | None = None) -> Ps1Token:
        prev = self._current
        try:
            if mode_hint is not None:
                self._current = self._gen.send(mode_hint)
            else:
                self._current = next(self._gen)
        except StopIteration:
            self._current = Ps1Token(Ps1TokenKind.EOF, '', len(self.source))
        return prev

    def _at(self, *kinds: Ps1TokenKind) -> bool:
        return self._current.kind in kinds

    def _eat(self, kind: Ps1TokenKind) -> Ps1Token | None:
        if self._current.kind == kind:
            return self._advance()
        return None

    def _eat_colon(self) -> bool:
        if self._current.kind == Ps1TokenKind.DOUBLE_COLON:
            self._advance()
            return True
        if self._current.kind == Ps1TokenKind.GENERIC_TOKEN and self._current.value == ':':
            self._advance()
            return True
        return False

    def _expect(self, kind: Ps1TokenKind) -> Ps1Token:
        if self._current.kind == kind:
            return self._advance()
        return Ps1Token(kind, '', self._current.offset)

    def _rescan_current(self):
        """
        Re-tokenize the current token under the active lexer mode. Used after mode changes
        (e.g. `pop_mode`) to ensure the lookahead token matches the new mode.
        """
        if self._current.offset >= 0:
            self._lexer.pos = self._current.offset
            self._advance()

    def _skip_newlines(self):
        while self._current.kind == Ps1TokenKind.NEWLINE:
            self._advance()

    def _parse_parenthesized_condition(self) -> Expression:
        self._expect(Ps1TokenKind.LPAREN)
        self._skip_newlines()
        expr = self._parse_pipeline_expression()
        self._skip_newlines()
        self._expect(Ps1TokenKind.RPAREN)
        if expr is None:
            return Ps1ErrorNode(offset=self._current.offset, message='missing condition')
        return expr

    def _skip_separators(self):
        while self._current.kind in (
            Ps1TokenKind.COMMA,
            Ps1TokenKind.NEWLINE,
            Ps1TokenKind.SEMICOLON,
        ):
            self._advance()

    @staticmethod
    def _bare_string(tok: Ps1Token) -> Ps1StringLiteral:
        return Ps1StringLiteral(offset=tok.offset, value=tok.value, raw=tok.value)

    @contextmanager
    def _comma_mode(self, disabled: bool):
        old = self._disable_comma
        self._disable_comma = disabled
        try:
            yield
        finally:
            self._disable_comma = old

    def _parse_redirection(
        self, tok: Ps1Token,
    ) -> Ps1FileRedirection | Ps1MergingRedirection:
        op = tok.value
        m = _MERGING_PATTERN.fullmatch(op)
        if m is not None:
            prefix, to_digit = m.group(1), int(m.group(2))
            if prefix is None:
                from_stream = Ps1RedirectionStream.OUTPUT
            elif prefix == '*':
                from_stream = Ps1RedirectionStream.ALL
            else:
                from_stream = Ps1RedirectionStream(int(prefix))
            return Ps1MergingRedirection(
                offset=tok.offset,
                from_stream=from_stream,
                to_stream=Ps1RedirectionStream(to_digit),
            )
        if op[0] == '*':
            stream = Ps1RedirectionStream.ALL
            rest = op[1:]
        elif op[0].isdigit():
            stream = Ps1RedirectionStream(int(op[0]))
            rest = op[1:]
        else:
            stream = Ps1RedirectionStream.OUTPUT
            rest = op
        append = rest == '>>'
        target = None
        if not self._is_pipeline_terminator():
            target = self._parse_single_argument_value()
        return Ps1FileRedirection(
            offset=tok.offset, stream=stream, target=target, append=append)

    @staticmethod
    def _skip_quoted_raw(
        src: str,
        pos: int,
        end: int,
        quote_set: frozenset[str],
        *,
        backtick: bool = False,
    ) -> int:
        """
        Starting just after an opening quote character, advance past the quoted string content
        and the closing quote. Handles doubled-quote escapes and optionally backtick escapes.
        Returns the position immediately after the closing quote.
        """
        while pos < end:
            ch = src[pos]
            if backtick and ch == '`' and pos + 1 < end:
                pos += 2
                continue
            if ch in quote_set:
                pos += 1
                if pos < end and src[pos] in quote_set:
                    pos += 1
                    continue
                return pos
            pos += 1
        return pos

    def _might_be_param_block(self) -> bool:
        if self._at(Ps1TokenKind.PARAM):
            return True
        if not self._at(Ps1TokenKind.LBRACKET):
            return False
        src = self.source
        pos = self._current.offset
        end = len(src)
        while pos < end and src[pos] == '[':
            depth = 1
            pos += 1
            while pos < end and depth > 0:
                ch = src[pos]
                if ch == '[':
                    depth += 1
                elif ch == ']':
                    depth -= 1
                elif ch in SINGLE_QUOTES and depth > 0:
                    pos = self._skip_quoted_raw(src, pos + 1, end, SINGLE_QUOTES)
                    continue
                elif ch in DOUBLE_QUOTES and depth > 0:
                    pos = self._skip_quoted_raw(src, pos + 1, end, DOUBLE_QUOTES, backtick=True)
                    continue
                pos += 1
            while pos < end and (src[pos] in WHITESPACE or src[pos] in '\r\n'):
                pos += 1
        return src[pos:pos + 5].lower().startswith('param') and (
            pos + 5 >= end or not src[pos + 5].isalnum() and src[pos + 5] != '_'
        )

    def _is_statement_terminator(self) -> bool:
        return self._current.kind in _STATEMENT_TERMINATORS

    def _eat_statement_terminator(self) -> bool:
        if self._current.kind in (Ps1TokenKind.NEWLINE, Ps1TokenKind.SEMICOLON):
            self._advance()
            return True
        return self._current.kind in (Ps1TokenKind.RBRACE, Ps1TokenKind.RPAREN, Ps1TokenKind.EOF)

    def parse(self) -> Ps1Script:
        return self._parse_script()

    def _parse_code_body(
        self,
        until: Ps1TokenKind | None = None,
    ) -> dict:
        self._skip_newlines()
        fields: dict = {}
        if self._might_be_param_block():
            fields['param_block'] = self._parse_param_block()
            self._skip_newlines()
        named = self._try_parse_named_blocks()
        if named is not None:
            begin_block, process_block, end_block, dynamicparam_block = named
            fields.update(
                begin_block=begin_block,
                process_block=process_block,
                end_block=end_block,
                dynamicparam_block=dynamicparam_block,
            )
        else:
            fields['body'] = self._parse_statement_list(until=until)
        return fields

    def _parse_script(self) -> Ps1Script:
        offset = self._current.offset
        return Ps1Script(offset=offset, **self._parse_code_body())

    def _try_parse_named_blocks(
        self,
    ) -> tuple[Block | None, Block | None, Block | None, Block | None] | None:
        if not self._at(
            Ps1TokenKind.BEGIN,
            Ps1TokenKind.PROCESS,
            Ps1TokenKind.END,
            Ps1TokenKind.DYNAMICPARAM,
        ):
            return None
        begin_block = None
        process_block = None
        end_block = None
        dynamicparam_block = None
        while self._at(
            Ps1TokenKind.BEGIN,
            Ps1TokenKind.PROCESS,
            Ps1TokenKind.END,
            Ps1TokenKind.DYNAMICPARAM,
        ):
            kw = self._advance()
            self._skip_newlines()
            block = self._parse_block()
            if kw.kind == Ps1TokenKind.BEGIN:
                begin_block = block
            elif kw.kind == Ps1TokenKind.PROCESS:
                process_block = block
            elif kw.kind == Ps1TokenKind.END:
                end_block = block
            elif kw.kind == Ps1TokenKind.DYNAMICPARAM:
                dynamicparam_block = block
            self._skip_newlines()
        return begin_block, process_block, end_block, dynamicparam_block

    def _parse_block(self) -> Block:
        offset = self._current.offset
        self._expect(Ps1TokenKind.LBRACE)
        self._skip_newlines()
        stmts = self._parse_statement_list(until=Ps1TokenKind.RBRACE)
        self._expect(Ps1TokenKind.RBRACE)
        return Block(offset=offset, body=stmts)

    def _parse_statement_list(self, until: Ps1TokenKind | None = None) -> list[Statement]:
        stmts: list[Statement] = []
        while not self._at(Ps1TokenKind.EOF):
            while self._at(Ps1TokenKind.NEWLINE, Ps1TokenKind.SEMICOLON):
                self._advance()
            if until is not None and self._at(until):
                break
            if self._at(Ps1TokenKind.EOF):
                break
            mark = self._current.offset
            stmt = self._parse_statement()
            if stmt is not None:
                stmts.append(stmt)
            elif self._current.offset == mark:
                tok = self._advance()
                stmts.append(Ps1ExpressionStatement(
                    offset=tok.offset,
                    expression=Ps1ErrorNode(offset=tok.offset, text=tok.value),
                ))
            while self._at(Ps1TokenKind.NEWLINE, Ps1TokenKind.SEMICOLON):
                self._advance()
        return stmts

    def _parse_statement(self) -> Statement | None:
        self._skip_newlines()
        tok = self._current
        kind = tok.kind

        label = None
        if kind == Ps1TokenKind.LABEL:
            label = tok.value
            self._advance()
            self._skip_newlines()
            kind = self._current.kind

        if kind == Ps1TokenKind.IF:
            return self._parse_if()
        if kind == Ps1TokenKind.WHILE:
            return self._parse_while(label)
        if kind == Ps1TokenKind.DO:
            return self._parse_do(label)
        if kind == Ps1TokenKind.FOR:
            return self._parse_for(label)
        if kind == Ps1TokenKind.FOREACH:
            return self._parse_foreach(label)
        if kind == Ps1TokenKind.SWITCH:
            return self._parse_switch(label)
        if kind == Ps1TokenKind.TRY:
            return self._parse_try()
        if kind == Ps1TokenKind.TRAP:
            return self._parse_trap()
        if kind in (Ps1TokenKind.FUNCTION, Ps1TokenKind.FILTER):
            return self._parse_function_definition()
        if kind == Ps1TokenKind.CLASS:
            return self._parse_class_definition()
        if kind == Ps1TokenKind.ENUM:
            return self._parse_enum_definition()
        if kind == Ps1TokenKind.RETURN:
            return self._parse_return()
        if kind == Ps1TokenKind.THROW:
            return self._parse_throw()
        if kind == Ps1TokenKind.BREAK:
            return self._parse_break()
        if kind == Ps1TokenKind.CONTINUE:
            return self._parse_continue()
        if kind == Ps1TokenKind.EXIT:
            return self._parse_exit()
        if kind == Ps1TokenKind.DATA:
            return self._parse_data()

        return self._parse_pipeline_or_assignment()

    def _absorb_suffix(
        self,
        literal: Ps1StringLiteral,
        separator_kind: Ps1TokenKind,
        separator: str,
        *,
        check_adjacent: bool = False,
    ) -> tuple[Ps1StringLiteral, bool]:
        """
        Try to absorb a `separator + identifier` sequence into `literal`. Returns the (possibly
        extended) literal and whether anything was absorbed. When `check_adjacent` is `True`,
        absorption is skipped if there is whitespace between the current literal and the separator
        token.
        """
        absorbed = False
        while self._at(separator_kind):
            if check_adjacent and self._current.offset > literal.offset + len(literal.raw):
                break
            saved_pos = self._lexer.pos
            saved_tok = self._current
            self._advance()
            if self._at(Ps1TokenKind.GENERIC_TOKEN) or self._current.kind.is_keyword:
                suffix = self._advance()
                literal = Ps1StringLiteral(
                    offset=literal.offset,
                    value=literal.value + separator + suffix.value,
                    raw=literal.raw + separator + suffix.value,
                )
                absorbed = True
            else:
                self._lexer.pos = saved_pos
                self._current = saved_tok
                break
        return literal, absorbed

    def _parse_pipeline_or_assignment(self) -> Statement | None:
        expr = self._parse_pipeline_expression()
        if expr is None:
            if self._at(Ps1TokenKind.EOF, Ps1TokenKind.RBRACE, Ps1TokenKind.RPAREN):
                return None
            tok = self._advance()
            return Ps1ExpressionStatement(
                offset=tok.offset,
                expression=Ps1ErrorNode(offset=tok.offset, text=tok.value),
            )
        return Ps1ExpressionStatement(offset=expr.offset, expression=expr)

    def _parse_pipeline_expression(self) -> Expression | None:
        self._lexer.mode = Ps1LexerMode.EXPRESSION
        if self._at(Ps1TokenKind.GENERIC_TOKEN, Ps1TokenKind.GENERIC_EXPAND, Ps1TokenKind.AMPERSAND, Ps1TokenKind.DOT):
            first = self._parse_command()
            if first is None:
                return None
            return self._parse_pipeline_tail(first)
        expr = self._parse_expression()
        if expr is None:
            return None
        if self._current.kind.is_assignment:
            op = self._advance()
            self._skip_newlines()
            if self._current.kind in _ASSIGNMENT_RHS_STATEMENT_KINDS:
                rhs = self._parse_statement()
            else:
                rhs = self._parse_pipeline_expression()
            expr = Ps1AssignmentExpression(
                offset=expr.offset, target=expr, operator=op.value, value=rhs)
        return self._parse_pipeline_tail(expr)

    def _parse_pipeline_tail(self, expr: Expression) -> Expression:
        if self._at(Ps1TokenKind.PIPE):
            elements = [Ps1PipelineElement(offset=expr.offset, expression=expr)]
            while self._eat(Ps1TokenKind.PIPE):
                self._skip_newlines()
                self._lexer.mode = Ps1LexerMode.ARGUMENT
                self._rescan_current()
                cmd = self._parse_command()
                if cmd is not None:
                    elements.append(Ps1PipelineElement(offset=cmd.offset, expression=cmd))
            if len(elements) > 1:
                return Ps1Pipeline(offset=elements[0].offset, elements=elements)
            return expr
        return expr

    def _parse_command(self) -> Expression | None:
        offset = self._current.offset
        invocation_operator = ''
        if self._at(Ps1TokenKind.AMPERSAND, Ps1TokenKind.DOT):
            invocation_operator = self._advance(Ps1LexerMode.ARGUMENT).value
            self._skip_newlines()

        name_expr: Expression | None = None

        if self._at(Ps1TokenKind.GENERIC_TOKEN, Ps1TokenKind.GENERIC_EXPAND):
            tok = self._advance()
            name_expr = self._bare_string(tok)
        elif self._at(Ps1TokenKind.VARIABLE, Ps1TokenKind.SPLAT_VARIABLE):
            name_expr = self._parse_variable()
        elif self._at(Ps1TokenKind.LBRACE):
            name_expr = self._parse_script_block()
        elif self._at(Ps1TokenKind.LPAREN):
            name_expr = self._parse_paren_expression()
        elif self._at(Ps1TokenKind.STRING_EXPAND, Ps1TokenKind.STRING_VERBATIM):
            name_expr = self._parse_string()
        elif self._at(Ps1TokenKind.PERCENT):
            tok = self._advance()
            name_expr = self._bare_string(tok)
        elif self._current.kind.is_keyword:
            tok = self._advance()
            name_expr = self._bare_string(tok)
        else:
            if invocation_operator:
                return Ps1CommandInvocation(offset=offset, invocation_operator=invocation_operator)
            return None

        if invocation_operator and name_expr is not None:
            self._lexer.mode = Ps1LexerMode.EXPRESSION
            self._rescan_current()
            name_expr = self._parse_primary_postfix(name_expr)

        if isinstance(name_expr, Ps1StringLiteral) and not invocation_operator:
            absorbed = True
            while absorbed:
                name_expr, absorbed = self._absorb_suffix(
                    name_expr, Ps1TokenKind.DOT, '.', check_adjacent=True)
                name_expr, dash_absorbed = self._absorb_suffix(
                    name_expr, Ps1TokenKind.DASH, '-', check_adjacent=True)
                absorbed = absorbed or dash_absorbed

        self._lexer.mode = Ps1LexerMode.ARGUMENT
        self._rescan_current()

        arguments: list[Ps1CommandArgument | Expression] = []
        redirections: list[Ps1FileRedirection | Ps1MergingRedirection] = []
        while not self._is_pipeline_terminator():
            self._lexer.mode = Ps1LexerMode.ARGUMENT
            self._rescan_current()
            if self._is_pipeline_terminator():
                break
            if self._at(Ps1TokenKind.PARAMETER):
                tok = self._advance()
                name = tok.value
                if name.endswith(':'):
                    name = name[:-1]
                    if not self._is_pipeline_terminator():
                        val = self._parse_argument_value()
                        arguments.append(Ps1CommandArgument(
                            offset=tok.offset,
                            kind=Ps1CommandArgumentKind.NAMED,
                            name=name,
                            value=val,
                        ))
                    else:
                        arguments.append(Ps1CommandArgument(
                            offset=tok.offset,
                            kind=Ps1CommandArgumentKind.SWITCH,
                            name=name,
                        ))
                else:
                    arguments.append(Ps1CommandArgument(
                        offset=tok.offset,
                        kind=Ps1CommandArgumentKind.SWITCH,
                        name=name,
                    ))
            elif self._at(Ps1TokenKind.REDIRECTION):
                tok = self._advance()
                redirections.append(self._parse_redirection(tok))
            elif self._at(Ps1TokenKind.OPERATOR):
                tok = self._advance()
                arguments.append(Ps1CommandArgument(
                    offset=tok.offset,
                    kind=Ps1CommandArgumentKind.SWITCH,
                    name=tok.value,
                ))
            else:
                val = self._parse_argument_value()
                if val is None:
                    break
                arguments.append(Ps1CommandArgument(
                    offset=val.offset,
                    kind=Ps1CommandArgumentKind.POSITIONAL,
                    value=val,
                ))

        return Ps1CommandInvocation(
            offset=offset,
            name=name_expr,
            arguments=arguments,
            invocation_operator=invocation_operator,
            redirections=redirections,
        )

    def _is_pipeline_terminator(self) -> bool:
        return self._current.kind in _PIPELINE_TERMINATORS

    def _parse_argument_value(self) -> Expression | None:
        first = self._parse_single_argument_value()
        if first is None:
            return None
        if not self._at(Ps1TokenKind.COMMA):
            return first
        elements = [first]
        while self._eat(Ps1TokenKind.COMMA):
            self._skip_newlines()
            elem = self._parse_single_argument_value()
            if elem is None:
                break
            elements.append(elem)
        if len(elements) == 1:
            return elements[0]
        return Ps1ArrayLiteral(offset=first.offset, elements=elements)

    def _parse_generic_as_string(self, tok: Ps1Token) -> Expression:
        if tok.kind == Ps1TokenKind.GENERIC_EXPAND:
            parts = self._split_generic_expandable(tok.value)
            if len(parts) == 1 and isinstance(parts[0], Ps1StringLiteral):
                return Ps1StringLiteral(
                    offset=tok.offset, value=parts[0].value, raw=tok.value)
            return Ps1ExpandableString(
                offset=tok.offset, parts=parts, raw=tok.value)
        return Ps1StringLiteral(
            offset=tok.offset, value=tok.value, raw=tok.value)

    def _parse_single_argument_value(self) -> Expression | None:
        if self._at(Ps1TokenKind.GENERIC_TOKEN, Ps1TokenKind.GENERIC_EXPAND):
            tok = self._advance()
            result = self._parse_generic_as_string(tok)
            if isinstance(result, Ps1StringLiteral):
                result, _ = self._absorb_suffix(result, Ps1TokenKind.DOT, '.')
            return result
        self._lexer.mode = Ps1LexerMode.EXPRESSION
        if self._current.kind in _EXPRESSION_START_KINDS:
            return self._parse_unary_expression()
        if self._at(Ps1TokenKind.STAR, Ps1TokenKind.SLASH, Ps1TokenKind.PERCENT):
            tok = self._advance()
            return self._bare_string(tok)
        return None

    def _parse_expression(self) -> Expression | None:
        return self._parse_binary_expression(0)

    def _current_binary_precedence(self) -> int | None:
        if self._current.kind == Ps1TokenKind.DOTDOT:
            return 70
        if self._current.kind in (Ps1TokenKind.STAR, Ps1TokenKind.SLASH, Ps1TokenKind.PERCENT):
            return 50
        if self._current.kind in (Ps1TokenKind.PLUS, Ps1TokenKind.DASH):
            return 40
        if self._current.kind == Ps1TokenKind.OPERATOR:
            v = self._current.value
            if v == '-f':
                return 60
            return _BINARY_PRECEDENCE.get(v)
        return None

    def _parse_binary_expression(self, min_prec: int) -> Expression | None:
        left = self._parse_array_literal_expression()
        if left is None:
            return None
        while True:
            prec = self._current_binary_precedence()
            if prec is None or prec < min_prec:
                break
            op = self._advance()
            self._skip_newlines()
            right = self._parse_binary_expression(prec + 1)
            if right is None:
                break
            if op.kind == Ps1TokenKind.DOTDOT:
                left = Ps1RangeExpression(offset=left.offset, start=left, end=right)
            else:
                left = Ps1BinaryExpression(offset=left.offset, left=left, operator=op.value, right=right)
        return left

    def _parse_array_literal_expression(self) -> Expression | None:
        first = self._parse_unary_expression()
        if first is None:
            return None
        if self._disable_comma or not self._at(Ps1TokenKind.COMMA):
            return first
        elements = [first]
        while self._eat(Ps1TokenKind.COMMA):
            self._skip_newlines()
            elem = self._parse_unary_expression()
            if elem is None:
                break
            elements.append(elem)
        if len(elements) == 1:
            return elements[0]
        return Ps1ArrayLiteral(offset=first.offset, elements=elements)

    def _parse_argument_expression(self) -> Expression | None:
        """
        Parse a single method argument expression. Uses the full expression
        grammar but disables the comma operator so that commas delimit
        arguments rather than forming array literals.
        """
        with self._comma_mode(disabled=True):
            return self._parse_expression()

    def _parse_unary_expression(self) -> Expression | None:
        tok = self._current

        if tok.kind == Ps1TokenKind.COMMA:
            if self._disable_comma:
                return None
            self._advance()
            self._skip_newlines()
            operand = self._parse_unary_expression()
            if operand is None:
                return Ps1ArrayLiteral(offset=tok.offset, elements=[])
            return Ps1ArrayLiteral(offset=tok.offset, elements=[operand])

        if tok.kind in (Ps1TokenKind.INCREMENT, Ps1TokenKind.DECREMENT):
            op = self._advance()
            self._skip_newlines()
            operand = self._parse_unary_expression()
            return Ps1UnaryExpression(
                offset=tok.offset, operator=op.value, operand=operand, prefix=True)

        if tok.kind == Ps1TokenKind.EXCLAIM:
            self._advance()
            self._skip_newlines()
            operand = self._parse_unary_expression()
            return Ps1UnaryExpression(
                offset=tok.offset, operator='!', operand=operand, prefix=True)

        if tok.kind == Ps1TokenKind.OPERATOR and tok.value in ('-not', '-bnot', '-split', '-csplit', '-isplit', '-join'):
            op = self._advance()
            self._skip_newlines()
            operand = self._parse_unary_expression()
            return Ps1UnaryExpression(
                offset=tok.offset, operator=op.value, operand=operand, prefix=True)

        if tok.kind in (Ps1TokenKind.PLUS, Ps1TokenKind.DASH):
            op = self._advance()
            self._skip_newlines()
            operand = self._parse_unary_expression()
            return Ps1UnaryExpression(
                offset=tok.offset, operator=op.value, operand=operand, prefix=True)

        if tok.kind == Ps1TokenKind.LBRACKET:
            saved_pos = self._lexer.pos
            saved_tok = self._current
            type_expr = self._try_parse_type_literal()
            if type_expr is not None:
                if self._at(Ps1TokenKind.DOUBLE_COLON):
                    return self._parse_primary_postfix(type_expr)
                if not self._at(Ps1TokenKind.NEWLINE, Ps1TokenKind.COMMA):
                    operand = self._parse_unary_expression()
                    if operand is not None:
                        return Ps1CastExpression(
                            offset=tok.offset, type_name=type_expr.name, operand=operand)
                return self._parse_primary_postfix(type_expr)
            self._lexer.pos = saved_pos
            self._current = saved_tok

        return self._parse_primary_expression()

    def _try_parse_type_literal(self) -> Ps1TypeExpression | None:
        if not self._at(Ps1TokenKind.LBRACKET):
            return None
        offset = self._current.offset
        self._advance()
        self._skip_newlines()
        name_parts: list[str] = []
        depth = 1
        while not self._at(Ps1TokenKind.EOF):
            if self._at(Ps1TokenKind.RBRACKET):
                depth -= 1
                if depth == 0:
                    self._advance()
                    break
                name_parts.append(']')
                self._advance()
            elif self._at(Ps1TokenKind.LBRACKET):
                depth += 1
                name_parts.append('[')
                self._advance()
            elif self._at(Ps1TokenKind.NEWLINE, Ps1TokenKind.SEMICOLON):
                return None
            else:
                name_parts.append(self._current.value)
                self._advance()
        name = ''.join(name_parts).strip()
        if not name:
            return None
        return Ps1TypeExpression(offset=offset, name=name)

    def _parse_primary_expression(self) -> Expression | None:
        expr = self._parse_primary_atom()
        if expr is None:
            return None
        return self._parse_primary_postfix(expr)

    def _parse_primary_postfix(self, expr: Expression) -> Expression:
        while True:
            if self._at(Ps1TokenKind.DOT, Ps1TokenKind.DOUBLE_COLON):
                expr = self._parse_member_access(expr)
            elif self._at(Ps1TokenKind.LBRACKET):
                expr = self._parse_index_expression(expr)
            elif self._at(Ps1TokenKind.INCREMENT):
                op = self._advance()
                expr = Ps1UnaryExpression(
                    offset=op.offset, operator='++', operand=expr, prefix=False)
            elif self._at(Ps1TokenKind.DECREMENT):
                op = self._advance()
                expr = Ps1UnaryExpression(
                    offset=op.offset, operator='--', operand=expr, prefix=False)
            else:
                break
        return expr

    def _parse_primary_atom(self) -> Expression | None:
        tok = self._current

        if tok.kind == Ps1TokenKind.INTEGER:
            return self._parse_integer()
        if tok.kind == Ps1TokenKind.REAL:
            return self._parse_real()
        if tok.kind in (Ps1TokenKind.STRING_VERBATIM, Ps1TokenKind.STRING_EXPAND):
            return self._parse_string()
        if tok.kind in (Ps1TokenKind.HSTRING_VERBATIM, Ps1TokenKind.HSTRING_EXPAND):
            return self._parse_here_string()
        if tok.kind in (Ps1TokenKind.VARIABLE, Ps1TokenKind.SPLAT_VARIABLE):
            return self._parse_variable()
        if tok.kind == Ps1TokenKind.LPAREN:
            return self._parse_paren_expression()
        if tok.kind == Ps1TokenKind.DOLLAR_LPAREN:
            return self._parse_sub_expression()
        if tok.kind == Ps1TokenKind.AT_LPAREN:
            return self._parse_array_expression()
        if tok.kind == Ps1TokenKind.AT_LBRACE:
            return self._parse_hash_literal()
        if tok.kind == Ps1TokenKind.LBRACE:
            return self._parse_script_block()
        if tok.kind == Ps1TokenKind.LBRACKET:
            return self._try_parse_type_literal()
        if tok.kind in (Ps1TokenKind.GENERIC_TOKEN, Ps1TokenKind.GENERIC_EXPAND):
            return self._parse_generic_as_string(self._advance())

        return None

    def _parse_integer(self) -> Ps1IntegerLiteral:
        tok = self._advance()
        raw = tok.value
        text = raw.rstrip('lL').replace('_', '')
        try:
            value = int(text, 0)
        except ValueError:
            value = 0
        return Ps1IntegerLiteral(offset=tok.offset, value=value, raw=raw)

    def _parse_real(self) -> Ps1RealLiteral:
        tok = self._advance()
        raw = tok.value
        text = raw.replace('_', '')
        value = 0.0
        for suffix, mult in _MULTIPLIER_SUFFIXES.items():
            if text.lower().endswith(suffix):
                text = text[:-len(suffix)].rstrip('lL')
                try:
                    value = float(int(text, 0)) * mult
                except (ValueError, OverflowError):
                    try:
                        value = float(text) * mult
                    except ValueError:
                        pass
                break
        else:
            for suffix in ('d', 'D'):
                if text.endswith(suffix):
                    text = text[:-1]
                    break
            try:
                value = float(text)
            except ValueError:
                pass
        return Ps1RealLiteral(offset=tok.offset, value=value, raw=raw)

    def _parse_string(self) -> Expression:
        tok = self._advance()
        raw = tok.value.translate(NORMALIZE_QUOTES)
        if tok.kind == Ps1TokenKind.STRING_VERBATIM:
            content = self._unescape_verbatim_string(tok.value[1:-1])
            return Ps1StringLiteral(offset=tok.offset, value=content, raw=raw)
        inner = raw[1:-1]
        parts = self._split_expandable_string(inner)
        if len(parts) == 1 and isinstance(parts[0], Ps1StringLiteral):
            return Ps1StringLiteral(offset=tok.offset, value=parts[0].value, raw=raw)
        return Ps1ExpandableString(offset=tok.offset, parts=parts, raw=raw)

    def _try_parse_dollar_expansion(self, text: str, pos: int) -> tuple[Expression | None, int]:
        length = len(text)
        if pos + 1 < length and text[pos + 1] == '(':
            node, new_pos = self._parse_embedded_subexpression(text, pos)
            return node, new_pos
        m = _VARIABLE_FRAG.match(text, pos)
        if m:
            return self._make_variable_from_text(m.group()), m.end()
        return None, pos

    def _split_expandable_string(self, text: str) -> list[Expression]:
        parts: list[Expression] = []
        pos = 0
        length = len(text)
        buf: list[str] = []

        def flush_text():
            if buf:
                raw_text = ''.join(buf)
                decoded = self._decode_dq_escapes(raw_text)
                parts.append(Ps1StringLiteral(offset=-1, value=decoded, raw=raw_text))
                buf.clear()

        while pos < length:
            c = text[pos]

            if c == '`' and pos + 1 < length:
                buf.append(c)
                buf.append(text[pos + 1])
                pos += 2
                continue

            if c in DOUBLE_QUOTES and pos + 1 < length and text[pos + 1] in DOUBLE_QUOTES:
                buf.append('""')
                pos += 2
                continue

            if c == '$':
                node, new_pos = self._try_parse_dollar_expansion(text, pos)
                if node is not None:
                    flush_text()
                    parts.append(node)
                    pos = new_pos
                    continue

            buf.append(c)
            pos += 1

        flush_text()
        return parts

    def _split_generic_expandable(self, text: str) -> list[Expression]:
        """
        Split a GENERIC_EXPAND token value into interleaved literal and expression parts. Unlike
        `refinery.lib.scripts.ps1.parser.Ps1Parser._split_expandable_string` (for double-quoted
        strings), this operates on raw source text that may contain embedded single/double-quoted
        strings and backtick escapes.
        """
        parts: list[Expression] = []
        pos = 0
        length = len(text)
        buf: list[str] = []

        def flush_text():
            if buf:
                value = ''.join(buf)
                parts.append(Ps1StringLiteral(offset=-1, value=value, raw=value))
                buf.clear()

        while pos < length:
            c = text[pos]
            if c == '`' and pos + 1 < length:
                nc = text[pos + 1]
                buf.append(BACKTICK_ESCAPE.get(nc, nc))
                pos += 2
                continue
            if c in SINGLE_QUOTES:
                pos += 1
                while pos < length:
                    if text[pos] in SINGLE_QUOTES:
                        pos += 1
                        if pos < length and text[pos] in SINGLE_QUOTES:
                            buf.append("'")
                            pos += 1
                            continue
                        break
                    buf.append(text[pos])
                    pos += 1
                continue
            if c in DOUBLE_QUOTES:
                flush_text()
                pos += 1
                inner_start = pos
                while pos < length:
                    if text[pos] == '`' and pos + 1 < length:
                        pos += 2
                        continue
                    if text[pos] in DOUBLE_QUOTES:
                        pos += 1
                        break
                    pos += 1
                inner = text[inner_start:pos - 1]
                sub_parts = self._split_expandable_string(inner)
                parts.extend(sub_parts)
                continue
            if c == '$':
                node, new_pos = self._try_parse_dollar_expansion(text, pos)
                if node is not None:
                    flush_text()
                    parts.append(node)
                    pos = new_pos
                    continue
            buf.append(c)
            pos += 1

        flush_text()
        return parts

    @classmethod
    def _scan_subexpression_extent(cls, text: str, pos: int) -> int:
        """
        Given that `'$(` occurs at `pos + 2`, skip past the matching closing parenthesis while
        correctly handling nested parentheses and quoted strings. Returns the position immediately
        after the last one.
        """
        length = len(text)
        depth = 1
        pos += 2
        while pos < length and depth > 0:
            sc = text[pos]
            if sc in SINGLE_QUOTES:
                pos = cls._skip_quoted_raw(text, pos + 1, length, SINGLE_QUOTES)
                continue
            if sc in DOUBLE_QUOTES:
                pos = cls._skip_quoted_raw(text, pos + 1, length, DOUBLE_QUOTES, backtick=True)
                continue
            if sc == '(':
                depth += 1
            elif sc == ')':
                depth -= 1
            pos += 1
        return pos

    def _parse_embedded_subexpression(self, text: str, start: int) -> tuple[Ps1SubExpression, int]:
        """
        Parse a `$(...)` subexpression embedded in a string starting at position `start` (which
        points at the dollar). Returns the AST node and the position after the closing parenthesis.
        """
        end = self._scan_subexpression_extent(text, start)
        sub_text = text[start + 2:end - 1]
        sub_parser = Ps1Parser(sub_text)
        sub_stmts = sub_parser._parse_statement_list()
        return Ps1SubExpression(offset=-1, body=sub_stmts), end

    def _decode_dq_escapes(self, text: str) -> str:
        result: list[str] = []
        i = 0
        length = len(text)
        while i < length:
            c = text[i]
            if c == '`' and i + 1 < length:
                nc = text[i + 1]
                result.append(BACKTICK_ESCAPE.get(nc, nc))
                i += 2
            elif c in DOUBLE_QUOTES and i + 1 < length and text[i + 1] in DOUBLE_QUOTES:
                result.append('"')
                i += 2
            else:
                result.append(c)
                i += 1
        return ''.join(result)

    @staticmethod
    def _unescape_verbatim_string(text: str) -> str:
        result: list[str] = []
        i = 0
        length = len(text)
        while i < length:
            c = text[i]
            if c in SINGLE_QUOTES and i + 1 < length and text[i + 1] in SINGLE_QUOTES:
                result.append("'")
                i += 2
            else:
                result.append(c)
                i += 1
        return ''.join(result)

    def _make_variable_from_text(self, text: str) -> Ps1Variable:
        name = text
        splatted = name.startswith('@')
        if name.startswith('$') or name.startswith('@'):
            name = name[1:]
        braced = False
        if name.startswith('{') and name.endswith('}'):
            braced = True
            name = name[1:-1]
        if '`' in name:
            name = _strip_backtick_noop(name)
        scope = Ps1ScopeModifier.NONE
        if ':' in name:
            prefix, rest = name.split(':', 1)
            prefix_lower = prefix.lower()
            try:
                scope = Ps1ScopeModifier(prefix_lower)
            except ValueError:
                scope = Ps1ScopeModifier.DRIVE
            name = rest
        if not braced and name.startswith('{') and name.endswith('}'):
            braced = True
            name = name[1:-1]
        return Ps1Variable(offset=-1, name=name, scope=scope, braced=braced, splatted=splatted)

    def _parse_here_string(self) -> Expression:
        tok = self._advance()
        raw = tok.value.translate(NORMALIZE_QUOTES)
        if tok.kind == Ps1TokenKind.HSTRING_VERBATIM:
            inner = self._strip_here_string(raw, "@'", "'@")
            return Ps1HereString(
                offset=tok.offset, value=inner, raw=raw)
        inner = self._strip_here_string(raw, '@"', '"@')
        parts = self._split_expandable_string(inner)
        if len(parts) == 1 and isinstance(parts[0], Ps1StringLiteral):
            return Ps1HereString(
                offset=tok.offset, value=parts[0].value, raw=raw)
        return Ps1ExpandableHereString(offset=tok.offset, parts=parts, raw=raw)

    @staticmethod
    def _strip_here_string(raw: str, open_delim: str, close_delim: str) -> str:
        inner = raw[len(open_delim):]
        if inner.endswith(close_delim):
            inner = inner[:-len(close_delim)]
        inner = inner.lstrip(' \t')
        if inner.startswith('\r\n'):
            inner = inner[2:]
        elif inner.startswith(('\n', '\r')):
            inner = inner[1:]
        if inner.endswith('\r\n'):
            inner = inner[:-2]
        elif inner.endswith(('\n', '\r')):
            inner = inner[:-1]
        return inner

    def _parse_variable(self) -> Ps1Variable:
        tok = self._advance()
        return self._make_variable_from_text(tok.value)

    def _parse_paren_expression(self) -> Expression:
        offset = self._current.offset
        self._expect(Ps1TokenKind.LPAREN)
        self._skip_newlines()
        self._lexer.push_mode(Ps1LexerMode.EXPRESSION)
        with self._comma_mode(disabled=False):
            expr = self._parse_pipeline_expression()
        self._skip_newlines()
        self._expect(Ps1TokenKind.RPAREN)
        self._lexer.pop_mode()
        self._rescan_current()
        return Ps1ParenExpression(offset=offset, expression=expr)

    def _parse_delimited_statement_block(
        self,
        open_kind: Ps1TokenKind,
        cls: type[Ps1SubExpression] | type[Ps1ArrayExpression],
    ) -> Expression:
        offset = self._current.offset
        self._expect(open_kind)
        self._skip_newlines()
        self._lexer.push_mode(Ps1LexerMode.EXPRESSION)
        with self._comma_mode(disabled=False):
            stmts = self._parse_statement_list(until=Ps1TokenKind.RPAREN)
        self._skip_newlines()
        self._expect(Ps1TokenKind.RPAREN)
        self._lexer.pop_mode()
        self._rescan_current()
        return cls(offset=offset, body=stmts)

    def _parse_sub_expression(self) -> Expression:
        return self._parse_delimited_statement_block(
            Ps1TokenKind.DOLLAR_LPAREN, Ps1SubExpression)

    def _parse_array_expression(self) -> Expression:
        return self._parse_delimited_statement_block(
            Ps1TokenKind.AT_LPAREN, Ps1ArrayExpression)

    def _parse_label_or_key(self) -> Expression | None:
        if self._at(
            Ps1TokenKind.GENERIC_TOKEN,
            Ps1TokenKind.GENERIC_EXPAND,
            Ps1TokenKind.LABEL,
        ) or self._current.kind.is_keyword:
            return self._bare_string(self._advance())
        if self._is_statement_terminator():
            return None
        with self._comma_mode(disabled=True):
            return self._parse_unary_expression()

    def _parse_hash_literal(self) -> Ps1HashLiteral:
        offset = self._current.offset
        self._expect(Ps1TokenKind.AT_LBRACE)
        self._skip_newlines()
        pairs: list[tuple[Expression, Expression]] = []
        while not self._at(Ps1TokenKind.RBRACE, Ps1TokenKind.EOF):
            self._skip_newlines()
            if self._at(Ps1TokenKind.RBRACE):
                break
            key = self._parse_label_or_key()
            if key is None:
                break
            self._skip_newlines()
            self._expect(Ps1TokenKind.EQUALS)
            self._skip_newlines()
            value = self._parse_pipeline_expression()
            if value is None:
                value = Ps1StringLiteral(offset=self._current.offset, value='', raw='')
            pairs.append((key, value))
            while self._current.kind in (Ps1TokenKind.NEWLINE, Ps1TokenKind.SEMICOLON):
                self._advance()
        self._skip_newlines()
        self._expect(Ps1TokenKind.RBRACE)
        return Ps1HashLiteral(offset=offset, pairs=pairs)

    def _parse_script_block(self) -> Ps1ScriptBlock:
        offset = self._current.offset
        self._expect(Ps1TokenKind.LBRACE)
        with self._comma_mode(disabled=False):
            fields = self._parse_code_body(until=Ps1TokenKind.RBRACE)
            self._skip_newlines()
            self._expect(Ps1TokenKind.RBRACE)
        return Ps1ScriptBlock(offset=offset, **fields)

    def _parse_member_access(self, obj: Expression) -> Expression:
        access_tok = self._advance()
        access = (
            Ps1AccessKind.STATIC
            if access_tok.kind == Ps1TokenKind.DOUBLE_COLON
            else Ps1AccessKind.INSTANCE
        )
        self._skip_newlines()

        member: str | Expression
        if self._at(Ps1TokenKind.GENERIC_TOKEN):
            tok = self._advance()
            member = tok.value
        elif self._at(Ps1TokenKind.VARIABLE):
            member = self._parse_variable()
        elif self._at(Ps1TokenKind.STRING_EXPAND, Ps1TokenKind.STRING_VERBATIM):
            member = self._parse_string()
        elif self._at(Ps1TokenKind.LPAREN):
            member = self._parse_paren_expression()
        elif self._at(Ps1TokenKind.DOLLAR_LPAREN):
            member = self._parse_sub_expression()
        else:
            tok = self._advance()
            member = tok.value

        if self._at(Ps1TokenKind.LPAREN):
            self._advance()
            self._skip_newlines()
            args: list[Expression] = []
            while not self._at(Ps1TokenKind.RPAREN, Ps1TokenKind.EOF):
                arg = self._parse_argument_expression()
                if arg is not None:
                    args.append(arg)
                self._skip_newlines()
                if not self._eat(Ps1TokenKind.COMMA):
                    break
                self._skip_newlines()
            self._expect(Ps1TokenKind.RPAREN)
            return Ps1InvokeMember(
                offset=obj.offset,
                object=obj,
                member=member,
                arguments=args,
                access=access,
            )

        return Ps1MemberAccess(offset=obj.offset, object=obj, member=member, access=access)

    def _parse_index_expression(self, obj: Expression) -> Expression:
        self._advance()
        self._skip_newlines()
        with self._comma_mode(disabled=False):
            index = self._parse_expression()
        self._skip_newlines()
        self._expect(Ps1TokenKind.RBRACKET)
        return Ps1IndexExpression(offset=obj.offset, object=obj, index=index)

    def _parse_if(self) -> Ps1IfStatement:
        offset = self._current.offset
        clauses: list[tuple[Expression, Block]] = []

        self._expect(Ps1TokenKind.IF)
        self._skip_newlines()
        cond = self._parse_parenthesized_condition()
        self._skip_newlines()
        body = self._parse_block()
        clauses.append((cond, body))

        self._skip_newlines()
        while self._at(Ps1TokenKind.ELSEIF):
            self._advance()
            self._skip_newlines()
            cond = self._parse_parenthesized_condition()
            self._skip_newlines()
            body = self._parse_block()
            clauses.append((cond, body))
            self._skip_newlines()

        else_block = None
        if self._at(Ps1TokenKind.ELSE):
            self._advance()
            self._skip_newlines()
            else_block = self._parse_block()

        return Ps1IfStatement(offset=offset, clauses=clauses, else_block=else_block)

    def _parse_while(self, label: str | None = None) -> Ps1WhileLoop:
        offset = self._current.offset
        self._expect(Ps1TokenKind.WHILE)
        self._skip_newlines()
        cond = self._parse_parenthesized_condition()
        self._skip_newlines()
        body = self._parse_block()
        return Ps1WhileLoop(offset=offset, condition=cond, body=body, label=label)

    def _parse_do(self, label: str | None = None) -> Statement:
        offset = self._current.offset
        self._expect(Ps1TokenKind.DO)
        self._skip_newlines()
        body = self._parse_block()
        self._skip_newlines()
        is_until = self._at(Ps1TokenKind.UNTIL)
        if is_until or self._at(Ps1TokenKind.WHILE):
            self._advance()
            self._skip_newlines()
            cond = self._parse_parenthesized_condition()
            return Ps1DoLoop(
                offset=offset, condition=cond, body=body, is_until=is_until, label=label)
        return Ps1DoLoop(offset=offset, body=body, label=label)

    def _parse_for(self, label: str | None = None) -> Ps1ForLoop:
        offset = self._current.offset
        self._expect(Ps1TokenKind.FOR)
        self._skip_newlines()
        self._expect(Ps1TokenKind.LPAREN)
        self._skip_newlines()
        init = None
        if not self._at(Ps1TokenKind.SEMICOLON):
            init = self._parse_pipeline_expression()
        self._eat(Ps1TokenKind.SEMICOLON)
        self._skip_newlines()
        cond = None
        if not self._at(Ps1TokenKind.SEMICOLON):
            cond = self._parse_pipeline_expression()
        self._eat(Ps1TokenKind.SEMICOLON)
        self._skip_newlines()
        iter_expr = None
        if not self._at(Ps1TokenKind.RPAREN):
            iter_expr = self._parse_pipeline_expression()
        self._skip_newlines()
        self._expect(Ps1TokenKind.RPAREN)
        self._skip_newlines()
        body = self._parse_block()
        return Ps1ForLoop(
            offset=offset, initializer=init, condition=cond, iterator=iter_expr, body=body, label=label)

    def _parse_foreach(self, label: str | None = None) -> Ps1ForEachLoop:
        offset = self._current.offset
        self._expect(Ps1TokenKind.FOREACH)
        self._skip_newlines()
        parallel = False
        if self._at(Ps1TokenKind.PARAMETER) and self._current.value.lower().startswith('-parallel'):
            self._advance()
            parallel = True
        self._expect(Ps1TokenKind.LPAREN)
        self._skip_newlines()
        var = self._parse_variable() if self._at(
            Ps1TokenKind.VARIABLE, Ps1TokenKind.SPLAT_VARIABLE) else None
        self._skip_newlines()
        self._expect(Ps1TokenKind.IN)
        self._skip_newlines()
        iterable = self._parse_pipeline_expression()
        self._skip_newlines()
        self._expect(Ps1TokenKind.RPAREN)
        self._skip_newlines()
        body = self._parse_block()
        return Ps1ForEachLoop(
            offset=offset, variable=var, iterable=iterable, body=body, parallel=parallel, label=label)

    def _parse_switch_clause_condition(self) -> Expression | None:
        """
        Parse a switch clause condition. The reference PowerShell parser uses
        GetSingleCommandArgument(SwitchCondition) here, which tokenizes in
        command mode and treats keyword tokens as bare-word string literals.
        """
        if self._current.kind.is_keyword:
            tok = self._advance()
            return self._bare_string(tok)
        self._lexer.mode = Ps1LexerMode.EXPRESSION
        return self._parse_expression()

    def _parse_switch(self, label: str | None = None) -> Ps1SwitchStatement:
        offset = self._current.offset
        self._expect(Ps1TokenKind.SWITCH)
        self._skip_newlines()
        self._lexer.mode = Ps1LexerMode.ARGUMENT
        self._rescan_current()
        regex = False
        wildcard = False
        exact = False
        case_sensitive = False
        file = False
        while self._at(Ps1TokenKind.PARAMETER):
            p = self._current.value.lower().lstrip('-').rstrip(':')
            self._advance()
            self._skip_newlines()
            if p == 'regex':
                regex = True
            elif p == 'wildcard':
                wildcard = True
            elif p == 'exact':
                exact = True
            elif p == 'casesensitive':
                case_sensitive = True
            elif p == 'file':
                file = True
        if file:
            self._lexer.mode = Ps1LexerMode.ARGUMENT
            value = self._parse_argument_value()
            self._skip_newlines()
        else:
            value = self._parse_parenthesized_condition()
            self._skip_newlines()
        self._expect(Ps1TokenKind.LBRACE)
        self._skip_newlines()
        clauses: list[tuple[Expression | None, Block]] = []
        while not self._at(Ps1TokenKind.RBRACE, Ps1TokenKind.EOF):
            self._skip_separators()
            if self._at(Ps1TokenKind.RBRACE):
                break
            if self._at(Ps1TokenKind.GENERIC_TOKEN, Ps1TokenKind.GENERIC_EXPAND) and self._current.value.lower() == 'default':
                self._advance()
                self._skip_newlines()
                block = self._parse_block()
                clauses.append((None, block))
            else:
                cond = self._parse_switch_clause_condition()
                self._skip_newlines()
                block = self._parse_block()
                clauses.append((cond, block))
            self._skip_separators()
        self._expect(Ps1TokenKind.RBRACE)
        return Ps1SwitchStatement(
            offset=offset,
            value=value,
            clauses=clauses,
            label=label,
            regex=regex,
            wildcard=wildcard,
            exact=exact,
            case_sensitive=case_sensitive,
            file=file,
        )

    def _parse_try(self) -> Ps1TryCatchFinally:
        offset = self._current.offset
        self._expect(Ps1TokenKind.TRY)
        self._skip_newlines()
        try_block = self._parse_block()
        self._skip_newlines()
        catch_clauses: list[Ps1CatchClause] = []
        while self._at(Ps1TokenKind.CATCH):
            self._advance()
            self._skip_newlines()
            types: list[str] = []
            while self._at(Ps1TokenKind.LBRACKET):
                te = self._try_parse_type_literal()
                if te:
                    types.append(te.name)
                self._skip_newlines()
                if not self._eat(Ps1TokenKind.COMMA):
                    break
                self._skip_newlines()
            body = self._parse_block()
            catch_clauses.append(Ps1CatchClause(
                offset=body.offset, types=types, body=body))
            self._skip_newlines()
        finally_block = None
        if self._at(Ps1TokenKind.FINALLY):
            self._advance()
            self._skip_newlines()
            finally_block = self._parse_block()
        return Ps1TryCatchFinally(
            offset=offset,
            try_block=try_block,
            catch_clauses=catch_clauses,
            finally_block=finally_block,
        )

    def _parse_trap(self) -> Ps1TrapStatement:
        offset = self._current.offset
        self._expect(Ps1TokenKind.TRAP)
        self._skip_newlines()
        type_name = ''
        if self._at(Ps1TokenKind.LBRACKET):
            te = self._try_parse_type_literal()
            if te:
                type_name = te.name
            self._skip_newlines()
        body = self._parse_block()
        return Ps1TrapStatement(offset=offset, type_name=type_name, body=body)

    def _parse_function_definition(self) -> Ps1FunctionDefinition:
        offset = self._current.offset
        kw = self._advance(Ps1LexerMode.ARGUMENT)
        is_filter = kw.kind == Ps1TokenKind.FILTER
        self._skip_newlines()
        name = ''
        if self._at(
            Ps1TokenKind.GENERIC_TOKEN,
            Ps1TokenKind.VARIABLE,
        ) or self._current.kind.is_keyword:
            name = self._advance().value
        self._lexer.mode = Ps1LexerMode.EXPRESSION
        self._skip_newlines()
        if self._at(Ps1TokenKind.LPAREN):
            self._advance()
            self._skip_newlines()
            params = self._parse_parameter_list()
            self._skip_newlines()
            self._expect(Ps1TokenKind.RPAREN)
            self._skip_newlines()
            self._expect(Ps1TokenKind.LBRACE)
            self._skip_newlines()
            script_body = self._parse_script_block_body(expect_close=True)
            script_body.param_block = Ps1ParamBlock(
                offset=offset, parameters=params)
            return Ps1FunctionDefinition(
                offset=offset, name=name, is_filter=is_filter, body=script_body)
        body = self._parse_script_block()
        return Ps1FunctionDefinition(
            offset=offset, name=name, is_filter=is_filter, body=body)

    def _parse_class_definition(self) -> Ps1ClassDefinition:
        offset = self._current.offset
        self._advance(Ps1LexerMode.ARGUMENT)
        self._skip_newlines()
        name = ''
        if self._at(Ps1TokenKind.GENERIC_TOKEN) or self._current.kind.is_keyword:
            name = self._advance().value
        self._skip_newlines()
        base_types: list[str] = []
        if self._eat_colon():
            self._skip_newlines()
            while not self._at(Ps1TokenKind.LBRACE, Ps1TokenKind.EOF):
                if self._at(Ps1TokenKind.GENERIC_TOKEN) or self._current.kind.is_keyword:
                    base_types.append(self._advance().value)
                elif self._at(Ps1TokenKind.LBRACKET):
                    type_lit = self._try_parse_type_literal()
                    if type_lit is not None:
                        base_types.append(type_lit.name)
                    else:
                        break
                elif self._eat(Ps1TokenKind.COMMA):
                    self._skip_newlines()
                    continue
                else:
                    break
                self._skip_newlines()
        self._skip_newlines()
        self._expect(Ps1TokenKind.LBRACE)
        self._lexer.mode = Ps1LexerMode.EXPRESSION
        self._skip_newlines()
        members: list[Ps1PropertyMember | Ps1MethodMember] = []
        while not self._at(Ps1TokenKind.RBRACE, Ps1TokenKind.EOF):
            while self._at(Ps1TokenKind.NEWLINE, Ps1TokenKind.SEMICOLON):
                self._advance()
            if self._at(Ps1TokenKind.RBRACE, Ps1TokenKind.EOF):
                break
            member = self._parse_class_member()
            if member is not None:
                members.append(member)
            else:
                break
        self._expect(Ps1TokenKind.RBRACE)
        return Ps1ClassDefinition(
            offset=offset,
            name=name,
            base_types=base_types,
            members=members,
        )

    def _parse_class_member(self) -> Ps1PropertyMember | Ps1MethodMember | None:
        self._skip_newlines()
        if self._at(Ps1TokenKind.RBRACE, Ps1TokenKind.EOF):
            return None
        offset = self._current.offset
        attributes: list[Ps1Attribute] = []
        type_constraint: Ps1TypeExpression | None = None
        modifiers = Ps1MemberModifier.NONE
        while True:
            self._skip_newlines()
            if self._at(Ps1TokenKind.LBRACKET):
                attr = self._parse_attribute()
                if isinstance(attr, Ps1Attribute):
                    attributes.append(attr)
                elif type_constraint is None:
                    type_constraint = attr
                self._skip_newlines()
                continue
            if (
                self._current.kind == Ps1TokenKind.GENERIC_TOKEN
                and self._current.value.lower() == 'static'
            ):
                modifiers |= Ps1MemberModifier.STATIC
                self._advance()
                continue
            if (
                self._current.kind == Ps1TokenKind.GENERIC_TOKEN
                and self._current.value.lower() == 'hidden'
            ):
                modifiers |= Ps1MemberModifier.HIDDEN
                self._advance()
                continue
            break
        if self._at(Ps1TokenKind.VARIABLE):
            var_tok = self._advance()
            var = self._make_variable_from_text(var_tok.value)
            initial_value: Expression | None = None
            if self._eat(Ps1TokenKind.EQUALS):
                self._skip_newlines()
                self._lexer.mode = Ps1LexerMode.EXPRESSION
                initial_value = self._parse_expression()
            while self._at(Ps1TokenKind.NEWLINE, Ps1TokenKind.SEMICOLON):
                self._advance()
            return Ps1PropertyMember(
                offset=offset,
                attributes=attributes,
                modifiers=modifiers,
                type_constraint=type_constraint,
                variable=var,
                initial_value=initial_value,
            )
        if (
            self._at(Ps1TokenKind.GENERIC_TOKEN)
            or self._current.kind.is_keyword
        ):
            method_name = self._advance().value
            self._lexer.mode = Ps1LexerMode.EXPRESSION
            self._skip_newlines()
            params: list[Ps1ParameterDeclaration] = []
            if self._at(Ps1TokenKind.LPAREN):
                self._advance()
                self._skip_newlines()
                params = self._parse_parameter_list()
                self._skip_newlines()
                self._expect(Ps1TokenKind.RPAREN)
            self._skip_newlines()
            self._expect(Ps1TokenKind.LBRACE)
            self._skip_newlines()
            script_body = self._parse_script_block_body(expect_close=True)
            if params:
                script_body.param_block = Ps1ParamBlock(
                    offset=offset, parameters=params)
            funcdef = Ps1FunctionDefinition(
                offset=offset,
                name=method_name,
                body=script_body,
            )
            return_type = type_constraint
            return Ps1MethodMember(
                offset=offset,
                attributes=attributes,
                modifiers=modifiers,
                return_type=return_type,
                definition=funcdef,
            )
        return None

    def _parse_enum_definition(self) -> Ps1EnumDefinition:
        offset = self._current.offset
        self._advance(Ps1LexerMode.ARGUMENT)
        self._skip_newlines()
        name = ''
        if self._at(Ps1TokenKind.GENERIC_TOKEN) or self._current.kind.is_keyword:
            name = self._advance().value
        self._skip_newlines()
        base_type = ''
        if self._eat_colon():
            self._skip_newlines()
            if self._at(Ps1TokenKind.LBRACKET):
                type_lit = self._try_parse_type_literal()
                if type_lit is not None:
                    base_type = type_lit.name
            elif self._at(Ps1TokenKind.GENERIC_TOKEN) or self._current.kind.is_keyword:
                base_type = self._advance().value
            self._skip_newlines()
        self._expect(Ps1TokenKind.LBRACE)
        self._skip_newlines()
        members: list[Ps1EnumMember] = []
        while not self._at(Ps1TokenKind.RBRACE, Ps1TokenKind.EOF):
            member = self._parse_enum_member()
            if member is not None:
                members.append(member)
            else:
                break
        self._expect(Ps1TokenKind.RBRACE)
        return Ps1EnumDefinition(
            offset=offset,
            name=name,
            base_type=base_type,
            members=members,
        )

    def _parse_enum_member(self) -> Ps1EnumMember | None:
        self._skip_newlines()
        if self._at(Ps1TokenKind.RBRACE, Ps1TokenKind.EOF):
            return None
        offset = self._current.offset
        if not (
            self._at(Ps1TokenKind.GENERIC_TOKEN)
            or self._current.kind.is_keyword
        ):
            return None
        name = self._advance().value
        value: Expression | None = None
        self._lexer.mode = Ps1LexerMode.EXPRESSION
        if self._eat(Ps1TokenKind.EQUALS):
            self._skip_newlines()
            value = self._parse_expression()
        while self._at(Ps1TokenKind.NEWLINE, Ps1TokenKind.SEMICOLON):
            self._advance()
        return Ps1EnumMember(offset=offset, name=name, value=value)

    def _parse_script_block_body(self, expect_close: bool = False) -> Ps1ScriptBlock:
        offset = self._current.offset
        fields = self._parse_code_body(until=Ps1TokenKind.RBRACE)
        self._skip_newlines()
        if expect_close:
            self._expect(Ps1TokenKind.RBRACE)
        return Ps1ScriptBlock(offset=offset, **fields)

    def _parse_param_block(self) -> Ps1ParamBlock:
        offset = self._current.offset
        attrs: list[Ps1Attribute] = []
        while self._at(Ps1TokenKind.LBRACKET):
            attr = self._parse_attribute()
            if isinstance(attr, Ps1Attribute):
                attrs.append(attr)
            self._skip_newlines()
        self._expect(Ps1TokenKind.PARAM)
        self._skip_newlines()
        self._expect(Ps1TokenKind.LPAREN)
        self._skip_newlines()
        params = self._parse_parameter_list()
        self._skip_newlines()
        self._expect(Ps1TokenKind.RPAREN)
        return Ps1ParamBlock(offset=offset, parameters=params, attributes=attrs)

    def _parse_parameter_list(self) -> list[Ps1ParameterDeclaration]:
        params: list[Ps1ParameterDeclaration] = []
        while not self._at(Ps1TokenKind.RPAREN, Ps1TokenKind.EOF):
            self._skip_newlines()
            if self._at(Ps1TokenKind.RPAREN):
                break
            param = self._parse_parameter_declaration()
            params.append(param)
            self._skip_newlines()
            if not self._eat(Ps1TokenKind.COMMA):
                break
            self._skip_newlines()
        return params

    def _parse_parameter_declaration(self) -> Ps1ParameterDeclaration:
        offset = self._current.offset
        attrs: list[Ps1Attribute | Ps1TypeExpression] = []
        while self._at(Ps1TokenKind.LBRACKET):
            attr = self._parse_attribute()
            attrs.append(attr)
            self._skip_newlines()
        var = None
        if self._at(Ps1TokenKind.VARIABLE, Ps1TokenKind.SPLAT_VARIABLE):
            var = self._parse_variable()
        default = None
        if self._eat(Ps1TokenKind.EQUALS):
            self._skip_newlines()
            with self._comma_mode(disabled=True):
                default = self._parse_expression()
        return Ps1ParameterDeclaration(
            offset=offset, variable=var, attributes=attrs, default_value=default)

    def _parse_attribute(self) -> Ps1Attribute | Ps1TypeExpression:
        offset = self._current.offset
        self._expect(Ps1TokenKind.LBRACKET)
        self._skip_newlines()
        name_parts: list[str] = []
        depth = 0
        while not self._at(Ps1TokenKind.LPAREN, Ps1TokenKind.EOF):
            if self._at(Ps1TokenKind.LBRACKET):
                depth += 1
                name_parts.append('[')
                self._advance()
            elif self._at(Ps1TokenKind.RBRACKET):
                if depth == 0:
                    break
                depth -= 1
                name_parts.append(']')
                self._advance()
            else:
                name_parts.append(self._current.value)
                self._advance()
        name = ''.join(name_parts).strip()
        if self._at(Ps1TokenKind.LPAREN):
            self._advance()
            self._skip_newlines()
            positional: list[Expression] = []
            named: list[tuple[str, Expression]] = []
            with self._comma_mode(disabled=True):
                while not self._at(Ps1TokenKind.RPAREN, Ps1TokenKind.EOF):
                    self._skip_newlines()
                    if self._at(Ps1TokenKind.RPAREN):
                        break
                    if self._at(Ps1TokenKind.GENERIC_TOKEN, Ps1TokenKind.GENERIC_EXPAND):
                        saved = self._current
                        saved_pos = self._lexer.pos
                        key_tok = self._advance()
                        if self._eat(Ps1TokenKind.EQUALS):
                            self._skip_newlines()
                            val = self._parse_expression()
                            if val is not None:
                                named.append((key_tok.value, val))
                                self._skip_newlines()
                                self._eat(Ps1TokenKind.COMMA)
                                continue
                        self._current = saved
                        self._lexer.pos = saved_pos
                    expr = self._parse_expression()
                    if expr is not None:
                        positional.append(expr)
                    self._skip_newlines()
                    if not self._eat(Ps1TokenKind.COMMA):
                        break
            self._expect(Ps1TokenKind.RPAREN)
            self._skip_newlines()
            self._expect(Ps1TokenKind.RBRACKET)
            return Ps1Attribute(
                offset=offset, name=name,
                positional_args=positional, named_args=named)
        self._expect(Ps1TokenKind.RBRACKET)
        return Ps1TypeExpression(offset=offset, name=name)

    def _parse_flow_with_pipeline(self, kind: Ps1TokenKind, cls: type[Ps1Exit]) -> Statement:
        offset = self._current.offset
        self._expect(kind)
        pipeline = None
        if not self._is_statement_terminator():
            pipeline = self._parse_pipeline_expression()
        return cls(offset=offset, pipeline=pipeline)

    def _parse_flow_with_label(self, kind: Ps1TokenKind, cls: type[Ps1Jump]) -> Statement:
        offset = self._current.offset
        self._expect(kind)
        label = None
        if not self._is_statement_terminator():
            label = self._parse_label_or_key()
        return cls(offset=offset, label=label)

    def _parse_return(self) -> Statement:
        return self._parse_flow_with_pipeline(Ps1TokenKind.RETURN, Ps1ReturnStatement)

    def _parse_throw(self) -> Statement:
        return self._parse_flow_with_pipeline(Ps1TokenKind.THROW, Ps1ThrowStatement)

    def _parse_break(self) -> Statement:
        return self._parse_flow_with_label(Ps1TokenKind.BREAK, Ps1BreakStatement)

    def _parse_continue(self) -> Statement:
        return self._parse_flow_with_label(Ps1TokenKind.CONTINUE, Ps1ContinueStatement)

    def _parse_exit(self) -> Statement:
        return self._parse_flow_with_pipeline(Ps1TokenKind.EXIT, Ps1ExitStatement)

    def _parse_data(self) -> Ps1DataSection:
        offset = self._current.offset
        self._expect(Ps1TokenKind.DATA)
        self._skip_newlines()
        name = ''
        if self._at(Ps1TokenKind.GENERIC_TOKEN):
            name = self._advance(Ps1LexerMode.ARGUMENT).value
            self._skip_newlines()
        commands: list[Expression] = []
        if self._at(Ps1TokenKind.PARAMETER):
            param = self._current.value.lower().lstrip('-').rstrip(':')
            self._advance()
            self._skip_newlines()
            if param == 'supportedcommand':
                while True:
                    self._skip_newlines()
                    arg = self._parse_single_argument_value()
                    if arg is None:
                        break
                    commands.append(arg)
                    if not self._eat(Ps1TokenKind.COMMA):
                        break
        self._lexer.mode = Ps1LexerMode.EXPRESSION
        body = self._parse_block()
        return Ps1DataSection(offset=offset, name=name, commands=commands, body=body)
