"""
Recursive-descent parser for PowerShell based on the PowerShell Language Specification 3.0.
"""
from __future__ import annotations

import re

from collections.abc import Callable
from contextlib import contextmanager
from typing import TypeVar

from refinery.lib.scripts import Block
from refinery.lib.scripts.ps1 import precedence
from refinery.lib.scripts.ps1.lexer import (
    _DASH_OPERATORS,
    Ps1Lexer,
    Ps1LexerMode,
)
from refinery.lib.scripts.ps1.model import (
    Expression,
    Node,
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
    Ps1InputRedirection,
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
    Ps1Redirection,
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
    Ps1Token,
    Ps1TokenKind,
    _strip_backtick_noop,
)

_T = TypeVar('_T')

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

precedence.register_comparisons(_COMPARISON_OPERATORS)

#: The two kinds that spell a bare word. `Ps1Parser._parse_primary_atom` reads one as the string it
#: spells, because six rules of the grammar reach it holding one: an attribute argument, a class
#: member initializer, an index, a method argument, an enum member and a parameter default. What
#: must never take it for an expression is the choice between a command and an expression, because
#: every command name in the language is spelled this way.
_BARE_WORD_KINDS = frozenset({
    Ps1TokenKind.GENERIC_EXPAND,
    Ps1TokenKind.GENERIC_TOKEN,
})

#: The prefix operators `Ps1Parser._parse_unary_expression` reads before it reaches an atom.
_UNARY_OPERATOR_KINDS = frozenset({
    Ps1TokenKind.COMMA,
    Ps1TokenKind.DASH,
    Ps1TokenKind.DECREMENT,
    Ps1TokenKind.EXCLAIM,
    Ps1TokenKind.INCREMENT,
    Ps1TokenKind.OPERATOR,
    Ps1TokenKind.PLUS,
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

#: Token kinds that can never stand as a command name or argument. Any other token that is not an
#: expression is read as the bare word it spells, which is what makes `Copy-Item . dest` three
#: elements of one command.
_ARGUMENT_FORBIDDEN_KINDS = _PIPELINE_TERMINATORS | {
    Ps1TokenKind.AMPERSAND,
    Ps1TokenKind.COMMA,
    Ps1TokenKind.DECREMENT,
    Ps1TokenKind.REDIRECTION,
    Ps1TokenKind.REDIRECT_IN,
}

#: A block comment may stand between an expression and a member access; whitespace may not.
_BLOCK_COMMENT = re.compile(r'<#.*?#>', re.DOTALL)

_VARIABLE_FRAG = re.compile(
    r'\$(?:' + _VARIABLE_PATTERN_CORE + r')',
    re.IGNORECASE,
)

_MERGING_PATTERN = re.compile(r'(\d|\*)?>&(\d)')

_MULTIPLIER_SUFFIXES = {
    'kb': 1024,
    'mb': 1024 ** 2,
    'gb': 1024 ** 3,
    'tb': 1024 ** 4,
    'pb': 1024 ** 5,
}


def _normalize_string_delimiters(text: str, width: int) -> str:
    """
    Normalize unicode smart quotes only in the `width` opening and closing delimiter characters of a
    string token, leaving the verbatim content untouched so that literal smart quotes inside the
    string survive byte-for-byte.
    """
    if len(text) <= 2 * width:
        return text.translate(NORMALIZE_QUOTES)
    head = text[:width].translate(NORMALIZE_QUOTES)
    tail = text[-width:].translate(NORMALIZE_QUOTES)
    return head + text[width:-width] + tail


def _decode_backtick(text: str, i: int, length: int) -> tuple[str, int]:
    """
    Decode the backtick escape at `text[i]` (the backtick). Handles the PowerShell 6+ unicode escape
    `` `u{XXXX} `` in addition to the single-character escapes in `BACKTICK_ESCAPE`. Returns the
    decoded text and the index of the first character after the escape.
    """
    nc = text[i + 1]
    if nc in ('u', 'U') and i + 2 < length and text[i + 2] == '{':
        end = text.find('}', i + 3)
        if end != -1:
            try:
                return chr(int(text[i + 3:end], 16)), end + 1
            except (ValueError, OverflowError):
                pass
    return BACKTICK_ESCAPE.get(nc, nc), i + 2


class Ps1Parser:

    def __init__(self, source: str):
        self.source = source
        self._lexer = Ps1Lexer(source)
        self._pending: Ps1Token | None = None
        self._previous_end = 0
        self._disable_comma = False

    @property
    def _current(self) -> Ps1Token:
        token = self._pending
        if token is None:
            token = self._pending = self._lexer.scan()
        return token

    def _advance(self) -> Ps1Token:
        token = self._current
        self._previous_end = self._lexer.pos
        self._pending = None
        return token

    def _adjacent(self) -> bool:
        """
        Whether the current token begins where the previous one ended. A member access, an index or
        a postfix operator binds to what precedes it only when nothing separates the two, so that
        `$a.Length` reads a property where `$a . Length` is two command arguments with a bare dot
        between them. A block comment does not separate them, which is the one thing 5.1 lets
        through.
        """
        gap_start = self._previous_end
        gap_end = self._current.offset
        if gap_start == gap_end:
            return True
        gap = self.source[gap_start:gap_end]
        if '<#' not in gap:
            return False
        return not _BLOCK_COMMENT.sub('', gap)

    def _error_since(self, offset: int, message: str) -> Ps1ErrorNode:
        """
        An error node standing for the source from `offset` up to the last token consumed. This is
        how a rule declines to build a shape the language has no spelling for — a `do` loop with no
        `while` and a `try` with neither `catch` nor `finally` are not statements — while still
        handing back every character it read, so that what an analyst gets out still contains what
        went in. Recording the span is what makes the recovery a fixed point: the text re-reads as
        the same error rather than as an empty node that prints nothing.

        The span ends at the last thing actually read: a rule that looked ahead for a keyword it
        did not find has skipped the newlines in between, and taking those along would grow the
        text by one line every time the output is read back and printed again.
        """
        return Ps1ErrorNode(
            offset=offset,
            text=self.source[offset:self._previous_end].rstrip(),
            message=message,
        )

    def _resync(self, offset: int):
        """
        Rewind to `offset` and drop the lookahead, so that the next read scans the source there
        again. Nothing is scanned here: the re-read happens when, and only if, a token is asked for.
        Where the rewind undoes tokens that were consumed, the end of the last consumed one moves
        back with it, because `Ps1Parser._adjacent` reads a gap between the two and a gap that runs
        backwards is not one.
        """
        self._lexer.pos = offset
        self._previous_end = min(self._previous_end, offset)
        self._pending = None

    def _switch_mode(self, mode: Ps1LexerMode):
        if mode is self._lexer.mode:
            return
        self._lexer.mode = mode
        token = self._pending
        if token is not None and not token.kind.mode_invariant:
            self._resync(token.offset)

    @contextmanager
    def _mode(self, mode: Ps1LexerMode):
        """
        Read the enclosed construct in `mode` and restore the caller's mode afterwards. Changing the
        mode discards the lookahead, so a token scanned in one mode is never handed to a parse that
        asked for another. That is the whole of the rule: it lives here rather than in the memory of
        whoever writes the next call site.
        """
        previous = self._lexer.mode
        self._switch_mode(mode)
        try:
            yield
        finally:
            self._switch_mode(previous)

    def _attempt(self, mode: Ps1LexerMode, rule: Callable[[], _T | None]) -> _T | None:
        """
        Read `rule` in `mode`, and leave the source where it was found if the rule declines. A
        speculative read is one thing and is written once: the mode the construct is spelled in, the
        place to return to, and the rule itself.

        What this replaces is a first-token guard kept outside the mode it asks about. In argument
        mode a `[` belongs to the word around it, so a caller that asks there whether a type name
        follows is told no about one that is plainly written; the guard belongs inside `rule`, where
        the mode is already the one the construct is read in.
        """
        offset = self._current.offset
        with self._mode(mode):
            result = rule()
        if result is None:
            self._resync(offset)
        return result

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

    def _skip_newlines(self):
        while self._current.kind == Ps1TokenKind.NEWLINE:
            self._advance()

    def _parse_parenthesized_condition(self) -> Expression:
        self._expect(Ps1TokenKind.LPAREN)
        self._skip_newlines()
        expr = self._parse_pipeline_expression(keyword_names_a_command=True)
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
        return Ps1FileRedirection(
            offset=tok.offset,
            stream=stream,
            target=self._parse_redirection_target(),
            append=append,
        )

    def _parse_input_redirection(self, tok: Ps1Token) -> Ps1InputRedirection:
        """
        Read a `<` and the file it names. PowerShell reserves the operator, reports it and then goes
        on reading the command around it, so what this must not do is end the command or turn into
        the write that `>` spells.
        """
        return Ps1InputRedirection(
            offset=tok.offset, source=self._parse_redirection_target())

    def _parse_redirection_target(self) -> Expression | None:
        with self._mode(Ps1LexerMode.ARGUMENT):
            if self._is_pipeline_terminator():
                return None
            return self._parse_single_argument_value()

    def _try_parse_redirection(self) -> Ps1Redirection | None:
        if self._at(Ps1TokenKind.REDIRECTION):
            return self._parse_redirection(self._advance())
        if self._at(Ps1TokenKind.REDIRECT_IN):
            return self._parse_input_redirection(self._advance())
        return None

    def _parse_redirections(self) -> list[Ps1Redirection]:
        redirections: list[Ps1Redirection] = []
        while (redirection := self._try_parse_redirection()) is not None:
            redirections.append(redirection)
        return redirections

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

    def _is_statement_terminator(self) -> bool:
        return self._current.kind in _STATEMENT_TERMINATORS

    def parse(self) -> Ps1Script:
        return self._parse_script()

    def _parse_code_body(
        self,
        until: Ps1TokenKind | None = None,
    ) -> dict:
        """
        Read the statements a body holds, in argument mode. Every path into a body comes through
        here — a script, a script block, a function with a parameter list, a class method — so the
        mode a statement is read in is settled once rather than at each of them, and a body cannot
        reach the statement list carrying the mode of whatever declared it.
        """
        with self._mode(Ps1LexerMode.ARGUMENT):
            return self._read_code_body(until)

    def _read_code_body(self, until: Ps1TokenKind | None) -> dict:
        self._skip_newlines()
        fields: dict = {}
        param_block = self._parse_param_block()
        if param_block is not None:
            fields['param_block'] = param_block
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

    def _parse_pipeline_or_assignment(self) -> Statement | None:
        expr = self._parse_pipeline_expression(keyword_names_a_command=True)
        if expr is None:
            if self._at(Ps1TokenKind.EOF, Ps1TokenKind.RBRACE, Ps1TokenKind.RPAREN):
                return None
            tok = self._advance()
            return Ps1ExpressionStatement(
                offset=tok.offset,
                expression=Ps1ErrorNode(offset=tok.offset, text=tok.value),
            )
        return Ps1ExpressionStatement(offset=expr.offset, expression=expr)

    def _starts_command(self, *, keyword_names_a_command: bool) -> bool:
        """
        Decide whether what comes next is a command or an expression. The token is re-scanned in
        expression mode first, so the kind classified is a fact about *this* pipeline element rather
        than about whatever was parsed before it, and it is then discarded again, which is what makes
        scanning it here safe: `_parse_command` re-scans in argument mode before it reads a name.

        Anything that cannot open an expression opens a command. Asking it in that direction is what
        keeps the answer tied to the grammar, but it also means a kind nobody thought about becomes a
        command name, so the kinds that may never be one are named in `_ARGUMENT_FORBIDDEN_KINDS` and
        `_parse_command` declines them.

        A keyword kind spells a command name only where nothing above will read it as a statement:
        at a statement start, where `_parse_statement` has already declined, inside `( )`, which
        holds a pipeline and never a statement, and after a `|`. Everywhere else — a `for` clause,
        the operand of `return` — the keyword still opens a statement, and taking it for a name loses
        that statement whole.
        """
        with self._mode(Ps1LexerMode.EXPRESSION):
            kind = self._current.kind
        if kind.is_keyword:
            return keyword_names_a_command
        return kind not in self._UNARY_START_KINDS

    def _parse_pipeline_expression(self, *, keyword_names_a_command: bool = False) -> Expression | None:
        """
        Read one pipeline, starting from whichever of a command and an expression `_starts_command`
        says it is.
        """
        if self._starts_command(keyword_names_a_command=keyword_names_a_command):
            first = self._parse_command()
            if first is None:
                return None
            return self._parse_pipeline_tail(first)
        with self._mode(Ps1LexerMode.EXPRESSION):
            expr = self._parse_binary_expression(0)
            if expr is None:
                return None
            operator = self._eat_assignment()
        if operator is not None:
            self._skip_newlines()
            expr = Ps1AssignmentExpression(
                offset=expr.offset,
                target=expr,
                operator=operator.value,
                value=self._parse_assigned_value(),
            )
        return self._parse_pipeline_tail(expr)

    def _eat_assignment(self) -> Ps1Token | None:
        if self._current.kind.is_assignment:
            return self._advance()
        return None

    def _parse_assigned_value(self) -> Node | None:
        """
        Read what an assignment assigns. It is a whole statement, so `$x = if ($c) { 1 }` and
        `$x = data { 1 }` are read alike and no list of the keywords worth allowing has to be kept.
        A statement that is only an expression is unwrapped again, because an assignment whose value
        is an expression is what the rest of the code reads. An assignment with nothing after it is
        left without a value rather than being given the token that ends it.

        Only a value that could open a statement is read as one. `_parse_statement` differs from the
        pipeline it falls through to for exactly the keyword and label starts, and every assignment
        in a chain costs the frames of whichever route it takes.
        """
        if self._is_statement_terminator():
            return None
        if not (self._current.kind.is_keyword or self._at(Ps1TokenKind.LABEL)):
            return self._parse_pipeline_expression()
        statement = self._parse_statement()
        if type(statement) is Ps1ExpressionStatement:
            return statement.expression
        return statement

    def _parse_pipeline_tail(self, expr: Expression) -> Expression:
        if not self._at(Ps1TokenKind.PIPE):
            return expr
        elements = [Ps1PipelineElement(offset=expr.offset, expression=expr)]
        while self._eat(Ps1TokenKind.PIPE):
            self._skip_newlines()
            element = self._parse_pipeline_element()
            if element is not None:
                elements.append(element)
        if len(elements) > 1:
            return Ps1Pipeline(offset=elements[0].offset, elements=elements)
        return expr

    def _parse_pipeline_element(self) -> Ps1PipelineElement | None:
        """
        Read one element after a `|`. It is classified the way the first element is, so `1 | 2` keeps
        the `2` as the number it spells; PowerShell reports that an expression may only come first
        and then reads it anyway, and what an analyst needs back is the expression, not a command
        named after it.

        A keyword names a command here without exception, because nothing above reads a statement
        from the middle of a pipeline. Asking with the caller's answer instead would sever
        `$x = Get-Process | ForEach-Object { }` at the pipe, `ForEach-Object` being the `foreach`
        keyword to a lexer in expression mode.
        """
        if self._starts_command(keyword_names_a_command=True):
            command = self._parse_command()
            if command is None:
                return None
            return Ps1PipelineElement(offset=command.offset, expression=command)
        expr = self._parse_expression()
        if expr is None:
            return None
        return Ps1PipelineElement(
            offset=expr.offset,
            expression=expr,
            redirections=self._parse_redirections(),
        )

    def _parse_command_name(self) -> Expression:
        """
        Read a command name from a token that is none of the shapes the caller has already taken. A
        token that begins an expression names the command with the expression it opens, so that
        `& $(Get-Command ls)`, `& @{ }` and a here-string each keep the structure they spell.
        Anything else is the bare word it spells, which is what makes `Copy-Item . dest` three
        elements of one command.
        """
        if self._current.kind in self._UNARY_START_KINDS:
            with self._mode(Ps1LexerMode.EXPRESSION):
                name = self._parse_primary_expression()
            if name is not None:
                return name
        return self._bare_string(self._advance())

    def _parse_command(self) -> Expression | None:
        """
        Read a command, starting from its name. Argument mode is entered *before* the name rather
        than after it, so the name arrives as the one token PowerShell resolves: `foo=123`,
        `C:\\x\\y.exe` and `.\\a.ps1` are each whole, while `. { }` and `. $sb` still split, because
        argument mode ends a token at a dot that is followed by a space.
        """
        with self._mode(Ps1LexerMode.ARGUMENT):
            offset = self._current.offset
            invocation_operator = ''
            if self._at(Ps1TokenKind.AMPERSAND, Ps1TokenKind.DOT):
                invocation_operator = self._advance().value
                self._skip_newlines()

            name_expr: Expression | None = None

            if self._at(Ps1TokenKind.VARIABLE, Ps1TokenKind.SPLAT_VARIABLE):
                name_expr = self._parse_variable()
            elif self._at(Ps1TokenKind.LBRACE):
                name_expr = self._parse_script_block()
            elif self._at(Ps1TokenKind.LPAREN):
                name_expr = self._parse_paren_expression()
            elif self._at(Ps1TokenKind.STRING_EXPAND, Ps1TokenKind.STRING_VERBATIM):
                name_expr = self._parse_string()
            elif self._current.kind in _ARGUMENT_FORBIDDEN_KINDS:
                if invocation_operator:
                    return Ps1CommandInvocation(
                        offset=offset, invocation_operator=invocation_operator)
                return None
            else:
                name_expr = self._parse_command_name()

            if invocation_operator and name_expr is not None:
                with self._mode(Ps1LexerMode.EXPRESSION):
                    name_expr = self._parse_primary_postfix(name_expr)

            arguments: list[Ps1CommandArgument | Expression] = []
            redirections: list[Ps1Redirection] = []
            while not self._is_pipeline_terminator():
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
                elif self._at(Ps1TokenKind.COMMA):
                    self._advance()
                elif (redirection := self._try_parse_redirection()) is not None:
                    redirections.append(redirection)
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
        # Decode both GENERIC_EXPAND and plain GENERIC_TOKEN through the same splitter so embedded
        # quotes and backtick escapes (e.g. `echo a'b c'd`) are resolved consistently. A plain
        # GENERIC_TOKEN never contains a `$` expansion, so the split yields a single literal.
        parts = self._split_generic_expandable(tok.value)
        if len(parts) == 1 and isinstance(parts[0], Ps1StringLiteral):
            return Ps1StringLiteral(
                offset=tok.offset, value=parts[0].value, raw=tok.value)
        return Ps1ExpandableString(
            offset=tok.offset, parts=parts, raw=tok.value)

    def _parse_single_argument_value(self) -> Expression | None:
        if self._at(Ps1TokenKind.GENERIC_TOKEN, Ps1TokenKind.GENERIC_EXPAND):
            tok = self._advance()
            return self._parse_generic_as_string(tok)
        if self._current.kind in _ARGUMENT_FORBIDDEN_KINDS:
            return None
        with self._mode(Ps1LexerMode.EXPRESSION):
            if self._current.kind in self._ARGUMENT_PRIMARY_KINDS:
                value = self._parse_unary_expression()
                if value is not None:
                    return value
        return self._bare_string(self._advance())

    def _parse_expression(self) -> Expression | None:
        with self._mode(Ps1LexerMode.EXPRESSION):
            return self._parse_binary_expression(0)

    def _current_binary_precedence(self) -> int | None:
        """
        The tier of the operator ahead, named from `refinery.lib.scripts.ps1.precedence` so that
        the synthesizer brackets by the same scale this reads by. The punctuation operators are
        recognized by token kind rather than by spelling, because the lexer accepts the unicode
        dashes and quotes an obfuscator substitutes and a spelling lookup would miss them.
        """
        kind = self._current.kind
        if kind is Ps1TokenKind.DOTDOT:
            return precedence.RANGE
        if kind in (Ps1TokenKind.STAR, Ps1TokenKind.SLASH, Ps1TokenKind.PERCENT):
            return precedence.MULTIPLICATIVE
        if kind in (Ps1TokenKind.PLUS, Ps1TokenKind.DASH):
            return precedence.ADDITIVE
        if kind is Ps1TokenKind.OPERATOR:
            return precedence.BINARY.get(self._current.value)
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
                return Ps1ErrorNode(
                    offset=tok.offset, text=tok.value, message='comma operator without operand')
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

        return self._parse_primary_expression()

    def _try_parse_type_literal(self) -> Ps1TypeExpression | None:
        """
        A type name is read in expression mode no matter which mode the caller left behind: a
        generic token does not end at `]` in argument mode, so the closing bracket is absorbed into
        the name and the bracket depth never returns to zero. In that mode the opening bracket is
        not a bracket either, which is why no caller may ask for one before calling this.
        """
        return self._attempt(Ps1LexerMode.EXPRESSION, self._read_type_literal)

    def _read_type_literal(self) -> Ps1TypeExpression | None:
        """
        Read the `[ ]` of a type name, or nothing at all. A bracket that the source never closes is
        not a type name, so everything that ends a statement or a block ends the attempt as well:
        the alternative is a name that swallows the brace its block was waiting for, and with it
        every statement that block still had to give.
        """
        if not self._at(Ps1TokenKind.LBRACKET):
            return None
        offset = self._current.offset
        self._advance()
        self._skip_newlines()
        name_parts: list[str] = []
        depth = 1
        while depth > 0:
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
            elif (
                self._at(Ps1TokenKind.NEWLINE, Ps1TokenKind.SEMICOLON, Ps1TokenKind.RBRACE)
                or self._at(Ps1TokenKind.EOF)
            ):
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
        while self._adjacent():
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
        rule = self._ATOM_RULES.get(self._current.kind)
        if rule is None:
            return None
        return rule(self)

    def _parse_bare_word(self) -> Expression:
        return self._parse_generic_as_string(self._advance())

    def _parse_integer(self) -> Ps1IntegerLiteral:
        tok = self._advance()
        raw = tok.value
        text = raw.rstrip('lL').replace('_', '')
        try:
            if text[:2].lower() in ('0x', '0b'):
                value = int(text, 0)
            else:
                # Plain decimal: parse with an explicit base so leading zeros (`007`) are accepted
                # as decimal instead of raising under `int(text, 0)`.
                value = int(text, 10)
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
        raw = _normalize_string_delimiters(tok.value, 1)
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
        `Ps1Parser._split_expandable_string` (for double-quoted
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
                decoded, pos = _decode_backtick(text, pos, length)
                buf.append(decoded)
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
                        if pos + 1 < length and text[pos + 1] in DOUBLE_QUOTES:
                            pos += 2
                            continue
                        inner_end = pos
                        pos += 1
                        break
                    pos += 1
                else:
                    inner_end = pos
                inner = text[inner_start:inner_end]
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
            if sc == '`' and pos + 1 < length:
                # A backtick escapes the next character (including a parenthesis) the same way the
                # lexer skips it, so the parser and lexer agree on where the subexpression ends.
                pos += 2
                continue
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
                decoded, i = _decode_backtick(text, i, length)
                result.append(decoded)
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
        drive = ''
        if ':' in name:
            prefix, rest = name.split(':', 1)
            prefix_lower = prefix.lower()
            try:
                scope = Ps1ScopeModifier(prefix_lower)
            except ValueError:
                scope = Ps1ScopeModifier.DRIVE
                drive = prefix
            name = rest
        if not braced and name.startswith('{') and name.endswith('}'):
            braced = True
            name = name[1:-1]
        return Ps1Variable(
            offset=-1, name=name, scope=scope, braced=braced, splatted=splatted, drive=drive
        )

    def _parse_here_string(self) -> Expression:
        tok = self._advance()
        raw = _normalize_string_delimiters(tok.value, 2)
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
        with self._mode(Ps1LexerMode.ARGUMENT):
            with self._comma_mode(disabled=False):
                expr = self._parse_pipeline_expression(keyword_names_a_command=True)
            self._skip_newlines()
            self._expect(Ps1TokenKind.RPAREN)
        return Ps1ParenExpression(offset=offset, expression=expr)

    def _parse_delimited_statement_block(
        self,
        open_kind: Ps1TokenKind,
        cls: type[Ps1SubExpression] | type[Ps1ArrayExpression],
    ) -> Expression:
        offset = self._current.offset
        self._expect(open_kind)
        self._skip_newlines()
        with self._mode(Ps1LexerMode.ARGUMENT):
            with self._comma_mode(disabled=False):
                stmts = self._parse_statement_list(until=Ps1TokenKind.RPAREN)
            self._skip_newlines()
            self._expect(Ps1TokenKind.RPAREN)
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
            with self._mode(Ps1LexerMode.EXPRESSION):
                key = self._parse_label_or_key()
                if key is None:
                    break
                self._skip_newlines()
                self._expect(Ps1TokenKind.EQUALS)
            with self._mode(Ps1LexerMode.ARGUMENT):
                self._skip_newlines()
                value = self._parse_assigned_value()
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

        if self._at(Ps1TokenKind.LPAREN) and self._adjacent():
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
        return Ps1ExpressionStatement(
            offset=offset,
            expression=self._error_since(offset, 'do loop without while or until'),
        )

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
        Read one switch clause condition, which is a command argument and not an expression, so that
        `Get-Thing` is one name there, as 5.1 reads it, and not a subtraction of `Thing` from `Get`.
        A comma still joins several of them into one array, which is how `1,2 { ... }` matches two
        values with one clause.
        """
        with self._mode(Ps1LexerMode.ARGUMENT):
            return self._parse_argument_value()

    def _parse_switch(self, label: str | None = None) -> Ps1SwitchStatement:
        offset = self._current.offset
        self._expect(Ps1TokenKind.SWITCH)
        self._skip_newlines()
        regex = False
        wildcard = False
        exact = False
        case_sensitive = False
        file = False
        value: Expression | None = None
        with self._mode(Ps1LexerMode.ARGUMENT):
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
                value = self._parse_argument_value()
        if not file:
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

    def _parse_try(self) -> Statement:
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
            while True:
                te = self._try_parse_type_literal()
                if te is None:
                    break
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
        if not catch_clauses and finally_block is None:
            return Ps1ExpressionStatement(
                offset=offset,
                expression=self._error_since(offset, 'try without catch or finally'),
            )
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
        te = self._try_parse_type_literal()
        if te is not None:
            type_name = te.name
            self._skip_newlines()
        body = self._parse_block()
        return Ps1TrapStatement(offset=offset, type_name=type_name, body=body)

    def _parse_function_definition(self) -> Ps1FunctionDefinition:
        offset = self._current.offset
        kw = self._advance()
        is_filter = kw.kind == Ps1TokenKind.FILTER
        name = ''
        with self._mode(Ps1LexerMode.ARGUMENT):
            self._skip_newlines()
            if self._at(
                Ps1TokenKind.GENERIC_TOKEN,
                Ps1TokenKind.VARIABLE,
            ) or self._current.kind.is_keyword:
                name = self._advance().value
        with self._mode(Ps1LexerMode.EXPRESSION):
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
                script_body.param_block.parent = script_body
                return Ps1FunctionDefinition(
                    offset=offset, name=name, is_filter=is_filter, body=script_body)
            body = self._parse_script_block()
        return Ps1FunctionDefinition(
            offset=offset, name=name, is_filter=is_filter, body=body)

    def _parse_class_definition(self) -> Ps1ClassDefinition:
        offset = self._current.offset
        self._advance()
        name = ''
        base_types: list[str] = []
        with self._mode(Ps1LexerMode.ARGUMENT):
            self._skip_newlines()
            if self._at(Ps1TokenKind.GENERIC_TOKEN) or self._current.kind.is_keyword:
                name = self._advance().value
            self._skip_newlines()
            if self._eat_colon():
                self._skip_newlines()
                while not self._at(Ps1TokenKind.LBRACE, Ps1TokenKind.EOF):
                    type_lit = self._try_parse_type_literal()
                    if type_lit is not None:
                        base_types.append(type_lit.name)
                    elif self._at(Ps1TokenKind.GENERIC_TOKEN) or self._current.kind.is_keyword:
                        base_types.append(self._advance().value)
                    elif self._eat(Ps1TokenKind.COMMA):
                        self._skip_newlines()
                        continue
                    else:
                        break
                    self._skip_newlines()
            self._skip_newlines()
            self._expect(Ps1TokenKind.LBRACE)
        members: list[Ps1PropertyMember | Ps1MethodMember] = []
        with self._mode(Ps1LexerMode.EXPRESSION):
            self._skip_newlines()
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
                script_body.param_block.parent = script_body
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
        self._advance()
        name = ''
        base_type = ''
        members: list[Ps1EnumMember] = []
        with self._mode(Ps1LexerMode.ARGUMENT):
            self._skip_newlines()
            if self._at(Ps1TokenKind.GENERIC_TOKEN) or self._current.kind.is_keyword:
                name = self._advance().value
            self._skip_newlines()
            if self._eat_colon():
                self._skip_newlines()
                type_lit = self._try_parse_type_literal()
                if type_lit is not None:
                    base_type = type_lit.name
                elif self._at(Ps1TokenKind.GENERIC_TOKEN) or self._current.kind.is_keyword:
                    base_type = self._advance().value
                self._skip_newlines()
            self._expect(Ps1TokenKind.LBRACE)
        with self._mode(Ps1LexerMode.EXPRESSION):
            self._skip_newlines()
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
        with self._mode(Ps1LexerMode.EXPRESSION):
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

    def _parse_param_block(self) -> Ps1ParamBlock | None:
        """
        A parameter list is read in expression mode no matter which mode the caller left behind: in
        argument mode a generic token does not end at `=`, so `param($x=1)` reads its default as
        part of one word and every unspaced default in the language is lost.

        Whether a body opens with one at all is decided by reading it, not by looking for the word
        `param` first. A body opens in argument mode, where `param.exe` is one word and the keyword
        is invisible, and it opens in expression mode over a script whose first statement is a call
        to a program of that name; only reading as far as the `(` tells the two apart.
        """
        return self._attempt(Ps1LexerMode.EXPRESSION, self._read_param_block)

    def _read_param_block(self) -> Ps1ParamBlock | None:
        offset = self._current.offset
        attrs: list[Ps1Attribute] = []
        while self._at(Ps1TokenKind.LBRACKET):
            attr = self._parse_attribute()
            if isinstance(attr, Ps1Attribute):
                attrs.append(attr)
            self._skip_newlines()
        if not self._eat(Ps1TokenKind.PARAM):
            return None
        self._skip_newlines()
        if not self._at(Ps1TokenKind.LPAREN):
            return None
        self._advance()
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
        """
        A type name and its arguments are read in expression mode no matter which mode the caller
        left behind, for the reason `_try_parse_type_literal` states: in argument mode a generic
        token does not end at `]`, so the name absorbs its own closing bracket and everything after
        it. `& { param([int]$x) $x }` reaches here in argument mode, because the block is an
        argument of the call operator, and swallowed the whole body before this.
        """
        with self._mode(Ps1LexerMode.EXPRESSION):
            return self._read_attribute()

    def _read_attribute(self) -> Ps1Attribute | Ps1TypeExpression:
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
                        key_tok = self._advance()
                        if self._eat(Ps1TokenKind.EQUALS):
                            self._skip_newlines()
                            val = self._parse_expression()
                            if val is not None:
                                named.append((key_tok.value, val))
                                self._skip_newlines()
                                self._eat(Ps1TokenKind.COMMA)
                                continue
                        self._resync(key_tok.offset)
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
        commands: list[Expression] = []
        with self._mode(Ps1LexerMode.ARGUMENT):
            if self._at(Ps1TokenKind.GENERIC_TOKEN):
                name = self._advance().value
                self._skip_newlines()
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
        with self._mode(Ps1LexerMode.EXPRESSION):
            body = self._parse_block()
        return Ps1DataSection(offset=offset, name=name, commands=commands, body=body)

    #: What a primary expression can begin with, and the rule that reads each one. Every question of
    #: the form "can an expression start here" is answered from this table rather than from a list
    #: kept beside it, because a list kept beside it drifts: the two that were here before this
    #: disagreed with the grammar and with each other.
    _ATOM_RULES: dict[Ps1TokenKind, Callable[[Ps1Parser], Expression | None]] = {
        Ps1TokenKind.AT_LBRACE        : _parse_hash_literal,     # noqa
        Ps1TokenKind.AT_LPAREN        : _parse_array_expression, # noqa
        Ps1TokenKind.DOLLAR_LPAREN    : _parse_sub_expression,   # noqa
        Ps1TokenKind.GENERIC_EXPAND   : _parse_bare_word,        # noqa
        Ps1TokenKind.GENERIC_TOKEN    : _parse_bare_word,        # noqa
        Ps1TokenKind.HSTRING_EXPAND   : _parse_here_string,      # noqa
        Ps1TokenKind.HSTRING_VERBATIM : _parse_here_string,      # noqa
        Ps1TokenKind.INTEGER          : _parse_integer,          # noqa
        Ps1TokenKind.LBRACE           : _parse_script_block,     # noqa
        Ps1TokenKind.LBRACKET         : _try_parse_type_literal, # noqa
        Ps1TokenKind.LPAREN           : _parse_paren_expression, # noqa
        Ps1TokenKind.REAL             : _parse_real,             # noqa
        Ps1TokenKind.SPLAT_VARIABLE   : _parse_variable,         # noqa
        Ps1TokenKind.STRING_EXPAND    : _parse_string,           # noqa
        Ps1TokenKind.STRING_VERBATIM  : _parse_string,           # noqa
        Ps1TokenKind.VARIABLE         : _parse_variable,         # noqa
    }

    #: What `Ps1Parser._parse_unary_expression` can begin with. A pipeline element that does not
    #: begin with one of these is a command, which is why the bare word has to come out: it is the
    #: spelling of every command name there is, and honouring it here takes `Get-ChildItem` apart.
    _UNARY_START_KINDS = (frozenset(_ATOM_RULES) - _BARE_WORD_KINDS) | _UNARY_OPERATOR_KINDS

    #: What a command argument can begin with. Narrower than the above by the two kinds that would
    #: read past the argument they start: an operator takes the next argument as its operand, so
    #: `echo a,-not` builds a unary expression with nothing under it, and a bracket reads
    #: `Write-Host [ 0 ]` as a type name rather than as the three words PowerShell passes.
    _ARGUMENT_PRIMARY_KINDS = _UNARY_START_KINDS - {
        Ps1TokenKind.LBRACKET,
        Ps1TokenKind.OPERATOR,
    }
