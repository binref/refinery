from __future__ import annotations

from contextlib import contextmanager

from refinery.lib.scripts.js.lexer import (
    JsLexer,
    JsLexerState,
    decode_js_string_body,
    decode_js_template_body,
    identifier_string_value,
)
from refinery.lib.scripts.js.model import (
    SCRIPT_CONTEXT,
    AwaitReading,
    CodeContext,
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
    JsDecorator,
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
    JsImportAttribute,
    JsImportDeclaration,
    JsImportDefaultSpecifier,
    JsImportExpression,
    JsImportNamespaceSpecifier,
    JsImportSpecifier,
    JsLabeledStatement,
    JsLogicalExpression,
    JsMemberExpression,
    JsMetaProperty,
    JsMethodDefinition,
    JsMethodKind,
    JsNewExpression,
    JsNullLiteral,
    JsNumericLiteral,
    JsObjectExpression,
    JsObjectPattern,
    JsParenthesizedExpression,
    JsPrivateIdentifier,
    JsProperty,
    JsPropertyDefinition,
    JsPropertyKind,
    JsRegExpLiteral,
    JsRestElement,
    JsReturnStatement,
    JsScript,
    JsSequenceExpression,
    JsSpreadElement,
    JsStaticBlock,
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
    JsVarKind,
    JsWhileStatement,
    JsWithStatement,
    JsYieldExpression,
    Statement,
    arrow_body_context,
    class_element_context,
    function_context,
)
from refinery.lib.scripts.js.strict import mark_directives, mark_module
from refinery.lib.scripts.js.token import RESERVED_WORD_NAMES, JsToken, JsTokenKind
from refinery.lib.scripts.js.utf16 import is_well_formed as is_well_formed_unicode

_PREC_EXPONENTIATION = 15

_BINARY_PREC: dict[JsTokenKind, tuple[int, bool]] = {
    JsTokenKind.QQ:         ( 4, True),   # noqa
    JsTokenKind.OR:         ( 5, True),   # noqa
    JsTokenKind.AND:        ( 6, True),   # noqa
    JsTokenKind.PIPE:       ( 7, False),  # noqa
    JsTokenKind.CARET:      ( 8, False),  # noqa
    JsTokenKind.AMP:        ( 9, False),  # noqa
    JsTokenKind.EQ2:        (10, False),  # noqa
    JsTokenKind.BANG_EQ:    (10, False),  # noqa
    JsTokenKind.EQ3:        (10, False),  # noqa
    JsTokenKind.BANG_EQ2:   (10, False),  # noqa
    JsTokenKind.LT:         (11, False),  # noqa
    JsTokenKind.GT:         (11, False),  # noqa
    JsTokenKind.LT_EQ:      (11, False),  # noqa
    JsTokenKind.GT_EQ:      (11, False),  # noqa
    JsTokenKind.INSTANCEOF: (11, False),  # noqa
    JsTokenKind.IN:         (11, False),  # noqa
    JsTokenKind.LT2:        (12, False),  # noqa
    JsTokenKind.GT2:        (12, False),  # noqa
    JsTokenKind.GT3:        (12, False),  # noqa
    JsTokenKind.PLUS:       (13, False),  # noqa
    JsTokenKind.MINUS:      (13, False),  # noqa
    JsTokenKind.STAR:       (14, False),  # noqa
    JsTokenKind.SLASH:      (14, False),  # noqa
    JsTokenKind.PERCENT:    (14, False),  # noqa
    JsTokenKind.STAR2:      (_PREC_EXPONENTIATION, False), # noqa
}

_VAR_KIND_MAP: dict[JsTokenKind, JsVarKind] = {
    JsTokenKind.VAR:   JsVarKind.VAR,    # noqa
    JsTokenKind.LET:   JsVarKind.LET,    # noqa
    JsTokenKind.CONST: JsVarKind.CONST,  # noqa
}

_PROP_KIND_MAP: dict[str, JsPropertyKind] = {
    'get': JsPropertyKind.GET,
    'set': JsPropertyKind.SET,
}


class JsParser:

    @staticmethod
    def _parse_int_text(text: str) -> int:
        if text.startswith(('0x', '0X')):
            return int(text, 16)
        if text.startswith(('0o', '0O')):
            return int(text, 8)
        if text.startswith(('0b', '0B')):
            return int(text, 2)
        if len(text) > 1 and text[0] == '0' and all(d in '01234567' for d in text):
            return int(text, 8)
        return int(text)

    def __init__(self, source: str):
        self._lexer = JsLexer(source)
        self._source = source
        self._tokens = self._lexer.tokenize()
        self._current: JsToken = JsToken(JsTokenKind.EOF, '', 0)
        self._preceded_by_newline: bool = False
        self._ahead: JsToken | None = None
        self._ahead_newline: bool = False
        self._ahead_state: tuple[JsLexerState, int] | None = None
        self._no_in: bool = False
        self._context: CodeContext = SCRIPT_CONTEXT
        self._pending_comments: list[str] = []
        self._recovered: bool = False
        self._prev_end: int = 0
        self._advance()

    def _pull_token(self) -> tuple[JsToken, bool]:
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
        return tok, had_newline

    def _advance(self) -> JsToken:
        prev = self._current
        self._prev_end = prev.offset + len(prev.value)
        if self._ahead is not None:
            self._current = self._ahead
            self._preceded_by_newline = self._ahead_newline
            self._ahead = None
            self._ahead_state = None
            return prev
        self._current, self._preceded_by_newline = self._pull_token()
        return prev

    def _drain_comments(self, node):
        if self._pending_comments:
            node.leading_comments.extend(self._pending_comments)
            self._pending_comments.clear()

    def _peek(self) -> JsToken:
        return self._current

    def _peek_next(self) -> JsToken:
        if self._ahead is None:
            self._ahead_state = self._lexer.capture(), len(self._pending_comments)
            self._ahead, self._ahead_newline = self._pull_token()
        return self._ahead

    def _rescan_as_regexp(self) -> JsToken:
        """
        Read the slash the parser is holding again, as the regular expression it begins. A slash is
        the one character whose token depends on where the grammar stands rather than on what the
        text says, and the lexer is not standing anywhere: it spells every slash as an operator, and
        this is the single place that knows that an expression is about to begin. Rewinding is what
        makes that affordable — reading a division that was a regular expression costs one token,
        whereas the other way around has already swallowed the rest of the line.

        Everything scanned since the slash is given back, because a lookahead token may have opened
        or closed a template hole and a skipped comment would otherwise be collected twice. The
        slash itself is given back too where no literal begins there, so that a scan which found no
        terminator on its line leaves the operator standing rather than a literal nobody wrote.
        """
        if self._ahead_state is None:
            state, comments = self._lexer.capture(), len(self._pending_comments)
        else:
            state, comments = self._ahead_state
        resume_pos, resume_state = self._lexer.pos, self._lexer.capture()
        self._lexer.rewind(self._current.offset, state)
        token = self._lexer.scan_regexp()
        if token is None:
            self._lexer.rewind(resume_pos, resume_state)
            return self._current
        del self._pending_comments[comments:]
        self._ahead = None
        self._ahead_newline = False
        self._ahead_state = None
        self._current = token
        self._tokens = self._lexer.tokenize()
        return self._current

    def _at(self, *kinds: JsTokenKind) -> bool:
        return self._current.kind in kinds

    def _eat(self, kind: JsTokenKind) -> JsToken | None:
        if self._current.kind == kind:
            return self._advance()
        return None

    def _expect(self, kind: JsTokenKind) -> JsToken:
        """
        The token that must stand here, where it does. Where it does not, the parser writes it
        itself and steps over what was there, so that a file it cannot read is still answered with a
        tree. That answer is a program the source does not hold, in both directions at once — a
        bracket nobody wrote is invented and the token that stood in its place is dropped — so the
        file is recorded as one the parser repaired. `JsScript.recovered` carries that to
        `refinery.lib.scripts.is_well_formed`, which is what keeps a truncated payload from being
        spliced into a host file as though it had been written whole.
        """
        if self._current.kind == kind:
            return self._advance()
        tok = self._current
        self._recovered = True
        self._advance()
        return JsToken(kind, tok.value, tok.offset, tok.terminated)

    def _require(self, kind: JsTokenKind) -> None:
        """
        The token the grammar requires here, consumed where it stands here. Where it does not the
        parser goes on without it and records the repair, leaving what is here to be read as
        whatever comes next.

        This is what a list separator wants, and it is why `_expect` is the wrong primitive for one:
        what follows a missing comma is the next element of the list, not a token to be thrown away,
        so `{ a: 1 b: 2 }` is a file the parser reports having repaired and still prints everything
        that was written in.
        """
        if self._eat(kind) is None:
            self._recovered = True

    def _at_identifier_name(self) -> bool:
        """
        Whether a word stands here. Every word the language has is an IdentifierName, a keyword no
        less than a name, so a position taking one takes them all and what this refuses is a token
        that spells no word at all.
        """
        return self._at(JsTokenKind.IDENTIFIER) or self._current.kind.is_keyword

    def _is_binding_identifier(self, token: JsToken) -> bool:
        """
        Whether the token can serve as an ordinary binding or reference name. Several contextual
        keywords (`as`, `from`, `of`, `let`, `async`) are always valid names, while `await` and
        `yield` are names only where the context the code is read under says so: `yield` is the
        operator in a generator, and `await` is the operator in an async function and reserved
        outright in a static class element. This is the identifier acceptance of
        `_parse_primary_expression` itself, so a name-reading site accepts exactly the tokens the
        expression grammar would treat as a reference.
        """
        kind = token.kind
        return (
            kind in (
                JsTokenKind.IDENTIFIER,
                JsTokenKind.AS,
                JsTokenKind.FROM,
                JsTokenKind.OF,
                JsTokenKind.LET,
                JsTokenKind.ASYNC,
            )
            or (kind is JsTokenKind.AWAIT and self._context.await_reading is AwaitReading.NAME)
            or (kind is JsTokenKind.YIELD and not self._context.yield_is_operator)
        )

    def _at_binding_identifier(self) -> bool:
        return self._is_binding_identifier(self._current)

    def _at_function_name(self) -> bool:
        """
        Whether the token standing here names the function whose `function` keyword was just read.
        Only a name or the parameter list may stand in that position, so `yield` and `await` are
        read as the name wherever they appear rather than through `_at_binding_identifier`, whose
        answer is about the context the function stands in.

        That answer is the wrong one here in both directions. A function expression's name takes its
        own kind and not the enclosing one, so `function* g() { var f = function yield() {}; }` is a
        program whose name would otherwise be dropped; and where the name really is an early error
        the tree must still spell it, so that
        `refinery.lib.scripts.js.strict.collect_strict_violations` reports it rather than the
        parameter list being read starting at the name.
        """
        return (
            self._at_binding_identifier()
            or self._at(JsTokenKind.YIELD, JsTokenKind.AWAIT)
        )

    def _at_variable_declaration(self, *, single_statement: bool = False) -> bool:
        """
        Whether a variable declaration begins here, rather than an expression that merely opens with
        the same word. ECMA-262 reserves `let` in strict code only, so wherever a statement may also
        be read as an expression, a `let` declares nothing unless a binding follows it: it is a name
        being called in `let(1)`, divided in `let / 2` and read in `let.a`, and only `let [` is the
        spelling a statement is forbidden to take as an expression.

        A *single_statement* position — the body of an `if` clause or of a loop, of `with`, or of a
        label — is handed a Statement by the grammar, and a lexical declaration is not one, so `let`
        opens no declaration there whatever follows it: after `if (0) let` and a line break, the
        word is the name it spells, automatic semicolon insertion ends the body at it, and the
        binding that seemed to follow is the next statement, outside the body.
        """
        if self._at(JsTokenKind.VAR, JsTokenKind.CONST):
            return True
        if single_statement or not self._at(JsTokenKind.LET):
            return False
        ahead = self._peek_next()
        return (
            self._is_binding_identifier(ahead)
            or ahead.kind in (JsTokenKind.LBRACKET, JsTokenKind.LBRACE)
        )

    def _eat_semicolon(self) -> bool:
        """
        The semicolon that ends a statement, whether the file wrote it or the language supplies it.
        ECMA-262 supplies one before a token a line terminator separates from what came before,
        before a closing brace, and at the end of the file, so those three are the whole of what a
        statement may end with instead of a semicolon.

        Where none of them stands here the parser writes the semicolon anyway, which is a repair
        like any other: `x = 1 y = 2` is a file no engine reads, and left unrecorded it comes back
        as the two statements the parser split it into. The one place the language inserts a
        semicolon on no such condition is after a `do` loop's `while` clause, which reads the
        semicolon it may find with `_eat` rather than asking here.
        """
        if self._eat(JsTokenKind.SEMICOLON):
            return True
        if self._at(JsTokenKind.RBRACE, JsTokenKind.EOF):
            return True
        if self._preceded_by_newline:
            return True
        self._recovered = True
        return False

    @contextmanager
    def _with_no_in(self, value: bool):
        saved = self._no_in
        self._no_in = value
        try:
            yield
        finally:
            self._no_in = saved

    @contextmanager
    def _code_context(self, context: CodeContext):
        """
        Read what the body does under *context*, which is what the model's
        `refinery.lib.scripts.js.model.code_context_within` answers for the node being built, and
        restore the enclosure's context afterwards.
        """
        saved = self._context
        self._context = context
        try:
            yield
        finally:
            self._context = saved

    def _function_body_context(self, is_async: bool, is_generator: bool):
        return self._code_context(function_context(is_async, is_generator))

    def parse(self) -> JsScript:
        script = self._parse_program()
        mark_directives(script)
        mark_module(script)
        return script

    def _parse_statement_list(self, *stop: JsTokenKind) -> list[Statement]:
        """
        The statements standing between here and the first of *stop*. A statement the parser could
        not read at all is the token it stopped on, kept as itself; one it gave up on partway is the
        whole span it had reached, kept the same way. Handing back nothing for that span is what
        would delete it: the tokens are already read, so the text they spell appears in no node, and
        a file that lost a statement prints as a shorter program nobody wrote.

        A statement list is where the `for` head's suppression of the `in` operator ends. The head
        reaches an expression and only an expression, and the one way a statement stands inside one
        is a function body, which is a fresh context: `for (function () { return 'k' in b; }; ; )`
        is a program, and `for (q => 'k' in b; ; )` is not, because a concise arrow body is an
        expression and inherits the suppression rather than ending it.
        """
        body: list[Statement] = []
        with self._with_no_in(False):
            while not self._at(*stop):
                mark = self._current.offset
                comments = list(self._pending_comments)
                self._pending_comments.clear()
                try:
                    stmt = self._parse_statement()
                except Exception:
                    stmt = None
                    if self._current.offset != mark:
                        stmt = self._unread_since(mark, 'a statement that could not be read')
                if stmt is not None:
                    stmt.leading_comments.extend(comments)
                    body.append(stmt)
                elif self._current.offset == mark:
                    tok = self._advance()
                    error = JsErrorNode(offset=tok.offset, text=tok.value)
                    error.leading_comments.extend(comments)
                    body.append(error)
        return body

    def _parse_program(self) -> JsScript:
        offset = self._current.offset
        body = self._parse_statement_list(JsTokenKind.EOF)
        return JsScript(
            body=body,
            offset=offset,
            recovered=self._recovered,
            html_comment=self._lexer.html_comment,
        )

    def _parse_statement(
        self,
        *,
        single_statement: bool = False,
        annex_b_function: bool = False,
    ) -> Statement | None:
        """
        One statement. A *single_statement* position takes no `let` or `const` and no class
        declaration: `let` reads as the name it spells, decided by `_at_variable_declaration`,
        while a `const` or a `class` reads as the declaration it opens with the repair recorded,
        every engine refusing the file. A `var` is a statement and reads there as it reads anywhere.
        The one spelling an ExpressionStatement may not open with is `let [`, with no line terminator
        freeing it, so a `let` the bracket follows reads as the member expression it spells with the
        repair recorded.

        A function declaration is admitted as a single statement only where *annex_b_function* says
        Annex B lets one stand — the clause of an `if` and the body of a label — and there only if it
        is a plain function, never a generator or an async one. The body of a loop and of `with` take
        no function at all. A function the position forbids reads as the declaration it opens with the
        repair recorded, since every engine refuses the file.
        """
        offset = self._current.offset
        kind = self._current.kind

        if kind == JsTokenKind.LBRACE:
            return self._parse_block_statement()
        if kind == JsTokenKind.SEMICOLON:
            self._advance()
            return JsEmptyStatement(offset=offset)
        if self._at_variable_declaration(single_statement=single_statement):
            if single_statement and self._at(JsTokenKind.CONST):
                self._recovered = True
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
            if single_statement and (
                not annex_b_function or self._peek_next().kind == JsTokenKind.STAR
            ):
                self._recovered = True
            return self._parse_function_declaration()
        if kind == JsTokenKind.AT:
            decorators = self._parse_decorators()
            if self._at(JsTokenKind.EXPORT):
                return self._parse_export_declaration(decorators)
            if self._at(JsTokenKind.CLASS):
                return self._parse_class_declaration(decorators)
            return JsErrorNode(
                text=self._source[offset:self._current.offset].rstrip(),
                message='decorators must precede a class',
                offset=offset,
            )
        if kind == JsTokenKind.CLASS:
            if single_statement:
                self._recovered = True
            return self._parse_class_declaration()
        if kind == JsTokenKind.DEBUGGER:
            self._advance()
            self._eat_semicolon()
            return JsDebuggerStatement(offset=offset)
        if kind == JsTokenKind.IMPORT and self._peek_next().kind not in (
            JsTokenKind.LPAREN, JsTokenKind.DOT,
        ):
            return self._parse_import_declaration()
        if kind == JsTokenKind.EXPORT:
            return self._parse_export_declaration()
        if self._at_async_function():
            if single_statement:
                self._recovered = True
            self._advance()
            return self._parse_function_declaration(is_async=True, start=offset)

        if (
            single_statement
            and kind == JsTokenKind.LET
            and self._peek_next().kind == JsTokenKind.LBRACKET
        ):
            self._recovered = True

        expr = self._parse_expression()

        if (
            isinstance(expr, JsIdentifier)
            and self._eat(JsTokenKind.COLON)
        ):
            body = self._parse_statement(single_statement=True, annex_b_function=True)
            return JsLabeledStatement(label=expr, body=body, offset=offset)

        self._eat_semicolon()
        if isinstance(expr, JsErrorNode):
            return expr
        return JsExpressionStatement(expression=expr, offset=offset)

    def _parse_block_statement(self) -> JsBlockStatement:
        offset = self._current.offset
        self._expect(JsTokenKind.LBRACE)
        body = self._parse_statement_list(JsTokenKind.RBRACE, JsTokenKind.EOF)
        self._expect(JsTokenKind.RBRACE)
        return JsBlockStatement(body=body, offset=offset)

    def _parse_variable_declaration(self) -> JsVariableDeclaration:
        offset = self._current.offset
        kind_tok = self._advance()
        kind = _VAR_KIND_MAP[kind_tok.kind]
        declarations: list[JsVariableDeclarator] = []
        declarations.append(self._parse_variable_declarator())
        while self._eat(JsTokenKind.COMMA):
            declarations.append(self._parse_variable_declarator())
        self._eat_semicolon()
        self._require_declarator_initializers(kind, declarations)
        return JsVariableDeclaration(declarations=declarations, kind=kind, offset=offset)

    def _require_declarator_initializers(
        self,
        kind: JsVarKind,
        declarations: list[JsVariableDeclarator],
    ) -> None:
        """
        A declarator is written with an initializer unless it binds a plain name under `var` or
        `let`: a `const` leaves nothing to hold the value it may not go without, and a destructuring
        target has nothing to take apart, so a bare one of either is a declaration every engine
        refuses. A for-in or for-of head is the one position that lifts the requirement, handing the
        binding its value on each pass, and it never reaches here — this is called for a statement,
        for the first clause of a C-style head, and for an exported declaration, all positions where
        the requirement stands. A file that breaks it is read with the repair recorded, so its text
        comes back as it went in and nothing takes the tree for a program.
        """
        for declarator in declarations:
            if declarator.init is not None:
                continue
            if kind is JsVarKind.CONST or isinstance(
                declarator.id, (JsArrayPattern, JsObjectPattern)
            ):
                self._recovered = True

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
        if self._at_binding_identifier():
            tok = self._advance()
        else:
            tok = self._expect(JsTokenKind.IDENTIFIER)
        return self._name_or_error(tok.value, offset, may_be_reserved=False)

    def _name_or_error(self, text: str, offset: int, *, may_be_reserved: bool) -> Expression:
        """
        The name a token spells, where it spells one. A file that ends in the middle of a
        declaration leaves the position a name was expected in holding nothing, and a name spelled
        by nothing has no text at all: printing it closes the source up over the gap, so `var` at
        the end of a file would come back as `var ;`. What is handed back instead is the span
        itself, which prints as what was written and states that the parser did not read it.

        Two further texts spell no name. One holds an escape naming no character a name may hold,
        which is a fact about the text alone and is refused wherever it stands. The other spells a
        reserved word, which the language refuses only where the name could also be a variable —
        `o.\\u0069f` reads a member and `var \\u0069f` declares nothing — and *may_be_reserved* is
        which of the two positions this is. Both come back as the span, so the file prints as it
        was written and no pass reads a name out of text no engine read one from.
        """
        if not text:
            return JsErrorNode(text=text, message='expected a name', offset=offset)
        name = identifier_string_value(text)
        if name is None:
            return JsErrorNode(text=text, message='not a name', offset=offset)
        if not may_be_reserved and name in RESERVED_WORD_NAMES:
            return JsErrorNode(text=text, message='reserved word', offset=offset)
        return JsIdentifier(name=name, raw=text if name != text else '', offset=offset)

    def _identifier(self, tok: JsToken) -> JsIdentifier:
        """
        The name a token spells, at a position whose slot holds a name and nothing else. A label
        and the name a function or class declaration gives itself are these, and a text spelling
        no name is kept there as it was written: what the model has no shape for, the parser has
        no way to state.
        """
        name = identifier_string_value(tok.value) or tok.value
        return JsIdentifier(
            name=name,
            raw=tok.value if name != tok.value else '',
            offset=tok.offset,
        )

    def _private_identifier(self, tok: JsToken, offset: int) -> Expression:
        """
        The private name a token spells. The `#` opens the name and is no part of it, so what
        follows it is an IdentifierName like any other and `this.#\\u0061` reads what `#a` declares.
        """
        text = tok.value[1:]
        name = identifier_string_value(text)
        if name is None:
            return JsErrorNode(text=tok.value, message='not a name', offset=offset)
        return JsPrivateIdentifier(
            name=name,
            raw=text if name != text else '',
            offset=offset,
        )

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
        consequent = self._parse_statement(single_statement=True, annex_b_function=True)
        alternate = None
        if self._eat(JsTokenKind.ELSE):
            alternate = self._parse_statement(single_statement=True, annex_b_function=True)
        return JsIfStatement(
            test=test, consequent=consequent, alternate=alternate, offset=offset)

    def _parse_while_statement(self) -> JsWhileStatement:
        offset = self._current.offset
        self._expect(JsTokenKind.WHILE)
        self._expect(JsTokenKind.LPAREN)
        test = self._parse_expression()
        self._expect(JsTokenKind.RPAREN)
        body = self._parse_statement(single_statement=True)
        return JsWhileStatement(test=test, body=body, offset=offset)

    def _parse_do_while_statement(self) -> JsDoWhileStatement:
        offset = self._current.offset
        self._expect(JsTokenKind.DO)
        body = self._parse_statement(single_statement=True)
        self._expect(JsTokenKind.WHILE)
        self._expect(JsTokenKind.LPAREN)
        test = self._parse_expression()
        self._expect(JsTokenKind.RPAREN)
        self._eat(JsTokenKind.SEMICOLON)
        return JsDoWhileStatement(test=test, body=body, offset=offset)

    def _parse_for_statement(self) -> Statement:
        """
        A `for await` head is read where `await` is the operator and at the top level of a file,
        which `refinery.lib.scripts.js.model.CodeContext.reads_for_await` decides: the goal symbol
        is not known while parsing, and a module spells a legal top-level `await` this way among
        others. Anywhere else the word is a name or refused outright, and the head is read as a
        plain `for` whose parenthesis is missing, with the repair recorded.
        """
        offset = self._current.offset
        self._expect(JsTokenKind.FOR)

        is_await = False
        if self._context.reads_for_await and self._eat(JsTokenKind.AWAIT):
            is_await = True

        self._expect(JsTokenKind.LPAREN)

        if self._at(JsTokenKind.SEMICOLON):
            self._advance()
            return self._parse_for_rest(None, offset)

        if self._at_variable_declaration():
            decl_offset = self._current.offset
            kind_tok = self._advance()
            kind = _VAR_KIND_MAP[kind_tok.kind]
            with self._with_no_in(True):
                declarator = self._parse_variable_declarator()
            decl = JsVariableDeclaration(
                declarations=[declarator], kind=kind, offset=decl_offset)
            result = self._parse_for_in_or_of(decl, is_await, offset)
            if result is not None:
                return result
            while self._eat(JsTokenKind.COMMA):
                with self._with_no_in(True):
                    decl.declarations.append(self._parse_variable_declarator())
            self._expect(JsTokenKind.SEMICOLON)
            self._require_declarator_initializers(kind, decl.declarations)
            return self._parse_for_rest(decl, offset)

        with self._with_no_in(True):
            init_expr = self._parse_expression()
        result = self._parse_for_in_or_of(init_expr, is_await, offset)
        if result is not None:
            return result
        self._expect(JsTokenKind.SEMICOLON)
        return self._parse_for_rest(init_expr, offset)

    def _parse_for_in_or_of(
        self,
        left: Expression | Statement,
        is_await: bool,
        offset: int,
    ) -> JsForInStatement | JsForOfStatement | None:
        if self._eat(JsTokenKind.IN):
            right = self._parse_expression()
            self._expect(JsTokenKind.RPAREN)
            body = self._parse_statement(single_statement=True)
            return JsForInStatement(left=left, right=right, body=body, offset=offset)
        if self._at(JsTokenKind.OF):
            self._advance()
            right = self._parse_assignment_expression()
            self._expect(JsTokenKind.RPAREN)
            body = self._parse_statement(single_statement=True)
            return JsForOfStatement(
                left=left, right=right, body=body, is_await=is_await, offset=offset)
        return None

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
        body = self._parse_statement(single_statement=True)
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
            self._recovered = True
            self._advance()
        body: list[Statement] = []
        while not self._at(
            JsTokenKind.CASE, JsTokenKind.DEFAULT, JsTokenKind.RBRACE, JsTokenKind.EOF,
        ):
            stmt = self._parse_statement()
            if stmt is not None:
                body.append(stmt)
        return JsSwitchCase(test=test, body=body, offset=offset)

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
        if handler is None and finalizer is None:
            self._recovered = True
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
        body = self._parse_statement(single_statement=True)
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
        if not self._preceded_by_newline and self._at_binding_identifier():
            tok = self._advance()
            label = self._identifier(tok)
        self._eat_semicolon()
        return JsBreakStatement(label=label, offset=offset)

    def _parse_continue_statement(self) -> JsContinueStatement:
        offset = self._current.offset
        self._expect(JsTokenKind.CONTINUE)
        label = None
        if not self._preceded_by_newline and self._at_binding_identifier():
            tok = self._advance()
            label = self._identifier(tok)
        self._eat_semicolon()
        return JsContinueStatement(label=label, offset=offset)

    def _record_source(
        self,
        node: JsFunctionDeclaration | JsFunctionExpression | JsArrowFunctionExpression,
        start: int,
    ) -> None:
        """
        Attach to a function the text between *start* and the end of the last token consumed for it,
        so that converting the function to a string answers the source it was written with. The end
        is the previous token's end rather than the current token's start, so a comment that trails
        the closing brace is not read as part of the function.
        """
        node.source_text = self._source[start:self._prev_end]

    def _parse_function_impl(
        self,
        *,
        as_expression: bool,
        is_async: bool = False,
        start: int | None = None,
    ) -> JsFunctionDeclaration | JsFunctionExpression:
        offset = self._current.offset
        if start is None:
            start = offset
        self._expect(JsTokenKind.FUNCTION)
        generator = bool(self._eat(JsTokenKind.STAR))
        id_node = None
        if self._at_function_name():
            tok = self._advance()
            id_node = self._identifier(tok)
        with self._function_body_context(is_async, generator):
            params = self._parse_formal_parameters()
            body = self._parse_block_statement()
        func: JsFunctionDeclaration | JsFunctionExpression
        if as_expression:
            func = JsFunctionExpression(
                id=id_node, params=params, body=body,
                generator=generator, is_async=is_async, offset=offset)
        else:
            func = JsFunctionDeclaration(
                id=id_node, params=params, body=body,
                generator=generator, is_async=is_async, offset=offset)
        self._record_source(func, start)
        return func

    def _parse_function_declaration(
        self,
        is_async: bool = False,
        start: int | None = None,
    ) -> JsFunctionDeclaration:
        return self._parse_function_impl(as_expression=False, is_async=is_async, start=start)

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

    def _parse_decorators(self) -> list[JsDecorator]:
        decorators: list[JsDecorator] = []
        while self._at(JsTokenKind.AT):
            decorators.append(self._parse_decorator())
        return decorators

    def _parse_decorator(self) -> JsDecorator:
        offset = self._current.offset
        self._expect(JsTokenKind.AT)
        if self._at(JsTokenKind.LPAREN):
            self._advance()
            inner = self._parse_expression()
            self._expect(JsTokenKind.RPAREN)
            return JsDecorator(expression=inner, offset=offset)
        if not self._at_binding_identifier():
            return JsDecorator(
                expression=JsErrorNode(
                    text=self._current.value, message='unexpected token', offset=offset),
                offset=offset,
            )
        tok = self._advance()
        expr: Expression = self._name_or_error(tok.value, tok.offset, may_be_reserved=False)
        while self._eat(JsTokenKind.DOT):
            prop = self._advance()
            expr = JsMemberExpression(
                object=expr,
                property=self._name_or_error(prop.value, prop.offset, may_be_reserved=True),
                computed=False,
                offset=expr.offset,
            )
        if self._at(JsTokenKind.LPAREN):
            expr = self._parse_call_arguments(expr, optional=False)
        return JsDecorator(expression=expr, offset=offset)

    def _parse_class_impl(
        self,
        *,
        as_expression: bool,
        decorators: list[JsDecorator] | None = None,
    ) -> JsClassDeclaration | JsClassExpression:
        offset = self._current.offset
        self._expect(JsTokenKind.CLASS)
        id_node = None
        if self._at_binding_identifier():
            tok = self._advance()
            id_node = self._identifier(tok)
        super_class = None
        if self._eat(JsTokenKind.EXTENDS):
            super_class = self._parse_assignment_expression()
        body = self._parse_class_body()
        if as_expression:
            return JsClassExpression(
                id=id_node,
                super_class=super_class,
                body=body,
                decorators=decorators or [],
                offset=offset,
            )
        return JsClassDeclaration(
            id=id_node,
            super_class=super_class,
            body=body,
            decorators=decorators or [],
            offset=offset,
        )

    def _parse_class_declaration(
        self, decorators: list[JsDecorator] | None = None,
    ) -> JsClassDeclaration:
        return self._parse_class_impl(as_expression=False, decorators=decorators)

    def _parse_class_body(self) -> JsClassBody:
        with self._with_no_in(False):
            offset = self._current.offset
            self._expect(JsTokenKind.LBRACE)
            members: list[JsMethodDefinition | JsPropertyDefinition | JsStaticBlock] = []
            while not self._at(JsTokenKind.RBRACE, JsTokenKind.EOF):
                if self._eat(JsTokenKind.SEMICOLON):
                    continue
                decorators = self._parse_decorators()
                member = self._parse_class_member()
                if decorators and isinstance(member, (JsMethodDefinition, JsPropertyDefinition)):
                    member.decorators = decorators
                    member._adopt(*decorators)
                members.append(member)
            self._expect(JsTokenKind.RBRACE)
            return JsClassBody(body=members, offset=offset)

    def _parse_static_block(self, offset: int) -> JsStaticBlock:
        with self._code_context(class_element_context(static=True)):
            block = self._parse_block_statement()
        return JsStaticBlock(body=block.body, offset=offset)

    def _parse_class_member(self) -> JsMethodDefinition | JsPropertyDefinition | JsStaticBlock:
        offset = self._current.offset
        value_offset = offset
        is_static = False
        if self._at(JsTokenKind.IDENTIFIER) and self._current.value == 'static':
            saved_pos = self._current
            self._advance()
            # A leading `static` is a ClassElement prefix, outside the MethodDefinition whose text
            # Function.prototype.toString answers, so the span starts after it — even where the
            # `static` is itself the method name, which `static() {}` stringifies without.
            value_offset = self._current.offset
            if self._at(JsTokenKind.LBRACE):
                return self._parse_static_block(offset)
            if self._at(JsTokenKind.LPAREN):
                key = JsIdentifier(name='static', offset=saved_pos.offset)
                return self._finish_class_member(key, False, False, offset, value_offset)
            if self._at_class_field_terminator():
                key = JsIdentifier(name='static', offset=saved_pos.offset)
                return self._finish_class_field(key, False, False, offset)
            is_static = True

        kind = JsMethodKind.METHOD
        is_generator = bool(self._eat(JsTokenKind.STAR))
        is_async = False

        if (
            not is_generator
            and self._at(JsTokenKind.IDENTIFIER)
            and self._current.value in ('get', 'set')
        ):
            saved = self._current
            self._advance()
            if self._at(JsTokenKind.LPAREN):
                key = JsIdentifier(name=saved.value, offset=saved.offset)
                return self._finish_class_member(key, is_static, False, offset, value_offset)
            if self._at_class_field_terminator():
                key = JsIdentifier(name=saved.value, offset=saved.offset)
                return self._finish_class_field(key, is_static, False, offset)
            kind = JsMethodKind.GET if saved.value == 'get' else JsMethodKind.SET
        elif not is_generator and self._at(JsTokenKind.ASYNC):
            saved = self._current
            self._advance()
            if self._at(JsTokenKind.LPAREN):
                key = JsIdentifier(name='async', offset=saved.offset)
                return self._finish_class_member(key, is_static, False, offset, value_offset)
            if self._preceded_by_newline or self._at_class_field_terminator():
                key = JsIdentifier(name='async', offset=saved.offset)
                return self._finish_class_field(key, is_static, False, offset)
            is_async = True
            if self._eat(JsTokenKind.STAR):
                is_generator = True

        key, computed = self._parse_property_key(class_element=True)

        if kind == JsMethodKind.METHOD and not is_generator and not self._at(JsTokenKind.LPAREN):
            return self._finish_class_field(key, is_static, computed, offset)

        return self._finish_class_member(
            key, is_static, is_generator, offset, value_offset, kind, computed, is_async=is_async)

    def _at_class_field_terminator(self) -> bool:
        """
        Whether the current token completes a class element as a field named by the identifier just consumed:
        an initializer (`=`), an explicit terminator (`;`), or the end of the class body (`}` / end of input).
        A modifier prefix (`static`/`get`/`set`/`async`) followed by one of these is an ordinary field whose
        name happens to be that word, not a modifier.
        """
        return self._at(
            JsTokenKind.EQUALS,
            JsTokenKind.SEMICOLON,
            JsTokenKind.RBRACE,
            JsTokenKind.EOF,
        )

    def _finish_class_field(
        self,
        key: Expression,
        is_static: bool,
        computed: bool,
        offset: int,
    ) -> JsPropertyDefinition:
        value = None
        if self._eat(JsTokenKind.EQUALS):
            with self._code_context(class_element_context(static=is_static)):
                value = self._parse_assignment_expression()
        self._eat_semicolon()
        return JsPropertyDefinition(
            key=key,
            value=value,
            computed=computed,
            is_static=is_static,
            offset=offset,
        )

    def _finish_class_member(
        self,
        key: Expression,
        is_static: bool,
        is_generator: bool,
        offset: int,
        value_offset: int,
        kind: JsMethodKind = JsMethodKind.METHOD,
        computed: bool = False,
        is_async: bool = False,
    ) -> JsMethodDefinition:
        func_offset = self._current.offset
        with self._function_body_context(is_async, is_generator):
            params = self._parse_formal_parameters()
            body = self._parse_block_statement()
        value = JsFunctionExpression(
            params=params,
            body=body,
            generator=is_generator,
            is_async=is_async,
            offset=func_offset,
        )
        self._record_source(value, value_offset)
        if isinstance(key, JsIdentifier) and key.name == 'constructor' and kind == JsMethodKind.METHOD:
            kind = JsMethodKind.CONSTRUCTOR
        return JsMethodDefinition(
            key=key,
            value=value,
            kind=kind,
            computed=computed,
            is_static=is_static,
            offset=offset,
        )

    def _parse_import_expression(self, offset: int) -> Expression:
        self._expect(JsTokenKind.IMPORT)
        if self._eat(JsTokenKind.DOT):
            prop = self._advance()
            return JsMetaProperty(meta='import', property=prop.value, offset=offset)
        if self._at(JsTokenKind.LPAREN):
            self._advance()
            source = self._parse_assignment_expression()
            options = None
            if self._eat(JsTokenKind.COMMA) and not self._at(JsTokenKind.RPAREN):
                options = self._parse_assignment_expression()
                self._eat(JsTokenKind.COMMA)
            self._expect(JsTokenKind.RPAREN)
            return JsImportExpression(source=source, options=options, offset=offset)
        return JsErrorNode(text='import', message='unexpected token', offset=offset)

    def _parse_import_attributes(self) -> tuple[str, list[JsImportAttribute]]:
        if self._preceded_by_newline:
            return '', []
        if self._at(JsTokenKind.WITH):
            keyword = 'with'
        elif self._at(JsTokenKind.IDENTIFIER) and self._current.value == 'assert':
            keyword = 'assert'
        else:
            return '', []
        self._advance()
        attributes: list[JsImportAttribute] = []
        self._expect(JsTokenKind.LBRACE)
        while not self._at(JsTokenKind.RBRACE, JsTokenKind.EOF):
            key = self._parse_property_name()
            self._expect(JsTokenKind.COLON)
            value = self._parse_string_literal()
            attributes.append(JsImportAttribute(key=key, value=value, offset=key.offset))
            if not self._eat(JsTokenKind.COMMA):
                break
        self._expect(JsTokenKind.RBRACE)
        return keyword, attributes

    def _module_specifier(self) -> JsStringLiteral | None:
        """
        The literal naming the module a declaration reads from, or `None` where none stands there.
        It is the one part of these declarations the grammar gives no default for, so a source that
        ends before writing it has not written the declaration at all; answering with a literal
        spelled by nothing states a module whose name is the empty string, which is a module the
        file could have named and did not.
        """
        if self._at(JsTokenKind.STRING_SINGLE, JsTokenKind.STRING_DOUBLE):
            return self._parse_string_literal()
        return None

    def _unread_since(self, offset: int, message: str) -> JsErrorNode:
        """
        The source from *offset* up to where reading stands, handed back as itself. A declaration
        the parser could not complete is kept whole rather than in the parts it did manage to read:
        what prints is then what was written, and reading that print again finds the same thing,
        where a half-built declaration prints the halves it has and reads back as something else.
        """
        return JsErrorNode(
            text=self._source[offset:self._current.offset].rstrip(),
            message=message,
            offset=offset,
        )

    def _parse_import_declaration(self) -> JsImportDeclaration | JsErrorNode:
        offset = self._current.offset
        self._expect(JsTokenKind.IMPORT)

        if self._at(JsTokenKind.STRING_SINGLE, JsTokenKind.STRING_DOUBLE):
            source = self._parse_string_literal()
            keyword, attributes = self._parse_import_attributes()
            self._eat_semicolon()
            return JsImportDeclaration(
                source=source, attributes=attributes, attributes_keyword=keyword, offset=offset)

        specifiers: list[
            JsImportSpecifier | JsImportDefaultSpecifier | JsImportNamespaceSpecifier
        ] = []

        if self._at_binding_identifier():
            tok = self._advance()
            specifiers.append(JsImportDefaultSpecifier(
                local=self._name_or_error(tok.value, tok.offset, may_be_reserved=False),
                offset=tok.offset,
            ))
            if self._eat(JsTokenKind.COMMA):
                if self._at(JsTokenKind.STAR):
                    specifiers.append(self._parse_namespace_import())
                elif self._at(JsTokenKind.LBRACE):
                    specifiers.extend(self._parse_named_imports())
                else:
                    self._recovered = True

        elif self._at(JsTokenKind.STAR):
            specifiers.append(self._parse_namespace_import())

        elif self._at(JsTokenKind.LBRACE):
            specifiers.extend(self._parse_named_imports())

        self._expect_contextual('from')
        source = self._module_specifier()
        if source is None:
            return self._unread_since(offset, 'a module declaration with no specifier')
        keyword, attributes = self._parse_import_attributes()
        self._eat_semicolon()
        return JsImportDeclaration(
            specifiers=specifiers,
            source=source,
            attributes=attributes,
            attributes_keyword=keyword,
            offset=offset,
        )

    def _parse_module_export_name(self) -> Expression:
        """
        The name an import or export list gives a binding on the far side of the module boundary. It
        is an IdentifierName rather than a name this file could refer to, so every word the language
        has stands here and none of them is a repair: `import { default as d } from 'm.js'` and
        `export * as default from 'm.js'` are both ordinary declarations.

        The shorthand `import { a }` writes one name in two positions at once, and this reads it as
        the boundary one, which is the wider of the two: what the shorthand also does is bind `a`
        locally, and no module may bind a word its strict code reserves. That rule is not applied
        anywhere yet, so nothing is lost by reading the shorthand here rather than gained by reading
        it as a binding.

        A word and a string literal are the whole of what the grammar writes here, and the two
        are different productions rather than two spellings of one. A string is read as the
        literal it is, because what it names is the text it denotes and not the way that text
        was written:

            export { a as 'b c' } from 'm';
            export { a as 'b\\u0020c' } from 'm';

        reach the one name `b c`, which no word spells, and asking a name reader for either
        would hand it a text that opens with a quote. Anything else is a token the parser steps
        over in order to answer with a name at all, and reading `,` as the name a module exports
        under is a repair however well it prints back.

        A module export name written as a string must denote a well-formed run of code units, a lone
        surrogate spelling no character a boundary name may carry, so a string holding one is read
        with the repair recorded.
        """
        if self._at(JsTokenKind.STRING_SINGLE, JsTokenKind.STRING_DOUBLE):
            literal = self._parse_string_literal()
            if literal.value is None or not is_well_formed_unicode(literal.value):
                self._recovered = True
            return literal
        if not self._at_identifier_name():
            self._recovered = True
        tok = self._advance()
        return self._name_or_error(tok.value, tok.offset, may_be_reserved=True)

    def _parse_namespace_import(self) -> JsImportNamespaceSpecifier:
        offset = self._current.offset
        self._expect(JsTokenKind.STAR)
        self._expect_contextual('as')
        return JsImportNamespaceSpecifier(
            local=self._parse_binding_identifier(),
            offset=offset,
        )

    def _parse_named_imports(self) -> list[JsImportSpecifier]:
        self._expect(JsTokenKind.LBRACE)
        specs: list[JsImportSpecifier] = []
        while not self._at(JsTokenKind.RBRACE, JsTokenKind.EOF):
            spec_offset = self._current.offset
            imported = self._parse_module_export_name()
            local = imported
            if self._at(JsTokenKind.AS):
                self._advance()
                local = self._parse_binding_identifier()
            elif isinstance(imported, JsStringLiteral):
                self._recovered = True
            specs.append(JsImportSpecifier(
                imported=imported, local=local, offset=spec_offset))
            if not self._at(JsTokenKind.RBRACE):
                self._expect(JsTokenKind.COMMA)
        self._expect(JsTokenKind.RBRACE)
        return specs

    def _parse_export_declaration(
        self, decorators: list[JsDecorator] | None = None,
    ) -> Statement:
        offset = self._current.offset
        self._expect(JsTokenKind.EXPORT)
        class_decorators = list(decorators or []) + self._parse_decorators()

        if self._eat(JsTokenKind.DEFAULT):
            class_decorators += self._parse_decorators()
            if self._at(JsTokenKind.FUNCTION):
                decl = self._parse_function_declaration()
                return JsExportDefaultDeclaration(declaration=decl, offset=offset)
            if self._at(JsTokenKind.CLASS):
                decl = self._parse_class_declaration(class_decorators)
                return JsExportDefaultDeclaration(declaration=decl, offset=offset)
            if self._at_async_function():
                async_start = self._current.offset
                self._advance()
                decl = self._parse_function_declaration(is_async=True, start=async_start)
                return JsExportDefaultDeclaration(declaration=decl, offset=offset)
            expr = self._parse_assignment_expression()
            self._eat_semicolon()
            return JsExportDefaultDeclaration(declaration=expr, offset=offset)

        if self._at(JsTokenKind.STAR):
            self._advance()
            exported = None
            if self._at(JsTokenKind.AS):
                self._advance()
                exported = self._parse_module_export_name()
            self._expect_contextual('from')
            source = self._module_specifier()
            if source is None:
                return self._unread_since(offset, 'a module declaration with no specifier')
            keyword, attributes = self._parse_import_attributes()
            self._eat_semicolon()
            return JsExportAllDeclaration(
                source=source,
                exported=exported,
                attributes=attributes,
                attributes_keyword=keyword,
                offset=offset,
            )

        if self._at(JsTokenKind.LBRACE):
            return self._parse_export_named(offset)

        if self._at(JsTokenKind.VAR, JsTokenKind.LET, JsTokenKind.CONST):
            decl = self._parse_variable_declaration()
            return JsExportNamedDeclaration(declaration=decl, offset=offset)
        if self._at(JsTokenKind.FUNCTION):
            decl = self._parse_function_declaration()
            return JsExportNamedDeclaration(declaration=decl, offset=offset)
        if self._at(JsTokenKind.CLASS):
            decl = self._parse_class_declaration(class_decorators)
            return JsExportNamedDeclaration(declaration=decl, offset=offset)
        if self._at_async_function():
            async_start = self._current.offset
            self._advance()
            decl = self._parse_function_declaration(is_async=True, start=async_start)
            return JsExportNamedDeclaration(declaration=decl, offset=offset)

        self._recovered = True
        self._advance()
        return JsExportNamedDeclaration(offset=offset)

    def _parse_export_named(self, offset: int) -> JsExportNamedDeclaration | JsErrorNode:
        self._expect(JsTokenKind.LBRACE)
        specifiers: list[JsExportSpecifier] = []
        while not self._at(JsTokenKind.RBRACE, JsTokenKind.EOF):
            spec_offset = self._current.offset
            local = self._parse_module_export_name()
            exported = local
            if self._at(JsTokenKind.AS):
                self._advance()
                exported = self._parse_module_export_name()
            specifiers.append(JsExportSpecifier(
                local=local, exported=exported, offset=spec_offset))
            if not self._at(JsTokenKind.RBRACE):
                self._expect(JsTokenKind.COMMA)
        self._expect(JsTokenKind.RBRACE)
        source = None
        keyword, attributes = '', []
        if self._at(JsTokenKind.FROM):
            self._advance()
            source = self._module_specifier()
            if source is None:
                return self._unread_since(offset, 'a module declaration with no specifier')
            keyword, attributes = self._parse_import_attributes()
        if source is None and any(
            isinstance(specifier.local, JsStringLiteral) for specifier in specifiers
        ):
            self._recovered = True
        self._eat_semicolon()
        return JsExportNamedDeclaration(
            specifiers=specifiers,
            source=source,
            attributes=attributes,
            attributes_keyword=keyword,
            offset=offset,
        )

    def _at_async_function(self) -> bool:
        """
        Whether the parser is positioned at `async function` with no line terminator between the two — the
        one form in which a leading `async` opens a declaration rather than an ordinary expression. Every
        other `async` (a call, member access, arrow, or bare reference) is left to the expression grammar,
        which reaches it through `_parse_async_expression` and applies the full call/member and operator
        parsing.
        """
        return (
            self._at(JsTokenKind.ASYNC)
            and self._peek_next().kind == JsTokenKind.FUNCTION
            and not self._ahead_newline
        )

    def _expect_contextual(self, keyword: str):
        """
        The word that must stand here, which is a word and not a token kind: `as` and `from` are
        names everywhere else, so the lexer hands them over as themselves in one form and as an
        identifier in the other. Where neither is what stands here the parser steps over whatever
        does, which drops it from the file, and that is a repair like any other.
        """
        if self._at(JsTokenKind.FROM) and keyword == 'from':
            self._advance()
            return
        if self._at(JsTokenKind.AS) and keyword == 'as':
            self._advance()
            return
        if self._at(JsTokenKind.IDENTIFIER) and self._current.value == keyword:
            self._advance()
            return
        self._recovered = True
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
        """
        An AssignmentExpression, which is the only production a YieldExpression is one of. Reading
        the `yield` here rather than among the primary expressions is what stops an operator from
        attaching to it: a `yield` that the line terminator restriction left without an argument
        ends the expression, and the slash that opens the next statement is not its divisor.
        """
        if self._at(JsTokenKind.YIELD) and self._context.yield_is_operator:
            return self._parse_yield_expression()
        left = self._parse_conditional_expression()
        if self._current.kind.is_assignment:
            op = self._advance().value
            right = self._parse_assignment_expression()
            left = self._to_param(left) if op == '=' else left
            return JsAssignmentExpression(
                left=left, operator=op, right=right, offset=left.offset)
        return left

    def _parse_conditional_expression(self) -> Expression:
        expr = self._parse_binary_expression()
        if self._eat(JsTokenKind.QUESTION):
            with self._with_no_in(False):
                consequent = self._parse_assignment_expression()
            if self._eat(JsTokenKind.COLON):
                alternate = self._parse_assignment_expression()
            else:
                # The colon a conditional requires is not here. Reading the alternate anyway would
                # spend `_expect`, which steps over whatever stands here to invent the colon — and
                # where that is the semicolon ending the statement, the next statement is read as
                # the alternate and the whole tail of the block is pulled into one expression. The
                # branch is left unwritten instead, so the boundary stays where it is and the
                # statement after the conditional is read as itself.
                self._recovered = True
                alternate = JsErrorNode(offset=self._current.offset, message='expected :')
            return JsConditionalExpression(
                test=expr,
                consequent=consequent,
                alternate=alternate,
                offset=expr.offset,
            )
        return expr

    def _parse_binary_expression(self, min_prec: int = 0) -> Expression:
        left = self._parse_unary_expression()
        while True:
            entry = _BINARY_PREC.get(self._current.kind)
            if entry is None:
                break
            prec, logical = entry
            if prec < min_prec:
                break
            if self._no_in and self._at(JsTokenKind.IN):
                break
            op = self._advance().value
            next_prec = prec if prec == _PREC_EXPONENTIATION else prec + 1
            right = self._parse_binary_expression(next_prec)
            node_type = JsLogicalExpression if logical else JsBinaryExpression
            left = node_type(
                left=left, operator=op, right=right, offset=left.offset)
        return left

    def _parse_unary_expression(self) -> Expression:
        if self._at(
            JsTokenKind.BANG,
            JsTokenKind.TILDE,
            JsTokenKind.TYPEOF,
            JsTokenKind.VOID,
            JsTokenKind.DELETE,
        ):
            tok = self._advance()
            operand = self._parse_unary_expression()
            return JsUnaryExpression(
                operator=tok.value, operand=operand, prefix=True, offset=tok.offset)
        if self._at(JsTokenKind.PLUS):
            tok = self._advance()
            operand = self._parse_unary_expression()
            return JsUnaryExpression(
                operator='+', operand=operand, prefix=True, offset=tok.offset)
        if self._at(JsTokenKind.MINUS):
            tok = self._advance()
            operand = self._parse_unary_expression()
            return JsUnaryExpression(
                operator='-', operand=operand, prefix=True, offset=tok.offset)
        if self._at(JsTokenKind.AWAIT) and self._context.await_reading is AwaitReading.OPERATOR:
            tok = self._advance()
            operand = self._parse_unary_expression()
            return JsAwaitExpression(argument=operand, offset=tok.offset)
        return self._parse_update_expression()

    @staticmethod
    def _is_simple_reference(node: Expression) -> bool:
        """
        Whether *node* is a reference `++` or `--` may write back to, which §13.4 requires of the
        operand of either: its AssignmentTargetType must be simple. A name is one, and so is a
        member access, and so is a call, in the sloppy code a script is until a directive makes it
        strict. A parenthesis wraps a reference only where what it holds is one, and a single `?.`
        anywhere in the chain makes the whole an optional expression the language forbids an update
        from writing to. Everything else — a function or class made on the spot, a literal, `this`,
        a `new`, a sequence — is a value and no reference, so an update written against it is an
        early error, and a file holding one is read with the repair recorded so that nothing takes
        the tree for a program.
        """
        current: Expression | None = node
        while isinstance(current, JsParenthesizedExpression):
            current = current.expression
        if isinstance(current, JsIdentifier):
            return True
        if not isinstance(current, (JsMemberExpression, JsCallExpression)):
            return False
        while isinstance(current, (JsMemberExpression, JsCallExpression)):
            if current.optional:
                return False
            current = current.object if isinstance(current, JsMemberExpression) else current.callee
        return True

    def _parse_update_expression(self) -> Expression:
        if self._at(JsTokenKind.INC, JsTokenKind.DEC):
            tok = self._advance()
            argument = self._parse_call_expression()
            if not self._is_simple_reference(argument):
                self._recovered = True
            return JsUpdateExpression(
                operator=tok.value, argument=argument, prefix=True, offset=tok.offset)
        expr = self._parse_call_expression()
        if not self._preceded_by_newline and self._at(
            JsTokenKind.INC, JsTokenKind.DEC,
        ):
            tok = self._advance()
            if not self._is_simple_reference(expr):
                self._recovered = True
            return JsUpdateExpression(
                operator=tok.value, argument=expr, prefix=False, offset=expr.offset)
        return expr

    def _parse_call_expression(self) -> Expression:
        """
        A left-hand side expression: what may be called, indexed, or used to tag a template. An
        arrow function is none of those. It is an AssignmentExpression and never a
        LeftHandSideExpression, so nothing may attach to it, and the tail that would have attached
        belongs to whatever follows instead — `f = a => {}` on one line and `[x].forEach(g)` on the
        next are two statements, and reading the bracket as an index into the arrow makes them one.
        """
        expr = self._parse_new_expression()
        if isinstance(expr, JsArrowFunctionExpression):
            return expr
        while True:
            if self._at(JsTokenKind.LPAREN):
                expr = self._parse_call_arguments(expr, optional=False)
            elif self._eat(JsTokenKind.DOT):
                prop = self._member_property()
                expr = JsMemberExpression(
                    object=expr, property=prop, computed=False, optional=False, offset=expr.offset)
            elif self._at(JsTokenKind.LBRACKET):
                expr = JsMemberExpression(
                    object=expr,
                    property=self._parse_computed_member_key(),
                    computed=True,
                    optional=False,
                    offset=expr.offset,
                )
            elif self._at(JsTokenKind.QUESTION_DOT) or (
                self._at(JsTokenKind.QUESTION)
                and self._peek_next().kind == JsTokenKind.DOT
            ):
                # A question mark whose next token is a dot is a `?.` the source split with
                # whitespace. That split is not a token the language has, and no well-formed program
                # reaches it: a conditional whose consequent opens with a dot opens with a number,
                # which the lexer reads as one float rather than a dot. Reading the two as the
                # optional-chain operator recovers the program the source meant, recorded as a
                # repair so the tree still reports that the file did not spell it whole.
                if self._eat(JsTokenKind.QUESTION_DOT) is None:
                    self._recovered = True
                    self._advance()
                    self._advance()
                if self._at(JsTokenKind.LPAREN):
                    expr = self._parse_call_arguments(expr, optional=True)
                elif self._at(JsTokenKind.LBRACKET):
                    expr = JsMemberExpression(
                        object=expr,
                        property=self._parse_computed_member_key(),
                        computed=True,
                        optional=True,
                        offset=expr.offset,
                    )
                else:
                    prop = self._member_property()
                    expr = JsMemberExpression(
                        object=expr, property=prop, computed=False, optional=True, offset=expr.offset)
            elif self._at(
                JsTokenKind.TEMPLATE_FULL, JsTokenKind.TEMPLATE_HEAD,
            ):
                quasi = self._parse_template_literal()
                expr = JsTaggedTemplateExpression(
                    tag=expr, quasi=quasi, offset=expr.offset)
            else:
                break
        return expr

    def _member_property(self) -> Expression:
        """
        The name behind a dot. It is an IdentifierName, which is every word the language has and not
        only the ones that may be a variable, so `a.if` and `a.default` are ordinary member reads.

        Where the text behind the dot spells no word at all there is no name to build. An identifier
        with no name spells nothing — printing it writes the dot and stops, which is not a program —
        so what was read is handed back as itself instead.
        """
        tok = self._advance()
        if tok.kind is JsTokenKind.PRIVATE_IDENTIFIER:
            return self._private_identifier(tok, tok.offset)
        if tok.kind is JsTokenKind.IDENTIFIER or tok.kind.is_keyword:
            return self._name_or_error(tok.value, tok.offset, may_be_reserved=True)
        return JsErrorNode(
            text=tok.value, message='expected a property name', offset=tok.offset)

    def _parse_computed_member_key(self) -> Expression:
        """
        The expression between the brackets of a computed member read. Like a call's arguments it is
        written `[+In]`, so `for (t["k" in b] = "set"; ; )` is an ordinary head: the bracket ends the
        reach of the suppression the head applies to a relational operator standing directly in it.
        """
        self._expect(JsTokenKind.LBRACKET)
        with self._with_no_in(False):
            key = self._parse_expression()
        self._expect(JsTokenKind.RBRACKET)
        return key

    def _parse_argument_list(self) -> list[Expression]:
        """
        The arguments between the brackets of a call. Each is written `[+In]`, so `in` is an operator
        here however the call was reached: what a `for` head suppresses is a relational operator
        standing in the head itself, and a bracket the head encloses is a fresh expression again.
        Owning that here rather than at each call site is what keeps `for (new Set("k" in b); ; )`
        reading the same way `for (f("k" in b); ; )` does.
        """
        args: list[Expression] = []
        with self._with_no_in(False):
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
        return args

    def _parse_call_arguments(
        self,
        callee: Expression,
        optional: bool,
    ) -> JsCallExpression:
        self._expect(JsTokenKind.LPAREN)
        args = self._parse_argument_list()
        return JsCallExpression(
            callee=callee, arguments=args, optional=optional, offset=callee.offset)

    def _parse_new_expression(self) -> Expression:
        if self._at(JsTokenKind.NEW):
            offset = self._current.offset
            self._advance()
            if self._at(JsTokenKind.DOT):
                self._advance()
                return JsMemberExpression(
                    object=JsIdentifier(name='new', offset=offset),
                    property=self._member_property(),
                    computed=False,
                    offset=offset,
                )
            if self._at(JsTokenKind.ASYNC) and not self._at_async_function():
                tok = self._advance()
                callee = self._name_or_error(tok.value, tok.offset, may_be_reserved=False)
            else:
                callee = self._parse_new_expression()
            while True:
                if self._eat(JsTokenKind.DOT):
                    prop = self._member_property()
                    callee = JsMemberExpression(
                        object=callee, property=prop, computed=False, offset=callee.offset)
                elif self._at(JsTokenKind.LBRACKET):
                    callee = JsMemberExpression(
                        object=callee,
                        property=self._parse_computed_member_key(),
                        computed=True,
                        offset=callee.offset,
                    )
                else:
                    break
            args: list[Expression] = []
            if self._at(JsTokenKind.LPAREN):
                self._advance()
                args = self._parse_argument_list()
            return JsNewExpression(callee=callee, arguments=args, offset=offset)
        return self._parse_primary_expression()

    def _parse_primary_expression(self) -> Expression:
        tok = self._current
        offset = tok.offset

        if self._at(JsTokenKind.ASYNC):
            return self._parse_async_expression()

        if self._at_binding_identifier():
            self._advance()
            if self._at(JsTokenKind.ARROW) and not self._preceded_by_newline:
                self._advance()
                param = self._name_or_error(tok.value, offset, may_be_reserved=False)
                body = self._parse_arrow_body()
                arrow = JsArrowFunctionExpression(
                    params=[param], body=body, offset=offset)
                self._record_source(arrow, offset)
                return arrow
            return self._name_or_error(tok.value, offset, may_be_reserved=False)

        if self._at(JsTokenKind.PRIVATE_IDENTIFIER):
            self._advance()
            return self._private_identifier(tok, offset)

        if self._at(JsTokenKind.IMPORT):
            return self._parse_import_expression(offset)

        if self._at(JsTokenKind.INTEGER):
            self._advance()
            raw = tok.value
            value = self._parse_int_text(raw.replace('_', ''))
            return JsNumericLiteral(value=value, raw=raw, offset=offset)

        if self._at(JsTokenKind.FLOAT):
            self._advance()
            raw = tok.value
            value = float(raw.replace('_', ''))
            return JsNumericLiteral(value=value, raw=raw, offset=offset)

        if self._at(JsTokenKind.BIGINT):
            self._advance()
            raw = tok.value
            value = self._parse_int_text(raw.replace('_', '').rstrip('n'))
            return JsBigIntLiteral(value=value, raw=raw, offset=offset)

        if self._at(JsTokenKind.STRING_SINGLE, JsTokenKind.STRING_DOUBLE):
            return self._parse_string_literal()

        if self._at(JsTokenKind.SLASH, JsTokenKind.SLASH_ASSIGN):
            tok = self._rescan_as_regexp()

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

        self._advance()
        return JsErrorNode(text=tok.value, message='unexpected token', offset=offset)

    def _parse_string_literal(self) -> JsStringLiteral:
        tok = self._advance()
        raw = tok.value
        end = len(raw) - 1 if tok.terminated else len(raw)
        return JsStringLiteral(
            value=decode_js_string_body(raw[1:end]),
            raw=raw,
            terminated=tok.terminated,
            offset=tok.offset,
        )

    @staticmethod
    def _template_element(tok: JsToken, tail: bool) -> JsTemplateElement:
        """
        One run of text of a template literal, taken from the token without the delimiters around
        it: one character opens every run, and the one that ends it is a backtick where the run
        ends the literal and `${` where a hole follows. The text between them is cooked into what
        it denotes, exactly as the body of a string literal is — a template that carries an escape
        means what the escape means, and reading it as the characters that spell it is how a `\\t`
        became two.
        """
        raw = tok.value
        end = len(raw) - (1 if tail else 2) if tok.terminated else len(raw)
        text = raw[1:end]
        return JsTemplateElement(
            value=decode_js_template_body(text),
            raw=text,
            tail=tail,
            terminated=tok.terminated,
            offset=tok.offset,
        )

    def _parse_template_literal(self) -> JsTemplateLiteral:
        offset = self._current.offset
        quasis: list[JsTemplateElement] = []
        expressions: list[Expression] = []

        if self._at(JsTokenKind.TEMPLATE_FULL):
            quasis.append(self._template_element(self._advance(), True))
            return JsTemplateLiteral(
                quasis=quasis, expressions=expressions, offset=offset)

        quasis.append(self._template_element(self._advance(), False))

        while True:
            with self._with_no_in(False):
                expressions.append(self._parse_expression())
            if self._at(JsTokenKind.TEMPLATE_TAIL):
                quasis.append(self._template_element(self._advance(), True))
                break
            elif self._at(JsTokenKind.TEMPLATE_MIDDLE):
                quasis.append(self._template_element(self._advance(), False))
            else:
                quasis.append(JsTemplateElement(
                    value='',
                    raw='',
                    tail=True,
                    terminated=False,
                    offset=self._current.offset,
                ))
                break

        return JsTemplateLiteral(
            quasis=quasis, expressions=expressions, offset=offset)

    def _parse_array_literal(self) -> JsArrayExpression:
        with self._with_no_in(False):
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
                    self._require(JsTokenKind.COMMA)
            self._expect(JsTokenKind.RBRACKET)
        return JsArrayExpression(elements=elements, offset=offset)

    def _parse_object_literal(self) -> JsObjectExpression:
        with self._with_no_in(False):
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
                    self._require(JsTokenKind.COMMA)
            self._expect(JsTokenKind.RBRACE)
        return JsObjectExpression(properties=properties, offset=offset)

    def _parse_object_property(self) -> JsProperty:
        offset = self._current.offset
        is_generator = bool(self._eat(JsTokenKind.STAR))

        if (
            self._at(JsTokenKind.IDENTIFIER)
            and self._current.value in ('get', 'set')
            and not is_generator
        ):
            kind_val = _PROP_KIND_MAP[self._current.value]
            saved = self._current
            self._advance()
            if self._at(JsTokenKind.LPAREN):
                key = JsIdentifier(name=saved.value, offset=saved.offset)
                return self._make_method_property(key, JsPropertyKind.INIT, False, offset)
            if self._at(
                JsTokenKind.COLON,
                JsTokenKind.COMMA,
                JsTokenKind.RBRACE,
                JsTokenKind.EQUALS,
            ):
                key = JsIdentifier(name=saved.value, offset=saved.offset)
                return self._finish_property_value(key, False, offset)
            key, computed = self._parse_property_key()
            return self._make_method_property(key, kind_val, False, offset, computed=computed)

        if self._at(JsTokenKind.ASYNC) and not is_generator:
            saved = self._current
            self._advance()
            if self._preceded_by_newline or self._at(
                JsTokenKind.COLON,
                JsTokenKind.COMMA,
                JsTokenKind.RBRACE,
                JsTokenKind.EQUALS,
                JsTokenKind.LPAREN,
            ):
                if self._at(JsTokenKind.LPAREN):
                    key = JsIdentifier(name='async', offset=saved.offset)
                    return self._make_method_property(key, JsPropertyKind.INIT, False, offset)
                key = JsIdentifier(name='async', offset=saved.offset)
                return self._finish_property_value(key, False, offset)
            gen = bool(self._eat(JsTokenKind.STAR))
            key, computed = self._parse_property_key()
            return self._make_method_property(
                key, JsPropertyKind.INIT, gen, offset, computed=computed, is_async=True)

        key, computed = self._parse_property_key()

        if is_generator or self._at(JsTokenKind.LPAREN):
            return self._make_method_property(key, JsPropertyKind.INIT, is_generator, offset, computed=computed)

        return self._finish_property_value(key, computed, offset)

    def _finish_property_value(
        self,
        key: Expression,
        computed: bool,
        offset: int,
    ) -> JsProperty:
        if self._eat(JsTokenKind.COLON):
            value = self._parse_assignment_expression()
            return JsProperty(
                key=key, value=value, computed=computed,
                shorthand=False, offset=offset)
        if not computed and self._eat(JsTokenKind.EQUALS):
            right = self._parse_assignment_expression()
            value = JsAssignmentPattern(left=key, right=right, offset=key.offset)
            return JsProperty(
                key=key, value=value, computed=computed,
                shorthand=True, offset=offset)
        return JsProperty(
            key=key, value=key, computed=computed,
            shorthand=True, offset=offset)

    def _make_method_property(
        self,
        key: Expression,
        kind: JsPropertyKind,
        is_generator: bool,
        offset: int,
        computed: bool = False,
        is_async: bool = False,
    ) -> JsProperty:
        func_offset = self._current.offset
        with self._function_body_context(is_async, is_generator):
            params = self._parse_formal_parameters()
            body = self._parse_block_statement()
        value = JsFunctionExpression(
            params=params, body=body, generator=is_generator,
            is_async=is_async, offset=func_offset)
        self._record_source(value, offset)
        return JsProperty(
            key=key, value=value, computed=computed,
            shorthand=False, method=True, kind=kind, offset=offset)

    def _parse_property_key(self, *, class_element: bool = False) -> tuple[Expression, bool]:
        if self._at(JsTokenKind.LBRACKET):
            self._advance()
            key = self._parse_assignment_expression()
            self._expect(JsTokenKind.RBRACKET)
            return key, True
        return self._parse_property_name(class_element=class_element), False

    def _parse_property_name(self, *, class_element: bool = False) -> Expression:
        """
        The name a property is written with: an IdentifierName, a string, or a numeral, and in a
        class body a private name besides. A `[` opens a computed key and is read before this is
        reached, so what stands here spells one of those or it spells no property name at all. A
        numeral carries its own kind, so a `1n` key is the BigInt it is anywhere else and not a
        name whose text reads `1n`.

        A punctuator is the token that spells no name, and so, outside a class body, is a private
        name the object grammar has no room for. A key written with either is an early error and
        the file no program, so it is read with the repair recorded — the tree kept so the file
        still prints as written — and `refinery.lib.scripts.is_well_formed`, the domain every
        fidelity law is stated over, answers False for it.
        """
        tok = self._current
        if self._at(JsTokenKind.INTEGER, JsTokenKind.FLOAT):
            self._advance()
            raw = tok.value
            text = raw.replace('_', '')
            return JsNumericLiteral(
                value=float(text) if tok.kind == JsTokenKind.FLOAT else self._parse_int_text(text),
                raw=raw,
                offset=tok.offset,
            )
        if self._at(JsTokenKind.BIGINT):
            self._advance()
            raw = tok.value
            return JsBigIntLiteral(
                value=self._parse_int_text(raw.replace('_', '').rstrip('n')),
                raw=raw,
                offset=tok.offset,
            )
        if self._at(JsTokenKind.STRING_SINGLE, JsTokenKind.STRING_DOUBLE):
            return self._parse_string_literal()
        if self._at(JsTokenKind.PRIVATE_IDENTIFIER):
            if not class_element:
                self._recovered = True
            self._advance()
            return self._private_identifier(tok, tok.offset)
        if not self._at_identifier_name():
            self._recovered = True
        self._advance()
        return self._name_or_error(tok.value, tok.offset, may_be_reserved=True)

    def _parse_paren_or_arrow(self, is_async: bool = False) -> Expression:
        """
        What ECMA-262 calls `CoverParenthesizedExpressionAndArrowParameterList`: a bracketed list
        that the token behind the closing bracket decides the reading of, because nothing inside it
        does. It is read as a list of assignment expressions either way and only then converted,
        which is what lets one pass read a head no expression grammar accepts.

        Three of its shapes belong to the parameter reading alone and are not expressions at all —
        the empty list, a rest element, and a trailing comma — so a list holding one of them is an
        arrow head or it is nothing. The rest element in particular may only stand last, and reading
        it as one of the list rather than as a case of its own is the whole difference between
        `(...a) => a` and `(b, ...a) => a`.

        Where such a list has no arrow behind it, the head stands with nothing to give its
        parameters, and what is missing is recorded where the body would be. Demanding the arrow
        instead consumes whatever does stand there — the semicolon ending the statement, say —
        and the body then reads the statement behind it, so `x = (a,); y = 2;` would take the
        second line into a function nobody wrote and leave nothing to say that it had.
        """
        with self._with_no_in(False):
            offset = self._current.offset
            self._expect(JsTokenKind.LPAREN)

            items: list[Expression] = []
            head_only = True

            while not self._at(JsTokenKind.RPAREN, JsTokenKind.EOF):
                if self._at(JsTokenKind.ELLIPSIS):
                    items.append(self._parse_rest_element())
                    head_only = True
                    break
                items.append(self._parse_assignment_expression())
                head_only = False
                if not self._eat(JsTokenKind.COMMA):
                    break
                head_only = self._at(JsTokenKind.RPAREN)

            self._expect(JsTokenKind.RPAREN)

            if self._at(JsTokenKind.ARROW) and not self._preceded_by_newline:
                self._advance()
                body = self._parse_arrow_body(is_async)
            elif head_only:
                body = JsErrorNode(
                    text='',
                    message='a parameter list with no arrow behind it',
                    offset=self._current.offset,
                )
            else:
                expression = items[0] if len(items) == 1 else JsSequenceExpression(
                    expressions=items, offset=offset)
                return JsParenthesizedExpression(expression=expression, offset=offset)

            arrow = JsArrowFunctionExpression(
                params=[self._to_param(item) for item in items],
                body=body,
                offset=offset,
            )
            self._record_source(arrow, offset)
            return arrow

    def _parse_arrow_body(self, is_async: bool = False) -> Expression | JsBlockStatement:
        with self._code_context(arrow_body_context(is_async, self._context)):
            if self._at(JsTokenKind.LBRACE):
                return self._parse_block_statement()
            return self._parse_assignment_expression()

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

    def _parse_function_expression(self) -> JsFunctionExpression:
        return self._parse_function_impl(as_expression=True)

    def _parse_class_expression(self) -> JsClassExpression:
        return self._parse_class_impl(as_expression=True)

    def _parse_async_expression(self) -> Expression:
        offset = self._current.offset
        self._advance()
        return self._parse_expression_starting_with_async(offset)

    def _parse_expression_starting_with_async(self, offset: int) -> Expression:
        if not self._preceded_by_newline:
            if self._at(JsTokenKind.FUNCTION):
                return self._parse_function_impl(as_expression=True, is_async=True, start=offset)

            if self._at(JsTokenKind.ARROW):
                self._advance()
                param = JsIdentifier(name='async', offset=offset)
                body = self._parse_arrow_body(False)
                arrow = JsArrowFunctionExpression(
                    params=[param], body=body, is_async=False, offset=offset)
                self._record_source(arrow, offset)
                return arrow

            if (
                self._at_binding_identifier()
                and self._peek_next().kind == JsTokenKind.ARROW
                and not self._ahead_newline
            ):
                tok = self._advance()
                self._advance()
                param = self._name_or_error(tok.value, tok.offset, may_be_reserved=False)
                body = self._parse_arrow_body(True)
                arrow = JsArrowFunctionExpression(
                    params=[param], body=body, is_async=True, offset=offset)
                self._record_source(arrow, offset)
                return arrow

            if self._at(JsTokenKind.LPAREN):
                self._advance()
                args = self._parse_argument_list()
                if self._at(JsTokenKind.ARROW) and not self._preceded_by_newline:
                    self._advance()
                    params = [self._to_param(arg) for arg in args]
                    body = self._parse_arrow_body(True)
                    arrow = JsArrowFunctionExpression(
                        params=params, body=body, is_async=True, offset=offset)
                    self._record_source(arrow, offset)
                    return arrow
                return JsCallExpression(
                    callee=JsIdentifier(name='async', offset=offset),
                    arguments=args,
                    optional=False,
                    offset=offset,
                )

        return JsIdentifier(name='async', offset=offset)

    def _parse_yield_expression(self) -> JsYieldExpression:
        """
        A YieldExpression, whose one line terminator restriction sits between the `yield` and what
        follows it. A newline there ends the expression, so neither a `*` nor an argument can still
        belong to it; a newline anywhere after the `*` is ordinary whitespace, and the argument is
        read across it.

        A token that closes the construct the `yield` stands in is not an argument, and the hole of
        a template is closed by the text that resumes it rather than by a brace of its own.
        """
        offset = self._current.offset
        self._advance()
        if self._preceded_by_newline:
            return JsYieldExpression(argument=None, delegate=False, offset=offset)
        delegate = self._eat(JsTokenKind.STAR) is not None
        argument = None
        if not self._at(
            JsTokenKind.SEMICOLON,
            JsTokenKind.RBRACE,
            JsTokenKind.RPAREN,
            JsTokenKind.RBRACKET,
            JsTokenKind.COMMA,
            JsTokenKind.COLON,
            JsTokenKind.TEMPLATE_MIDDLE,
            JsTokenKind.TEMPLATE_TAIL,
            JsTokenKind.EOF,
        ):
            argument = self._parse_assignment_expression()
        return JsYieldExpression(
            argument=argument, delegate=delegate, offset=offset)
