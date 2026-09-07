from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Callable, Literal, TypeVar, overload

from refinery.lib.scripts import Node
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
from refinery.lib.tools import RecursionDepth

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


class JsParseError(Exception):
    """
    A token the grammar refuses where the parser stands. It is raised at the point of refusal and
    caught by the statement, or class element, that was being read, which keeps its source verbatim.
    """
    def __init__(self, message: str, offset: int):
        super().__init__(message)
        self.message = message
        self.offset = offset


_CLOSERS = {
    JsTokenKind.RPAREN: JsTokenKind.LPAREN,
    JsTokenKind.RBRACKET: JsTokenKind.LBRACKET,
    JsTokenKind.RBRACE: JsTokenKind.LBRACE,
}
_OPENERS = frozenset(_CLOSERS.values())

#: The tokens behind which a slash divides rather than opening a regular expression literal: an
#: operand has just ended. Behind anything else, a keyword included, an expression may begin.
_DIVISION_FOLLOWS = frozenset({
    JsTokenKind.IDENTIFIER,
    JsTokenKind.PRIVATE_IDENTIFIER,
    JsTokenKind.INTEGER,
    JsTokenKind.FLOAT,
    JsTokenKind.BIGINT,
    JsTokenKind.STRING_SINGLE,
    JsTokenKind.STRING_DOUBLE,
    JsTokenKind.REGEXP,
    JsTokenKind.TEMPLATE_FULL,
    JsTokenKind.TEMPLATE_TAIL,
    JsTokenKind.RPAREN,
    JsTokenKind.RBRACKET,
    JsTokenKind.RBRACE,
    JsTokenKind.THIS,
    JsTokenKind.SUPER,
    JsTokenKind.NULL,
    JsTokenKind.TRUE,
    JsTokenKind.FALSE,
    JsTokenKind.INC,
    JsTokenKind.DEC,
})

_STRING_KINDS = frozenset({JsTokenKind.STRING_SINGLE, JsTokenKind.STRING_DOUBLE})

#: How deep statements and expressions may nest before the parser refuses to read further in. A
#: level of nesting costs up to some thirty-five interpreter frames, and `JsParser.parse` runs
#: under a recursion depth of ten thousand.
_NESTING_LIMIT = 200


@dataclass(frozen=True)
class _Boundary:
    """
    Where the text of a list item the parser could not read ends. `stops` are the tokens that begin
    the next item or end the list and are left standing; `consumes` the token that ends the item
    itself and goes with it; `line_bound` whether a line terminator ends it; and `continued` the
    words that carry a block-bodied item on past a block that closed at the nesting it began at, or
    `None` for an item no block ends.
    """
    stops: frozenset[JsTokenKind] = frozenset()
    consumes: frozenset[JsTokenKind] = frozenset()
    line_bound: bool = False
    continued: frozenset[JsTokenKind] | None = None


_STATEMENT = _Boundary(consumes=frozenset({JsTokenKind.SEMICOLON}), line_bound=True)
_CLASS_ELEMENT = _Boundary(
    consumes=frozenset({JsTokenKind.SEMICOLON}), line_bound=True, continued=frozenset())
_SWITCH_CLAUSE = _Boundary(stops=frozenset({JsTokenKind.CASE, JsTokenKind.DEFAULT}))
_COMMA_ITEM = _Boundary(stops=frozenset({JsTokenKind.COMMA}))
_TEMPLATE_HOLE = _Boundary(stops=frozenset({JsTokenKind.TEMPLATE_MIDDLE, JsTokenKind.TEMPLATE_TAIL}))

#: The statements a block ends, keyed by the token they open with, mapped to the words that carry
#: the statement on past that block.
_BLOCK_STATEMENTS: dict[JsTokenKind, frozenset[JsTokenKind]] = {
    JsTokenKind.IF: frozenset({JsTokenKind.ELSE}),
    JsTokenKind.TRY: frozenset({JsTokenKind.CATCH, JsTokenKind.FINALLY}),
    JsTokenKind.DO: frozenset({JsTokenKind.WHILE}),
    JsTokenKind.FOR: frozenset(),
    JsTokenKind.WHILE: frozenset(),
    JsTokenKind.WITH: frozenset(),
    JsTokenKind.SWITCH: frozenset(),
    JsTokenKind.FUNCTION: frozenset(),
    JsTokenKind.CLASS: frozenset(),
    JsTokenKind.AT: frozenset(),
}

_T = TypeVar('_T', bound=Node)


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
        self._pending_comments: list[JsToken] = []
        self._brackets: list[JsTokenKind] = []
        self._recovered: bool = False
        self._prev: JsToken = self._current
        self._hashbang: str | None = None
        self._depth: int = 0
        self._advance()

    def _pull_token(self) -> tuple[JsToken, bool]:
        had_newline = False
        while True:
            tok = next(self._tokens, JsToken(JsTokenKind.EOF, '', len(self._source)))
            if tok.kind == JsTokenKind.NEWLINE:
                had_newline = True
                continue
            if tok.kind == JsTokenKind.HASHBANG:
                self._hashbang = tok.value
                continue
            if tok.kind == JsTokenKind.COMMENT:
                self._pending_comments.append(tok)
                continue
            break
        return tok, had_newline

    def _track_bracket(self, tok: JsToken) -> None:
        if tok.kind in _OPENERS:
            self._brackets.append(tok.kind)
        elif tok.kind in _CLOSERS:
            opener = _CLOSERS[tok.kind]
            if opener in self._brackets:
                while self._brackets.pop() is not opener:
                    pass

    def _take_comments(self) -> list[str]:
        comments = [tok.value for tok in self._pending_comments]
        self._pending_comments.clear()
        return comments

    @property
    def _prev_end(self) -> int:
        return self._prev.offset + len(self._prev.value)

    def _advance(self) -> JsToken:
        prev = self._current
        self._prev = prev
        self._track_bracket(prev)
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
            node.leading_comments.extend(self._take_comments())

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
        raise JsParseError(F'expected {kind.name}', self._current.offset)

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
            raise JsParseError(F'expected {kind.name}', self._current.offset)

    @staticmethod
    def _numeral_ends(tok: JsToken) -> None:
        """
        A numeral the lexer could not end where the grammar ends one — a name or a digit pressed
        against it, a prefix with no digits — is text no engine reads, and is refused here rather
        than turned into a number it does not spell.
        """
        if not tok.terminated:
            raise JsParseError('a numeral the language refuses', tok.offset)

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
        raise JsParseError('expected ;', self._current.offset)

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
        with RecursionDepth(10000):
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
                try:
                    stmt = self._parse_statement()
                except JsParseError as error:
                    stmt = self._unread_token(error)
                if stmt is not None:
                    body.append(stmt)
        return body

    def _closes_the_enclosure(self, tok: JsToken) -> bool:
        """
        Whether *tok* is a closing bracket that closes a bracket the enclosing constructs hold open:
        a closing brace closing any open brace, since braces are the skeleton a file keeps, or a
        closing parenthesis or bracket closing the innermost open bracket. Such a token belongs to
        the enclosure and is never taken into text an inner list keeps.
        """
        if tok.kind not in _CLOSERS:
            return False
        opener = _CLOSERS[tok.kind]
        if tok.kind is JsTokenKind.RBRACE:
            return opener in self._brackets
        return bool(self._brackets) and self._brackets[-1] is opener

    def _unread_token(self, error: JsParseError) -> JsErrorNode:
        """
        The one token standing here, kept as itself: what a list holds where no item could begin.
        A token that closes the enclosure is the enclosure's, and the refusal is handed on to it.
        """
        if self._closes_the_enclosure(self._current):
            raise error
        comments = self._take_comments()
        tok = self._advance()
        node = JsErrorNode(offset=tok.offset, text=tok.value, message=error.message)
        node.leading_comments.extend(comments)
        return node

    @contextmanager
    def _nested(self):
        self._depth += 1
        try:
            if self._depth > _NESTING_LIMIT:
                raise JsParseError('nesting too deep', self._current.offset)
            yield
        finally:
            self._depth -= 1

    def _skip_to_boundary(self, mark: int, base: int, boundary: _Boundary) -> None:
        """
        Step over the rest of the item that could not be read, to where *boundary* says it ends.
        Brackets the item opened are closed on the way, so nothing inside them ends it. A closing
        brace that closes any brace the enclosure holds open ends it and is left for the enclosure,
        since braces are the skeleton a file keeps; a closing parenthesis or bracket does so only
        for the innermost bracket the enclosure holds open, and any other closing bracket closes
        nothing and goes with the item. A line terminator
        ends a line-bound item only behind something the item read, since the one in front of its
        first token separates it from the item before. A slash is read as the regular expression
        it opens wherever an operand did not just end, so that a bracket or a semicolon inside the
        literal is not taken for one outside it.
        """
        while not self._at(JsTokenKind.EOF):
            tok = self._current
            opened = len(self._brackets) > base
            if tok.kind in _CLOSERS:
                opener = _CLOSERS[tok.kind]
                if opened and opener in self._brackets[base:]:
                    self._advance()
                    if (
                        boundary.continued is not None
                        and tok.kind is JsTokenKind.RBRACE
                        and len(self._brackets) == base
                        and self._current.kind not in boundary.continued
                    ):
                        break
                    continue
                if self._closes_the_enclosure(tok):
                    break
                self._advance()
                continue
            if not opened:
                if tok.kind in boundary.stops:
                    break
                if boundary.line_bound and self._preceded_by_newline and self._prev_end > mark:
                    break
                if tok.kind in boundary.consumes:
                    self._advance()
                    break
            if (
                tok.kind in (JsTokenKind.SLASH, JsTokenKind.SLASH_ASSIGN)
                and self._prev.kind not in _DIVISION_FOLLOWS
            ):
                self._rescan_as_regexp()
            self._advance()
        del self._brackets[base:]

    def _unread_item(
        self,
        mark: int,
        base: int,
        error: JsParseError,
        boundary: _Boundary,
    ) -> JsErrorNode:
        """
        The source from *mark* to the boundary of the item that could not be read, kept verbatim. An
        item that consumed nothing is no item, and the refusal is handed back to the list. An item
        ending in a string a line terminator ended takes the terminator with it, since the same
        text at the end of a file spells a string the file ended inside.
        """
        self._skip_to_boundary(mark, base, boundary)
        end = self._prev_end
        if end <= mark:
            raise error
        if self._prev.kind in _STRING_KINDS and not self._prev.terminated and end < len(self._source):
            end += 2 if self._source.startswith('\r\n', end) else 1
        self._pending_comments = [
            tok for tok in self._pending_comments if not mark <= tok.offset < end
        ]
        return JsErrorNode(text=self._source[mark:end], message=error.message, offset=mark)

    def _read_item(
        self,
        reader: Callable[[], _T],
        boundary: _Boundary,
        *,
        carries_comments: bool = False,
    ) -> _T | JsErrorNode:
        """
        One item of a list, read by *reader*, or the text it stands in where the reader refused it.
        Where the list's items carry comments — statements, class elements, switch clauses — the
        comments that led the item lead whatever is built for it, and go back to the list along
        with the refusal where nothing at all was read. An expression carries none: a comment
        inside one is carried by the next statement, as it is anywhere else.
        """
        mark = self._current.offset
        base = len(self._brackets)
        comments = list(self._pending_comments) if carries_comments else []
        if carries_comments:
            self._pending_comments.clear()
        try:
            item = reader()
        except JsParseError as error:
            try:
                item = self._unread_item(mark, base, error, boundary)
            except JsParseError:
                self._pending_comments[:0] = comments
                raise
        item.leading_comments[:0] = [tok.value for tok in comments]
        return item

    @overload
    def _comma_list(
        self,
        closer: JsTokenKind,
        reader: Callable[[], _T],
        *,
        holes: Literal[True],
    ) -> tuple[list[_T | JsErrorNode | None], bool]:
        ...

    @overload
    def _comma_list(
        self,
        closer: JsTokenKind,
        reader: Callable[[], _T],
        *,
        holes: Literal[False] = False,
    ) -> tuple[list[_T | JsErrorNode], bool]:
        ...

    def _comma_list(
        self,
        closer: JsTokenKind,
        reader: Callable[[], _T],
        *,
        holes: bool = False,
    ) -> tuple[list[Any], bool]:
        """
        The items between here and *closer*, separated by commas, and whether a comma stood behind
        the last of them. The closer is consumed, and a file that ends before it is refused: a list
        of expressions the file ends inside is text, and the statement holding it keeps it as such.
        An item the reader refuses is kept as its text up to the next comma or the closer, and
        where no item could begin at all, the token standing there begins the text; a rest element
        may only stand last. With *holes*, a comma standing where an item would is an element that
        was left out.
        """
        items: list[_T | JsErrorNode | None] = []
        trailing_comma = False

        def item_and_separator() -> _T:
            item = reader()
            if isinstance(item, JsRestElement) and not self._at(closer):
                raise JsParseError('a rest element must stand last', self._current.offset)
            if not self._at(closer):
                self._expect(JsTokenKind.COMMA)
            return item

        while not self._at(closer, JsTokenKind.EOF):
            trailing_comma = False
            if holes and self._at(JsTokenKind.COMMA):
                items.append(None)
                self._advance()
                trailing_comma = True
                continue
            mark = self._current.offset
            base = len(self._brackets)
            try:
                items.append(self._read_item(item_and_separator, _COMMA_ITEM))
            except JsParseError as error:
                if self._closes_the_enclosure(self._current):
                    raise
                self._advance()
                items.append(self._unread_item(mark, base, error, _COMMA_ITEM))
            if isinstance(items[-1], JsErrorNode):
                self._eat(JsTokenKind.COMMA)
            trailing_comma = self._prev.kind is JsTokenKind.COMMA
        self._expect(closer)
        return items, trailing_comma

    def _parse_program(self) -> JsScript:
        offset = self._current.offset
        body = self._parse_statement_list(JsTokenKind.EOF)
        script = JsScript(
            body=body,
            offset=offset,
            recovered=self._recovered,
            html_comment=self._lexer.html_comment,
            terminated=self._lexer.open_comment is None,
        )
        if self._hashbang is not None:
            script.leading_comments.append(self._hashbang)
        script.trailing_comments.extend(self._take_comments())
        return script

    def _parse_statement(
        self,
        *,
        single_statement: bool = False,
        annex_b_function: bool = False,
    ) -> Statement | None:
        continued = _BLOCK_STATEMENTS.get(self._current.kind)
        if self._at_async_function():
            continued = frozenset()
        boundary = _STATEMENT if continued is None else _Boundary(
            consumes=_STATEMENT.consumes, line_bound=True, continued=continued)

        def statement() -> Statement:
            with self._nested():
                stmt = self._read_statement(
                    single_statement=single_statement, annex_b_function=annex_b_function)
            if stmt is None:
                raise JsParseError('expected a statement', self._current.offset)
            return stmt

        return self._read_item(statement, boundary, carries_comments=True)

    def _read_statement(
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
            raise JsParseError('decorators must precede a class', self._current.offset)
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
        block = JsBlockStatement(body=body, offset=offset)
        self._close_list(block, JsTokenKind.RBRACE)
        return block

    def _close_list(
        self,
        owner: JsBlockStatement | JsStaticBlock | JsClassBody | JsSwitchStatement,
        closer: JsTokenKind,
    ) -> None:
        """
        Close the list *owner* holds. The comments standing behind its last item are its trailing
        comments, and whether its closing bracket was there is recorded on it, which is the one
        fact a truncated construct carries: where the file ended instead, the comments stay pending
        and end as the file's tail, since the owner may yet be refused along with the item it
        stands in, and the file's end is what carries them then. Anything else standing here is
        refused.
        """
        if self._at(closer):
            owner.trailing_comments.extend(self._take_comments())
            self._advance()
        elif self._at(JsTokenKind.EOF):
            owner.terminated = False
        else:
            raise JsParseError(F'expected {closer.name}', self._current.offset)

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
        if not self._at_identifier_name():
            raise JsParseError('expected a name', offset)
        tok = self._advance()
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

    def _parse_binding_element(self) -> Expression:
        if self._at(JsTokenKind.ELLIPSIS):
            return self._parse_rest_element()
        elem = self._parse_binding_pattern()
        if self._eat(JsTokenKind.EQUALS):
            right = self._parse_assignment_expression()
            elem = JsAssignmentPattern(left=elem, right=right, offset=elem.offset)
        return elem

    def _parse_array_pattern(self) -> JsArrayPattern:
        offset = self._current.offset
        self._expect(JsTokenKind.LBRACKET)
        elements, _ = self._comma_list(JsTokenKind.RBRACKET, self._parse_binding_element, holes=True)
        return JsArrayPattern(elements=elements, offset=offset)

    def _parse_object_pattern(self) -> JsObjectPattern:
        offset = self._current.offset
        self._expect(JsTokenKind.LBRACE)

        def member() -> JsProperty | JsRestElement:
            if self._at(JsTokenKind.ELLIPSIS):
                return self._parse_rest_element()
            return self._parse_object_pattern_property()

        properties, _ = self._comma_list(JsTokenKind.RBRACE, member)
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
        cases: list[JsSwitchCase | JsErrorNode] = []
        while not self._at(JsTokenKind.RBRACE, JsTokenKind.EOF):
            try:
                cases.append(self._read_item(
                    self._parse_switch_case, _SWITCH_CLAUSE, carries_comments=True))
            except JsParseError as error:
                cases.append(self._unread_token(error))
        switch = JsSwitchStatement(discriminant=discriminant, cases=cases, offset=offset)
        self._close_list(switch, JsTokenKind.RBRACE)
        return switch

    def _parse_switch_case(self) -> JsSwitchCase:
        offset = self._current.offset
        test = None
        if self._eat(JsTokenKind.CASE):
            test = self._parse_expression()
            self._expect(JsTokenKind.COLON)
        elif self._eat(JsTokenKind.DEFAULT):
            self._expect(JsTokenKind.COLON)
        else:
            raise JsParseError('expected case or default', self._current.offset)
        body = self._parse_statement_list(
            JsTokenKind.CASE, JsTokenKind.DEFAULT, JsTokenKind.RBRACE, JsTokenKind.EOF,
        )
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
        params, _ = self._comma_list(JsTokenKind.RPAREN, self._parse_binding_element)
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
            raise JsParseError('unexpected token', self._current.offset)
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
            members: list[JsMethodDefinition | JsPropertyDefinition | JsStaticBlock | JsErrorNode] = []
            while not self._at(JsTokenKind.RBRACE, JsTokenKind.EOF):
                if self._eat(JsTokenKind.SEMICOLON):
                    continue
                try:
                    members.append(self._read_item(
                        self._parse_class_element, _CLASS_ELEMENT, carries_comments=True))
                except JsParseError as error:
                    members.append(self._unread_token(error))
            body = JsClassBody(body=members, offset=offset)
            self._close_list(body, JsTokenKind.RBRACE)
            return body

    def _parse_class_element(self) -> JsMethodDefinition | JsPropertyDefinition | JsStaticBlock:
        decorators = self._parse_decorators()
        member = self._parse_class_member()
        if decorators and isinstance(member, (JsMethodDefinition, JsPropertyDefinition)):
            member.decorators = decorators
            member._adopt(*decorators)
        return member

    def _parse_static_block(self, offset: int) -> JsStaticBlock:
        with self._code_context(class_element_context(static=True)):
            self._expect(JsTokenKind.LBRACE)
            body = self._parse_statement_list(JsTokenKind.RBRACE, JsTokenKind.EOF)
            static = JsStaticBlock(body=body, offset=offset)
            self._close_list(static, JsTokenKind.RBRACE)
        return static

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
        raise JsParseError('unexpected token', offset)

    def _parse_import_attributes(self) -> tuple[str, list[JsImportAttribute | JsErrorNode]]:
        if self._preceded_by_newline:
            return '', []
        if self._at(JsTokenKind.WITH):
            keyword = 'with'
        elif self._at(JsTokenKind.IDENTIFIER) and self._current.value == 'assert':
            keyword = 'assert'
        else:
            return '', []
        self._advance()
        self._expect(JsTokenKind.LBRACE)

        def attribute() -> JsImportAttribute:
            key = self._parse_property_name()
            self._expect(JsTokenKind.COLON)
            value = self._parse_string_literal()
            return JsImportAttribute(key=key, value=value, offset=key.offset)

        attributes, _ = self._comma_list(JsTokenKind.RBRACE, attribute)
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
            JsImportSpecifier | JsImportDefaultSpecifier | JsImportNamespaceSpecifier | JsErrorNode
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
                    raise JsParseError('expected an import specifier', self._current.offset)

        elif self._at(JsTokenKind.STAR):
            specifiers.append(self._parse_namespace_import())

        elif self._at(JsTokenKind.LBRACE):
            specifiers.extend(self._parse_named_imports())

        self._expect_contextual('from')
        source = self._module_specifier()
        if source is None:
            raise JsParseError('a module declaration with no specifier', self._current.offset)
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
            raise JsParseError('expected a module export name', self._current.offset)
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

    def _parse_named_imports(self) -> list[JsImportSpecifier | JsErrorNode]:
        self._expect(JsTokenKind.LBRACE)

        def specifier() -> JsImportSpecifier:
            spec_offset = self._current.offset
            imported = self._parse_module_export_name()
            local = imported
            if self._at(JsTokenKind.AS):
                self._advance()
                local = self._parse_binding_identifier()
            elif isinstance(imported, JsStringLiteral):
                self._recovered = True
            return JsImportSpecifier(imported=imported, local=local, offset=spec_offset)

        specs, _ = self._comma_list(JsTokenKind.RBRACE, specifier)
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
                raise JsParseError('a module declaration with no specifier', self._current.offset)
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

        raise JsParseError('expected an export', self._current.offset)

    def _parse_export_named(self, offset: int) -> JsExportNamedDeclaration | JsErrorNode:
        self._expect(JsTokenKind.LBRACE)

        def specifier() -> JsExportSpecifier:
            spec_offset = self._current.offset
            local = self._parse_module_export_name()
            exported = local
            if self._at(JsTokenKind.AS):
                self._advance()
                exported = self._parse_module_export_name()
            return JsExportSpecifier(local=local, exported=exported, offset=spec_offset)

        specifiers, _ = self._comma_list(JsTokenKind.RBRACE, specifier)
        source = None
        keyword, attributes = '', []
        if self._at(JsTokenKind.FROM):
            self._advance()
            source = self._module_specifier()
            if source is None:
                raise JsParseError('a module declaration with no specifier', self._current.offset)
            keyword, attributes = self._parse_import_attributes()
        if source is None and any(
            isinstance(specifier, JsExportSpecifier) and isinstance(specifier.local, JsStringLiteral)
            for specifier in specifiers
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
        raise JsParseError(F'expected {keyword}', self._current.offset)

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
        with self._nested():
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
                raise JsParseError('expected :', self._current.offset)
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
            self._no_arrow_operand(right)
            node_type = JsLogicalExpression if logical else JsBinaryExpression
            left = node_type(
                left=left, operator=op, right=right, offset=left.offset)
        return left

    @staticmethod
    def _no_arrow_operand(operand: Expression) -> None:
        """
        An arrow function is an AssignmentExpression and nothing smaller (§15.3), so it may not
        stand as the operand of a unary or binary operator: `a / b => c` is a file every engine
        refuses, and reading it as `a / (b => c)` would write the brackets that turn it into one.
        """
        if isinstance(operand, JsArrowFunctionExpression):
            raise JsParseError('an arrow function as an operand', operand.offset)

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
            self._no_arrow_operand(operand)
            return JsUnaryExpression(
                operator=tok.value, operand=operand, prefix=True, offset=tok.offset)
        if self._at(JsTokenKind.PLUS):
            tok = self._advance()
            operand = self._parse_unary_expression()
            self._no_arrow_operand(operand)
            return JsUnaryExpression(
                operator='+', operand=operand, prefix=True, offset=tok.offset)
        if self._at(JsTokenKind.MINUS):
            tok = self._advance()
            operand = self._parse_unary_expression()
            self._no_arrow_operand(operand)
            return JsUnaryExpression(
                operator='-', operand=operand, prefix=True, offset=tok.offset)
        if self._at(JsTokenKind.AWAIT) and self._context.await_reading is AwaitReading.OPERATOR:
            tok = self._advance()
            operand = self._parse_unary_expression()
            self._no_arrow_operand(operand)
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
        tok = self._current
        if tok.kind is JsTokenKind.PRIVATE_IDENTIFIER:
            self._advance()
            return self._private_identifier(tok, tok.offset)
        if tok.kind is JsTokenKind.IDENTIFIER or tok.kind.is_keyword:
            self._advance()
            return self._name_or_error(tok.value, tok.offset, may_be_reserved=True)
        raise JsParseError('expected a property name', tok.offset)

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
        with self._with_no_in(False):
            args, _ = self._comma_list(JsTokenKind.RPAREN, self._parse_element_expression)
        return args

    def _parse_element_expression(self) -> Expression:
        """
        One element of an argument list or an array literal: an assignment expression, or the
        spread of one.
        """
        if self._at(JsTokenKind.ELLIPSIS):
            offset = self._current.offset
            self._advance()
            return JsSpreadElement(argument=self._parse_assignment_expression(), offset=offset)
        return self._parse_assignment_expression()

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
            self._numeral_ends(tok)
            self._advance()
            raw = tok.value
            value = self._parse_int_text(raw.replace('_', ''))
            return JsNumericLiteral(value=value, raw=raw, offset=offset)

        if self._at(JsTokenKind.FLOAT):
            self._numeral_ends(tok)
            self._advance()
            raw = tok.value
            value = float(raw.replace('_', ''))
            return JsNumericLiteral(value=value, raw=raw, offset=offset)

        if self._at(JsTokenKind.BIGINT):
            self._numeral_ends(tok)
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

        raise JsParseError('unexpected token', offset)

    def _parse_string_literal(self) -> JsStringLiteral:
        """
        The string literal standing here. One the file ended inside is kept, unterminated, since
        the text it holds is all the file has; one a line terminator ended is text no engine reads
        and no literal spells, and is refused, so that the statement holding it is kept as written.
        """
        tok = self._current
        if not tok.terminated and tok.offset + len(tok.value) < len(self._source):
            raise JsParseError('a string literal the line ends inside', tok.offset)
        self._advance()
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

        def hole() -> Expression:
            expression = self._parse_expression()
            if not self._at(JsTokenKind.TEMPLATE_MIDDLE, JsTokenKind.TEMPLATE_TAIL, JsTokenKind.EOF):
                raise JsParseError('expected the template to resume', self._current.offset)
            return expression

        while True:
            with self._with_no_in(False):
                try:
                    expressions.append(self._read_item(hole, _TEMPLATE_HOLE))
                except JsParseError as error:
                    if not self._at(JsTokenKind.TEMPLATE_MIDDLE, JsTokenKind.TEMPLATE_TAIL):
                        raise
                    expressions.append(JsErrorNode(
                        text='', message=error.message, offset=self._current.offset))
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
                    opened=False,
                    offset=self._current.offset,
                ))
                break

        return JsTemplateLiteral(
            quasis=quasis, expressions=expressions, offset=offset)

    def _parse_array_literal(self) -> JsArrayExpression:
        with self._with_no_in(False):
            offset = self._current.offset
            self._expect(JsTokenKind.LBRACKET)
            elements, _ = self._comma_list(
                JsTokenKind.RBRACKET, self._parse_element_expression, holes=True)
        return JsArrayExpression(elements=elements, offset=offset)

    def _parse_object_literal(self) -> JsObjectExpression:
        with self._with_no_in(False):
            offset = self._current.offset
            self._expect(JsTokenKind.LBRACE)

            def member() -> JsProperty | JsSpreadElement:
                if self._at(JsTokenKind.ELLIPSIS):
                    so = self._current.offset
                    self._advance()
                    return JsSpreadElement(argument=self._parse_assignment_expression(), offset=so)
                return self._parse_object_property()

            properties, _ = self._comma_list(JsTokenKind.RBRACE, member)
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
            self._numeral_ends(tok)
            self._advance()
            raw = tok.value
            text = raw.replace('_', '')
            return JsNumericLiteral(
                value=float(text) if tok.kind == JsTokenKind.FLOAT else self._parse_int_text(text),
                raw=raw,
                offset=tok.offset,
            )
        if self._at(JsTokenKind.BIGINT):
            self._numeral_ends(tok)
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
            raise JsParseError('expected a property name', tok.offset)
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

            def item() -> Expression:
                if self._at(JsTokenKind.ELLIPSIS):
                    return self._parse_rest_element()
                return self._parse_assignment_expression()

            items, trailing_comma = self._comma_list(JsTokenKind.RPAREN, item)
            head_only = (
                not items
                or trailing_comma
                or isinstance(items[-1], JsRestElement)
            )

            if self._at(JsTokenKind.ARROW) and not self._preceded_by_newline:
                self._advance()
                body = self._parse_arrow_body(is_async)
            elif head_only:
                raise JsParseError('a parameter list with no arrow behind it', self._current.offset)
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
            props: list[JsProperty | JsRestElement | JsErrorNode] = []
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
