"""
Recursive-descent parser for AutoIt3, based on the official operator table
(autoitscript.com/autoit3/docs/intro/lang_operators.htm) and the PEG.js grammar for AutoIt
3.3.14.5 (`autoit3-pegjs`). Where the two disagree the docs win: `And`/`Or` share one
left-to-right level and the ternary sits between the comparisons and `And`/`Or`, while the
grammar splits `And` from `Or` and puts the ternary loosest; and the grammar's right-recursive
binary rules are rejected with it, since the docs state that all binary operators are evaluated
left to right.

Assignment is a statement, not an expression: in statement position one postfix expression is
parsed first, and when an assignment operator follows it and the postfix is an lvalue, the
statement is an assignment whose right side is a plain expression (`$x = $y = 1` assigns the
result of the comparison `$y = 1`). Otherwise the postfix resumes the binary ladder through
`_parse_binary_from`, so `If $x = 1 Then` compares.

AutoIt is line-oriented, so NEWLINE tokens are structural: the statement list terminates each
statement itself and attaches comments along the way. A comment always ends its line, so the
tokenizer can tell a comment trailing the statement being parsed from one standing on a line of
its own; the former become `trailing_comments` and the latter the `leading_comments` of whatever
statement follows.

On any statement the parser cannot read, it resynchronizes just past the next NEWLINE and
re-reads the statement's source text verbatim into an `Au3ErrorNode`, so malformed input still
yields a tree that covers every character of the file and can be scored by `guess_language`.
Missing tokens are synthesized with `_expect`, which records the error without abandoning the
statement — except on a single line: a statement there that needed such a repair, or that is
followed by more text on its line, is abandoned and its whole line recovered verbatim, because
the interpreter rejects the line when it reaches it, so a repaired reading would be code that
never runs as written. Only multi-line blocks keep their repairs, and a construct that opens one
is multi-line whether or not the file ended before its closer. A line holding a block closer or
divider keeps the repaired reading, since recovering it whole would swallow the boundary and
move every statement after it into the wrong block — a closer or divider a member access names
after its dot is no boundary. Stray block terminators become one-token error statements rather
than consuming the rest of their line.

The single-line form of `If` parses to the same tree as the block form (`body` holds one
statement), so the synthesizer can always print block form. A leading-dot member access builds
an `Au3WithMember` only while a `With` statement is being parsed; `.x` outside one is not an
expression, and the recovery pass keeps its text.
"""
from __future__ import annotations

import re

from refinery.lib.scripts import Expression, Statement
from refinery.lib.scripts.au3.lexer import Au3Lexer, decode_au3_string
from refinery.lib.scripts.au3.model import (
    Au3ArrayAccess,
    Au3ArrayLiteral,
    Au3Assignment,
    Au3BinaryExpression,
    Au3BooleanLiteral,
    Au3Call,
    Au3CaseRange,
    Au3ContinueCaseStatement,
    Au3ContinueLoopStatement,
    Au3DefaultLiteral,
    Au3Directive,
    Au3DoUntilStatement,
    Au3ElseIf,
    Au3EnumDeclaration,
    Au3EnumDeclarator,
    Au3ErrorNode,
    Au3ExpressionStatement,
    Au3ExitLoopStatement,
    Au3ExitStatement,
    Au3FloatLiteral,
    Au3ForInStatement,
    Au3ForStatement,
    Au3FunctionDeclaration,
    Au3Identifier,
    Au3IfStatement,
    Au3Include,
    Au3IncludeOnce,
    Au3IntLiteral,
    Au3Macro,
    Au3MemberAccess,
    Au3NullLiteral,
    Au3Parameter,
    Au3ParenExpression,
    Au3ReDimStatement,
    Au3ReDimTarget,
    Au3ReturnStatement,
    Au3Script,
    Au3ScopeKind,
    Au3SelectCase,
    Au3SelectStatement,
    Au3StringLiteral,
    Au3SwitchCase,
    Au3SwitchStatement,
    Au3Ternary,
    Au3UnaryExpression,
    Au3Variable,
    Au3VariableDeclaration,
    Au3VariableDeclarator,
    Au3WhileStatement,
    Au3WithMember,
    Au3WithStatement,
)
from refinery.lib.scripts.au3.token import Au3Token, KEYWORD_SPELLINGS
from refinery.lib.scripts.au3.token import Au3TokenKind as K

#: The precedence of `?` on the scale of `_CLIMB_PRECEDENCE`. The ternary is handled inside the
#: climbing loop rather than through the table because its two operands are parsed at the level
#: below `And`/`Or`, which a table entry cannot express.
_TERNARY_PRECEDENCE = 4

#: The level of the whole expression: `And`/`Or`, the loosest operators.
_EXPRESSION_PRECEDENCE = 2

#: The level just above the ternary, at which its operands are parsed.
_TERNARY_OPERAND_PRECEDENCE = 5

_CLIMB_PRECEDENCE: dict[K, int] = {
    K.OR             : 2,   # noqa
    K.AND            : 2,   # noqa
    K.ASSIGN_OR_EQ   : 6,   # noqa
    K.EQ_STRICT      : 6,   # noqa
    K.NE             : 6,   # noqa
    K.LE             : 6,   # noqa
    K.GE             : 6,   # noqa
    K.LT             : 6,   # noqa
    K.GT             : 6,   # noqa
    K.AMP            : 8,   # noqa
    K.PLUS           : 10,  # noqa
    K.MINUS          : 10,  # noqa
    K.STAR           : 12,  # noqa
    K.SLASH          : 12,  # noqa
    K.CARET          : 14,  # noqa
}

_BINARY_OPERATORS: dict[K, str] = {
    K.OR             : 'or',  # noqa
    K.AND            : 'and',  # noqa
    K.ASSIGN_OR_EQ   : '=',   # noqa
    K.EQ_STRICT      : '==',  # noqa
    K.NE             : '<>',  # noqa
    K.LE             : '<=',  # noqa
    K.GE             : '>=',  # noqa
    K.LT             : '<',   # noqa
    K.GT             : '>',   # noqa
    K.AMP            : '&',   # noqa
    K.PLUS           : '+',   # noqa
    K.MINUS          : '-',   # noqa
    K.STAR           : '*',   # noqa
    K.SLASH          : '/',   # noqa
    K.CARET          : '^',   # noqa
}

_ASSIGN_OPS: dict[K, str] = {
    K.ASSIGN_OR_EQ   : '=',   # noqa
    K.PLUS_ASSIGN    : '+=',  # noqa
    K.MINUS_ASSIGN   : '-=',  # noqa
    K.MUL_ASSIGN     : '*=',  # noqa
    K.DIV_ASSIGN     : '/=',  # noqa
    K.CONCAT_ASSIGN  : '&=',  # noqa
}

_SCOPE_KINDS: dict[K, Au3ScopeKind] = {
    K.DIM   : Au3ScopeKind.DIM,    # noqa
    K.LOCAL : Au3ScopeKind.LOCAL,  # noqa
    K.GLOBAL: Au3ScopeKind.GLOBAL, # noqa
}

_DECLARATION_STARTERS = frozenset({K.DIM, K.LOCAL, K.GLOBAL, K.CONST, K.STATIC, K.ENUM})

#: The keyword kinds that open a multi-line block. Public: the unread-text reader derives its
#: block-keyword universe from this set and the terminator set below.
BLOCK_OPENERS = frozenset({K.IF, K.WHILE, K.DO, K.FOR, K.SELECT, K.SWITCH, K.WITH, K.FUNC})

#: The keywords that close or divide the construct a statement list belongs to. A stray one is a
#: one-token error statement; a legitimate one never reaches statement dispatch because the list
#: it closes stops at it first.
STRAY_TERMINATORS = frozenset({
    K.ELSE,
    K.ELSEIF,
    K.ENDIF,
    K.WEND,
    K.UNTIL,
    K.NEXT,
    K.CASE,
    K.ENDSELECT,
    K.ENDSWITCH,
    K.ENDWITH,
    K.ENDFUNC,
})

#: The statements a block opener parses to: constructs whose closer stands on a line of its own,
#: read or synthesized, so no repair they hold is a single-line reading — the `If` is absent,
#: because its single-line form is the one construct whose closer is optional.
_BLOCK_CONSTRUCTS = (
    Au3DoUntilStatement,
    Au3ForInStatement,
    Au3ForStatement,
    Au3FunctionDeclaration,
    Au3SelectStatement,
    Au3SwitchStatement,
    Au3WhileStatement,
    Au3WithStatement,
)

#: The tokens that can end a statement whose optional operand is being decided: the line, the
#: file, or the boundary of the construct the statement sits in.
_BOUNDARY_KINDS = STRAY_TERMINATORS | {K.NEWLINE, K.EOF}

_INCLUDE_ONCE = re.compile(r'\s*#\s*include-once\s*$', re.IGNORECASE)
_INCLUDE = re.compile(r'\s*#\s*include\s*([<"])([^<>"\r\n]*)[>"]\s*$', re.IGNORECASE)


class Au3ParseError(Exception):
    """
    Raised to abandon a statement the parser cannot read. The recovery pass then re-reads the
    statement's source text verbatim into an `Au3ErrorNode`, which keeps every character of the
    file accounted for.
    """


def _parse_int_value(raw: str) -> int:
    """
    The value of an integer literal the way AutoIt reads it: a hexadecimal literal is
    sign-extended from 32 bits at up to eight digits and from 64 bits at nine to sixteen, so
    `0x80000000` is -2147483648 while `0x080000000` is 2147483648.
    """
    if raw[:2].lower() == '0x':
        value = int(raw[2:], 16)
        if len(raw) - 2 <= 8:
            if value >= 0x80000000:
                value -= 0x100000000
        elif value >= 0x8000000000000000:
            value -= 0x10000000000000000
        return value
    return int(raw)


class Au3Parser:
    """
    Parser for AutoIt3 source text. The input is tokenized up front so that the modifier lists
    of declarations, `Volatile Func`, and `For ... In` need only bounded lookahead. Comments are
    diverted into side tables while the token list is built, since a comment always ends its
    line: one after statement text is a trailing comment of that statement, one on a line of its
    own is a leading comment of the next.
    """

    def __init__(self, source: str):
        self._source = source
        self._tokens: list[Au3Token] = []
        self._trivia: dict[int, list[str]] = {}
        self._trailing: dict[int, list[str]] = {}
        self._index = 0
        self._errors: list[Au3ErrorNode] = []
        self._with_depth = 0
        self._materialize()

    def _materialize(self):
        pending: list[str] = []
        at_line_start = True
        for tok in Au3Lexer(source=self._source).tokenize():
            if tok.kind is K.COMMENT:
                pending.append(tok.value)
                continue
            if tok.kind is K.NEWLINE:
                if pending and at_line_start:
                    # The break follows a comment standing on a line of its own, so it ends no
                    # statement: leaving it out keeps a comment line invisible to the token
                    # stream the way a blank line already is, and the comment travels as trivia
                    # to whatever token follows it.
                    pass
                else:
                    self._tokens.append(tok)
                    if pending:
                        self._trailing[len(self._tokens) - 1] = pending
                        pending = []
                at_line_start = True
                continue
            if pending:
                self._trivia[len(self._tokens)] = pending
                pending = []
            self._tokens.append(tok)
            at_line_start = False
            if tok.kind is K.EOF:
                break
        if not self._tokens or self._tokens[-1].kind is not K.EOF:
            self._tokens.append(Au3Token(K.EOF, '', len(self._source)))

    @property
    def _current(self) -> Au3Token:
        return self._tokens[self._index]

    def _peek(self, ahead: int = 0) -> Au3Token:
        i = self._index + ahead
        if i >= len(self._tokens):
            return self._tokens[-1]
        return self._tokens[i]

    def _at(self, *kinds: K) -> bool:
        return self._current.kind in kinds

    def _advance(self) -> Au3Token:
        tok = self._tokens[self._index]
        if self._index < len(self._tokens) - 1:
            self._index += 1
        return tok

    def _eat(self, kind: K) -> Au3Token | None:
        if self._current.kind is kind:
            return self._advance()
        return None

    def _expect(self, kind: K) -> Au3Token:
        if self._current.kind is kind:
            return self._advance()
        tok = self._current
        spelling = KEYWORD_SPELLINGS.get(kind, kind.value)
        self._error(tok, F'expected {spelling}')
        return Au3Token(kind, tok.value, tok.offset)

    def _error(self, tok: Au3Token, message: str) -> Au3ErrorNode:
        node = Au3ErrorNode(text=tok.value, message=message, offset=tok.offset)
        self._errors.append(node)
        return node

    def parse(self) -> Au3Script:
        body, comments = self._parse_statement_list()
        script = Au3Script(body=body, errors=self._errors, offset=0)
        script.trailing_comments.extend(comments)
        return script

    def parse_expression(self) -> Expression | None:
        """
        One expression spanning the whole input, or `None` when the input holds anything else: a
        statement, a declaration, two expressions, a truncated one. This is the entry the
        `Execute` flattening reads its argument through, because the interpreter evaluates
        exactly one expression there — where `=` climbs as a comparison, never an assignment.
        """
        try:
            expression = self._parse_expression()
        except Exception:
            return None
        while self._at(K.NEWLINE):
            self._advance()
        if not self._at(K.EOF) or self._errors:
            return None
        return expression

    def _parse_statement_list(self, *stop: K) -> tuple[list[Statement], list[str]]:
        """
        Read statements until one of *stop* appears. The second return value holds the comments
        that stood between the last statement and the stop token: with no statement left to carry
        them, the construct the list belongs to holds them instead.
        """
        body: list[Statement] = []
        while True:
            while self._at(K.NEWLINE):
                self._advance()
            if self._at(K.EOF) or self._at(*stop):
                break
            comments = self._trivia.pop(self._index, None)
            start = self._current.offset
            mark = self._index
            recorded = len(self._errors)
            try:
                stmt = self._parse_statement()
                abandoned = self._statement_is_abandoned(stmt, mark, recorded)
            except RecursionError:
                raise
            except Exception:
                abandoned = True
            if abandoned:
                del self._errors[recorded:]
                error = self._recover_statement(start, mark)
                if comments:
                    error.leading_comments[:0] = comments
                body.append(error)
                continue
            self._terminate_statement(stmt)
            if comments:
                stmt.leading_comments[:0] = comments
            body.append(stmt)
        trailing = self._trivia.pop(self._index, None) or []
        if trailing and body:
            body[-1].trailing_comments.extend(trailing)
            trailing = []
        return body, trailing

    def _statement_is_abandoned(self, stmt: Statement, mark: int, recorded: int) -> bool:
        """
        Whether *stmt* leaves the tree for the verbatim text of its whole line: it spans a single
        line — no line break between its first token and the parser's position after it — and
        either a token it needed was synthesized while it was read or more text follows it on its
        line, so the interpreter rejects the line when it reaches it and a repaired reading would
        be code that never runs as written. A construct that opens a multi-line block is never
        abandoned — its closer stands on a line of its own, read or synthesized — and an `If` with
        no body is that construct's header, which the file ended before it closed. A stray closer
        or divider is itself such a statement, and a line that holds one keeps the repaired
        reading instead: recovering it whole would swallow the boundary and move every statement
        after it into the wrong block. A closer or divider a member access names after its dot is
        not a boundary.
        """
        if isinstance(stmt, Au3ErrorNode):
            return False
        if isinstance(stmt, _BLOCK_CONSTRUCTS):
            return False
        if isinstance(stmt, Au3IfStatement) and not stmt.body:
            return False
        if len(self._errors) == recorded and self._at(K.NEWLINE, K.EOF):
            return False
        if any(tok.kind is K.NEWLINE for tok in self._tokens[mark:self._index]):
            return False
        index = mark
        previous: K | None = None
        while True:
            kind = self._tokens[index].kind
            if kind in (K.NEWLINE, K.EOF):
                return True
            if kind in STRAY_TERMINATORS and previous is not K.DOT:
                return False
            previous = kind
            index += 1

    def _terminate_statement(self, stmt: Statement):
        if self._at(K.NEWLINE):
            index = self._index
            self._advance()
            trailing = self._trailing.pop(index, None)
            if trailing:
                stmt.trailing_comments.extend(trailing)
        elif not self._at(K.EOF):
            self._error(self._current, 'expected end of statement')

    def _recover_statement(self, start: int, mark: int) -> Au3ErrorNode:
        self._index = mark
        while not self._at(K.NEWLINE, K.EOF):
            self._advance()
        last = self._tokens[self._index - 1]
        end = last.offset + len(last.value)
        if self._at(K.NEWLINE):
            index = self._index
            self._advance()
            trailing = self._trailing.pop(index, None)
        else:
            trailing = None
        # The slice stops at the last token on the line: what stands between it and the line
        # break is whitespace and any trailing comment, which the node carries separately, and
        # the synthesizer ends every statement line with exactly one break, so excluding the
        # break itself lets printing the node and reading the print back yield the same slice.
        text = self._source[start:end]
        node = Au3ErrorNode(text=text, message='statement could not be parsed', offset=start)
        if trailing:
            node.trailing_comments.extend(trailing)
        self._errors.append(node)
        return node

    def _parse_statement(self) -> Statement:
        kind = self._current.kind
        if kind is K.DIRECTIVE:
            return self._parse_directive()
        if kind in STRAY_TERMINATORS:
            tok = self._advance()
            return self._error(tok, F'unexpected {tok.value}')
        if kind is K.IF:
            return self._parse_if()
        if kind is K.WHILE:
            return self._parse_while()
        if kind is K.DO:
            return self._parse_do_until()
        if kind is K.FOR:
            return self._parse_for()
        if kind is K.SELECT:
            return self._parse_select()
        if kind is K.SWITCH:
            return self._parse_switch()
        if kind is K.WITH:
            return self._parse_with()
        if kind in _DECLARATION_STARTERS:
            return self._parse_declaration()
        if kind is K.REDIM:
            return self._parse_redim()
        if kind is K.FUNC:
            return self._parse_function()
        if kind is K.VOLATILE and self._peek(1).kind is K.FUNC:
            return self._parse_function(is_volatile=True)
        if kind is K.RETURN:
            return self._parse_return()
        if kind is K.EXIT:
            return self._parse_exit()
        if kind is K.EXITLOOP:
            return self._parse_exit_loop()
        if kind is K.CONTINUELOOP:
            return self._parse_continue_loop()
        if kind is K.CONTINUECASE:
            tok = self._advance()
            return Au3ContinueCaseStatement(offset=tok.offset)
        return self._parse_expression_statement()

    def _parse_directive(self) -> Statement:
        tok = self._advance()
        text = tok.value
        if _INCLUDE_ONCE.match(text):
            return Au3IncludeOnce(offset=tok.offset)
        match = _INCLUDE.match(text)
        if match is not None:
            quote, path = match.groups()
            return Au3Include(library=quote == '<', path=path, offset=tok.offset)
        return Au3Directive(text=text, offset=tok.offset)

    def _parse_if(self) -> Au3IfStatement:
        offset = self._current.offset
        self._expect(K.IF)
        test = self._parse_expression()
        self._expect(K.THEN)
        if self._at(K.NEWLINE, K.EOF):
            comments = self._expect_eol()
            body, orphaned = self._parse_statement_list(K.ELSEIF, K.ELSE, K.ENDIF)
            elseifs: list[Au3ElseIf] = []
            while self._at(K.ELSEIF):
                elseifs.append(self._parse_elseif())
            else_body = None
            if self._eat(K.ELSE):
                comments.extend(self._expect_eol())
                else_body, else_orphaned = self._parse_statement_list(K.ENDIF)
                orphaned.extend(else_orphaned)
            self._expect(K.ENDIF)
            node = Au3IfStatement(
                test=test, body=body, elseifs=elseifs, else_body=else_body, offset=offset)
            node.trailing_comments.extend([*comments, *orphaned])
            return node
        stmt = self._parse_inline_statement()
        return Au3IfStatement(test=test, body=[stmt], elseifs=[], else_body=None, offset=offset)

    def _parse_elseif(self) -> Au3ElseIf:
        offset = self._current.offset
        self._expect(K.ELSEIF)
        test = self._parse_expression()
        self._expect(K.THEN)
        comments = self._expect_eol()
        body, orphaned = self._parse_statement_list(K.ELSEIF, K.ELSE, K.ENDIF)
        node = Au3ElseIf(test=test, body=body, offset=offset)
        node.trailing_comments.extend([*comments, *orphaned])
        return node

    def _parse_inline_statement(self) -> Statement:
        if self._at(*BLOCK_OPENERS):
            raise Au3ParseError('a single-line If consequent cannot open a block')
        return self._parse_statement()

    def _parse_while(self) -> Au3WhileStatement:
        offset = self._current.offset
        self._expect(K.WHILE)
        test = self._parse_expression()
        comments = self._expect_eol()
        body, orphaned = self._parse_statement_list(K.WEND)
        self._expect(K.WEND)
        node = Au3WhileStatement(test=test, body=body, offset=offset)
        node.trailing_comments.extend([*comments, *orphaned])
        return node

    def _parse_do_until(self) -> Au3DoUntilStatement:
        offset = self._current.offset
        self._expect(K.DO)
        comments = self._expect_eol()
        body, orphaned = self._parse_statement_list(K.UNTIL)
        self._expect(K.UNTIL)
        test = self._parse_expression()
        node = Au3DoUntilStatement(body=body, test=test, offset=offset)
        node.trailing_comments.extend([*comments, *orphaned])
        return node

    def _parse_for(self) -> Statement:
        offset = self._current.offset
        self._expect(K.FOR)
        variable = self._parse_variable()
        if self._eat(K.IN):
            iterable = self._parse_expression()
            comments = self._expect_eol()
            body, orphaned = self._parse_statement_list(K.NEXT)
            self._expect(K.NEXT)
            node = Au3ForInStatement(
                variable=variable, iterable=iterable, body=body, offset=offset)
            node.trailing_comments.extend([*comments, *orphaned])
            return node
        self._expect(K.ASSIGN_OR_EQ)
        start = self._parse_expression()
        self._expect(K.TO)
        limit = self._parse_expression()
        step = None
        if self._eat(K.STEP):
            step = self._parse_expression()
        comments = self._expect_eol()
        body, orphaned = self._parse_statement_list(K.NEXT)
        self._expect(K.NEXT)
        node = Au3ForStatement(
            variable=variable, start=start, limit=limit, step=step, body=body, offset=offset)
        node.trailing_comments.extend([*comments, *orphaned])
        return node

    def _parse_select(self) -> Au3SelectStatement:
        offset = self._current.offset
        self._expect(K.SELECT)
        comments = self._expect_eol()
        pending = self._trivia.pop(self._index, None) or []
        cases: list[Au3SelectCase] = []
        if self._at(K.CASE):
            first = self._parse_select_case()
            first.leading_comments.extend(pending)
            cases.append(first)
            while self._at(K.CASE):
                cases.append(self._parse_select_case())
        self._expect(K.ENDSELECT)
        node = Au3SelectStatement(cases=cases, offset=offset)
        if not cases:
            pending.extend(comments)
            comments = pending
        node.trailing_comments.extend(comments)
        return node

    def _parse_select_case(self) -> Au3SelectCase:
        offset = self._current.offset
        self._expect(K.CASE)
        test = None
        if not self._eat(K.ELSE):
            test = self._parse_expression()
        comments = self._expect_eol()
        body, orphaned = self._parse_statement_list(K.CASE, K.ENDSELECT)
        node = Au3SelectCase(test=test, body=body, offset=offset)
        node.trailing_comments.extend([*comments, *orphaned])
        return node

    def _parse_switch(self) -> Au3SwitchStatement:
        offset = self._current.offset
        self._expect(K.SWITCH)
        discriminant = self._parse_expression()
        comments = self._expect_eol()
        pending = self._trivia.pop(self._index, None) or []
        cases: list[Au3SwitchCase] = []
        if self._at(K.CASE):
            first = self._parse_switch_case()
            first.leading_comments.extend(pending)
            cases.append(first)
            while self._at(K.CASE):
                cases.append(self._parse_switch_case())
        self._expect(K.ENDSWITCH)
        node = Au3SwitchStatement(discriminant=discriminant, cases=cases, offset=offset)
        if not cases:
            pending.extend(comments)
            comments = pending
        node.trailing_comments.extend(comments)
        return node

    def _parse_switch_case(self) -> Au3SwitchCase:
        offset = self._current.offset
        self._expect(K.CASE)
        values: list | None
        if self._eat(K.ELSE):
            values = None
        else:
            values = [self._parse_switch_value()]
            while self._eat(K.COMMA):
                values.append(self._parse_switch_value())
        comments = self._expect_eol()
        body, orphaned = self._parse_statement_list(K.CASE, K.ENDSWITCH)
        node = Au3SwitchCase(values=values, body=body, offset=offset)
        node.trailing_comments.extend([*comments, *orphaned])
        return node

    def _parse_switch_value(self):
        start = self._parse_expression()
        if self._eat(K.TO):
            end = self._parse_expression()
            return Au3CaseRange(start=start, end=end, offset=start.offset)
        return start

    def _parse_with(self) -> Au3WithStatement:
        offset = self._current.offset
        self._expect(K.WITH)
        obj = self._parse_expression()
        comments = self._expect_eol()
        self._with_depth += 1
        try:
            body, orphaned = self._parse_statement_list(K.ENDWITH)
        finally:
            self._with_depth -= 1
        self._expect(K.ENDWITH)
        node = Au3WithStatement(object=obj, body=body, offset=offset)
        node.trailing_comments.extend([*comments, *orphaned])
        return node

    def _parse_declaration(self) -> Statement:
        offset = self._current.offset
        scope = None
        is_const = False
        is_static = False
        while self._at(K.DIM, K.LOCAL, K.GLOBAL, K.CONST, K.STATIC):
            kind = self._advance().kind
            if kind in _SCOPE_KINDS:
                scope = _SCOPE_KINDS[kind]
            elif kind is K.CONST:
                is_const = True
            else:
                is_static = True
        if self._at(K.ENUM):
            return self._parse_enum(offset, scope, is_const)
        if not self._at(K.VARIABLE):
            raise Au3ParseError('expected a variable after the declaration keywords')
        declarations = [self._parse_declarator()]
        while self._eat(K.COMMA):
            declarations.append(self._parse_declarator())
        return Au3VariableDeclaration(
            declarations=declarations,
            scope=scope,
            is_const=is_const,
            is_static=is_static,
            offset=offset,
        )

    def _parse_declarator(self) -> Au3VariableDeclarator:
        variable = self._parse_variable()
        dimensions: list[Expression | None] = []
        while self._eat(K.LBRACKET):
            dimension = None
            if not self._at(K.RBRACKET):
                dimension = self._parse_expression()
            self._expect(K.RBRACKET)
            dimensions.append(dimension)
        initializer = None
        if self._at(K.ASSIGN_OR_EQ):
            self._advance()
            initializer = self._parse_expression()
        return Au3VariableDeclarator(
            variable=variable,
            dimensions=dimensions,
            initializer=initializer,
            offset=variable.offset,
        )

    def _parse_enum(
        self, offset: int, scope: Au3ScopeKind | None, is_const: bool,
    ) -> Au3EnumDeclaration:
        self._expect(K.ENUM)
        step_operator = '+'
        step_value = 1
        if self._eat(K.STEP):
            if self._at(K.PLUS, K.MINUS, K.STAR):
                step_operator = self._advance().value
            step_value = int(self._expect(K.INTEGER).value)
        if not self._at(K.VARIABLE):
            raise Au3ParseError('expected a variable in the enum declaration')
        declarations = [self._parse_enum_declarator()]
        while self._eat(K.COMMA):
            declarations.append(self._parse_enum_declarator())
        return Au3EnumDeclaration(
            declarations=declarations,
            scope=scope,
            is_const=is_const,
            step_operator=step_operator,
            step_value=step_value,
            offset=offset,
        )

    def _parse_enum_declarator(self) -> Au3EnumDeclarator:
        variable = self._parse_variable()
        initializer = None
        if self._at(K.ASSIGN_OR_EQ):
            self._advance()
            initializer = self._parse_expression()
        return Au3EnumDeclarator(
            variable=variable, initializer=initializer, offset=variable.offset)

    def _parse_redim(self) -> Au3ReDimStatement:
        offset = self._current.offset
        self._expect(K.REDIM)
        targets = [self._parse_redim_target()]
        while self._eat(K.COMMA):
            targets.append(self._parse_redim_target())
        return Au3ReDimStatement(targets=targets, offset=offset)

    def _parse_redim_target(self) -> Au3ReDimTarget:
        variable = self._parse_variable()
        dimensions = [self._parse_redim_dimension()]
        while self._at(K.LBRACKET):
            dimensions.append(self._parse_redim_dimension())
        return Au3ReDimTarget(
            variable=variable, dimensions=dimensions, offset=variable.offset)

    def _parse_redim_dimension(self) -> Expression:
        self._expect(K.LBRACKET)
        if self._at(K.RBRACKET):
            raise Au3ParseError('ReDim requires an explicit dimension')
        dimension = self._parse_expression()
        self._expect(K.RBRACKET)
        return dimension

    def _parse_function(self, is_volatile: bool = False) -> Au3FunctionDeclaration:
        offset = self._current.offset
        if self._at(K.VOLATILE):
            self._advance()
        self._expect(K.FUNC)
        name = self._parse_identifier()
        self._expect(K.LPAREN)
        params: list[Au3Parameter] = []
        if not self._at(K.RPAREN):
            params.append(self._parse_parameter())
            while self._eat(K.COMMA):
                params.append(self._parse_parameter())
        self._expect(K.RPAREN)
        comments = self._expect_eol()
        body, orphaned = self._parse_statement_list(K.ENDFUNC)
        self._expect(K.ENDFUNC)
        node = Au3FunctionDeclaration(
            name=name, params=params, body=body, is_volatile=is_volatile, offset=offset)
        node.trailing_comments.extend([*comments, *orphaned])
        return node

    def _parse_parameter(self) -> Au3Parameter:
        offset = self._current.offset
        by_ref = False
        is_const = False
        while self._at(K.CONST, K.BYREF):
            kind = self._advance().kind
            if kind is K.CONST:
                is_const = True
            else:
                by_ref = True
        variable = self._parse_variable()
        default = None
        if self._at(K.ASSIGN_OR_EQ):
            self._advance()
            default = self._parse_expression()
        return Au3Parameter(
            variable=variable,
            by_ref=by_ref,
            is_const=is_const,
            default=default,
            offset=offset,
        )

    def _parse_return(self) -> Au3ReturnStatement:
        tok = self._advance()
        value = None
        if not self._at(*_BOUNDARY_KINDS):
            value = self._parse_expression()
        return Au3ReturnStatement(value=value, offset=tok.offset)

    def _parse_exit(self) -> Au3ExitStatement:
        tok = self._advance()
        code = None
        if not self._at(*_BOUNDARY_KINDS):
            code = self._parse_expression()
        return Au3ExitStatement(code=code, offset=tok.offset)

    def _parse_exit_loop(self) -> Au3ExitLoopStatement:
        tok = self._advance()
        level = None
        if not self._at(*_BOUNDARY_KINDS):
            level = self._parse_expression()
        return Au3ExitLoopStatement(level=level, offset=tok.offset)

    def _parse_continue_loop(self) -> Au3ContinueLoopStatement:
        tok = self._advance()
        level = None
        if not self._at(*_BOUNDARY_KINDS):
            level = self._parse_expression()
        return Au3ContinueLoopStatement(level=level, offset=tok.offset)

    def _parse_expression_statement(self) -> Au3ExpressionStatement:
        offset = self._current.offset
        if self._at(K.NOT, K.PLUS, K.MINUS):
            expr = self._parse_expression()
            return Au3ExpressionStatement(expression=expr, offset=offset)
        left = self._parse_postfix()
        operator = _ASSIGN_OPS.get(self._current.kind)
        if operator is not None and self._is_lvalue(left):
            self._advance()
            value = self._parse_expression()
            assignment = Au3Assignment(
                target=left, operator=operator, value=value, offset=left.offset)
            return Au3ExpressionStatement(expression=assignment, offset=offset)
        expr = self._parse_binary_from(left, _EXPRESSION_PRECEDENCE)
        return Au3ExpressionStatement(expression=expr, offset=offset)

    def _is_lvalue(self, node: Expression) -> bool:
        if isinstance(node, (Au3Variable, Au3WithMember)):
            return True
        if isinstance(node, Au3ArrayAccess):
            return node.array is not None and self._is_lvalue(node.array)
        if isinstance(node, Au3MemberAccess):
            return node.object is not None and self._is_lvalue(node.object)
        return False

    def _parse_expression(self) -> Expression:
        return self._parse_binary(_EXPRESSION_PRECEDENCE)

    def _parse_binary(self, min_prec: int) -> Expression:
        return self._parse_binary_from(self._parse_unary(), min_prec)

    def _parse_binary_from(self, left: Expression, min_prec: int) -> Expression:
        while True:
            kind = self._current.kind
            if kind is K.QUESTION and _TERNARY_PRECEDENCE >= min_prec:
                self._advance()
                consequent = self._parse_ternary_operand()
                self._expect(K.COLON)
                alternate = self._parse_ternary_operand()
                left = Au3Ternary(
                    condition=left,
                    consequent=consequent,
                    alternate=alternate,
                    offset=left.offset,
                )
                continue
            precedence = _CLIMB_PRECEDENCE.get(kind)
            if precedence is None or precedence < min_prec:
                break
            self._advance()
            right = self._parse_binary(precedence + 1)
            left = Au3BinaryExpression(
                operator=_BINARY_OPERATORS[kind], left=left, right=right, offset=left.offset)
        return left

    def _parse_ternary_operand(self) -> Expression:
        """
        One operand of a ternary: everything tighter than `?`, plus a nested ternary. A nested
        `?` after the operand makes the chain right-associative, so `$a ? $b : $c ? $d : $e`
        reads as `$a ? $b : ($c ? $d : $e)`.
        """
        operand = self._parse_binary(_TERNARY_OPERAND_PRECEDENCE)
        if self._at(K.QUESTION):
            self._advance()
            consequent = self._parse_ternary_operand()
            self._expect(K.COLON)
            alternate = self._parse_ternary_operand()
            operand = Au3Ternary(
                condition=operand,
                consequent=consequent,
                alternate=alternate,
                offset=operand.offset,
            )
        return operand

    def _parse_unary(self) -> Expression:
        offset = self._current.offset
        kind = self._current.kind
        if kind is K.NOT:
            self._advance()
            return Au3UnaryExpression(operator='not', operand=self._parse_unary(), offset=offset)
        if kind in (K.PLUS, K.MINUS):
            self._advance()
            return Au3UnaryExpression(
                operator=kind.value, operand=self._parse_unary(), offset=offset)
        return self._parse_postfix()

    def _parse_postfix(self) -> Expression:
        expr = self._parse_primary()
        while True:
            kind = self._current.kind
            if kind is K.DOT:
                self._advance()
                member, raw = self._parse_member_name()
                expr = Au3MemberAccess(
                    object=expr, member=member, raw=raw, offset=expr.offset)
            elif kind is K.LBRACKET:
                self._advance()
                index = None
                if not self._at(K.RBRACKET):
                    index = self._parse_expression()
                self._expect(K.RBRACKET)
                expr = Au3ArrayAccess(array=expr, index=index, offset=expr.offset)
            elif kind is K.LPAREN:
                arguments = self._parse_arguments()
                expr = Au3Call(callee=expr, arguments=arguments, offset=expr.offset)
            else:
                break
        return expr

    def _parse_arguments(self) -> list[Expression]:
        self._expect(K.LPAREN)
        arguments: list[Expression] = []
        if not self._at(K.RPAREN):
            arguments.append(self._parse_expression())
            while self._eat(K.COMMA):
                arguments.append(self._parse_expression())
        self._expect(K.RPAREN)
        return arguments

    def _parse_member_name(self) -> tuple[str, str]:
        tok = self._current
        if tok.kind is not K.IDENTIFIER and not tok.kind.is_keyword:
            raise Au3ParseError(F'expected a member name, found {tok.value!r}')
        tok = self._advance()
        return tok.value.lower(), tok.value

    def _parse_primary(self) -> Expression:
        tok = self._current
        kind = tok.kind
        if kind is K.INTEGER:
            self._advance()
            return Au3IntLiteral(
                value=_parse_int_value(tok.value), raw=tok.value, offset=tok.offset)
        if kind is K.FLOAT:
            self._advance()
            return Au3FloatLiteral(value=float(tok.value), raw=tok.value, offset=tok.offset)
        if kind is K.STRING:
            self._advance()
            return Au3StringLiteral(
                value=decode_au3_string(tok.value), raw=tok.value, offset=tok.offset)
        if kind in (K.TRUE, K.FALSE):
            self._advance()
            return Au3BooleanLiteral(value=kind is K.TRUE, offset=tok.offset)
        if kind is K.NULL:
            self._advance()
            return Au3NullLiteral(offset=tok.offset)
        if kind is K.DEFAULT:
            self._advance()
            return Au3DefaultLiteral(offset=tok.offset)
        if kind is K.VARIABLE:
            self._advance()
            return Au3Variable(name=tok.value[1:].lower(), raw=tok.value, offset=tok.offset)
        if kind is K.MACRO:
            self._advance()
            return Au3Macro(name=tok.value[1:].lower(), raw=tok.value, offset=tok.offset)
        if kind is K.IDENTIFIER:
            self._advance()
            return Au3Identifier(name=tok.value.lower(), raw=tok.value, offset=tok.offset)
        if kind is K.LPAREN:
            self._advance()
            inner = self._parse_expression()
            self._expect(K.RPAREN)
            return Au3ParenExpression(expression=inner, offset=tok.offset)
        if kind is K.LBRACKET:
            return self._parse_array_literal()
        if kind is K.DOT and self._with_depth > 0:
            self._advance()
            member, raw = self._parse_member_name()
            return Au3WithMember(member=member, raw=raw, offset=tok.offset)
        raise Au3ParseError(F'unexpected {tok.value!r} in expression')

    def _parse_array_literal(self) -> Au3ArrayLiteral:
        offset = self._current.offset
        self._expect(K.LBRACKET)
        elements: list[Expression] = []
        if not self._at(K.RBRACKET):
            elements.append(self._parse_expression())
            while self._eat(K.COMMA):
                elements.append(self._parse_expression())
        self._expect(K.RBRACKET)
        return Au3ArrayLiteral(elements=elements, offset=offset)

    def _parse_variable(self) -> Au3Variable:
        # A name read from a token the file never provided is not synthesized: an empty or foreign
        # name would build a node no text spells, so the statement is handed to recovery instead.
        tok = self._current
        if tok.kind is not K.VARIABLE:
            raise Au3ParseError(F'expected a variable, found {tok.value!r}')
        self._advance()
        return Au3Variable(name=tok.value[1:].lower(), raw=tok.value, offset=tok.offset)

    def _parse_identifier(self) -> Au3Identifier:
        tok = self._current
        if tok.kind is not K.IDENTIFIER:
            raise Au3ParseError(F'expected an identifier, found {tok.value!r}')
        self._advance()
        return Au3Identifier(name=tok.value.lower(), raw=tok.value, offset=tok.offset)

    def _expect_eol(self) -> list[str]:
        """
        Consume the end of a header line and return whatever comment trailed it. Such a comment
        belongs to no statement a list will read, so it travels with the construct the header
        opens.
        """
        if self._at(K.NEWLINE):
            index = self._index
            self._advance()
            return self._trailing.pop(index, [])
        if not self._at(K.EOF):
            self._error(self._current, 'expected end of line')
        return []
