from __future__ import annotations

from refinery.lib.scripts.php.lexer import (
    PhpLexer,
    decode_php_double_quoted,
    decode_php_single_quoted,
)
from refinery.lib.scripts.php.model import (
    Expression,
    PhpArg,
    PhpArray,
    PhpArrayDimFetch,
    PhpArrayItem,
    PhpArrowFunction,
    PhpAssignment,
    PhpAttribute,
    PhpAttributeGroup,
    PhpBinaryExpression,
    PhpBlock,
    PhpBooleanLiteral,
    PhpBreak,
    PhpCase,
    PhpCastExpression,
    PhpCatch,
    PhpClass,
    PhpClassConst,
    PhpClassConstFetch,
    PhpClassKind,
    PhpClassMethod,
    PhpClone,
    PhpClosure,
    PhpClosureUse,
    PhpConst,
    PhpConstDeclaration,
    PhpConstFetch,
    PhpContinue,
    PhpDeclare,
    PhpDeclareDirective,
    PhpDoWhile,
    PhpEcho,
    PhpEchoTagStatement,
    PhpElseIf,
    PhpEmpty,
    PhpEnumCase,
    PhpErrorNode,
    PhpErrorSuppress,
    PhpEval,
    PhpExit,
    PhpExpressionStatement,
    PhpFloatLiteral,
    PhpFor,
    PhpForeach,
    PhpFunctionCall,
    PhpFunctionDeclaration,
    PhpGlobal,
    PhpGoto,
    PhpGroupUse,
    PhpHaltCompiler,
    PhpHeredoc,
    PhpIdentifier,
    PhpIf,
    PhpInclude,
    PhpInlineHTML,
    PhpInstanceof,
    PhpIntLiteral,
    PhpInterpolatedString,
    PhpIsset,
    PhpLabel,
    PhpList,
    PhpMagicConstant,
    PhpMatch,
    PhpMatchArm,
    PhpMethodCall,
    PhpName,
    PhpNameKind,
    PhpNamespace,
    PhpNew,
    PhpNewAnonymous,
    PhpNop,
    PhpNullableType,
    PhpNullLiteral,
    PhpParam,
    PhpParenExpression,
    PhpPrint,
    PhpProperty,
    PhpPropertyDeclaration,
    PhpPropertyFetch,
    PhpReturn,
    PhpScript,
    PhpShellExec,
    PhpStaticCall,
    PhpStaticPropertyFetch,
    PhpStaticVar,
    PhpStaticVarDeclaration,
    PhpStringLiteral,
    PhpSwitch,
    PhpTernary,
    PhpThrowExpression,
    PhpThrowStatement,
    PhpTraitAdaptation,
    PhpTraitUse,
    PhpTry,
    PhpUnaryExpression,
    PhpUnionType,
    PhpIntersectionType,
    PhpUnset,
    PhpUpdateExpression,
    PhpUse,
    PhpUseItem,
    PhpUseKind,
    PhpVariable,
    PhpVariableVariable,
    PhpVisibility,
    PhpWhile,
    PhpYield,
    PhpYieldFrom,
    Statement,
)
from refinery.lib.scripts.php.token import PhpToken, PhpTokenKind as K

# Tuple: (precedence, right_associative, non_associative).
# PHP declares ==, !=, ===, !==, <=>, <, <=, >, >= as %nonassoc in its grammar.
_BINARY_PREC: dict[K, tuple[int, bool, bool]] = {
    K.COALESCE:            (11, True,  False),  # noqa
    K.BOOLEAN_OR:          (12, False, False),  # noqa
    K.BOOLEAN_AND:         (13, False, False),  # noqa
    K.PIPE:                (14, False, False),  # noqa
    K.CARET:               (15, False, False),  # noqa
    K.AMP:                 (16, False, False),  # noqa
    K.IS_EQUAL:            (17, False, True),   # noqa
    K.IS_NOT_EQUAL:        (17, False, True),   # noqa
    K.IS_IDENTICAL:        (17, False, True),   # noqa
    K.IS_NOT_IDENTICAL:    (17, False, True),   # noqa
    K.SPACESHIP:           (17, False, True),   # noqa
    K.LT:                  (18, False, True),   # noqa
    K.IS_SMALLER_OR_EQUAL: (18, False, True),   # noqa
    K.GT:                  (18, False, True),   # noqa
    K.IS_GREATER_OR_EQUAL: (18, False, True),   # noqa
    K.DOT:                 (20, False, False),  # noqa
    K.SL:                  (21, False, False),  # noqa
    K.SR:                  (21, False, False),  # noqa
    K.PLUS:                (22, False, False),  # noqa
    K.MINUS:               (22, False, False),  # noqa
    K.STAR:                (23, False, False),  # noqa
    K.SLASH:               (23, False, False),  # noqa
    K.PERCENT:             (23, False, False),  # noqa
    K.POW:                 (27, True,  False),  # noqa
}

# The word operators are the lowest-precedence operators in PHP, below assignment, with
# or < xor < and. They are handled by `_parse_logical` outside `_BINARY_PREC` so they wrap
# assignment rather than binding tighter than it.
_LOGICAL_PREC: dict[K, int] = {
    K.LOGICAL_OR:  1,  # noqa
    K.LOGICAL_XOR: 2,  # noqa
    K.LOGICAL_AND: 3,  # noqa
}

_ASSIGN_OPS: dict[K, str] = {
    K.EQUALS:         '=',    # noqa
    K.PLUS_EQUAL:     '+=',   # noqa
    K.MINUS_EQUAL:    '-=',   # noqa
    K.MUL_EQUAL:      '*=',   # noqa
    K.DIV_EQUAL:      '/=',   # noqa
    K.MOD_EQUAL:      '%=',   # noqa
    K.POW_EQUAL:      '**=',  # noqa
    K.CONCAT_EQUAL:   '.=',   # noqa
    K.AND_EQUAL:      '&=',   # noqa
    K.OR_EQUAL:       '|=',   # noqa
    K.XOR_EQUAL:      '^=',   # noqa
    K.SL_EQUAL:       '<<=',  # noqa
    K.SR_EQUAL:       '>>=',  # noqa
    K.COALESCE_EQUAL: '??=',  # noqa
}

_CAST_TEXT: dict[K, str] = {
    K.INT_CAST:    'int',     # noqa
    K.FLOAT_CAST:  'float',   # noqa
    K.STRING_CAST: 'string',  # noqa
    K.ARRAY_CAST:  'array',   # noqa
    K.OBJECT_CAST: 'object',  # noqa
    K.BOOL_CAST:   'bool',    # noqa
    K.UNSET_CAST:  'unset',   # noqa
}

_MODIFIER_KINDS = frozenset({
    K.PUBLIC,
    K.PROTECTED,
    K.PRIVATE,
    K.STATIC,
    K.ABSTRACT,
    K.FINAL,
    K.READONLY,
    K.VAR,
})

_INCLUDE_KEYWORDS: dict[K, str] = {
    K.INCLUDE:      'include',       # noqa
    K.INCLUDE_ONCE: 'include_once',  # noqa
    K.REQUIRE:      'require',       # noqa
    K.REQUIRE_ONCE: 'require_once',  # noqa
}

_NAME_KINDS = frozenset({K.IDENTIFIER, K.NS_SEPARATOR, K.NAMESPACE})

_MAGIC_CONSTANTS = frozenset({
    K.LINE,
    K.FILE,
    K.DIR,
    K.CLASS_C,
    K.TRAIT_C,
    K.METHOD_C,
    K.FUNC_C,
    K.NS_C,
})

_TYPE_KEYWORDS = frozenset({
    K.ARRAY,
    K.CALLABLE,
    K.STATIC,
})

_SEMI_RESERVED = frozenset({
    K.INCLUDE,
    K.INCLUDE_ONCE,
    K.REQUIRE,
    K.REQUIRE_ONCE,
    K.EVAL,
    K.PRINT,
    K.ECHO,
    K.EXIT,
    K.LOGICAL_OR,
    K.LOGICAL_XOR,
    K.LOGICAL_AND,
    K.INSTANCEOF,
    K.NEW,
    K.CLONE,
    K.YIELD,
    K.IF,
    K.ELSEIF,
    K.ELSE,
    K.ENDIF,
    K.DO,
    K.WHILE,
    K.ENDWHILE,
    K.FOR,
    K.ENDFOR,
    K.FOREACH,
    K.ENDFOREACH,
    K.SWITCH,
    K.ENDSWITCH,
    K.CASE,
    K.DEFAULT,
    K.MATCH,
    K.BREAK,
    K.CONTINUE,
    K.GOTO,
    K.RETURN,
    K.THROW,
    K.TRY,
    K.CATCH,
    K.FINALLY,
    K.DECLARE,
    K.ENDDECLARE,
    K.AS,
    K.FUNCTION,
    K.FN,
    K.CONST,
    K.USE,
    K.INSTEADOF,
    K.GLOBAL,
    K.STATIC,
    K.ABSTRACT,
    K.FINAL,
    K.PRIVATE,
    K.PROTECTED,
    K.PUBLIC,
    K.READONLY,
    K.VAR,
    K.UNSET,
    K.ISSET,
    K.EMPTY,
    K.HALT_COMPILER,
    K.LIST,
    K.ARRAY,
    K.CALLABLE,
    K.CLASS,
    K.TRAIT,
    K.INTERFACE,
    K.ENUM,
    K.EXTENDS,
    K.IMPLEMENTS,
    K.NAMESPACE,
})


class PhpParser:
    """
    Recursive-descent parser for PHP based on the Zend language grammar
    (`Zend/zend_language_parser.y`). The parser tokenizes the entire input up front so that the
    multi-token lookahead required by name resolution, modifier lists, `static fn`, and cast
    detection can be satisfied without backtracking the lexer. On statement or expression failure it
    resynchronizes and emits a `PhpErrorNode`, so malformed input still yields a tree whose error
    coverage can be scored by `guess_language`.
    """

    def __init__(self, source: str):
        self._source = source
        self._tokens: list[PhpToken] = []
        self._trivia: dict[int, list[str]] = {}
        self._index = 0
        self._errors: list[PhpErrorNode] = []
        self._materialize()

    def _materialize(self):
        pending: list[str] = []
        for tok in PhpLexer(source=self._source).tokenize():
            if tok.kind in (K.COMMENT, K.DOC_COMMENT):
                pending.append(tok.value)
                continue
            if pending:
                self._trivia[len(self._tokens)] = pending
                pending = []
            self._tokens.append(tok)
            if tok.kind is K.EOF:
                break
        if not self._tokens or self._tokens[-1].kind is not K.EOF:
            self._tokens.append(PhpToken(K.EOF, '', len(self._source)))

    @property
    def _current(self) -> PhpToken:
        return self._tokens[self._index]

    def _peek(self, ahead: int = 0) -> PhpToken:
        i = self._index + ahead
        if i >= len(self._tokens):
            return self._tokens[-1]
        return self._tokens[i]

    def _at(self, *kinds: K) -> bool:
        return self._current.kind in kinds

    def _advance(self) -> PhpToken:
        tok = self._tokens[self._index]
        if self._index < len(self._tokens) - 1:
            self._index += 1
        return tok

    def _eat(self, kind: K) -> PhpToken | None:
        if self._current.kind == kind:
            return self._advance()
        return None

    def _expect(self, kind: K) -> PhpToken:
        if self._current.kind == kind:
            return self._advance()
        tok = self._current
        self._error(tok, F'expected {kind.name}')
        return PhpToken(kind, tok.value, tok.offset)

    def _error(self, tok: PhpToken, message: str) -> PhpErrorNode:
        node = PhpErrorNode(text=tok.value, message=message, offset=tok.offset)
        self._errors.append(node)
        return node

    def parse(self) -> PhpScript:
        offset = self._current.offset
        body = self._parse_statement_list(K.EOF)
        return PhpScript(body=body, errors=self._errors, offset=offset)

    def _parse_statement_list(self, *stop: K) -> list[Statement]:
        body: list[Statement] = []
        while not self._at(*stop) and not self._at(K.EOF):
            mark = self._index
            comments = self._trivia.pop(self._index, None)
            try:
                stmt = self._parse_statement()
            except RecursionError:
                raise
            except Exception:
                stmt = None
            if stmt is not None:
                if comments:
                    stmt.leading_comments[:0] = comments
                body.append(stmt)
            elif self._index == mark:
                tok = self._advance()
                error = self._error(tok, 'unexpected token')
                if comments:
                    error.leading_comments[:0] = comments
                body.append(error)
            else:
                if comments:
                    self._trivia.setdefault(mark, [])
                    self._trivia[mark][:0] = comments
        trailing = self._trivia.pop(self._index, None)
        if trailing and body:
            body[-1].leading_comments.extend(trailing)
        return body

    def _parse_statement(self) -> Statement | None:
        offset = self._current.offset
        kind = self._current.kind

        if kind is K.INLINE_HTML:
            tok = self._advance()
            return PhpInlineHTML(value=tok.value, offset=offset)
        if kind in (K.OPEN_TAG, K.CLOSE_TAG):
            self._advance()
            return None
        if kind is K.OPEN_TAG_ECHO:
            return self._parse_echo_tag()
        if kind is K.SEMICOLON:
            self._advance()
            return PhpNop(offset=offset)
        if kind is K.LBRACE:
            return self._parse_block()
        if kind is K.ATTRIBUTE:
            return self._parse_attributed_declaration()
        if kind is K.NAMESPACE and not self._peek(1).kind is K.NS_SEPARATOR:
            return self._parse_namespace()
        if kind is K.USE:
            return self._parse_use()
        if kind is K.CONST:
            return self._parse_const()
        if kind is K.IF:
            return self._parse_if()
        if kind is K.WHILE:
            return self._parse_while()
        if kind is K.DO:
            return self._parse_do_while()
        if kind is K.FOR:
            return self._parse_for()
        if kind is K.FOREACH:
            return self._parse_foreach()
        if kind is K.SWITCH:
            return self._parse_switch()
        if kind is K.BREAK:
            return self._parse_break()
        if kind is K.CONTINUE:
            return self._parse_continue()
        if kind is K.RETURN:
            return self._parse_return()
        if kind is K.THROW:
            return self._parse_throw_statement()
        if kind is K.TRY:
            return self._parse_try()
        if kind is K.ECHO:
            return self._parse_echo()
        if kind is K.UNSET:
            return self._parse_unset()
        if kind is K.GLOBAL:
            return self._parse_global()
        if kind is K.GOTO:
            return self._parse_goto()
        if kind is K.DECLARE:
            return self._parse_declare()
        if kind is K.HALT_COMPILER:
            return self._parse_halt_compiler()
        if kind is K.FUNCTION and self._starts_function_declaration():
            return self._parse_function_declaration()
        if kind is K.STATIC and self._peek(1).kind in (K.VARIABLE, K.DOLLAR):
            return self._parse_static_var()
        if self._starts_class_like():
            return self._parse_class_like([])

        if (
            kind is K.IDENTIFIER
            and self._peek(1).kind is K.COLON
            and self._peek(2).kind is not K.COLON
        ):
            tok = self._advance()
            self._advance()
            return PhpLabel(name=tok.value, offset=offset)

        expr = self._parse_expression()
        self._eat(K.SEMICOLON)
        return PhpExpressionStatement(expression=expr, offset=offset)

    def _starts_function_declaration(self) -> bool:
        nxt = self._peek(1)
        if nxt.kind is K.AMP:
            nxt = self._peek(2)
        return nxt.kind is K.IDENTIFIER or nxt.kind in _SEMI_RESERVED

    def _starts_class_like(self) -> bool:
        kind = self._current.kind
        if kind in (K.CLASS, K.INTERFACE, K.TRAIT):
            return True
        if kind is K.ENUM and self._peek(1).kind is K.IDENTIFIER:
            return True
        if kind in (K.ABSTRACT, K.FINAL, K.READONLY):
            i = 0
            while self._peek(i).kind in (K.ABSTRACT, K.FINAL, K.READONLY):
                i += 1
            return self._peek(i).kind is K.CLASS
        return False

    def _parse_echo_tag(self) -> PhpEchoTagStatement:
        offset = self._current.offset
        self._advance()
        expressions = [self._parse_expression()]
        while self._eat(K.COMMA):
            expressions.append(self._parse_expression())
        self._eat(K.SEMICOLON)
        self._eat(K.CLOSE_TAG)
        return PhpEchoTagStatement(expressions=expressions, offset=offset)

    def _parse_block(self) -> PhpBlock:
        offset = self._current.offset
        self._expect(K.LBRACE)
        body = self._parse_statement_list(K.RBRACE)
        self._expect(K.RBRACE)
        return PhpBlock(body=body, offset=offset)

    def _parse_statement_body(self, *terminators: K) -> list[Statement]:
        """
        Parse either a single statement or, when the alternative colon syntax is in force, a run of
        statements terminated by one of *terminators*. The caller consumes the terminating keyword.
        """
        if self._eat(K.COLON):
            return self._parse_statement_list(*terminators)
        stmt = self._parse_statement()
        if isinstance(stmt, PhpBlock):
            return stmt.body
        return [stmt] if stmt is not None else []

    def _parse_if(self) -> PhpIf:
        offset = self._current.offset
        self._expect(K.IF)
        self._expect(K.LPAREN)
        condition = self._parse_expression()
        self._expect(K.RPAREN)
        alt = self._at(K.COLON)
        if alt:
            consequent = self._parse_statement_body(
                K.ELSEIF, K.ELSE, K.ENDIF)
        else:
            consequent = self._parse_statement_body()
        elseifs: list[PhpElseIf] = []
        alternate: list[Statement] | None = None
        while self._at(K.ELSEIF):
            ei_offset = self._current.offset
            self._advance()
            self._expect(K.LPAREN)
            ei_cond = self._parse_expression()
            self._expect(K.RPAREN)
            if alt:
                ei_body = self._parse_statement_body(K.ELSEIF, K.ELSE, K.ENDIF)
            else:
                ei_body = self._parse_statement_body()
            elseifs.append(PhpElseIf(condition=ei_cond, body=ei_body, offset=ei_offset))
        if self._eat(K.ELSE):
            if alt:
                alternate = self._parse_statement_body(K.ENDIF)
            else:
                alternate = self._parse_statement_body()
        if alt:
            self._expect(K.ENDIF)
            self._eat(K.SEMICOLON)
        return PhpIf(
            condition=condition,
            consequent=consequent,
            elseifs=elseifs,
            alternate=alternate,
            alternative_syntax=alt,
            offset=offset,
        )

    def _parse_while(self) -> PhpWhile:
        offset = self._current.offset
        self._expect(K.WHILE)
        self._expect(K.LPAREN)
        condition = self._parse_expression()
        self._expect(K.RPAREN)
        alt = self._at(K.COLON)
        body = self._parse_statement_body(K.ENDWHILE)
        if alt:
            self._expect(K.ENDWHILE)
            self._eat(K.SEMICOLON)
        return PhpWhile(
            condition=condition, body=body, alternative_syntax=alt, offset=offset)

    def _parse_do_while(self) -> PhpDoWhile:
        offset = self._current.offset
        self._expect(K.DO)
        body = self._parse_statement_body()
        self._expect(K.WHILE)
        self._expect(K.LPAREN)
        condition = self._parse_expression()
        self._expect(K.RPAREN)
        self._eat(K.SEMICOLON)
        return PhpDoWhile(body=body, condition=condition, offset=offset)

    def _parse_expression_list(self, *stop: K) -> list[Expression]:
        exprs: list[Expression] = []
        if self._at(*stop):
            return exprs
        exprs.append(self._parse_expression())
        while self._eat(K.COMMA):
            exprs.append(self._parse_expression())
        return exprs

    def _parse_for(self) -> PhpFor:
        offset = self._current.offset
        self._expect(K.FOR)
        self._expect(K.LPAREN)
        init = self._parse_expression_list(K.SEMICOLON)
        self._expect(K.SEMICOLON)
        condition = self._parse_expression_list(K.SEMICOLON)
        self._expect(K.SEMICOLON)
        update = self._parse_expression_list(K.RPAREN)
        self._expect(K.RPAREN)
        alt = self._at(K.COLON)
        body = self._parse_statement_body(K.ENDFOR)
        if alt:
            self._expect(K.ENDFOR)
            self._eat(K.SEMICOLON)
        return PhpFor(
            init=init,
            condition=condition,
            update=update,
            body=body,
            alternative_syntax=alt,
            offset=offset,
        )

    def _parse_foreach(self) -> PhpForeach:
        offset = self._current.offset
        self._expect(K.FOREACH)
        self._expect(K.LPAREN)
        subject = self._parse_expression()
        self._expect(K.AS)
        by_ref = bool(self._eat(K.AMP))
        first = self._parse_expression()
        key = None
        value = first
        if self._eat(K.DOUBLE_ARROW):
            key = first
            by_ref = bool(self._eat(K.AMP))
            value = self._parse_expression()
        self._expect(K.RPAREN)
        alt = self._at(K.COLON)
        body = self._parse_statement_body(K.ENDFOREACH)
        if alt:
            self._expect(K.ENDFOREACH)
            self._eat(K.SEMICOLON)
        return PhpForeach(
            subject=subject,
            key=key,
            value=value,
            by_ref=by_ref,
            body=body,
            alternative_syntax=alt,
            offset=offset,
        )

    def _parse_switch(self) -> PhpSwitch:
        offset = self._current.offset
        self._expect(K.SWITCH)
        self._expect(K.LPAREN)
        subject = self._parse_expression()
        self._expect(K.RPAREN)
        alt = bool(self._eat(K.COLON))
        if not alt:
            self._expect(K.LBRACE)
        cases: list[PhpCase] = []
        while not self._at(K.RBRACE, K.ENDSWITCH, K.EOF):
            case_offset = self._current.offset
            test = None
            if self._eat(K.CASE):
                test = self._parse_expression()
            elif self._eat(K.DEFAULT):
                pass
            else:
                break
            if not self._eat(K.COLON):
                self._eat(K.SEMICOLON)
            case_body = self._parse_statement_list(
                K.CASE, K.DEFAULT, K.RBRACE, K.ENDSWITCH)
            cases.append(PhpCase(test=test, body=case_body, offset=case_offset))
        if alt:
            self._expect(K.ENDSWITCH)
            self._eat(K.SEMICOLON)
        else:
            self._expect(K.RBRACE)
        return PhpSwitch(
            subject=subject, cases=cases, alternative_syntax=alt, offset=offset)

    def _parse_break(self) -> PhpBreak:
        offset = self._current.offset
        self._expect(K.BREAK)
        level = None
        if not self._at(K.SEMICOLON, K.CLOSE_TAG, K.EOF):
            level = self._parse_expression()
        self._eat(K.SEMICOLON)
        return PhpBreak(level=level, offset=offset)

    def _parse_continue(self) -> PhpContinue:
        offset = self._current.offset
        self._expect(K.CONTINUE)
        level = None
        if not self._at(K.SEMICOLON, K.CLOSE_TAG, K.EOF):
            level = self._parse_expression()
        self._eat(K.SEMICOLON)
        return PhpContinue(level=level, offset=offset)

    def _parse_return(self) -> PhpReturn:
        offset = self._current.offset
        self._expect(K.RETURN)
        value = None
        if not self._at(K.SEMICOLON, K.CLOSE_TAG, K.EOF):
            value = self._parse_expression()
        self._eat(K.SEMICOLON)
        return PhpReturn(value=value, offset=offset)

    def _parse_throw_statement(self) -> PhpThrowStatement:
        offset = self._current.offset
        self._expect(K.THROW)
        operand = self._parse_expression()
        self._eat(K.SEMICOLON)
        return PhpThrowStatement(operand=operand, offset=offset)

    def _parse_try(self) -> PhpTry:
        offset = self._current.offset
        self._expect(K.TRY)
        body = self._parse_block().body
        catches: list[PhpCatch] = []
        while self._at(K.CATCH):
            catch_offset = self._current.offset
            self._advance()
            self._expect(K.LPAREN)
            types = [self._parse_name()]
            while self._eat(K.PIPE):
                types.append(self._parse_name())
            variable = None
            if self._at(K.VARIABLE):
                var_tok = self._advance()
                variable = PhpVariable(name=var_tok.value, offset=var_tok.offset)
            self._expect(K.RPAREN)
            catch_body = self._parse_block().body
            catches.append(PhpCatch(
                types=types, variable=variable, body=catch_body, offset=catch_offset))
        finally_body = None
        if self._eat(K.FINALLY):
            finally_body = self._parse_block().body
        return PhpTry(
            body=body, catches=catches, finally_body=finally_body, offset=offset)

    def _parse_echo(self) -> PhpEcho:
        offset = self._current.offset
        self._expect(K.ECHO)
        expressions = [self._parse_expression()]
        while self._eat(K.COMMA):
            expressions.append(self._parse_expression())
        self._eat(K.SEMICOLON)
        return PhpEcho(expressions=expressions, offset=offset)

    def _parse_unset(self) -> PhpUnset:
        offset = self._current.offset
        self._expect(K.UNSET)
        self._expect(K.LPAREN)
        variables = self._parse_expression_list(K.RPAREN)
        self._expect(K.RPAREN)
        self._eat(K.SEMICOLON)
        return PhpUnset(variables=variables, offset=offset)

    def _parse_global(self) -> PhpGlobal:
        offset = self._current.offset
        self._expect(K.GLOBAL)
        variables: list[PhpVariable] = []
        while self._at(K.VARIABLE, K.DOLLAR):
            if self._at(K.DOLLAR):
                variables.append(self._parse_variable_variable())
            else:
                tok = self._advance()
                variables.append(PhpVariable(name=tok.value, offset=tok.offset))
            if not self._eat(K.COMMA):
                break
        self._eat(K.SEMICOLON)
        return PhpGlobal(variables=variables, offset=offset)

    def _parse_static_var(self) -> PhpStaticVar:
        offset = self._current.offset
        self._expect(K.STATIC)
        declarations: list[PhpStaticVarDeclaration] = []
        while self._at(K.VARIABLE, K.DOLLAR):
            decl_offset = self._current.offset
            if self._at(K.DOLLAR):
                variable = self._parse_variable_variable()
            else:
                tok = self._advance()
                variable = PhpVariable(name=tok.value, offset=tok.offset)
            default = None
            if self._eat(K.EQUALS):
                default = self._parse_expression()
            declarations.append(PhpStaticVarDeclaration(
                variable=variable, default=default, offset=decl_offset))
            if not self._eat(K.COMMA):
                break
        self._eat(K.SEMICOLON)
        return PhpStaticVar(declarations=declarations, offset=offset)

    def _parse_goto(self) -> PhpGoto:
        offset = self._current.offset
        self._expect(K.GOTO)
        tok = self._expect(K.IDENTIFIER)
        self._eat(K.SEMICOLON)
        return PhpGoto(label=tok.value, offset=offset)

    def _parse_declare(self) -> PhpDeclare:
        offset = self._current.offset
        self._expect(K.DECLARE)
        self._expect(K.LPAREN)
        directives: list[PhpDeclareDirective] = []
        while not self._at(K.RPAREN, K.EOF):
            dir_offset = self._current.offset
            name_tok = self._advance()
            self._expect(K.EQUALS)
            value = self._parse_expression()
            directives.append(PhpDeclareDirective(
                name=name_tok.value, value=value, offset=dir_offset))
            if not self._eat(K.COMMA):
                break
        self._expect(K.RPAREN)
        body: list[Statement] | None = None
        alternative_syntax = False
        if self._at(K.LBRACE):
            body = self._parse_block().body
        elif self._eat(K.COLON):
            alternative_syntax = True
            body = self._parse_statement_list(K.ENDDECLARE)
            self._expect(K.ENDDECLARE)
            self._eat(K.SEMICOLON)
        else:
            self._eat(K.SEMICOLON)
        return PhpDeclare(directives=directives, body=body, alternative_syntax=alternative_syntax, offset=offset)

    def _parse_halt_compiler(self) -> PhpHaltCompiler:
        offset = self._current.offset
        self._expect(K.HALT_COMPILER)
        self._eat(K.LPAREN)
        self._eat(K.RPAREN)
        self._eat(K.SEMICOLON)
        remainder = self._source[self._current.offset:]
        self._index = len(self._tokens) - 1
        return PhpHaltCompiler(remainder=remainder, offset=offset)

    def _parse_name(self) -> PhpName:
        offset = self._current.offset
        kind = PhpNameKind.UNQUALIFIED
        parts: list[str] = []
        if self._eat(K.NS_SEPARATOR):
            kind = PhpNameKind.FULLY_QUALIFIED
        elif self._at(K.NAMESPACE):
            self._advance()
            self._eat(K.NS_SEPARATOR)
            kind = PhpNameKind.RELATIVE
        if self._at(K.IDENTIFIER) or self._current.kind in _SEMI_RESERVED:
            parts.append(self._advance().value)
        while self._at(K.NS_SEPARATOR) and (
            self._peek(1).kind is K.IDENTIFIER or self._peek(1).kind in _SEMI_RESERVED
        ):
            self._advance()
            parts.append(self._advance().value)
            if kind is PhpNameKind.UNQUALIFIED:
                kind = PhpNameKind.QUALIFIED
        return PhpName(parts=parts, kind=kind, offset=offset)

    def _parse_namespace(self) -> PhpNamespace:
        offset = self._current.offset
        self._expect(K.NAMESPACE)
        name = None
        if self._at(K.IDENTIFIER, K.NS_SEPARATOR):
            name = self._parse_name()
        body: list[Statement] | None = None
        if self._at(K.LBRACE):
            body = self._parse_block().body
        else:
            self._eat(K.SEMICOLON)
        return PhpNamespace(name=name, body=body, offset=offset)

    def _parse_use_kind(self) -> PhpUseKind:
        if self._eat(K.FUNCTION):
            return PhpUseKind.FUNCTION
        if self._eat(K.CONST):
            return PhpUseKind.CONSTANT
        return PhpUseKind.NORMAL

    def _parse_use(self) -> Statement:
        offset = self._current.offset
        self._expect(K.USE)
        kind = self._parse_use_kind()
        first = self._parse_name()
        if self._eat(K.NS_SEPARATOR):
            self._expect(K.LBRACE)
            items = self._parse_group_use_items()
            self._expect(K.RBRACE)
            self._eat(K.SEMICOLON)
            return PhpGroupUse(prefix=first, uses=items, kind=kind, offset=offset)
        alias = None
        if self._eat(K.AS):
            alias = self._expect(K.IDENTIFIER).value
        uses = [PhpUseItem(name=first, alias=alias, offset=first.offset)]
        while self._eat(K.COMMA):
            name = self._parse_name()
            item_alias = None
            if self._eat(K.AS):
                item_alias = self._expect(K.IDENTIFIER).value
            uses.append(PhpUseItem(name=name, alias=item_alias, offset=name.offset))
        self._eat(K.SEMICOLON)
        return PhpUse(uses=uses, kind=kind, offset=offset)

    def _parse_group_use_items(self) -> list[PhpUseItem]:
        items: list[PhpUseItem] = []
        while not self._at(K.RBRACE, K.EOF):
            item_offset = self._current.offset
            item_kind = None
            if self._at(K.FUNCTION):
                self._advance()
                item_kind = PhpUseKind.FUNCTION
            elif self._at(K.CONST):
                self._advance()
                item_kind = PhpUseKind.CONSTANT
            name = self._parse_name()
            alias = None
            if self._eat(K.AS):
                alias = self._expect(K.IDENTIFIER).value
            items.append(PhpUseItem(
                name=name, alias=alias, kind=item_kind, offset=item_offset))
            if not self._eat(K.COMMA):
                break
        return items

    def _parse_const(self) -> PhpConst:
        offset = self._current.offset
        self._expect(K.CONST)
        consts = self._parse_const_declarations()
        self._eat(K.SEMICOLON)
        return PhpConst(consts=consts, offset=offset)

    def _parse_const_declarations(self) -> list[PhpConstDeclaration]:
        consts: list[PhpConstDeclaration] = []
        while True:
            decl_offset = self._current.offset
            name_tok = self._advance()
            self._expect(K.EQUALS)
            value = self._parse_expression()
            consts.append(PhpConstDeclaration(
                name=name_tok.value, value=value, offset=decl_offset))
            if not self._eat(K.COMMA):
                break
        return consts

    def _parse_attribute_groups(self) -> list[PhpAttributeGroup]:
        groups: list[PhpAttributeGroup] = []
        while self._at(K.ATTRIBUTE):
            group_offset = self._current.offset
            self._advance()
            attributes: list[PhpAttribute] = []
            while not self._at(K.RBRACKET, K.EOF):
                attr_offset = self._current.offset
                name = self._parse_name()
                args: list[PhpArg] = []
                if self._at(K.LPAREN):
                    args = self._parse_arguments()
                attributes.append(PhpAttribute(
                    name=name, args=args, offset=attr_offset))
                if not self._eat(K.COMMA):
                    break
            self._expect(K.RBRACKET)
            groups.append(PhpAttributeGroup(
                attributes=attributes, offset=group_offset))
        return groups

    def _parse_attributed_declaration(self) -> Statement:
        offset = self._current.offset
        attributes = self._parse_attribute_groups()
        if self._at(K.FUNCTION) and self._starts_function_declaration():
            node = self._parse_function_declaration()
            node.attributes = attributes
            node.offset = offset
            for group in attributes:
                node._adopt(group)
            return node
        if self._starts_class_like():
            return self._parse_class_like(attributes, offset)
        expr = self._parse_expression()
        self._eat(K.SEMICOLON)
        return PhpExpressionStatement(expression=expr, offset=offset)

    def _parse_function_declaration(self) -> PhpFunctionDeclaration:
        offset = self._current.offset
        self._expect(K.FUNCTION)
        by_ref = bool(self._eat(K.AMP))
        name_tok = self._advance()
        params = self._parse_parameters()
        return_type = None
        if self._eat(K.COLON):
            return_type = self._parse_type()
        body = None
        if self._at(K.LBRACE):
            body = self._parse_block()
        else:
            self._eat(K.SEMICOLON)
        return PhpFunctionDeclaration(
            name=name_tok.value,
            params=params,
            return_type=return_type,
            body=body,
            by_ref=by_ref,
            offset=offset,
        )

    def _parse_parameters(self) -> list[PhpParam]:
        params: list[PhpParam] = []
        self._expect(K.LPAREN)
        while not self._at(K.RPAREN, K.EOF):
            params.append(self._parse_parameter())
            if not self._eat(K.COMMA):
                break
        self._expect(K.RPAREN)
        return params

    def _parse_parameter(self) -> PhpParam:
        offset = self._current.offset
        attributes = self._parse_attribute_groups()
        modifiers: list[K] = []
        while self._current.kind in _MODIFIER_KINDS:
            modifiers.append(self._advance().kind)
        param_type = None
        if not self._at(K.VARIABLE, K.AMP, K.ELLIPSIS):
            param_type = self._parse_type()
        by_ref = bool(self._eat(K.AMP))
        variadic = bool(self._eat(K.ELLIPSIS))
        name_tok = self._expect(K.VARIABLE)
        default = None
        if self._eat(K.EQUALS):
            default = self._parse_expression()
        visibility = None
        for mod in modifiers:
            if mod is K.PUBLIC:
                visibility = PhpVisibility.PUBLIC
            elif mod is K.PROTECTED:
                visibility = PhpVisibility.PROTECTED
            elif mod is K.PRIVATE:
                visibility = PhpVisibility.PRIVATE
        readonly = K.READONLY in modifiers
        return PhpParam(
            name=name_tok.value,
            type=param_type,
            default=default,
            by_ref=by_ref,
            variadic=variadic,
            visibility=visibility,
            readonly=readonly,
            attributes=attributes,
            offset=offset,
        )

    def _parse_type(self) -> Expression:
        offset = self._current.offset
        nullable = bool(self._eat(K.QUESTION))
        first = self._parse_type_atom()
        if self._at(K.PIPE):
            types = [first]
            while self._eat(K.PIPE):
                types.append(self._parse_type_atom())
            result: Expression = PhpUnionType(types=types, offset=offset)
        elif self._at(K.AMP) and self._peek(1).kind in (K.IDENTIFIER, K.NS_SEPARATOR):
            types = [first]
            while self._at(K.AMP) and self._peek(1).kind in (
                K.IDENTIFIER, K.NS_SEPARATOR,
            ):
                self._advance()
                types.append(self._parse_type_atom())
            result = PhpIntersectionType(types=types, offset=offset)
        else:
            result = first
        if nullable:
            return PhpNullableType(type=result, offset=offset)
        return result

    def _parse_type_atom(self) -> Expression:
        offset = self._current.offset
        if self._eat(K.LPAREN):
            inner = self._parse_type()
            self._expect(K.RPAREN)
            return inner
        if self._current.kind in _TYPE_KEYWORDS:
            tok = self._advance()
            return PhpName(parts=[tok.value], offset=offset)
        return self._parse_name()

    def _parse_class_like(
        self,
        attributes: list[PhpAttributeGroup],
        offset: int | None = None,
    ) -> PhpClass:
        if offset is None:
            offset = self._current.offset
        modifiers: list[str] = []
        while self._current.kind in (K.ABSTRACT, K.FINAL, K.READONLY):
            modifiers.append(self._advance().value)
        kind_tok = self._advance()
        kind = {
            K.CLASS: PhpClassKind.CLASS,
            K.INTERFACE: PhpClassKind.INTERFACE,
            K.TRAIT: PhpClassKind.TRAIT,
            K.ENUM: PhpClassKind.ENUM,
        }.get(kind_tok.kind, PhpClassKind.CLASS)
        name_tok = self._expect(K.IDENTIFIER)
        enum_backing_type = None
        if kind is PhpClassKind.ENUM and self._eat(K.COLON):
            enum_backing_type = self._parse_type()
        extends: list[PhpName] = []
        implements: list[PhpName] = []
        if self._eat(K.EXTENDS):
            extends.append(self._parse_name())
            while self._eat(K.COMMA):
                extends.append(self._parse_name())
        if self._eat(K.IMPLEMENTS):
            implements.append(self._parse_name())
            while self._eat(K.COMMA):
                implements.append(self._parse_name())
        members = self._parse_class_body()
        return PhpClass(
            name=name_tok.value,
            kind=kind,
            extends=extends,
            implements=implements,
            members=members,
            modifiers=modifiers,
            enum_backing_type=enum_backing_type,
            attributes=attributes,
            offset=offset,
        )

    def _parse_class_body(self) -> list[Statement]:
        members: list[Statement] = []
        self._expect(K.LBRACE)
        while not self._at(K.RBRACE, K.EOF):
            mark = self._index
            comments = self._trivia.pop(self._index, None)
            member = self._parse_class_member()
            if member is not None:
                if comments:
                    member.leading_comments[:0] = comments
                members.append(member)
            elif self._index == mark:
                tok = self._advance()
                self._error(tok, 'unexpected token')
        trailing = self._trivia.pop(self._index, None)
        if trailing and members:
            members[-1].leading_comments.extend(trailing)
        self._expect(K.RBRACE)
        return members

    def _parse_class_member(self) -> Statement | None:
        offset = self._current.offset
        if self._at(K.SEMICOLON):
            self._advance()
            return None
        attributes = self._parse_attribute_groups()
        if self._at(K.USE):
            return self._parse_trait_use()
        if self._at(K.CASE):
            return self._parse_enum_case(attributes, offset)
        modifiers: list[str] = []
        while self._current.kind in _MODIFIER_KINDS:
            modifiers.append(self._advance().value)
        if self._at(K.CONST):
            return self._parse_class_const(attributes, modifiers, offset)
        if self._at(K.FUNCTION):
            return self._parse_class_method(attributes, modifiers, offset)
        return self._parse_property(attributes, modifiers, offset)

    def _parse_trait_use(self) -> PhpTraitUse:
        offset = self._current.offset
        self._expect(K.USE)
        traits = [self._parse_name()]
        while self._eat(K.COMMA):
            traits.append(self._parse_name())
        adaptations: list[PhpTraitAdaptation] = []
        if self._at(K.LBRACE):
            self._advance()
            while not self._at(K.RBRACE, K.EOF):
                adaptations.append(self._parse_trait_adaptation())
            self._expect(K.RBRACE)
        else:
            self._eat(K.SEMICOLON)
        return PhpTraitUse(traits=traits, adaptations=adaptations, offset=offset)

    def _parse_trait_adaptation(self) -> PhpTraitAdaptation:
        offset = self._current.offset
        trait: PhpName | None = None
        method = ''
        first = self._parse_name()
        if self._eat(K.DOUBLE_COLON):
            trait = first
            method = self._advance().value
        else:
            method = first.parts[0] if first.parts else ''
        if self._at(K.INSTEADOF):
            self._advance()
            insteadof = [self._parse_name()]
            while self._eat(K.COMMA):
                insteadof.append(self._parse_name())
            self._eat(K.SEMICOLON)
            return PhpTraitAdaptation(
                trait=trait,
                method=method,
                kind='insteadof',
                insteadof=insteadof,
                offset=offset,
            )
        self._expect(K.AS)
        new_modifier: str | None = None
        new_name: str | None = None
        if self._current.kind in _MODIFIER_KINDS:
            new_modifier = self._advance().value
        if self._at(K.IDENTIFIER) or self._current.kind in _SEMI_RESERVED:
            new_name = self._advance().value
        self._eat(K.SEMICOLON)
        return PhpTraitAdaptation(
            trait=trait,
            method=method,
            kind='alias',
            new_name=new_name,
            new_modifier=new_modifier,
            offset=offset,
        )

    def _parse_enum_case(
        self,
        attributes: list[PhpAttributeGroup],
        offset: int,
    ) -> PhpEnumCase:
        self._expect(K.CASE)
        name_tok = self._advance()
        value = None
        if self._eat(K.EQUALS):
            value = self._parse_expression()
        self._eat(K.SEMICOLON)
        return PhpEnumCase(
            name=name_tok.value, value=value, attributes=attributes, offset=offset)

    def _parse_class_const(
        self,
        attributes: list[PhpAttributeGroup],
        modifiers: list[str],
        offset: int,
    ) -> PhpClassConst:
        self._expect(K.CONST)
        const_type = None
        if self._peek(1).kind not in (K.EQUALS, K.COMMA, K.SEMICOLON):
            const_type = self._parse_type()
        consts = self._parse_const_declarations()
        self._eat(K.SEMICOLON)
        return PhpClassConst(
            consts=consts,
            modifiers=modifiers,
            type=const_type,
            attributes=attributes,
            offset=offset,
        )

    def _parse_class_method(
        self,
        attributes: list[PhpAttributeGroup],
        modifiers: list[str],
        offset: int,
    ) -> PhpClassMethod:
        self._expect(K.FUNCTION)
        by_ref = bool(self._eat(K.AMP))
        name_tok = self._advance()
        params = self._parse_parameters()
        return_type = None
        if self._eat(K.COLON):
            return_type = self._parse_type()
        body = None
        if self._at(K.LBRACE):
            body = self._parse_block()
        else:
            self._eat(K.SEMICOLON)
        return PhpClassMethod(
            name=name_tok.value,
            params=params,
            return_type=return_type,
            body=body,
            modifiers=modifiers,
            by_ref=by_ref,
            attributes=attributes,
            offset=offset,
        )

    def _parse_property(
        self,
        attributes: list[PhpAttributeGroup],
        modifiers: list[str],
        offset: int,
    ) -> PhpProperty:
        prop_type = None
        if not self._at(K.VARIABLE):
            prop_type = self._parse_type()
        props: list[PhpPropertyDeclaration] = []
        while self._at(K.VARIABLE):
            decl_offset = self._current.offset
            var_tok = self._advance()
            variable = PhpVariable(name=var_tok.value, offset=var_tok.offset)
            default = None
            if self._eat(K.EQUALS):
                default = self._parse_expression()
            props.append(PhpPropertyDeclaration(
                variable=variable, default=default, offset=decl_offset))
            if not self._eat(K.COMMA):
                break
        self._eat(K.SEMICOLON)
        return PhpProperty(
            props=props,
            modifiers=modifiers,
            type=prop_type,
            attributes=attributes,
            offset=offset,
        )

    def _parse_expression(self) -> Expression:
        return self._parse_logical(1)

    def _parse_logical(self, min_prec: int) -> Expression:
        left = self._parse_assignment()
        while True:
            prec = _LOGICAL_PREC.get(self._current.kind)
            if prec is None or prec < min_prec:
                break
            op = self._advance().value
            right = self._parse_logical(prec + 1)
            left = PhpBinaryExpression(
                operator=op, left=left, right=right, offset=left.offset)
        return left

    def _parse_assignment(self) -> Expression:
        if self._at(K.THROW):
            offset = self._current.offset
            self._advance()
            operand = self._parse_assignment()
            return PhpThrowExpression(operand=operand, offset=offset)
        if self._at(K.YIELD):
            return self._parse_yield()
        if self._at(K.PRINT):
            offset = self._current.offset
            self._advance()
            operand = self._parse_assignment()
            return PhpPrint(operand=operand, offset=offset)
        if self._current.kind in _INCLUDE_KEYWORDS:
            offset = self._current.offset
            kind = self._advance().kind
            operand = self._parse_assignment()
            return PhpInclude(
                kind=_INCLUDE_KEYWORDS[kind], operand=operand, offset=offset)
        left = self._parse_ternary()
        op = _ASSIGN_OPS.get(self._current.kind)
        if op is not None:
            self._advance()
            if op == '=' and self._eat(K.AMP):
                value = self._parse_assignment()
                return PhpAssignment(
                    operator='=', target=left, value=value, by_ref=True, offset=left.offset)
            value = self._parse_assignment()
            return PhpAssignment(
                operator=op, target=left, value=value, offset=left.offset)
        return left

    def _parse_yield(self) -> Expression:
        offset = self._current.offset
        self._expect(K.YIELD)
        if self._at(K.IDENTIFIER) and self._current.value.lower() == 'from':
            self._advance()
            operand = self._parse_assignment()
            return PhpYieldFrom(operand=operand, offset=offset)
        if self._at(
            K.SEMICOLON, K.RPAREN, K.RBRACKET, K.RBRACE, K.COMMA, K.CLOSE_TAG, K.EOF,
        ):
            return PhpYield(offset=offset)
        first = self._parse_ternary()
        if self._eat(K.DOUBLE_ARROW):
            value = self._parse_ternary()
            return PhpYield(key=first, value=value, offset=offset)
        return PhpYield(value=first, offset=offset)

    def _parse_ternary(self) -> Expression:
        condition = self._parse_binary(0)
        if self._eat(K.QUESTION):
            consequent = None
            if not self._at(K.COLON):
                consequent = self._parse_assignment()
            self._expect(K.COLON)
            alternate = self._parse_assignment()
            return PhpTernary(
                condition=condition,
                consequent=consequent,
                alternate=alternate,
                offset=condition.offset,
            )
        return condition

    def _parse_binary(self, min_prec: int) -> Expression:
        left = self._parse_not()
        while True:
            entry = _BINARY_PREC.get(self._current.kind)
            if entry is None:
                break
            prec, right_assoc, non_assoc = entry
            if prec < min_prec:
                break
            op = self._advance().value
            next_prec = prec if right_assoc else prec + 1
            right = self._parse_binary(next_prec)
            left = PhpBinaryExpression(
                operator=op, left=left, right=right, offset=left.offset)
            if non_assoc:
                following = _BINARY_PREC.get(self._current.kind)
                if following is not None and following[0] == prec:
                    break
        return left

    def _parse_not(self) -> Expression:
        if self._at(K.BANG):
            offset = self._current.offset
            self._advance()
            operand = self._parse_not()
            return PhpUnaryExpression(operator='!', operand=operand, offset=offset)
        return self._parse_instanceof()

    def _parse_instanceof(self) -> Expression:
        left = self._parse_prefix()
        if self._at(K.INSTANCEOF):
            self._advance()
            class_name = self._parse_instanceof_target()
            left = PhpInstanceof(
                operand=left, class_name=class_name, offset=left.offset)
        return left

    def _parse_instanceof_target(self) -> Expression:
        if self._at(K.VARIABLE, K.DOLLAR, K.LPAREN, K.STATIC):
            return self._parse_prefix()
        return self._parse_name()

    def _parse_prefix(self) -> Expression:
        offset = self._current.offset
        kind = self._current.kind
        if kind in (K.PLUS, K.MINUS, K.TILDE):
            self._advance()
            operand = self._parse_prefix()
            return PhpUnaryExpression(operator=kind.value, operand=operand, offset=offset)
        if kind is K.AT:
            self._advance()
            operand = self._parse_prefix()
            return PhpErrorSuppress(operand=operand, offset=offset)
        if kind in _CAST_TEXT:
            self._advance()
            operand = self._parse_prefix()
            return PhpCastExpression(
                cast=_CAST_TEXT[kind], operand=operand, offset=offset)
        if kind in (K.INC, K.DEC):
            self._advance()
            operand = self._parse_prefix()
            return PhpUpdateExpression(
                operator=kind.value, operand=operand, prefix=True, offset=offset)
        if kind is K.CLONE:
            self._advance()
            operand = self._parse_prefix()
            return PhpClone(operand=operand, offset=offset)
        return self._parse_pow()

    def _parse_pow(self) -> Expression:
        base = self._parse_postfix()
        if self._at(K.POW):
            self._advance()
            exponent = self._parse_prefix()
            return PhpBinaryExpression(
                operator='**', left=base, right=exponent, offset=base.offset)
        return base

    def _parse_postfix(self) -> Expression:
        expr = self._parse_primary()
        while True:
            kind = self._current.kind
            if kind in (K.OBJECT_OPERATOR, K.NULLSAFE_OPERATOR):
                nullsafe = kind is K.NULLSAFE_OPERATOR
                self._advance()
                name = self._parse_member_name()
                if self._at(K.LPAREN):
                    args, fcc = self._parse_call_or_fcc()
                    expr = PhpMethodCall(
                        receiver=expr,
                        method=name,
                        args=args,
                        nullsafe=nullsafe,
                        first_class_callable=fcc,
                        offset=expr.offset,
                    )
                else:
                    expr = PhpPropertyFetch(
                        receiver=expr, name=name, nullsafe=nullsafe, offset=expr.offset)
            elif kind is K.DOUBLE_COLON:
                self._advance()
                expr = self._parse_static_access(expr)
            elif kind is K.LBRACKET:
                self._advance()
                index = None
                if not self._at(K.RBRACKET):
                    index = self._parse_expression()
                self._expect(K.RBRACKET)
                expr = PhpArrayDimFetch(
                    receiver=expr, index=index, offset=expr.offset)
            elif kind is K.LBRACE:
                self._advance()
                index = self._parse_expression()
                self._expect(K.RBRACE)
                expr = PhpArrayDimFetch(
                    receiver=expr, index=index, offset=expr.offset)
            elif kind is K.LPAREN:
                args, fcc = self._parse_call_or_fcc()
                expr = PhpFunctionCall(
                    callee=expr, args=args, first_class_callable=fcc, offset=expr.offset)
            elif kind in (K.INC, K.DEC):
                self._advance()
                expr = PhpUpdateExpression(
                    operator=kind.value, operand=expr, prefix=False, offset=expr.offset)
            else:
                break
        return expr

    def _parse_member_name(self) -> Expression:
        if self._at(K.VARIABLE):
            tok = self._advance()
            return PhpVariable(name=tok.value, offset=tok.offset)
        if self._at(K.DOLLAR):
            return self._parse_variable_variable()
        if self._at(K.LBRACE):
            self._advance()
            expr = self._parse_expression()
            self._expect(K.RBRACE)
            return expr
        tok = self._advance()
        return PhpIdentifier(name=tok.value, offset=tok.offset)

    def _parse_static_access(self, class_name: Expression) -> Expression:
        offset = class_name.offset
        if self._at(K.VARIABLE):
            tok = self._advance()
            prop = PhpVariable(name=tok.value, offset=tok.offset)
            if self._at(K.LPAREN):
                args, fcc = self._parse_call_or_fcc()
                return PhpStaticCall(
                    class_name=class_name, method=prop, args=args,
                    first_class_callable=fcc, offset=offset)
            return PhpStaticPropertyFetch(
                class_name=class_name, name=prop, offset=offset)
        if self._at(K.LBRACE):
            self._advance()
            member = self._parse_expression()
            self._expect(K.RBRACE)
            if self._at(K.LPAREN):
                args, fcc = self._parse_call_or_fcc()
                return PhpStaticCall(
                    class_name=class_name, method=member, args=args,
                    first_class_callable=fcc, offset=offset)
            return PhpClassConstFetch(
                class_name=class_name, name=member, offset=offset)
        if self._at(K.DOLLAR):
            member = self._parse_variable_variable()
            return PhpStaticPropertyFetch(
                class_name=class_name, name=member, offset=offset)
        name_tok = self._advance()
        member = PhpIdentifier(name=name_tok.value, offset=name_tok.offset)
        if self._at(K.LPAREN):
            args, fcc = self._parse_call_or_fcc()
            return PhpStaticCall(
                class_name=class_name, method=member, args=args,
                first_class_callable=fcc, offset=offset)
        return PhpClassConstFetch(
            class_name=class_name, name=member, offset=offset)

    def _parse_call_or_fcc(self) -> tuple[list[PhpArg], bool]:
        if (
            self._at(K.LPAREN)
            and self._peek(1).kind is K.ELLIPSIS
            and self._peek(2).kind is K.RPAREN
        ):
            self._advance()
            self._advance()
            self._advance()
            return [], True
        return self._parse_arguments(), False

    def _parse_arguments(self) -> list[PhpArg]:
        args: list[PhpArg] = []
        self._expect(K.LPAREN)
        while not self._at(K.RPAREN, K.EOF):
            arg_offset = self._current.offset
            name = None
            if (
                (self._at(K.IDENTIFIER) or self._current.kind in _SEMI_RESERVED)
                and self._peek(1).kind is K.COLON
                and self._peek(2).kind is not K.COLON
            ):
                name = self._advance().value
                self._advance()
            spread = bool(self._eat(K.ELLIPSIS))
            value = self._parse_expression()
            args.append(PhpArg(
                value=value, name=name, spread=spread, offset=arg_offset))
            if not self._eat(K.COMMA):
                break
        self._expect(K.RPAREN)
        return args

    def _parse_variable_variable(self) -> Expression:
        offset = self._current.offset
        self._expect(K.DOLLAR)
        if self._at(K.LBRACE):
            self._advance()
            expr = self._parse_expression()
            self._expect(K.RBRACE)
            return PhpVariableVariable(expression=expr, offset=offset)
        inner = self._parse_primary()
        return PhpVariableVariable(expression=inner, offset=offset)

    def _parse_primary(self) -> Expression:
        tok = self._current
        offset = tok.offset
        kind = tok.kind

        if kind is K.VARIABLE:
            self._advance()
            return PhpVariable(name=tok.value, offset=offset)
        if kind is K.DOLLAR:
            return self._parse_variable_variable()
        if kind is K.INTEGER:
            self._advance()
            return PhpIntLiteral(
                value=_parse_int_text(tok.value), raw=tok.value, offset=offset)
        if kind is K.FLOAT:
            self._advance()
            return PhpFloatLiteral(
                value=float(tok.value.replace('_', '')), raw=tok.value, offset=offset)
        if kind is K.STRING_SINGLE:
            self._advance()
            return PhpStringLiteral(
                value=decode_php_single_quoted(tok.value[1:-1]),
                raw=tok.value,
                offset=offset,
            )
        if kind is K.STRING_DOUBLE:
            self._advance()
            return self._make_double_quoted(tok.value, offset)
        if kind is K.SHELL_EXEC:
            self._advance()
            return PhpShellExec(raw=tok.value, offset=offset)
        if kind in (K.HEREDOC, K.NOWDOC):
            self._advance()
            return PhpHeredoc(raw=tok.value, nowdoc=kind is K.NOWDOC, offset=offset)
        if kind in _MAGIC_CONSTANTS:
            self._advance()
            return PhpMagicConstant(name=tok.value, offset=offset)
        if kind is K.LPAREN:
            self._advance()
            expr = self._parse_expression()
            self._expect(K.RPAREN)
            return PhpParenExpression(expression=expr, offset=offset)
        if kind is K.LBRACKET:
            return self._parse_array(short=True)
        if kind is K.ARRAY and self._peek(1).kind is K.LPAREN:
            return self._parse_array(short=False)
        if kind is K.LIST:
            return self._parse_list()
        if kind is K.MATCH and self._peek(1).kind is K.LPAREN:
            return self._parse_match()
        if kind is K.FUNCTION:
            return self._parse_closure(is_static=False)
        if kind is K.FN:
            return self._parse_arrow_function(is_static=False)
        if kind is K.STATIC and self._peek(1).kind in (K.FUNCTION, K.FN):
            self._advance()
            if self._at(K.FUNCTION):
                return self._parse_closure(is_static=True, offset=offset)
            return self._parse_arrow_function(is_static=True, offset=offset)
        if kind is K.STATIC:
            tok = self._advance()
            return PhpName(parts=[tok.value], offset=offset)
        if kind is K.NEW:
            return self._parse_new()
        if kind is K.ISSET:
            self._advance()
            self._expect(K.LPAREN)
            variables = self._parse_expression_list(K.RPAREN)
            self._expect(K.RPAREN)
            return PhpIsset(variables=variables, offset=offset)
        if kind is K.EMPTY:
            self._advance()
            self._expect(K.LPAREN)
            operand = self._parse_expression()
            self._expect(K.RPAREN)
            return PhpEmpty(operand=operand, offset=offset)
        if kind is K.EVAL:
            self._advance()
            self._expect(K.LPAREN)
            operand = self._parse_expression()
            self._expect(K.RPAREN)
            return PhpEval(operand=operand, offset=offset)
        if kind is K.EXIT:
            self._advance()
            operand = None
            if self._eat(K.LPAREN):
                if not self._at(K.RPAREN):
                    operand = self._parse_expression()
                self._expect(K.RPAREN)
            return PhpExit(operand=operand, keyword=tok.value, offset=offset)
        if kind in (K.IDENTIFIER, K.NS_SEPARATOR, K.NAMESPACE):
            return self._parse_name_or_const(offset)

        self._advance()
        return self._error(tok, 'unexpected token')

    def _parse_name_or_const(self, offset: int) -> Expression:
        name = self._parse_name()
        lowered = '\\'.join(name.parts).lower()
        if name.kind is PhpNameKind.UNQUALIFIED and len(name.parts) == 1:
            if lowered == 'true':
                return PhpBooleanLiteral(value=True, raw=name.parts[0], offset=offset)
            if lowered == 'false':
                return PhpBooleanLiteral(value=False, raw=name.parts[0], offset=offset)
            if lowered == 'null':
                return PhpNullLiteral(raw=name.parts[0], offset=offset)
        return PhpConstFetch(name=name, offset=offset)

    def _make_double_quoted(self, raw: str, offset: int) -> Expression:
        body = raw[1:-1]
        if _has_interpolation(body):
            return PhpInterpolatedString(raw=raw, offset=offset)
        return PhpStringLiteral(
            value=decode_php_double_quoted(body), raw=raw, offset=offset)

    def _parse_array(self, short: bool) -> PhpArray:
        offset = self._current.offset
        if short:
            self._expect(K.LBRACKET)
            close = K.RBRACKET
        else:
            self._expect(K.ARRAY)
            self._expect(K.LPAREN)
            close = K.RPAREN
        items = self._parse_array_items(close)
        self._expect(close)
        return PhpArray(items=items, short=short, offset=offset)

    def _parse_array_items(self, close: K) -> list[PhpArrayItem | None]:
        items: list[PhpArrayItem | None] = []
        while not self._at(close, K.EOF):
            if self._at(K.COMMA):
                items.append(None)
                self._advance()
                continue
            items.append(self._parse_array_item())
            if not self._eat(K.COMMA):
                break
        return items

    def _parse_array_item(self) -> PhpArrayItem:
        offset = self._current.offset
        if self._eat(K.ELLIPSIS):
            value = self._parse_expression()
            return PhpArrayItem(value=value, spread=True, offset=offset)
        by_ref = bool(self._eat(K.AMP))
        first = self._parse_expression()
        if not by_ref and self._eat(K.DOUBLE_ARROW):
            value_by_ref = bool(self._eat(K.AMP))
            value = self._parse_expression()
            return PhpArrayItem(
                key=first, value=value, by_ref=value_by_ref, offset=offset)
        return PhpArrayItem(value=first, by_ref=by_ref, offset=offset)

    def _parse_list(self) -> PhpList:
        offset = self._current.offset
        self._expect(K.LIST)
        self._expect(K.LPAREN)
        items = self._parse_array_items(K.RPAREN)
        self._expect(K.RPAREN)
        return PhpList(items=items, short=False, offset=offset)

    def _parse_match(self) -> PhpMatch:
        offset = self._current.offset
        self._expect(K.MATCH)
        self._expect(K.LPAREN)
        subject = self._parse_expression()
        self._expect(K.RPAREN)
        self._expect(K.LBRACE)
        arms: list[PhpMatchArm] = []
        while not self._at(K.RBRACE, K.EOF):
            arm_offset = self._current.offset
            conditions: list[Expression] = []
            is_default = False
            if self._eat(K.DEFAULT):
                is_default = True
            else:
                conditions.append(self._parse_expression())
                while self._eat(K.COMMA):
                    if self._at(K.DOUBLE_ARROW):
                        break
                    conditions.append(self._parse_expression())
            self._expect(K.DOUBLE_ARROW)
            body = self._parse_expression()
            arms.append(PhpMatchArm(
                conditions=conditions,
                body=body,
                is_default=is_default,
                offset=arm_offset,
            ))
            if not self._eat(K.COMMA):
                break
        self._expect(K.RBRACE)
        return PhpMatch(subject=subject, arms=arms, offset=offset)

    def _parse_closure(
        self,
        is_static: bool,
        offset: int | None = None,
    ) -> PhpClosure:
        if offset is None:
            offset = self._current.offset
        self._expect(K.FUNCTION)
        by_ref = bool(self._eat(K.AMP))
        params = self._parse_parameters()
        uses: list[PhpClosureUse] = []
        if self._eat(K.USE):
            self._expect(K.LPAREN)
            while not self._at(K.RPAREN, K.EOF):
                use_offset = self._current.offset
                use_ref = bool(self._eat(K.AMP))
                var_tok = self._expect(K.VARIABLE)
                uses.append(PhpClosureUse(
                    variable=PhpVariable(name=var_tok.value, offset=var_tok.offset),
                    by_ref=use_ref,
                    offset=use_offset,
                ))
                if not self._eat(K.COMMA):
                    break
            self._expect(K.RPAREN)
        return_type = None
        if self._eat(K.COLON):
            return_type = self._parse_type()
        body = self._parse_block()
        return PhpClosure(
            params=params,
            uses=uses,
            return_type=return_type,
            body=body,
            is_static=is_static,
            by_ref=by_ref,
            offset=offset,
        )

    def _parse_arrow_function(
        self,
        is_static: bool,
        offset: int | None = None,
    ) -> PhpArrowFunction:
        if offset is None:
            offset = self._current.offset
        self._expect(K.FN)
        by_ref = bool(self._eat(K.AMP))
        params = self._parse_parameters()
        return_type = None
        if self._eat(K.COLON):
            return_type = self._parse_type()
        self._expect(K.DOUBLE_ARROW)
        body = self._parse_assignment()
        return PhpArrowFunction(
            params=params,
            return_type=return_type,
            body=body,
            is_static=is_static,
            by_ref=by_ref,
            offset=offset,
        )

    def _parse_new(self) -> Expression:
        offset = self._current.offset
        self._expect(K.NEW)
        modifiers: list[str] = []
        while self._current.kind in (K.ABSTRACT, K.FINAL, K.READONLY):
            modifiers.append(self._advance().value)
        if self._at(K.CLASS):
            self._advance()
            has_parens = self._at(K.LPAREN)
            args: list[PhpArg] = []
            if has_parens:
                args = self._parse_arguments()
            declaration = self._parse_anonymous_class(offset, modifiers)
            return PhpNewAnonymous(
                args=args, declaration=declaration, has_parens=has_parens, offset=offset)
        class_name = self._parse_new_target()
        has_parens = self._at(K.LPAREN)
        args = []
        if has_parens:
            args = self._parse_arguments()
        return PhpNew(class_name=class_name, args=args, has_parens=has_parens, offset=offset)

    def _parse_new_target(self) -> Expression:
        if self._at(K.VARIABLE):
            return self._parse_postfix()
        if self._at(K.DOLLAR):
            return self._parse_postfix()
        if self._at(K.STATIC) and self._peek(1).kind is not K.DOUBLE_COLON:
            tok = self._advance()
            return PhpName(parts=[tok.value], offset=tok.offset)
        if self._at(K.LPAREN):
            self._advance()
            expr = self._parse_expression()
            self._expect(K.RPAREN)
            return PhpParenExpression(expression=expr, offset=expr.offset)
        name = self._parse_name()
        if self._at(K.DOUBLE_COLON):
            self._advance()
            return self._parse_static_access(PhpConstFetch(name=name, offset=name.offset))
        return PhpConstFetch(name=name, offset=name.offset)

    def _parse_anonymous_class(self, offset: int, modifiers: list[str] | None = None) -> PhpClass:
        extends: list[PhpName] = []
        implements: list[PhpName] = []
        if self._eat(K.EXTENDS):
            extends.append(self._parse_name())
        if self._eat(K.IMPLEMENTS):
            implements.append(self._parse_name())
            while self._eat(K.COMMA):
                implements.append(self._parse_name())
        members = self._parse_class_body()
        return PhpClass(
            name='',
            kind=PhpClassKind.CLASS,
            extends=extends,
            implements=implements,
            members=members,
            modifiers=modifiers or [],
            offset=offset,
        )


def _parse_int_text(text: str) -> int:
    text = text.replace('_', '')
    if not text:
        return 0
    if text[:2] in ('0x', '0X'):
        return int(text, 16) if len(text) > 2 else 0
    if text[:2] in ('0b', '0B'):
        return int(text, 2) if len(text) > 2 else 0
    if text[:2] in ('0o', '0O'):
        return int(text, 8) if len(text) > 2 else 0
    if len(text) > 1 and text[0] == '0':
        try:
            return int(text, 8)
        except ValueError:
            return int(text, 10)
    return int(text)


def _has_interpolation(body: str) -> bool:
    """
    Return whether a double-quoted string body contains an unescaped interpolation trigger: a `$`
    that begins a variable or `${...}` expansion, or a `{$...}` complex expansion.
    """
    i = 0
    length = len(body)
    while i < length:
        c = body[i]
        if c == '\\':
            i += 2
            continue
        if c == '$' and i + 1 < length and (
            body[i + 1].isalpha() or body[i + 1] in '_{'
        ):
            return True
        if c == '{' and i + 1 < length and body[i + 1] == '$':
            return True
        i += 1
    return False
