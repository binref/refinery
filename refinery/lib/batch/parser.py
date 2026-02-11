from __future__ import annotations

import io
import re

from collections import deque

from refinery.lib.batch.lexer import BatchLexer
from refinery.lib.batch.model import (
    AstCommand,
    AstCondition,
    AstConditionalStatement,
    AstFor,
    AstForOptions,
    AstForParserMode,
    AstForVariant,
    AstGroup,
    AstIf,
    AstIfCmp,
    AstIfVariant,
    AstLabel,
    AstPipeline,
    AstSequence,
    Ctrl,
    EmulatorException,
    RedirectIO,
    Token,
    UnexpectedToken,
    Word,
)
from refinery.lib.batch.state import BatchState
from refinery.lib.batch.util import batchint, batchrange, unquote
from refinery.lib.types import buf


class LookAhead:
    preview: deque[Token]
    offsets: deque[int]

    def __init__(self, lexer: BatchLexer, offset: int, scope: int = 1):
        self.lexer = lexer
        self.tokens = lexer.tokens(offset)
        self.preview = deque()
        self.offsets = deque()
        self._offset = offset
        self.done = False
        self.scope = scope
        self._collect()

    def offset(self, index: int = 0):
        try:
            return self.offsets[index]
        except IndexError:
            return self._offset

    def pop(self, *value):
        if not (preview := self.preview):
            return Ctrl.EndOfFile in value
        if value and preview[0] not in value:
            return False
        next(self)
        return True

    def pop_nonspace(self):
        if not (preview := self.preview):
            return None
        if (peek := preview[0]).isspace():
            return None
        if isinstance(peek, RedirectIO):
            return None
        assert self.__next__() == peek
        return peek

    def pop_string(self, key: str):
        if not (preview := self.preview):
            return False
        if preview[0].upper() != key:
            return False
        self.__next__()
        return True

    def skip_space(self):
        spaces = []
        while (t := self.peek()) != Ctrl.NewLine and t.isspace():
            spaces.append(next(self))
        if not spaces:
            return None
        return ''.join(spaces)

    def consume_nonspace_words(self):
        self.skip_space()
        with io.StringIO() as fused:
            while tok := self.pop_nonspace():
                fused.write(tok)
            return fused.getvalue()

    def word(self, upper=False) -> Word | Ctrl:
        self.skip_space()
        if isinstance((token := next(self)), RedirectIO):
            raise UnexpectedToken(str(token))
        if upper:
            token = token.upper()
        return token

    def peek(self, index: int = 0) -> Token:
        try:
            return self.preview[index]
        except IndexError:
            return Ctrl.EndOfFile

    def drop_and_peek(self):
        self.__next__()
        return self.peek()

    def _collect(self):
        offsets = self.offsets
        preview = self.preview
        while len(preview) < self.scope:
            try:
                token = next(self.tokens)
            except StopIteration:
                break
            preview.append(token)
            if not (c := self.lexer.cursor).substituting:
                self._offset = c.offset
            offsets.append(self._offset)

    def __iter__(self):
        return self

    def __next__(self):
        if self.done:
            raise StopIteration
        try:
            self.offsets.popleft()
            token = self.preview.popleft()
        except IndexError:
            self.done = True
            raise StopIteration
        else:
            self._collect()
            return token


class BatchParser:

    def __init__(self, data: str | buf | BatchParser, state: BatchState | None = None):
        if isinstance(data, BatchParser):
            if state is not None:
                raise NotImplementedError
            src = data.lexer
        else:
            src = data
        self.lexer = BatchLexer(src, state)

    @property
    def state(self):
        return self.lexer.state

    @property
    def environment(self):
        return self.state.environment

    def skip_prefix(self, tokens: LookAhead) -> tuple[int, list[Token]]:
        token = tokens.peek()
        prefix = []
        skip = {
            Ctrl.At,
            Ctrl.Semicolon,
            Ctrl.Comma,
            Ctrl.Equals,
        }
        at = 0
        while True:
            if isinstance(token, Word):
                if not token.isspace():
                    break
                prefix.append(token)
            elif token not in skip:
                break
            else:
                prefix.append(token)
                if token == Ctrl.At:
                    at += 1
                else:
                    at = 0
            token = tokens.drop_and_peek()
        return at, prefix

    def command(
        self,
        tokens: LookAhead,
        redirects: dict[int, RedirectIO],
        in_group: bool,
        silenced: bool,
    ) -> AstCommand | None:
        ast = AstCommand(tokens.offset(), silenced, redirects)
        tok = tokens.peek()
        cmd = ast.fragments

        eat_token = False
        set_logic = False
        add_space = False

        if not ast.redirects:
            assert not isinstance(tok, RedirectIO)
            tok_upper = tok.upper()
            if tok_upper == 'SET':
                self.lexer.parse_set()
                set_logic = True
            elif tok_upper.startswith('ECHO'):
                if len(tok_upper) > 4 and tok_upper[4] == '.':
                    cmd.append(tok[:4])
                    cmd.append(' ')
                    tok = tok[5:]
                    add_space = False
                else:
                    add_space = True
                    eat_token = True
            cmd.append(tok)
            tok = tokens.drop_and_peek()

        nonspace = io.StringIO()

        while tok not in (
            Ctrl.CommandSeparator,
            Ctrl.RunOnFailure,
            Ctrl.RunOnSuccess,
            Ctrl.Pipe,
            Ctrl.NewLine,
            Ctrl.EndOfFile,
        ):
            if in_group and tok == Ctrl.EndGroup:
                break
            if isinstance(tok, RedirectIO):
                ast.redirects[tok.source] = tok
            elif add_space:
                add_space = False
                if not tok.isspace():
                    cmd.append(' ')
                    if eat_token:
                        tok = tok[1:]
                if tok:
                    cmd.append(tok)
            elif set_logic:
                cmd.append(tok)
            elif tok.isspace() or tok.startswith('/'):
                if nsp := nonspace.getvalue():
                    nonspace.seek(0)
                    nonspace.truncate(0)
                    cmd.append(nsp)
                cmd.append(tok)
            else:
                nonspace.write(tok)
            tok = tokens.drop_and_peek()
        if nsp := nonspace.getvalue():
            cmd.append(nsp)
        if ast:
            return ast

    def redirects(self, tokens: LookAhead):
        redirects = {}
        while isinstance((t := tokens.peek()), RedirectIO):
            redirects[t.source] = t
            tokens.pop()
            tokens.skip_space()
        return redirects

    def pipeline(self, tokens: LookAhead, in_group: bool, silenced: bool) -> AstPipeline | None:
        ast = AstPipeline(tokens.offset(), silenced)
        while True:
            redirects = self.redirects(tokens)
            if not (cmd := self.group(tokens, redirects, silenced)):
                if not (cmd := self.command(tokens, redirects, in_group, silenced)):
                    break
            ast.parts.append(cmd)
            if not tokens.pop(Ctrl.Pipe):
                break
            at, _ = self.skip_prefix(tokens)
            silenced = at > 0
        if ast.parts:
            return ast

    def ifthen(self, tokens: LookAhead, in_group: bool, silenced: bool) -> AstIf | None:
        offset = tokens.offset()

        if not tokens.pop_string('IF'):
            return None

        casefold = False
        negated = False
        lhs = None
        rhs = None

        token = tokens.word()

        if token.upper() == '/I':
            casefold = True
            token = tokens.word()
        if token.upper() == 'NOT':
            negated = True
            token = tokens.word()
        try:
            variant = AstIfVariant(token.upper())
        except Exception:
            tokens.skip_space()
            variant = None
            lhs = token
            cmp = next(tokens)

            if cmp == Ctrl.Equals:
                if tokens.pop(Ctrl.Equals):
                    cmp = AstIfCmp('==')
                else:
                    raise UnexpectedToken(tokens.peek())
            else:
                try:
                    cmp = AstIfCmp(cmp.upper())
                except Exception:
                    raise UnexpectedToken(cmp)
                if cmp != AstIfCmp.STR and self.state.extensions_version < 1:
                    raise UnexpectedToken(cmp)

            rhs = tokens.consume_nonspace_words()

            try:
                ilh = batchint(lhs)
                irh = batchint(rhs)
            except ValueError:
                pass
            else:
                lhs = ilh
                rhs = irh
        else:
            lhs = unquote(tokens.consume_nonspace_words())
            rhs = None
            cmp = None
            try:
                lhs = batchint(lhs)
            except ValueError:
                pass

        then_do = self.sequence(tokens, in_group)

        if then_do is None:
            raise UnexpectedToken(tokens.peek())

        tokens.skip_space()

        if tokens.peek().upper() == 'ELSE':
            tokens.pop()
            else_do = self.sequence(tokens, in_group)
        else:
            else_do = None

        return AstIf(
            offset,
            silenced,
            then_do,
            else_do,
            variant,
            casefold,
            negated,
            cmp,
            lhs, rhs # type:ignore
        )

    def forloop_options(self, options: str) -> AstForOptions:
        result = AstForOptions()

        if not options:
            return result
        elif not (quote := re.search('"(.*?)"', options)):
            raise UnexpectedToken(options)
        else:
            options = quote[1]

        parts = options.strip().split()
        count = len(parts)

        for k, part in enumerate(parts, 1):
            key, eq, value = part.partition('=')
            key = key.lower()
            if key == 'usebackq':
                if eq or value:
                    raise ValueError
                result.usebackq = True
            elif not eq:
                raise ValueError
            elif key == 'eol':
                if len(value) != 1:
                    raise ValueError
                result.comment = value
            elif key == 'skip':
                try:
                    result.skip = batchint(value)
                except Exception:
                    raise ValueError
            elif key == 'delims':
                if k == count:
                    _, _, value = options.rpartition('=')
                result.delims = value
            elif key == 'tokens':
                tokens: set[int] = set()
                if value.endswith('*'):
                    result.asterisk = True
                    value = value[:-1]
                for x in value.split(','):
                    x, _, y = x.partition('-')
                    x = batchint(x) - 1
                    if x < 0:
                        raise ValueError
                    y = batchint(y) if y else x + 1
                    for t in range(x, y):
                        tokens.add(t)
                result.tokens = tuple(sorted(tokens))
            else:
                raise ValueError

        return result

    def forloop(self, tokens: LookAhead, in_group: bool, silenced: bool) -> AstFor | None:
        offset = tokens.offset()

        if not tokens.pop_string('FOR'):
            return None

        def isvar(token: str):
            return len(token) == 2 and token.startswith('%')

        path = None
        mode = AstForParserMode.FileSet
        spec = []
        options = ''

        if isvar(variable := tokens.word()):
            variant = AstForVariant.Default
        elif len(variable) != 2 or not variable.startswith('/'):
            raise UnexpectedToken(variable)
        else:
            try:
                variant = AstForVariant(variable[1].upper())
            except ValueError:
                raise UnexpectedToken(variable)
            variable = tokens.word()
            if not isvar(variable):
                if variant == AstForVariant.FileParsing:
                    options = variable
                elif variant == AstForVariant.DescendRecursively:
                    path = unquote(variable)
                else:
                    raise UnexpectedToken(variable)
                variable = tokens.word()
                if not isvar(variable):
                    raise UnexpectedToken(variable)

        if (t := tokens.word()).upper() != 'IN':
            raise UnexpectedToken(t)

        tokens.skip_space()

        if not tokens.pop(Ctrl.NewGroup):
            raise UnexpectedToken(tokens.peek())

        with io.StringIO() as _spec:
            while not tokens.pop(Ctrl.EndGroup):
                if isinstance((t := next(tokens)), RedirectIO):
                    raise UnexpectedToken(t)
                _spec.write(t)
            spec_string = _spec.getvalue().strip()

        tokens.skip_space()

        if not tokens.pop_string('DO'):
            raise UnexpectedToken(tokens.peek())

        if not (body := self.sequence(tokens, in_group)):
            raise UnexpectedToken(tokens.peek())

        options = self.forloop_options(options)

        if variant == AstForVariant.FileParsing:
            quote_literal = "'" if options.usebackq else '"'
            quote_command = '`' if options.usebackq else "'"
            for q, m in (
                (quote_literal, AstForParserMode.Literal),
                (quote_command, AstForParserMode.Command),
            ):
                if spec_string.startswith(q):
                    if not spec_string.endswith(q):
                        raise UnexpectedToken(spec_string)
                    mode = m
                    spec = [spec_string[1:-1]]
                    break

        if not spec:
            spec = re.split('[\\s,;]+', spec_string)

        if variant == AstForVariant.NumericLoop:
            init = [0, 0, 0]
            for k, v in enumerate(spec):
                init[k] = batchint(v, 0)
            spec = batchrange(*init)

        return AstFor(
            offset,
            silenced,
            variant,
            variable[1],
            options,
            body,
            spec,
            spec_string,
            path,
            mode,
        )

    def block(self, tokens: LookAhead, in_group: bool):
        while True:
            while tokens.pop(Ctrl.NewLine):
                continue
            if in_group and tokens.pop(Ctrl.EndGroup):
                break
            if tokens.pop(Ctrl.EndOfFile):
                break
            if sequence := self.sequence(tokens, in_group):
                yield sequence
            else:
                break

    def group(
        self,
        tokens: LookAhead,
        redirects: dict[int, RedirectIO],
        silenced: bool,
    ) -> AstGroup | None:
        offset = tokens.offset()
        if tokens.peek() == Ctrl.NewGroup:
            self.lexer.parse_group()
            tokens.pop()
            sequences = list(self.block(tokens, True))
            group = AstGroup(offset, silenced, redirects, sequences)
            tokens.skip_space()
            group.redirects.update(self.redirects(tokens))
            return group

    def label(self, tokens: LookAhead, silenced: bool) -> AstLabel | None:
        if tokens.peek() != Ctrl.Label:
            return None
        offset = tokens.offset()
        lexer = self.lexer
        lexer.parse_label()
        tokens.pop()
        line = tokens.word()
        label = lexer.label(line)
        if (x := lexer.labels[label]) != offset:
            raise RuntimeError(F'Expected offset for label {label} to be {offset}, got {x} instead.')
        return AstLabel(offset, silenced, line, label)

    def statement(self, tokens: LookAhead, in_group: bool):
        at, _ = self.skip_prefix(tokens)
        silenced = at > 0
        if at <= 1 and (s := self.label(tokens, silenced)):
            return s
        if s := self.ifthen(tokens, in_group, silenced):
            return s
        if s := self.forloop(tokens, in_group, silenced):
            return s
        return self.pipeline(tokens, in_group, silenced)

    def sequence(self, tokens: LookAhead, in_group: bool) -> AstSequence | None:
        tokens.skip_space()
        head = self.statement(tokens, in_group)
        if head is None:
            return None
        node = AstSequence(head.offset, head)
        tokens.skip_space()
        while condition := AstCondition.Try(tokens.peek()):
            tokens.pop()
            tokens.skip_space()
            if not (statement := self.statement(tokens, in_group)):
                raise EmulatorException('Failed to parse conditional statement.')
            node.tail.append(
                AstConditionalStatement(statement.offset, condition, statement))
            tokens.skip_space()
        return node

    def parse(self, offset: int):
        tokens = LookAhead(self.lexer, offset)
        yield from self.block(tokens, False)
