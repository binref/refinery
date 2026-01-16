from __future__ import annotations

import io
import re

from collections import deque
from typing import overload

from refinery.lib.batch.lexer import BatchLexer
from refinery.lib.batch.model import (
    AstCommand,
    AstCondition,
    AstConditionalStatement,
    AstFor,
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
)
from refinery.lib.batch.state import BatchState
from refinery.lib.batch.util import batchint, unquote
from refinery.lib.patterns import formats
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
            return False
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
        while self.peek().isspace():
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

    def word(self, upper=False):
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

    def command(self, tokens: LookAhead, in_group: bool) -> AstCommand | None:
        ast = AstCommand(tokens.offset())
        tok = tokens.peek()
        cmd = ast.tokens
        if tok.upper() == 'SET':
            self.lexer.parse_set()
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
            cmd.append(tok)
            tokens.pop()
            tok = tokens.peek()
        if ast.tokens:
            return ast

    def pipeline(self, tokens: LookAhead, in_group: bool) -> AstPipeline | None:
        if head := self.command(tokens, in_group):
            node = AstPipeline(head.offset, [head])
            while tokens.pop(Ctrl.Pipe):
                if cmd := self.command(tokens, in_group):
                    node.parts.append(cmd)
                    continue
                raise UnexpectedToken(tokens.peek())
            return node

    def ifthen(self, tokens: LookAhead, in_group: bool) -> AstIf | None:
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
            try:
                cmp = AstIfCmp(cmp)
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
            then_do,
            else_do,
            variant,
            casefold,
            negated,
            cmp,
            lhs, rhs # type:ignore
        )

    def forloop(self, tokens: LookAhead, in_group: bool) -> AstFor | None:
        if not tokens.pop_string('FOR'):
            return None
        return None

    def group(self, tokens: LookAhead) -> AstGroup | None:
        offset = tokens.offset()
        if tokens.pop(Ctrl.NewGroup):
            self.lexer.parse_group()
            sequences: list[AstSequence] = []
            while not tokens.pop(Ctrl.EndGroup) and (sequence := self.sequence(tokens, True)):
                sequences.append(sequence)
            return AstGroup(offset, sequences)

    def label(self, tokens: LookAhead) -> AstLabel | None:
        offset = tokens.offset()
        lexer = self.lexer
        lexer.parse_label()
        if not tokens.pop(Ctrl.Label):
            lexer.parse_label_abort()
            return None
        line = tokens.word()
        label = lexer.label(line)
        if (x := lexer.labels[label]) != offset:
            raise RuntimeError(F'Expected offset for label {label} to be {offset}, got {x} instead.')
        return AstLabel(offset, line, label)

    def statement(self, tokens: LookAhead, in_group: bool):
        if s := self.label(tokens):
            return s
        if s := self.ifthen(tokens, in_group):
            return s
        if s := self.group(tokens):
            return s
        if s := self.forloop(tokens, in_group):
            return s
        return self.pipeline(tokens, in_group)

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
        while sequence := self.sequence(tokens, False):
            yield sequence
