from __future__ import annotations

import abc
import enum
import io
import itertools

from typing import Generic, TypeVar

from refinery.lib.batch.model import (
    AstCommand,
    AstFor,
    AstForOptions,
    AstForVariant,
    AstGroup,
    AstIf,
    AstLabel,
    AstNode,
    AstPipeline,
    AstSequence,
    AstStatement,
)

_A = TypeVar('_A', bound=AstNode)


class K(str, enum.Enum):
    DO = 'DO'
    ELSE = 'ELSE'
    FOR = 'FOR'
    IF = 'IF'
    IN = 'IN'
    NOT = 'NOT'
    SP = '\x20'

    def __str__(self):
        return self.value


class SynNodeBase(Generic[_A], abc.ABC):
    def __init__(self, ast: _A):
        self.ast = ast
        self.tab = 4 * K.SP

    @abc.abstractmethod
    def pretty(self, out: io.StringIO, indent: int = 0, indented: bool = False) -> bool:
        ...

    def __str__(self) -> str:
        with io.StringIO() as out:
            self.pretty(out)
            return out.getvalue()

    __repr__ = __str__


class SynNode(SynNodeBase[_A]):

    @abc.abstractmethod
    def __str__(self) -> str:
        ...

    def pretty(self, out: io.StringIO, indent: int = 0, indented: bool = False):
        if not indented:
            out.write(indent * self.tab)
        out.write(str(self))
        return True


class SynCommand(SynNode[AstCommand]):
    args: list[str]
    verb: str

    def __init__(self, ast: AstCommand):
        super().__init__(ast)
        self.silent = False
        self.args = []
        self.verb = ''
        arg_string = io.StringIO()
        for token in self.ast.fragments:
            if token.isspace():
                if self.verb:
                    arg_string.write(token)
                continue
            if not self.verb:
                self.verb = token.strip()
                continue
            self.args.append(token)
            arg_string.write(token)
        if not self.verb:
            raise ValueError('Empty Command')
        self.argument_string = arg_string.getvalue().lstrip()

    def __str__(self):
        with io.StringIO() as out:
            for rd in self.ast.redirects.values():
                out.write(str(rd))
                out.write(K.SP)
            if self.ast.silenced:
                out.write('@')
            out.write(self.verb)
            for a in itertools.islice(self.ast.fragments, 1, None):
                out.write(a)
            return out.getvalue()


class SynGroup(SynNodeBase[AstGroup]):
    def pretty(self, out: io.StringIO, indent: int = 0, indented: bool = False):
        tab = indent * self.tab
        if not indented:
            out.write(tab)
        out.write('(')
        for seq in self.ast.fragments:
            out.write('\n')
            SynSequence(seq).pretty(out, indent + 1, False)
        out.write('\n')
        out.write(tab)
        out.write(')')
        for rd in self.ast.redirects.values():
            out.write(K.SP)
            out.write(str(rd))
        return True


class SynPipeline(SynNode[AstPipeline]):
    def __str__(self):
        return '\x20|\x20'.join(str(SynCommand(p)) for p in self.ast.parts)


class SynLabel(SynNode[AstLabel]):
    def __str__(self):
        return F':{self.ast.label}'


class SynFor(SynNodeBase[AstFor]):
    def options(self, opt: AstForOptions) -> str:
        options = []
        if opt.usebackq:
            options.append('usebackq')
        if (ast := opt.asterisk) or opt.tokens != (0,):
            tokens = ','.join(str(t) for t in opt.tokens)
            if ast:
                tokens = F'{tokens}*'
            options.append(tokens)
        if c := opt.comment:
            options.append(F'eol={c}')
        if s := opt.skip:
            options.append(F'skip={s}')
        if (d := opt.delims) != '\x20\t':
            options.append(F'delims={d}')
        if not options:
            return ''
        options = ' '.join(options)
        return F' "{options}"'

    def pretty(self, out: io.StringIO, indent: int = 0, indented: bool = False):
        if not indented:
            out.write(self.tab * indent)
        if flag := (ast := self.ast).variant:
            out.write(F'{K.FOR} /')
            out.write(flag.value)
            if flag == AstForVariant.FileParsing:
                out.write(self.options(ast.options))
            elif flag == AstForVariant.DescendRecursively and (path := ast.path):
                out.write(K.SP)
                out.write(path)
        else:
            out.write(K.FOR)
        out.write(' %%')
        out.write(ast.variable)
        out.write(F' {K.IN} (')
        out.write(ast.spec_string)
        out.write(F') {K.DO} ')
        return SynSequence(ast.body).pretty(out, indent, True)


class SynIf(SynNodeBase[AstIf]):
    def pretty(self, out: io.StringIO, indent: int = 0, indented: bool = False):
        ast = self.ast
        if not indented:
            out.write(indent * self.tab)
        out.write(K.IF)
        if ast.casefold:
            out.write(' /I')
        if ast.negated:
            out.write(K.SP)
            out.write(K.NOT)
        if var := ast.variant:
            out.write(K.SP)
            out.write(var.value)
            out.write(K.SP)
            out.write(str(ast.lhs))
        else:
            cmp = ast.cmp
            assert cmp is not None
            out.write(F' {ast.lhs!s} {cmp.value} {ast.rhs!s}')
        out.write(K.SP)
        indented = SynSequence(ast.then_do).pretty(out, indent, indented)
        if else_do := ast.else_do:
            out.write(K.SP)
            out.write(K.ELSE)
            out.write(K.SP)
            indented = SynSequence(else_do).pretty(out, indent, indented)
        return indented


class SynSequence(SynNodeBase[AstSequence]):
    def pretty(self, out: io.StringIO, indent: int = 0, indented: bool = False):
        ast = self.ast
        indented = SynStatement(ast.head).pretty(out, indent, indented)
        for cmd in ast.tail:
            out.write(cmd.condition)
            out.write(K.SP)
            indented = SynStatement(cmd.statement).pretty(out, indent, indented)
        return indented


def SynStatement(ast: AstStatement):
    if isinstance(ast, AstFor):
        return SynFor(ast)
    if isinstance(ast, AstIf):
        return SynIf(ast)
    if isinstance(ast, AstPipeline):
        return SynPipeline(ast)
    if isinstance(ast, AstSequence):
        return SynSequence(ast)
    if isinstance(ast, AstGroup):
        return SynGroup(ast)
    if isinstance(ast, AstLabel):
        return SynLabel(ast)
    raise TypeError
