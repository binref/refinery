from __future__ import annotations

import enum
import sys

from dataclasses import dataclass, field
from functools import cached_property
from typing import Generic, TypeVar, Union

from refinery.lib.batch.util import batchrange
from refinery.lib.structures import FlagAccessMixin

IntOrStr = TypeVar('IntOrStr', int, str)


class Ctrl(str, enum.Enum):
    At                  = '@'   # noqa;
    Semicolon           = ';'   # noqa;
    Comma               = ','   # noqa;
    Label               = ':'   # noqa;
    Equals              = '='   # noqa;
    NewGroup            = '('   # noqa;
#   The following can terminate a command:
    EndGroup            = ')'   # noqa;
    NewLine             = '\n'  # noqa;
    Ampersand           = '&'   # noqa;
    Pipe                = '|'   # noqa;
    EndOfFile           = ''    # noqa;

    def __str__(self):
        return self.value

    def upper(self):
        return self


class Word(str):
    def upper(self):
        return Word(super().upper())


class Expected(str):
    pass


class Redirect(str, enum.Enum):
    OutCreate = '>'
    OutAppend = '>>'
    In = '<'

    def __str__(self):
        return self.value

    def __repr__(self):
        return self.name


@dataclass(unsafe_hash=True)
class RedirectIO:
    type: Redirect
    source: int
    target: int | str = -1

    @property
    def target_is_file(self) -> bool:
        return isinstance(self.target, str)

    @property
    def is_out_create(self):
        return self.type == Redirect.OutCreate

    @property
    def is_out_append(self):
        return self.type == Redirect.OutAppend

    @property
    def is_input(self):
        return self.type == Redirect.In

    def __str__(self):
        target = self.target
        string = F'{self.source}{self.type!s}'
        if target is None:
            return string
        if isinstance(target, int):
            target = F'&{target}'
        elif any(p in target for p in ';,=\x20\t\v'):
            target = F'"{target}"'
        return F'{string}{target}'

    def isspace(self):
        return False

    def upper(self):
        return self


Token = Union[Word, Ctrl, RedirectIO]


class ArgVarFlags(FlagAccessMixin, enum.IntFlag):
    Empty = 0

    q = 0b0000_00001
    d = 0b0000_00010
    p = 0b0000_00100
    n = 0b0000_01000
    x = 0b0000_10000
    s = 0b0001_00000
    a = 0b0010_00000
    t = 0b0100_00000
    z = 0b1000_00000
    f = d | p | n | x

    StripQuotes   = q # noqa
    FullPath      = f # noqa
    DriveLetter   = d # noqa
    FilePath      = p # noqa
    FileName      = n # noqa
    FileExtension = x # noqa
    ShortName     = s # noqa
    Attributes    = a # noqa
    DateTime      = t # noqa
    FileSize      = z # noqa

    def __str__(self):
        options = self.__class__
        value = self.value
        string = ''
        for flag, char in (
            (options.q, '~'),
            (options.f, 'f'),
        ):
            if value & flag == flag:
                string += char
                value ^= flag
        for flag in options:
            if value & flag == flag:
                assert flag.name
                string += flag.name
        return string

    @classmethod
    def FromToken(cls, t: int):
        c = chr(t)
        if c == '~':
            return cls(1)
        if c == 'q':
            raise KeyError
        return cls[c]


@dataclass
class ArgVar:
    offset: int | ellipsis = -1
    path: str | None = None
    flags: ArgVarFlags = ArgVarFlags.Empty

    def __repr__(self):
        k = self.offset
        if k is (...):
            assert self.path is None
            assert self.flags is ArgVarFlags.Empty
            return '%*'
        elif k < 0:
            k = '?'
        p = F'${p}' if (p := self.path) is not None else ''
        return F'%{self.flags!s}{p}{k}'

    __str__ = __repr__


class AstCondition(str, enum.Enum):
    NoCheck = '&'
    Success = '&&'
    Failure = '||'

    def __str__(self):
        return self.value


@dataclass(repr=False)
class AstNode:
    offset: int
    parent: AstNode | None

    def is_descendant_of(self, ast: AstNode | None):
        parent = self.parent
        if parent is ast:
            return True
        if parent is None:
            return False
        return parent.is_descendant_of(ast)

    @cached_property
    def depth(self):
        if (p := self.parent) is None:
            return 0
        return 1 + p.depth

    def __repr__(self):
        try:
            synth = sys.modules['refinery.lib.batch.synth']
        except KeyError:
            return super().__repr__()
        else:
            return str(synth.synthesize(self))


@dataclass(repr=False)
class AstStatement(AstNode):
    silenced: bool


@dataclass(repr=False)
class AstLabel(AstStatement):
    line: str = ''
    label: str = ''


@dataclass(repr=False)
class AstCommand(AstStatement):
    redirects: dict[int, RedirectIO] = field(default_factory=dict)
    fragments: list[str] = field(default_factory=list)


@dataclass(repr=False)
class AstGroup(AstStatement):
    redirects: dict[int, RedirectIO] = field(default_factory=dict)
    fragments: list[AstSequence] = field(default_factory=list)


@dataclass(repr=False)
class AstPipeline(AstStatement):
    parts: list[AstCommand | AstGroup] = field(default_factory=list)


@dataclass(repr=False)
class AstConditionalStatement(AstNode):
    condition: AstCondition
    statement: AstStatement

    def __repr__(self):
        return F'{self.condition.value} {self.statement!r}'


@dataclass(repr=False)
class AstSequence(AstNode):
    head: AstStatement
    tail: list[AstConditionalStatement] = field(default_factory=list)


class AstForVariant(str, enum.Enum):
    D = 'D'
    R = 'R'
    L = 'L'
    F = 'F'
    Default = ''
    MatchFolders = D
    DescendRecursively = R
    NumericLoop = L
    FileParsing = F


class AstForParserMode(enum.IntEnum):
    FileSet = 0
    Literal = 1
    Command = 2


@dataclass
class AstForOptions:
    comment: str | None = None
    skip: int = 0
    tokens: tuple[int, ...] = (0,)
    asterisk: bool = False
    delims: str = '\x20\t'
    usebackq: bool = False


@dataclass(repr=False)
class AstFor(AstStatement):
    variant: AstForVariant
    variable: str
    options: AstForOptions
    body: AstSequence
    spec: list[str] | batchrange
    spec_string: str
    path: str | None
    mode: AstForParserMode

    @property
    def specline(self):
        spec = self.spec
        if isinstance(spec, batchrange):
            raise AttributeError
        try:
            return spec[0]
        except IndexError:
            raise AttributeError


class AstIfVariant(str, enum.Enum):
    Defined = 'DEFINED'             # IF DEFINED VARIABLE
    CmdExtVersion = 'CMDEXTVERSION' # IF CMDEXTVERSION NUMBER
    Exist = 'EXIST'                 # IF EXIST PATH
    ErrorLevel = 'ERRORLEVEL'       # IF ERRORLEVEL NUMBER


class AstIfCmp(str, enum.Enum):
    STR = '=='
    EQU = 'EQU'
    NEQ = 'NEQ'
    LSS = 'LSS'
    LEQ = 'LEQ'
    GTR = 'GTR'
    GEQ = 'GEQ'


@dataclass(repr=False)
class AstIf(AstStatement, Generic[IntOrStr]):
    then_do: AstSequence
    else_do: AstSequence | None = None
    variant: AstIfVariant | None = None
    casefold: bool = True
    negated: bool = False
    cmp: AstIfCmp | None = None
    lhs: IntOrStr | None = None
    rhs: IntOrStr | None = None

    @property
    def var_int(self):
        var = self.lhs
        if isinstance(var, int):
            return var
        raise AttributeError

    @property
    def var_str(self):
        var = self.lhs
        if isinstance(var, str):
            return var
        raise AttributeError


class If(enum.IntFlag):
    Inactive = 0b0000
    Active = 0b0001
    Block = 0b0010
    Then = 0b0100
    Else = 0b1000

    def skip_block(self):
        skip = If.Then not in self
        if If.Else in self:
            skip = not skip
        return skip


class MissingVariable(LookupError):
    pass


class EmulatorException(Exception):
    pass


class InputLocked(EmulatorException):
    def __str__(self):
        return 'The emulation could not continue because a command is waiting for input.'


class AbortExecution(EmulatorException):
    pass


class EmulatorLongJump(EmulatorException):
    pass


class Goto(EmulatorLongJump):
    def __init__(self, label: str):
        self.label = label


class Call(EmulatorLongJump):
    def __init__(self, label: str, offset: int):
        self.label = label
        self.offset = offset


class Exit(EmulatorLongJump):
    def __init__(self, code: int, exit: bool):
        self.code = code
        self.exit = exit


class UnexpectedEOF(EmulatorException, EOFError):
    pass


class UnexpectedToken(EmulatorException):
    def __init__(self, token, msg: str | None = None) -> None:
        if isinstance(token, int):
            token = chr(token)
        else:
            token = str(token)
        end = msg and F': {msg}' or '.'
        super().__init__(F'The token "{token}" was unexpected{end}')


class UnexpectedFirstToken(UnexpectedToken):
    def __init__(self, token: str | int) -> None:
        super().__init__(token, 'This token may not occur as the first token in a line.')


class InvalidLabel(EmulatorException):
    def __init__(self, label: str):
        self.label = label

    def __str__(self):
        return F'The following label was not found: {self.label}'
