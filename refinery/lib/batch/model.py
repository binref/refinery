from __future__ import annotations

import enum
import io

from dataclasses import dataclass, field
from typing import Generic, TypeVar, Union

from refinery.lib.batch.const import TILDE
from refinery.lib.structures import FlagAccessMixin

IntOrStr = TypeVar('IntOrStr', int, str)


class Ctrl(str, enum.Enum):
    NewLine             = '\n'  # noqa;
    NewGroup            = '('   # noqa;
    EndGroup            = ')'   # noqa;
    RunOnSuccess        = '&&'  # noqa;
    RunOnFailure        = '||'  # noqa;
    CommandSeparator    = '&'   # noqa;
    Pipe                = '|'   # noqa;
    EndOfFile           = ''    # noqa;
    Label               = ':'   # noqa;
    Equals              = '='   # noqa;
    IsEqualTo           = '=='  # noqa;

    def __str__(self):
        return self.value


class Word(str):
    pass


class Expected(str):
    pass


class Redirect(str, enum.Enum):
    Out = '>'
    OutAppend = '>>'
    In = '<'

    def __str__(self):
        return self.value


@dataclass
class RedirectIO:
    type: Redirect
    source: int
    target: int | str = -1

    @property
    def target_is_file(self) -> bool:
        return isinstance(self.target, str)

    @property
    def outbound(self):
        return self.type in (Redirect.Out, Redirect.OutAppend)

    def __str__(self):
        target = self.target
        string = F'{self.source}{self.type!s}'
        if target is None:
            return string
        return F'{string}{target}'

    def isspace(self):
        return False

    def upper(self):
        return None


Token = Union[str, Ctrl, RedirectIO]


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

    StripQuotes = q # noqa
    FullPath    = f # noqa
    DriveLetter = d # noqa
    PathOnly    = p # noqa
    NameOnly    = n # noqa
    Extension   = x # noqa
    ShortName   = s # noqa
    Attributes  = a # noqa
    DateTime    = t # noqa
    FileSize    = z # noqa

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
        if t == TILDE:
            return cls(1)
        return cls[chr(t)]


@dataclass
class ArgVar:
    offset: int | ellipsis = 0
    path: str | None = None
    flags: ArgVarFlags = ArgVarFlags.Empty

    def __str__(self):
        k = self.offset
        if k is (...):
            assert self.path is None
            assert self.flags is ArgVarFlags.Empty
            return '%*'
        p = F'${p}' if (p := self.path) is not None else ''
        return F'%{self.flags!s}{p}{k}'


class AstCondition(str, enum.Enum):
    NoCheck = '&'
    Success = '&&'
    Failure = '||'

    @classmethod
    def Try(cls, value):
        try:
            return cls(value)
        except ValueError:
            return None

    def __str__(self):
        return self.value


@dataclass
class AstNode:
    offset: int


@dataclass
class AstStatement(AstNode):
    ...


@dataclass
class AstLabel(AstStatement):
    line: str = ''
    label: str = ''


@dataclass
class AstCommand(AstNode):
    tokens: list[str | RedirectIO] = field(default_factory=list)


@dataclass
class AstSet(AstCommand):
    name: str = ""
    value: str = ""


@dataclass
class AstPipeline(AstStatement):
    parts: list[AstCommand] = field(default_factory=list)


@dataclass
class AstConditionalStatement(AstNode):
    condition: AstCondition
    statement: AstStatement


@dataclass
class AstSequence(AstStatement):
    head: AstStatement
    tail: list[AstConditionalStatement] = field(default_factory=list)


@dataclass
class AstGroup(AstStatement):
    sequences: list[AstSequence] = field(default_factory=list)


class AstForVariant(str, enum.Enum):
    D = 'D'
    R = 'R'
    L = 'L'
    F = 'F'
    Default = ''
    Folders = D
    Recurse = R
    Numbers = L
    FileSet = F


@dataclass
class AstFor(AstStatement):
    variant: AstForVariant
    variable: str
    body: AstNode
    spec: str | range
    path: str | None = None
    options: str | None = None


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


@dataclass
class AstIf(AstStatement, Generic[IntOrStr]):
    then_do: AstStatement
    else_do: AstStatement | None = None
    variant: AstIfVariant | None = None
    casefold: bool = True
    negated: bool = False
    cmp: AstIfCmp | None = None
    lhs: IntOrStr | None = None
    rhs: IntOrStr | None = None

    @property
    def var_int(self):
        var = self.lhs
        if not isinstance(var, int):
            raise RuntimeError
        return var

    @property
    def var_str(self):
        var = self.lhs
        if not isinstance(var, str):
            raise RuntimeError
        return var


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


class EmulatorException(Exception):
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


class EmulatorCommand:
    ast: AstCommand
    args: list[str]
    verb: str
    redirects: list[RedirectIO]

    def __init__(self, ast_command: AstCommand):
        self.ast = ast_command
        self.redirects = []
        self.args = []
        self.verb = ''
        argstr = io.StringIO()
        for token in ast_command.tokens:
            if isinstance(token, RedirectIO):
                self.redirects.append(token)
                continue
            if token.isspace():
                if self.verb:
                    argstr.write(token)
                continue
            if not self.verb:
                self.verb = token.strip()
                continue
            self.args.append(token)
            argstr.write(token)
        if not self.verb:
            raise ValueError('Empty Command')
        self.argument_string = argstr.getvalue().lstrip()

    def __str__(self):
        return ''.join(str(t) for t in self.ast.tokens).lstrip()
