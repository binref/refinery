from __future__ import annotations

import array
import codecs
import enum
import itertools
import ntpath
import re

from abc import ABC, abstractmethod
from typing import Generator, Generic, List, TypeVar, Union, overload

from refinery.lib.deobfuscation import cautious_eval_or_default
from refinery.lib.patterns import formats
from refinery.lib.types import buf

BatchCode = Union[str, List['BatchCode']]
Block = List[BatchCode]
IntOrStr = TypeVar('IntOrStr', int, str)


def batchint(expr: str):
    m = int(expr.startswith('-'))
    if expr[m:m + 2] in ('0x', '0X'):
        base = 16
    elif expr[m:m + 1] == '0':
        base = 8
    else:
        base = 10
    return int(expr, base)


class IfEq(Generic[IntOrStr]):
    def __init__(
        self,
        lhs: IntOrStr,
        rhs: IntOrStr,
    ):
        self.lhs = lhs
        self.rhs = rhs

    def EQU(self):
        return self.lhs == self.rhs

    def LEQ(self):
        return self.lhs <= self.rhs

    def LSS(self):
        return self.lhs < self.rhs


_PAREN_OPEN = 0x28
_PAREN_CLOSE = 0x29
_CARET = 0x5E
_QUOTE = 0x22
_LINEBREAK = 0x0A


class EmulatorError(Exception):
    pass


class UnexpectedToken(EmulatorError):
    def __init__(self, token: str) -> None:
        super().__init__(F'Unexpected token: {token}')


class ExecutionResult(ABC):
    @abstractmethod
    def longjump(self) -> bool:
        pass


class Exit(ExecutionResult):
    def __init__(self, code: int = 0, script_only: bool = True):
        self.code = code
        self.script_only = script_only

    def longjump(self) -> bool:
        return not self.script_only


class Goto(ExecutionResult):
    def __init__(self, label: str):
        self.label = label

    def longjump(self) -> bool:
        return True


class InvalidLabel(EmulatorError):
    def __init__(self, label: str):
        super().__init__(F'The following label was not found: {label}')


class EmulatedCommand(str):
    pass


class Condition(str, enum.Enum):
    Always = '&'
    IfOk = '&&'
    IfNotOk = '||'


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


class BatchFileEmulator:

    environments: list[dict[str, str]]
    code: Block
    labels: dict[str, list[int]]
    args: list[str]

    def __init__(
        self,
        data: str | buf,
        delayed_expansion: bool = False,
        extensions_enabled: bool = True,
        extensions_version: int = 2,
        file_system: dict | None = None,
        cwd: str = 'C:\\'
    ):
        self.delayed_expansion = delayed_expansion
        self.extensions_version = extensions_version
        self.extensions_enabled = extensions_enabled
        self.file_sytem_seed = file_system or {}
        self.cwd = cwd
        self.parse(data)

    @property
    def cwd(self):
        return self._cwd

    @cwd.setter
    def cwd(self, new: str):
        new = new.replace('/', '\\')
        if not new.endswith('\\'):
            new = F'{new}\\'
        if not ntpath.isabs(new):
            new = ntpath.join(self.cwd, new)
        if not ntpath.isabs(new):
            raise ValueError(F'Invalid absolute path: {new}')
        self._cwd = ntpath.normcase(ntpath.normpath(new))

    @property
    def ec(self) -> int:
        return self.errorlevel

    @ec.setter
    def ec(self, value: int | None):
        ec = value or 0
        self.environment['ERRORLEVEL'] = str(ec)
        self.errorlevel = ec

    def reset(self):
        self.labels = {}
        self.environments = [{}]
        self.delayexpands = [self.delayed_expansion]
        self.ext_settings = [self.extensions_enabled]
        self.file_system = dict(self.file_sytem_seed)
        self.dirstack = []
        self.args = []
        self.ec = None

    def _resolved(self, path: str) -> str:
        if not ntpath.isabs(path):
            path = F'{self.cwd}{path}'
        return ntpath.normcase(ntpath.normpath(path))

    def create_file(self, path: str, data: str = ''):
        self.file_system[self._resolved(path)] = data

    def append_file(self, path: str, data: str):
        path = self._resolved(path)
        if left := self.file_system.get(path, None):
            data = F'{left}{data}'
        self.file_system[path] = data

    def remove_file(self, path: str):
        self.file_system.pop(self._resolved(path), None)

    def ingest_file(self, path: str) -> str | None:
        return self.file_system.get(self._resolved(path))

    def exists_file(self, path: str) -> bool:
        return self._resolved(path) in self.file_system

    @property
    def environment(self):
        return self.environments[-1]

    @property
    def delayexpand(self):
        return self.delayexpands[-1]

    @property
    def ext_setting(self):
        return self.ext_settings[-1]

    @staticmethod
    def split_head(
        expression: str,
        toupper: bool = False,
        uncaret: bool = True,
        unquote: bool = False,
        terminator_letters: bytes = B'\x20\x09\x0B',
        terminator_strings: tuple[bytes, ...] = (),
    ):
        quote = False
        caret = False
        token = array.array("H")
        utf16 = expression.encode('utf-16le')
        utf16 = memoryview(utf16).cast('H')
        t1 = terminator_letters
        t2 = terminator_strings

        for k, char in enumerate(utf16):
            if not quote and not caret:
                if char in t1 or any(utf16[k:k + len(t)] == t for t in t2):
                    tail = expression[k:]
                    break
            if char == _QUOTE:
                quote = not quote
                if unquote:
                    continue
            elif quote:
                pass
            elif caret:
                caret = False
            elif char == _CARET:
                caret = True
                if uncaret:
                    continue
            token.append(char)
        else:
            tail = ''
        head = token.tobytes().decode('utf-16le')
        if toupper:
            head = head.upper()
        return head, tail.lstrip()

    @overload
    def expand(self, block: str, delay: bool = False) -> str:
        ...

    @overload
    def expand(self, block: list, delay: bool = False) -> list:
        ...

    def expand(self, block: BatchCode, delay: bool = False):
        def expansion(match: re.Match[str]):
            name = match.group(1)
            base = self.environment.get(name.upper(), '')
            if not (modifier := match.group(2)):
                return base
            if '=' in modifier:
                old, _, new = modifier.partition('=')
                kwargs = {}
                if old.startswith('~'):
                    old = old[1:]
                    kwargs.update(count=1)
                return base.replace(old, new, **kwargs)
            else:
                if not modifier.startswith(':~'):
                    raise EmulatorError
                offset, _, length = modifier[2:].partition(',')
                offset = batchint(offset)
                if offset < 0:
                    offset = max(0, len(base) + offset)
                if length:
                    end = offset + batchint(length)
                else:
                    end = len(base)
                return base[offset:end]
        if delay:
            pattern = r'!([^!:\n]*)()!'
        else:
            pattern = rf'%([^%:\n]*)(:(?:~{formats.integer}(?:,{formats.integer})?|[^=%\n]+=[^%\r\n]*))?%'
        if isinstance(block, str):
            return re.sub(pattern, expansion, block)
        else:
            return [self.expand(child) for child in block]

    def execute_set(self, command: str):
        check, rest = self.split_head(command, toupper=True)
        if check == '/P':
            self.ec = yield EmulatedCommand(F'set {command}')
            return
        if check == '/A':
            arithmetic = True
            command = rest
        else:
            arithmetic = False
        if not command:
            return
        command, _ = self.split_head(command, terminator_letters=B'')
        if command.startswith('"'):
            # This is how it works based on testing, even if it seems insane.
            command, _, what = command[1:].rpartition('"')
            command = command or what
        if arithmetic:
            integers = {}
            updated = {}
            for name, value in self.environment.items():
                try:
                    integers[name] = batchint(value)
                except ValueError:
                    pass
            for assignment in command.split(','):
                assignment = assignment.strip()
                name, _, expression = assignment.partition('=')
                expression = cautious_eval_or_default(expression, environment=integers)
                if expression is not None:
                    integers[name] = expression
                    updated[name] = str(expression)
                self.environment.update(updated)
        else:
            name, _, content = command.partition('=')
            name = name.upper()
            content, _ = self.split_head(content, terminator_letters=B'')
            if not content:
                self.environment.pop(name, None)
            else:
                self.environment[name] = content

    def execute_if(self, command: str):
        casefold = False
        negate = False
        check, rest = self.split_head(command, toupper=True)
        if check == '/I':
            casefold = True
            command, check, rest = rest, *self.split_head(rest)
        if check == 'NOT':
            negate = True
            command, check, rest = rest, *self.split_head(rest)
        if check == 'ERRORLEVEL':
            limit, rest = self.split_head(rest)
            limit = int(limit.strip(), 10)
            condition = limit <= self.ec
        elif check == 'CMDEXTVERSION':
            limit, rest = self.split_head(rest)
            limit = int(limit.strip(), 10)
            condition = limit <= self.extensions_version
        elif check == 'EXIST':
            path, rest = self.split_head(rest, unquote=True)
            condition = self.exists_file(path)
        elif check == 'DEFINED':
            name, rest = self.split_head(rest)
            condition = name.upper() in self.environment
        else:
            lhs, rest = self.split_head(
                command,
                toupper=False,
                unquote=True,
                terminator_strings=(B'==',)
            )
            if rest.startswith('=='):
                rest = rest[2:].lstrip()
                rhs, rest = self.split_head(rest, toupper=False, unquote=True)
                if casefold:
                    lhs = lhs.casefold()
                    rhs = rhs.casefold()
                condition = lhs == rhs
            else:
                cmp, rest = self.split_head(rest)
                if self.extensions_version < 1:
                    raise UnexpectedToken(cmp)
                rhs, rest = self.split_head(rest)
                if cmp == 'GTR':
                    rhs, lhs, cmp = lhs, rhs, 'LSS'
                if cmp == 'GEQ':
                    rhs, lhs, cmp = lhs, rhs, 'LEQ'
                if cmp == 'NEQ':
                    negate, cmp = not negate, 'EQU'
                try:
                    ilh = batchint(lhs)
                    irh = batchint(rhs)
                except ValueError:
                    pair = IfEq(lhs, rhs)
                else:
                    pair = IfEq(ilh, irh)
                if cmp == 'EQU':
                    condition = pair.EQU()
                elif cmp == 'LSS':
                    condition = pair.LSS()
                elif cmp == 'LEQ':
                    condition = pair.LEQ()
                else:
                    raise UnexpectedToken(cmp)
        if negate:
            condition = not condition
        return condition, rest

    def _commands(self, line: str):
        quote = False
        caret = False
        check = 0
        again = None
        for k, char in enumerate(line):
            if again:
                if quote or caret:
                    raise EmulatorError
                how = None
                end = None
                if again == char:
                    how = 2 * again
                    end = k + 1
                elif again == Condition.Always:
                    how = again
                    end = k
                again = None
                if end is not None and how is not None:
                    cmd = line[check:k - 1]
                    yield cmd.lstrip(), Condition(how)
                    check = end
                    continue
            if char == '"':
                quote = not quote
                continue
            if char == '\n':
                raise ValueError
            if quote:
                continue
            if caret:
                caret = False
                continue
            if char == '^':
                caret = True
                continue
            if char in '|&':
                again = char
        if (rest := line[check:]) and rest.strip():
            yield rest.lstrip(), Condition.Always

    def _check_condition(self, condition: Condition):
        if condition == Condition.Always:
            return True
        if condition == Condition.IfNotOk:
            return self.ec != 0
        if condition == Condition.IfOk:
            return self.ec == 0
        raise TypeError(condition)

    def goto(self, index: list[int]) -> tuple[Block, BatchCode, int]:
        if not index:
            index = [0]
        line = 0
        code = cursor = self.code
        for line in index:
            code, cursor = cursor, cursor[line]
        assert isinstance(code, list)
        return code, cursor, line

    def emulate(self, *args: str) -> Generator[EmulatedCommand, int | None, ExecutionResult]:
        index = [0]
        self.args[:] = args
        while True:
            block, _, offset = self.goto(index)
            state = yield from self.emulate_block(
                block,
                offset=offset,
                expand=True,
            )
            if isinstance(state, Goto):
                label = state.label.upper()
                if label == 'EOF':
                    return Exit()
                try:
                    index = self.labels[label]
                except KeyError as KE:
                    raise InvalidLabel(label) from KE
                else:
                    continue
            if isinstance(state, Exit):
                self.ec = state.code
                return state
            raise TypeError(state)

    def emulate_block(
        self,
        block: Block,
        offset: int = 0,
        expand: bool = False,
    ) -> Generator[EmulatedCommand, int | None, ExecutionResult]:
        it = block if offset <= 0 else itertools.islice(block, offset, None)
        ifelse = If.Inactive
        for code in it:
            if expand:
                code = self.expand(code)
            if If.Block in ifelse:
                if not isinstance(code, list):
                    raise EmulatorError(F'Expected a block while parsing If/Else; {ifelse!r}')
                if not ifelse.skip_block():
                    exit = (yield from self.emulate_block(code))
                    if exit.longjump():
                        return exit
                if If.Else in ifelse:
                    ifelse = If.Inactive
                else:
                    ifelse |= If.Else
                    ifelse &= ~If.Block
                continue
            if isinstance(code, list):
                if ifelse != If.Inactive:
                    raise EmulatorError('Unexpected block in the middle of if/else statement.')
                exit = (yield from self.emulate_block(code))
                if exit.longjump():
                    return exit
                continue
            condition = Condition.Always
            for command, next_condition in self._commands(code):
                if not self._check_condition(condition):
                    break
                condition = next_condition
                if self.delayexpand:
                    command = self.expand(command, True)
                head, tail = self.split_head(
                    command, toupper=True, uncaret=False)
                head = head.lstrip('@')
                if head == 'SET':
                    yield from self.execute_set(tail)
                elif head == 'SETLOCAL':
                    setting = tail.strip().upper()
                    delay = {
                        'DISABLEDELAYEDEXPANSION': False,
                        'ENABLEDELAYEDEXPANSION' : True,
                    }.get(setting, self.delayexpand)
                    cmdxt = {
                        'DISABLEEXTENSIONS': False,
                        'ENABLEEXTENSIONS' : True,
                    }.get(setting, self.ext_setting)
                    self.delayexpands.append(delay)
                    self.ext_settings.append(cmdxt)
                    self.environments.append(dict(self.environment))
                elif head == 'ENDLOCAL' and len(self.environments) > 1:
                    self.environments.pop()
                    self.delayexpands.pop()
                elif head == 'IF':
                    then, cmd = self.execute_if(tail)
                    if not cmd:
                        ifelse = If.Active | If.Block
                        if then:
                            ifelse |= If.Then
                        continue
                    elif then:
                        self.ec = yield EmulatedCommand(cmd)
                elif head == 'ELSE':
                    if If.Else not in ifelse:
                        raise UnexpectedToken(head)
                    if If.Then not in ifelse:
                        if not (cmd := tail.lstrip()):
                            ifelse |= If.Block
                            continue
                        else:
                            self.ec = yield EmulatedCommand(cmd)
                elif head == 'EXIT':
                    token, tail = self.split_head(tail, toupper=True)
                    script_only = False
                    if token == '/B':
                        script_only = True
                        token, tail = self.split_head(tail)
                    try:
                        exit_code = int(token, 10)
                    except ValueError:
                        exit_code = 0
                    return Exit(exit_code, script_only)
                elif head == 'CD' or head == 'CHDIR':
                    directory, _ = self.split_head(tail, unquote=True, terminator_letters=B'')
                    self.cwd = directory.rstrip()
                elif head == 'PUSHD':
                    directory, _ = self.split_head(tail, unquote=True, terminator_letters=B'')
                    self.dirstack.append(self.cwd)
                    self.cwd = directory.rstrip()
                elif head == 'POPD':
                    try:
                        self.cwd = self.dirstack.pop()
                    except IndexError:
                        pass
                elif head == 'GOTO':
                    label, tail = self.split_head(tail)
                    if label.startswith(':'):
                        label = label[1:]
                    self.ec = yield EmulatedCommand(command)
                    return Goto(label)
                else:
                    self.ec = yield EmulatedCommand(command)
                ifelse = If.Inactive
        return Exit()

    def _decode(self, data: buf):
        if data[:3] == B'\xEF\xBB\xBF':
            return codecs.decode(data[3:], 'utf8')
        elif data[:2] == B'\xFF\xFE':
            return codecs.decode(data[2:], 'utf-16le')
        elif data[:2] == B'\xFE\xFF':
            return codecs.decode(data[2:], 'utf-16be')
        else:
            return codecs.decode(data, 'cp1252')

    def parse(self, text: str | buf):
        self.reset()

        if not isinstance(text, str):
            text = self._decode(text)
        text = '\n'.join(
            line.rstrip() for line in re.split(r'[\r\n]+', text.strip()))

        utf16 = text.encode('utf-16le')
        utf16 = memoryview(utf16).cast('H')

        quote = False
        caret = False
        check = 0
        lines = self.code = []
        path_to_root = []

        def linebreak(k: int):
            nonlocal check
            line = text[check:k]
            check = k + 1
            strip = line.strip()
            if not strip:
                return
            lines.append(line)
            if strip[0] != ':':
                return
            label = strip[1:].strip()
            if not label:
                return
            if label[0] == ':':
                return
            label = label.upper()
            index = [len(n) - 1 for n in path_to_root]
            index.append(len(lines) - 1)
            self.labels[label] = index

        for k, char in enumerate(utf16):
            if char == _QUOTE:
                if quote := not quote:
                    caret = False
                continue
            if char == _LINEBREAK:
                if caret:
                    caret = False
                else:
                    linebreak(k)
                    quote = False
                continue
            if quote:
                continue
            if caret:
                caret = False
                continue
            if char == _CARET:
                caret = True
                continue
            if char == _PAREN_OPEN:
                linebreak(k)
                path_to_root.append(lines)
                block = []
                lines.append(block)
                lines = block
            if char == _PAREN_CLOSE:
                if not path_to_root:
                    continue
                linebreak(k)
                lines = path_to_root.pop()

        linebreak(len(text))
