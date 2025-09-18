from __future__ import annotations

import codecs
import enum
import re

from typing import List, Union, overload

from refinery.lib.deobfuscation import cautious_eval_or_default
from refinery.lib.types import buf

Block = Union[str, List['Block']]


class UnexpectedToken(RuntimeError):
    def __init__(self, token: str):
        super().__init__(F'Unexpected token: "{token}"')


class EmulatedCommand(str):
    pass


class Condition(str, enum.Enum):
    Always = '&'
    IfOk = '&&'
    IfNotOk = '||'


class BatchFileEmulator:

    environments: list[dict[str, str]]
    blocks: list[Block]
    labels: dict[str, list[int]]

    def __init__(self, data: str | buf, delayed_expansion: bool = False):
        self.delayed_expansion = delayed_expansion
        self.parse(data)

    def reset(self):
        self.blocks = []
        self.labels = {}
        self.environments = [{}]
        self.delayexpands = [self.delayed_expansion]
        self.errorlevel = 0
        self._current_index = None
        self._current_block = None

    @property
    def environment(self):
        return self.environments[-1]

    @property
    def delayexpand(self):
        return self.delayexpands[-1]

    @staticmethod
    def split_head(expression: str, uppercase_head: bool = True):
        quote = False
        split = 0
        for k, token in enumerate(expression):
            if token.isspace():
                if not quote:
                    split = k
            elif split:
                head = expression[:split]
                tail = expression[k:]
                break
            elif token == '"':
                quote = not quote
        else:
            head = expression
            tail = ''
        if uppercase_head:
            head = head.upper()
        return head, tail

    @overload
    def expand(self, block: str, delay: bool = False) -> str:
        ...

    @overload
    def expand(self, block: list, delay: bool = False) -> list:
        ...

    def expand(self, block: Block, delay: bool = False):
        def expansion(match: re.Match[str]):
            name = match.group(1)
            base = self.environment.get(name.casefold(), '')
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
                    raise RuntimeError
                offset, _, length = modifier[2:].partition(',')
                offset = int(offset)
                if offset < 0:
                    offset = max(0, len(base) + offset)
                if length:
                    end = offset + int(length)
                else:
                    end = len(base)
                return base[offset:end]
        if delay:
            pattern = r'!([^!:\n]*)()!'
        else:
            pattern = r'%([^%:\n]*)(:(?:~-?\d+(?:,-?\d+)?|[^=%\n]+=[^%\r\n]*))?%'
        if isinstance(block, str):
            return re.sub(pattern, expansion, block)
        else:
            return [self.expand(child) for child in block]

    def execute_set(self, command: str):
        check, rest = self.split_head(command)
        if check == '/P':
            yield EmulatedCommand(F'set {command}')
            return
        if check == '/A':
            arithmetic = True
            command = rest
        else:
            arithmetic = False
        if not command:
            return
        if command.startswith('"'):
            # This is how it works based on testing, even if it seems insane.
            command, _, _ = command[1:].rpartition('"')
        if arithmetic:
            integers = {}
            updated = {}
            for name, value in self.environment.items():
                try:
                    integers[name] = int(value, 0)
                except Exception:
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
            name = name.casefold()
            if not content:
                self.environment.pop(name, None)
            else:
                self.environment[name] = content

    def _commands(self, line: str):
        quote = False
        caret = False
        check = 0
        again = None
        for k, char in enumerate(line):
            if again:
                if quote or caret:
                    raise RuntimeError
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
            return self.errorlevel != 0
        if condition == Condition.IfOk:
            return self.errorlevel == 0
        raise TypeError(condition)

    def _start_access(self, index: list[int]):
        path = iter(index)
        main = next(path)
        if self._current_index == main:
            cursor = self._current_block
            if cursor is None:
                raise RuntimeError
        else:
            cursor = self.blocks[main]
            cursor = self.expand(cursor)
            self._current_index = main
            self._current_block = cursor
        return cursor, path

    def goto(self, index: list[int], advance=True):
        cursor, path = self._start_access(index)
        for k in path:
            cursor = cursor[k]
        return cursor

    def advance(self, index: list[int], condition: Condition) -> str | None:
        cursor, path = self._start_access(index)
        ceiling = [self.blocks]
        for k in path:
            if not isinstance(cursor, list):
                raise IndexError
            ceiling.append(cursor)
            cursor = cursor[k]
        if execute_block := self._check_condition(condition):
            while isinstance(cursor, list):
                index.append(0)
                ceiling.append(cursor)
                cursor = cursor[0]
        for i in range(len(index) - 1, -1, -1):
            k = index[i] + 1
            if k < len(ceiling[i]):
                index[i] = k
                del index[i + 1:]
                break
        else:
            index.clear()
        if execute_block:
            if not isinstance(cursor, str):
                raise RuntimeError
            return cursor

    def emulate(self):
        index = [0]
        condition = Condition.Always

        while index:
            if (block := self.advance(index, condition)) is None:
                condition = Condition.Always
                continue
            for command, condition in self._commands(block):
                if self.delayexpand:
                    command = self.expand(command, True)
                head, tail = self.split_head(command, True)
                if head == 'SET':
                    yield from self.execute_set(tail)
                elif head == 'SETLOCAL':
                    delay = {
                        'DISABLEDELAYEDEXPANSION': False,
                        'ENABLEDELAYEDEXPANSION' : True,
                    }.get(tail.strip().upper(), self.delayexpand)
                    self.delayexpands.append(delay)
                    self.environments.append(dict(self.environment))
                elif head == 'ENDLOCAL' and len(self.environments) > 1:
                    self.environments.pop()
                    self.delayexpands.pop()
                else:
                    yield EmulatedCommand(command)

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

        quote = False
        caret = False
        check = 0
        lines = self.blocks
        path_to_root = []

        def commit(k: int):
            nonlocal check
            line = text[check:k]
            check = k + 1
            if not line.strip():
                return
            lines.append(line)
            if not line.startswith(':'):
                return
            label = line[1:].strip().casefold()
            if not label.startswith(':'):
                self.labels[label] = [len(n) - 1 for n in path_to_root]

        for k, char in enumerate(text):
            if char == '"':
                quote = not quote
                continue
            if char == '\n':
                if caret:
                    caret = False
                else:
                    commit(k)
                    quote = False
                continue
            if quote:
                continue
            if caret:
                caret = False
                continue
            if char == '^':
                caret = True
                continue
            if char == '(':
                commit(k)
                path_to_root.append(lines)
                block = []
                lines.append(block)
                lines = block
            if char == ')':
                commit(k)
                try:
                    lines = path_to_root.pop()
                except IndexError as IE:
                    raise UnexpectedToken(char) from IE

        commit(len(text))
