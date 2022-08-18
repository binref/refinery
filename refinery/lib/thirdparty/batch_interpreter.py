#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Based on source code from: https://github.com/DissectMalware/batch_deobfuscator
# Original License: MIT License
# Copyright (c) 2018 Malwrologist
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# NOTE: The code was refactored and the following modifications were made:
#  - allow stripping used variable definitions
#  - allow stripping echo commands
#  - allow stripping comments
#  - allow processing of strings rather than files
from __future__ import annotations

import re
import os
import io

from dataclasses import dataclass, field
from enum import Enum, IntFlag, auto
from typing import Dict, Generator, List, NamedTuple, Optional
from collections import defaultdict


class _T(str, Enum):
    OPEN    = '(' # noqa
    CLOSE   = ')' # noqa
    ESCAPE  = '^' # noqa
    CONNECT = '&' # noqa
    PIPE    = '|' # noqa
    QUOTE   = '"' # noqa
    V1      = '%' # noqa
    V2      = '!' # noqa
    SPACE   = ' ' # noqa


class _S(int, Enum):
    INIT = auto()
    STRING = auto()
    ESCAPE = auto()
    VARIABLE_TYPE1 = auto()
    VARIABLE_TYPE2 = auto()


class STRIP(IntFlag):
    DEFINITION = 0b001 # noqa
    ECHO       = 0b010 # noqa
    COMMENT    = 0b100 # noqa
    ALL        = 0b111 # noqa
    NONE       = 0b000 # noqa


@dataclass
class ScriptVariable:
    definitions: Dict[int, str] = field(default_factory=dict)
    evaluations: List[int] = field(default_factory=list)

    @property
    def value(self):
        latest = max(self.definitions)
        return self.definitions[latest]


class DeobfuscatedLine(NamedTuple):
    depth: int
    value: str


class BatchDeobfuscator:
    variables: Dict[str, ScriptVariable]
    pending_subcommand: Optional[str]

    def __init__(self):
        if os.name == 'nt':
            variables = {name.lower(): value for name, value in os.environ.items()}
        else:
            variables = {
                'allusersprofile'                 : 'C:\\ProgramData',
                'appdata'                         : 'C:\\Users\\puncher\\AppData\\Roaming',
                'commonprogramfiles'              : 'C:\\Program Files\\Common Files',
                'commonprogramfiles(x86)"'        : 'C:\\Program Files (x86)\\Common Files',
                'commonprogramw6432'              : 'C:\\Program Files\\Common Files',
                'computername'                    : 'MISCREANTTEARS',
                'comspec'                         : 'C:\\WINDOWS\\system32\\cmd.exe',
                'driverdata'                      : 'C:\\Windows\\System32\\Drivers\\DriverData',
                'fps_browser_app_profile_string'  : 'Internet Explorer',
                'fps_browser_user_profile_string' : 'Default',
                'homedrive'                       : 'C:',
                'homepath'                        : '\\Users\\puncher',
                'java_home'                       : 'C:\\Program Files\\Amazon Corretto\\jdk11.0.7_10',
                'localappdata'                    : 'C:\\Users\\puncher\\AppData\\Local',
                'logonserver'                     : '\\\\MISCREANTTEARS',
                'number_of_processors'            : '4',
                'onedrive'                        : 'C:\\Users\\puncher\\OneDrive',
                'os'                              : 'Windows_NT',
                'path'                            : 'C:\\Program Files\\Amazon Corretto\\jdk11.0.7_10\\bin;C:\\WINDOWS\\system32;'
                                                    'C:\\WINDOWS;C:\\WINDOWS\\System32\\Wbem;C:\\WINDOWS\\System32\\WindowsPowerS'
                                                    'hell\\v1.0\\;C:\\Program Files\\dotnet\\;C:\\Program Files\\Microsoft SQL Se'
                                                    'rver\\130\\Tools\\Binn\\;C:\\Users\\puncher\\AppData\\Local\\Microsoft\\Wind'
                                                    'owsApps;%USERPROFILE%\\AppData\\Local\\Microsoft\\WindowsApps;',
                'pathext'                         : '.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC',
                'processor_architecture'          : 'AMD64',
                'processor_identifier'            : 'Intel Core Ti-83 Family 6 Model 158 Stepping 10, GenuineIntel',
                'processor_level'                 : '6',
                'processor_revision'              : '9e0a',
                'programdata'                     : 'C:\\ProgramData',
                'programfiles'                    : 'C:\\Program Files',
                'programfiles(x86)"'              : 'C:\\Program Files (x86)',
                'programw6432'                    : 'C:\\Program Files',
                'psmodulepath'                    : 'C:\\WINDOWS\\system32\\WindowsPowerShell\\v1.0\\Modules\\',
                'public'                          : 'C:\\Users\\Public',
                'sessionname'                     : 'Console',
                'systemdrive'                     : 'C:',
                'systemroot'                      : 'C:\\WINDOWS',
                'temp'                            : 'C:\\Users\\puncher\\AppData\\Local\\Temp',
                'tmp'                             : 'C:\\Users\\puncher\\AppData\\Local\\Temp',
                'userdomain'                      : 'MISCREANTTEARS',
                'userdomain_roamingprofile'       : 'MISCREANTTEARS',
                'username'                        : 'puncher',
                'userprofile'                     : 'C:\\Users\\puncher',
                'windir'                          : 'C:\\WINDOWS',
                '__compat_layer'                  : 'DetectorsMessageBoxErrors',
            }
        self.pending_subcommand = None
        self.variables = defaultdict(ScriptVariable)
        for name, value in variables.items():
            self.variables[name].definitions[-1] = value

    def read_logical_lines(self, text: str):
        logical_line = io.StringIO()
        for line in text.splitlines(False):
            if not line.endswith(_T.ESCAPE):
                logical_line.write(line)
                yield logical_line.getvalue()
                logical_line.seek(0)
                logical_line.truncate(0)
            else:
                logical_line.write(line)
                logical_line.write('\n')

    def commands(self, logical_line: str) -> Generator[str, None, None]:
        state = _S.INIT
        start = 0
        for offset, token in enumerate(logical_line):
            if state is _S.INIT:
                if token == _T.QUOTE:
                    state = _S.STRING
                elif token == _T.ESCAPE:
                    state = _S.ESCAPE
                elif token == _T.CONNECT or token == _T.PIPE:
                    yield logical_line[start:offset].strip()
                    start = offset + 1
            elif state is _S.STRING:
                if token == _T.QUOTE:
                    state = state.INIT
            elif state is _S.ESCAPE:
                state = _S.INIT
        last_command = logical_line[start:].strip()
        if last_command:
            yield last_command

    def evaluate_variable(self, lno, variable):
        pattern = (
            r'''(?P<delim>%|!)\s*(?P<name>[\w#$'()*+,-.?@\[\]`{}~ ]+)'''
            r'''(:~\s*(?P<index>[+-]?\d+)\s*,\s*(?P<length>[+-]?\d+)\s*)?(?P=delim)''')
        match = re.fullmatch(pattern, variable)
        if match is None:
            return variable
        var = self.variables.get(match.group('name').lower())
        if var is None:
            return variable
        value = var.value
        var.evaluations.append(lno)
        if match.group('index'):
            index = int(match.group('index'))
            length = int(match.group('length'))
            if length >= 0:
                value = value[index : length + index]
            else:
                value = value[index : length]
            return value
        return value

    def interpret(self, lno: int, command: str) -> None:
        command = command.strip()
        index = 0
        last = len(command) - 1
        while index < last and (command[index] == _T.SPACE or command[index] == _T.OPEN):
            if command[index] == _T.OPEN:
                while last > index and (command[last] == _T.SPACE or command[last] == _T.CLOSE):
                    if command[last] == _T.CLOSE:
                        last -= 1
                        break
                    last -= 1
            index += 1
        command = command[index : last + 1]
        if command.lower().startswith('cmd'):
            pattern = r"\s*(call)?cmd(.exe)?\s*((\/A|\/U|\/Q|\/D)\s+|((\/E|\/F|\/V):(ON|OFF))\s*)*(\/c|\/r)\s*(?P<cmd>.*)"
            match = re.search(pattern, command, re.IGNORECASE)
            if match and match.group('cmd'):
                cmd = match.group('cmd').strip(_T.QUOTE)
                self.pending_subcommand = cmd
        else:
            pattern = (
                r"(\s*(call)?\s*set\s+\"?(?P<var>[\w#$'()*+,-.?@\[\]`{}~ ]+)=\s*(?P<val>[^\"\n]*)\"?)|"
                r"(\s*(call)?\s*set\s+/p\s+\"?(?P<input>[\w#$'()*+,-.?@\[\]`{}~ ]+)=[^\"\n]*\"?)"
            )
            match = re.search(pattern, command, re.IGNORECASE)
            if match is None:
                return
            var = match.group('input')
            if var is not None:
                var = var.lower()
                val = '__input__'
            else:
                var = match.group('var').lower()
                val = match.group('val')
            self.variables[var].definitions[lno] = val

    def normalize(self, lno: int, command: str):
        result = ''
        state = _S.INIT
        stack = []
        for token in command:
            if state == _S.INIT:
                if token == _T.QUOTE:
                    state = _S.STRING
                    result += token
                elif token in ',;\t':
                    # commas (",") are replaced by spaces, unless they are part of a string in doublequotes
                    # semicolons (";") are replaced by spaces, unless they are part of a string in doublequotes
                    # tabs are replaced by a single space
                    # http://www.robvanderwoude.com/parameters.php
                    result += _T.SPACE
                elif token == _T.ESCAPE:
                    state = _S.ESCAPE
                    stack.append(_S.INIT)
                elif token == _T.V1:
                    variable_start = len(result)
                    result += _T.V1
                    stack.append(_S.INIT)
                    state = _S.VARIABLE_TYPE1
                elif token == _T.V2:
                    variable_start = len(result)
                    result += _T.V1
                    stack.append(_S.INIT)
                    state = _S.VARIABLE_TYPE2
                else:
                    result += token
            elif state == _S.STRING:
                if token == _T.QUOTE:
                    state = _S.INIT
                    result += token
                elif token == _T.V1:
                    variable_start = len(result)
                    result += _T.V1
                    stack.append(_S.STRING)
                    state = _S.VARIABLE_TYPE1
                elif token == _T.V2:
                    variable_start = len(result)
                    result += _T.V1
                    stack.append(_S.STRING)
                    state = _S.VARIABLE_TYPE2
                elif token == _T.ESCAPE:
                    state = _S.ESCAPE
                    stack.append(_S.STRING)
                else:
                    result += token
            elif state == _S.VARIABLE_TYPE1:
                if token.isdigit() and result[-1] == _T.V1:
                    result += token
                    state = stack.pop()
                elif token == _T.V1 and result[-1] != _T.V1:
                    result += _T.V1
                    value = self.evaluate_variable(lno, result[variable_start:].lower())
                    result = result[:variable_start]
                    result += value
                    state = stack.pop()
                elif token == _T.V1:
                    variable_start = len(result)
                    result += token
                elif token == _T.QUOTE:
                    if stack[-1] == _S.STRING:
                        result += token
                        stack.pop()
                        state = _S.INIT
                    else:
                        result += token
                elif token == _T.ESCAPE:
                    state = _S.ESCAPE
                    stack.append(_S.VARIABLE_TYPE1)
                else:
                    result += token
            elif state == _S.VARIABLE_TYPE2:
                if token == _T.V2 and result[-1] != _T.V1:
                    result += _T.V1
                    value = self.evaluate_variable(lno, result[variable_start:].lower())
                    result = result[:variable_start]
                    result += value
                    state = stack.pop()
                elif token == _T.V2:
                    variable_start = len(result)
                    result += token
                elif token == _T.QUOTE:
                    if stack[-1] == _S.STRING:
                        result += token
                        stack.pop()
                        state = _S.INIT
                    else:
                        result += token
                elif token == _T.ESCAPE:
                    state = _S.ESCAPE
                    stack.append(_S.VARIABLE_TYPE1)
                else:
                    result += token
            elif state == _S.ESCAPE:
                result += token
                state = stack.pop()
        return result.strip()

    def _interpret(self, text: str, lno: int = 0, depth: int = 0) -> Generator[DeobfuscatedLine, None, None]:
        for line in self.read_logical_lines(text):
            for command in self.commands(line):
                normalized = self.normalize(lno, command)
                self.interpret(lno, normalized)
                yield DeobfuscatedLine(depth, normalized)
                lno += 1
                if self.pending_subcommand is not None:
                    subcommand = BatchDeobfuscator()
                    for name, var in self.variables.items():
                        subcommand.variables[name].definitions[-1] = var.value
                    for result in subcommand._interpret(self.pending_subcommand, lno, depth + 1):
                        yield result
                        lno += 1
                    self.pending_subcommand = None

    def deobfuscate(
        self,
        text: str,
        mode: STRIP = STRIP.NONE
    ) -> str:
        lines = list(self._interpret(text))
        used = set()

        if mode & STRIP.DEFINITION:
            for variable in self.variables.values():
                if variable.evaluations:
                    used.update(variable.definitions.keys())

        def tab(depth):
            return ' ' * 3 * depth

        def output():
            depth = 0
            for lno, line in enumerate(lines):
                if lno in used:
                    continue
                if not line.value:
                    continue
                cmd = line.value.split()[0].lower()
                cmd, _, _ = cmd.partition('/')
                if mode & STRIP.ECHO and cmd == 'echo':
                    continue
                if mode & STRIP.COMMENT and (line.value.startswith('::') or cmd == 'rem'):
                    continue
                if line.depth > depth:
                    yield F'{tab(depth)}:: SUBCOMMAND'
                depth = line.depth
                yield F'{tab(depth)}{line.value}'

        return '\n'.join(output())
