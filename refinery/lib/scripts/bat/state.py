from __future__ import annotations

import ntpath

from datetime import datetime
from enum import Enum
from random import randrange, seed
from uuid import uuid4

from refinery.lib.dt import date_from_timestamp, isodate
from refinery.lib.scripts.bat.model import MissingVariable
from refinery.lib.scripts.win32const import make_win32_environment


class ErrorZero(int, Enum):
    Val = 0

    def __bool__(self):
        return True

    def __str__(self):
        return '0'

    __repr__ = __str__


class RetainVariable(str, Enum):
    Val = ''


class BatchState:

    name: str
    args: list[str]

    now: datetime
    start_time: datetime

    environment_stack: list[dict[str, str | RetainVariable]]
    delayexpand_stack: list[bool]
    cmdextended_stack: list[bool]

    _for_loops: list[dict[str, str]]
    file_system: dict[str, str]

    def __init__(
        self,
        delayexpand: bool = False,
        extensions_enabled: bool = True,
        extensions_version: int = 2,
        environment: dict | None = None,
        file_system: dict | None = None,
        username: str = 'Administrator',
        hostname: str | None = None,
        now: int | float | str | datetime | None = None,
        cwd: str = 'C:\\',
        filename: str | None = '',
        echo: bool = True,
        codec: str = 'cp1252',
    ):
        self.extensions_version = extensions_version
        file_system = file_system or {}
        environment = environment or {}
        if hostname is None:
            hostname = str(uuid4())
        for key, value in make_win32_environment(username, hostname).items():
            environment.setdefault(key.upper(), value)
        if isinstance(now, str):
            now = isodate(now)
        if isinstance(now, (int, float)):
            now = date_from_timestamp(now)
        if now is None:
            now = datetime.now()
        self.cwd = cwd
        self.now = now
        self.start_time = now
        seed(self.now.timestamp())
        self.hostname = hostname
        self.username = username
        self.labels = {}
        self._for_loops = []
        self.environment_stack = [environment]
        self.delayexpand_stack = [delayexpand]
        self.cmdextended_stack = [extensions_enabled]
        self.file_system = file_system
        self.dirstack = []
        self.linebreaks = []
        self.name = filename or F'{uuid4()}.bat'
        self.args = []
        self._cmd = ''
        self.ec = None
        self.echo = echo
        self.codec = codec

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
    def ec(self) -> int | ErrorZero:
        return self.errorlevel

    @ec.setter
    def ec(self, value: int | ErrorZero | None):
        ec = value or 0
        self.environment['ERRORLEVEL'] = str(ec)
        self.errorlevel = ec

    @property
    def command_line(self):
        return self._cmd

    @command_line.setter
    def command_line(self, value: str):
        self._cmd = value
        self.args = value.split()

    def envar(self, name: str, default: str | None = None) -> str | RetainVariable:
        name = name.upper()
        if name in (e := self.environment):
            return e[name]
        elif name == 'DATE':
            return self.now.strftime('%Y-%m-%d')
        elif name == 'TIME':
            time = self.now.strftime('%M:%S,%f')
            return F'{self.now.hour:2d}:{time:.8}'
        elif name == 'RANDOM':
            return str(randrange(0, 32767))
        elif name == 'ERRORLEVEL':
            return str(self.ec)
        elif name == 'CD':
            return self.cwd
        elif name == 'CMDCMDLINE':
            line = self.envar('COMSPEC', 'cmd.exe')
            if args := self.args:
                args = ' '.join(args)
                line = F'{line} /c "{args}"'
            return line
        elif name == 'CMDEXTVERSION':
            return str(self.extensions_version)
        elif name == 'HIGHESTNUMANODENUMBER':
            return '0'
        elif default is not None:
            return default
        else:
            raise MissingVariable

    def resolve_path(self, path: str) -> str:
        if not ntpath.isabs(path):
            path = F'{self.cwd}{path}'
        return ntpath.normcase(ntpath.normpath(path))

    def create_file(self, path: str, data: str = ''):
        self.file_system[self.resolve_path(path)] = data

    def append_file(self, path: str, data: str):
        path = self.resolve_path(path)
        if left := self.file_system.get(path, None):
            data = F'{left}{data}'
        self.file_system[path] = data

    def remove_file(self, path: str):
        self.file_system.pop(self.resolve_path(path), None)

    def ingest_file(self, path: str) -> str | None:
        return self.file_system.get(self.resolve_path(path))

    def exists_file(self, path: str) -> bool:
        return self.resolve_path(path) in self.file_system

    def sizeof_file(self, path: str) -> int:
        if data := self.ingest_file(path):
            return len(data)
        return -1

    def new_forloop(self) -> dict[str, str]:
        new = {}
        old = self.for_loop_variables
        if old is not None:
            new.update(old)
        self._for_loops.append(new)
        return new

    def end_forloop(self):
        self._for_loops.pop()

    @property
    def environment(self):
        return self.environment_stack[-1]

    @property
    def delayexpand(self):
        return self.delayexpand_stack[-1]

    @delayexpand.setter
    def delayexpand(self, v):
        self.delayexpand_stack[-1] = v

    @property
    def cmdextended(self):
        return self.cmdextended_stack[-1]

    @cmdextended.setter
    def cmdextended(self, v):
        self.cmdextended_stack[-1] = v

    @property
    def for_loop_variables(self):
        if vars := self._for_loops:
            return vars[-1]
        else:
            return None
