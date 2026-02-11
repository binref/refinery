from __future__ import annotations

import ntpath

from datetime import datetime
from random import randrange, seed
from uuid import uuid4

from refinery.lib.batch.model import MissingVariable
from refinery.lib.dt import date_from_timestamp, isodate

_DEFAULT_ENVIRONMENT = {
    'ALLUSERSPROFILE'           : r'C:\ProgramData',
    'APPDATA'                   : r'C:\Users\{u}\AppData\Roaming',
    'CommonProgramFiles'        : r'C:\Program Files\Common Files',
    'CommonProgramFiles(x86)'   : r'C:\Program Files (x86)\Common Files',
    'CommonProgramW6432'        : r'C:\Program Files\Common Files',
    'COMPUTERNAME'              : r'{h}',
    'ComSpec'                   : r'C:\WINDOWS\system32\cmd.exe',
    'DriverData'                : r'C:\Windows\System32\Drivers\DriverData',
    'HOMEDRIVE'                 : r'C:',
    'HOMEPATH'                  : r'\Users\{u}',
    'LOCALAPPDATA'              : r'C:\Users\{u}\AppData\Local',
    'LOGONSERVER'               : r'\\{h}',
    'NUMBER_OF_PROCESSORS'      : r'16',
    'OneDrive'                  : r'C:\Users\{u}\OneDrive',
    'OS'                        : r'Windows_NT',
    'PATHEXT'                   : r'.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC',
    'PROCESSOR_ARCHITECTURE'    : r'AMD64',
    'PROCESSOR_IDENTIFIER'      : r'Intel64 Family 6 Model 158 Stepping 10, GenuineIntel',
    'PROCESSOR_LEVEL'           : r'6',
    'PROCESSOR_REVISION'        : r'99ff',
    'ProgramData'               : r'C:\ProgramData',
    'ProgramW6432'              : r'C:\Program Files',
    'ProgramFiles'              : r'C:\Program Files',
    'ProgramFiles(x86)'         : r'C:\Program Files (x86)',
    'PUBLIC'                    : r'C:\Users\Public',
    'SESSIONNAME'               : r'Console',
    'SystemDrive'               : r'C:',
    'SystemRoot'                : r'C:\WINDOWS',
    'TEMP'                      : r'C:\Users\{u}\AppData\Local\Temp',
    'TMP'                       : r'C:\Users\{u}\AppData\Local\Temp',
    'USERDOMAIN'                : r'{h}',
    'USERDOMAIN_ROAMINGPROFILE' : r'{h}',
    'USERNAME'                  : r'{u}',
    'USERPROFILE'               : r'C:\Users\{u}',
    'WINDIR'                    : r'C:\WINDOWS',
    'PATH': ';'.join(
        [
            r'C:\Windows',
            r'C:\Windows\System32',
            r'C:\Windows\System32\Wbem',
            r'C:\Windows\System32\WindowsPowerShell\v1.0\\',
            r'C:\Windows\System32\OpenSSH\\',
            r'C:\Program Files\dotnet\\',
        ]
    ),
}


class BatchState:

    name: str | None
    args: list[str]

    environments: list[dict[str, str]]
    delayexpands: list[bool]
    ext_settings: list[bool]

    _for_loops: list[dict[str, str]]
    file_system: dict[str, str]

    def __init__(
        self,
        delayed_expansion: bool = False,
        extensions_enabled: bool = True,
        extensions_version: int = 2,
        environment: dict | None = None,
        file_system: dict | None = None,
        username: str = 'Administrator',
        hostname: str | None = None,
        now: int | float | str | datetime | None = None,
        cwd: str = 'C:\\',
        filename: str | None = '',
        echo: bool = True
    ):
        self.extensions_version = extensions_version
        file_system = file_system or {}
        environment = environment or {}
        if hostname is None:
            hostname = str(uuid4())
        for key, value in _DEFAULT_ENVIRONMENT.items():
            environment.setdefault(
                key.upper(),
                value.format(h=hostname, u=username)
            )
        if isinstance(now, str):
            now = isodate(now)
        if isinstance(now, (int, float)):
            now = date_from_timestamp(now)
        if now is None:
            now = datetime.now()
        self.cwd = cwd
        self.now = now
        seed(self.now.timestamp())
        self.hostname = hostname
        self.username = username
        self.labels = {}
        self._for_loops = []
        self.environments = [environment]
        self.delayexpands = [delayed_expansion]
        self.ext_settings = [extensions_enabled]
        self.file_system = file_system
        self.dirstack = []
        self.linebreaks = []
        self.name = filename
        if self.name == '':
            self.name = F'{uuid4()}.bat'
        self.args = []
        self._cmd = ''
        self.ec = None
        self.echo = echo

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

    @property
    def command_line(self):
        return self._cmd

    @command_line.setter
    def command_line(self, value: str):
        self._cmd = value
        self.args = value.split()

    def envar(self, name: str, default: str | None = None) -> str:
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
        return self.environments[-1]

    @property
    def delayexpand(self):
        return self.delayexpands[-1]

    @property
    def ext_setting(self):
        return self.ext_settings[-1]

    @property
    def for_loop_variables(self):
        if vars := self._for_loops:
            return vars[-1]
        else:
            return None
