from __future__ import annotations

import base64
import codecs
import io
import os
import re

from refinery.units import Unit


def _split_argv(cmdline: str) -> list[str]:
    """
    Split a command line into argv using MSVC CRT rules.

    The algorithm follows the MSVC C runtime documentation:
    - Whitespace outside quotes separates arguments.
    - A double quote toggles quote state.
    - Backslashes are literal unless immediately preceding a double quote.
    - 2N   backslashes before a quote produce N backslashes and the quote toggles state.
    - 2N+1 backslashes before a quote produce N backslashes and a literal quote.
    """
    args: list[str] = []
    buf = io.StringIO()
    i = 0
    n = len(cmdline)
    quoted = False

    while i < n:
        c = cmdline[i]
        if c == '\\':
            bs = 0
            while i < n and cmdline[i] == '\\':
                bs += 1
                i += 1
            if i < n and cmdline[i] == '"':
                buf.write('\\' * (bs // 2))
                if bs % 2 == 1:
                    buf.write('"')
                else:
                    quoted = not quoted
                i += 1
            else:
                buf.write('\\' * bs)
        elif c == '"':
            quoted = not quoted
            i += 1
        elif c in (' ', '\t') and not quoted:
            if b := buf.getvalue():
                args.append(b)
                buf.seek(0)
                buf.truncate(0)
            i += 1
        else:
            buf.write(c)
            i += 1
    if b := buf.getvalue():
        args.append(b)
    return args


_PS_EXECUTABLE_NAMES = frozenset({
    'powershell',
    'powershell.exe',
    'pwsh',
    'pwsh.exe',
})

_WMIC_EXECUTABLE_NAMES = frozenset({
    'wmic',
    'wmic.exe',
})

_CMD_EXECUTABLE_NAMES = frozenset({
    '%comspec%',
    'cmd',
    'cmd.exe',
})

_START_EXECUTABLE_NAMES = frozenset({
    'start',
})

_START_SWITCHES_WITH_ARG = frozenset({
    'd',
    'node',
    'affinity',
})

_PARAM_WITH_NEXT_ARG = {
    'executionpolicy',
    'ep',
    'windowstyle',
    'configurationname',
    'custompipename',
    'settingsfile',
    'workingdirectory',
    'encodedarguments',
    'encodedargument',
    'outputformat',
    'inputformat',
}

_KNOWN_SWITCHES = {
    'command'           : 'c',
    'encodedcommand'    : 'e',
    'file'              : 'f',
    'executionpolicy'   : 'ex',
    'ep'                : 'ep',
    'windowstyle'       : 'w',
    'noprofile'         : 'nop',
    'noninteractive'    : 'noni',
    'nologo'            : 'nol',
    'noexit'            : 'noe',
    'sta'               : 's',
    'mta'               : 'm',
    'outputformat'      : 'o',
    'inputformat'       : 'inp',
    'configurationname' : 'con',
    'custompipename'    : 'cu',
    'settingsfile'      : 'se',
    'workingdirectory'  : 'wo',
    'encodedarguments'  : 'encodeda',
    'encodedargument'   : 'encodeda',
    'version'           : 'v',
    'login'             : 'l',
    'help'              : 'h',
}


def _match_switch(key: str) -> str | None:
    """
    Match a PowerShell command-line switch using prefix matching. Strips the leading dash or
    slash, then does a case-insensitive prefix match against known parameters, respecting the
    minimum unique prefix length.
    """
    key = key.lstrip('-/')
    if key.startswith('-'):
        key = key[1:]
    key = key.lower()
    if not key:
        return None
    for param, min_prefix in _KNOWN_SWITCHES.items():
        if param.startswith(key) and len(key) >= len(min_prefix):
            return param
    return None


def _executable_name(token: str) -> str:
    return os.path.basename(token.strip("'")).lower()


def _strip_outer_quotes(text: str) -> str:
    text = text.strip()
    if len(text) < 2 or text[0] != '"':
        return text
    k = len(text) - 1
    if text[k] != '"':
        return text
    bs = 0
    j = k - 1
    while j >= 0 and text[j] == '\\':
        bs += 1
        j -= 1
    if bs % 2 == 0:
        return text[1:k]
    return text


_RE_WMIC_CREATE = re.compile(r"""(?ix)
    (?:\S+[\\/])?
       (?P<quote0>["']?) wmic(?:\.exe)? (?P=quote0)\s+
    (?:/\S+\s+)*
    (?:(?P<quote1>["']?) path           (?P=quote1)\s+)?
       (?P<quote2>["']?) process        (?P=quote2)\s+
       (?P<quote3>["']?) call           (?P=quote3)\s+
       (?P<quote4>["']?) create         (?P=quote4)\s*
""")

_RE_CMD_RUN = re.compile(r"""(?ix)
    (?:%comspec%|(?:\S+[\\/])?
       cmd(?:\.exe)?)
    (?:\s+/[a-z](?::\w+)?)*
       \s+/[ck]\s+
""")


class cmdarg(Unit):
    """
    Extracts and unescapes arguments passed to wmic, cmd, start, or powershell commands.

    The following types of command invocations are currently supported:

    - `wmic process call create "COMMAND"`
    - `cmd /c "COMMAND"`
    - `cmd /k "COMMAND"`
    - `start [/b] [/min] [/max] [/wait] COMMAND`
    - `powershell -EncodedCommand COMMAND`
    - `powershell -Command COMMAND`

    Layers are peeled until the innermost recognizable payload is reached. This is useful
    for extracting PowerShell code from obfuscated batch files and WMI-based launchers.
    """

    def process(self, data: bytearray):
        text = codecs.decode(data, self.codec, errors='surrogateescape')
        for _ in range(10):
            text = text.strip()
            if not text:
                raise ValueError('empty command line')
            if result := self._dispatch(text):
                text = result
                self.log_info(F'unwrapped a layer, continuing with: {result}', clip=True)
                continue
            return codecs.encode(text, self.codec, errors='surrogateescape')
        raise ValueError('command chain exceeds maximum nesting depth')

    def _dispatch(self, text: str) -> str | None:
        first = text.split()[0]
        name = _executable_name(first)
        if name in _PS_EXECUTABLE_NAMES or re.fullmatch(
            r'(?i)(?:.*[\\/])?(?:powershell|pwsh)(?:\.exe)?', first
        ):
            return self._extract_powershell(_split_argv(text), skip_executable=True)
        if name in _WMIC_EXECUTABLE_NAMES or re.fullmatch(
            r'(?i)(?:.*[\\/])?wmic(?:\.exe)?', first
        ):
            return self._extract_wmic(text)
        if name in _CMD_EXECUTABLE_NAMES or re.fullmatch(
            r'(?i)(?:.*[\\/])?cmd(?:\.exe)?', first
        ):
            return self._extract_cmd(text)
        if name in _START_EXECUTABLE_NAMES:
            return self._extract_start(_split_argv(text))
        if first.startswith(('-', '/')):
            return self._extract_powershell(_split_argv(text), skip_executable=False)
        return None

    def _extract_powershell(self, argv: list[str], skip_executable: bool) -> str:
        i = 1 if skip_executable else 0
        command_args: list[str] = []
        while i < len(argv):
            arg = argv[i]
            if not arg.startswith(('-', '/')):
                command_args.append(arg)
                i += 1
                continue
            switch = _match_switch(arg)
            self.log_info(switch)
            if switch == 'command':
                return ' '.join(argv[i + 1:])
            if switch == 'encodedcommand':
                i += 1
                if i >= len(argv):
                    raise ValueError('-EncodedCommand requires an argument')
                blob = argv[i]
                blob += '=' * (-len(blob) % 4)
                raw = base64.b64decode(blob)
                return codecs.decode(raw, 'utf-16-le')
            if switch == 'file':
                raise ValueError(
                    '-File parameter found; code is in a file, not in the command line')
            if switch is not None and switch in _PARAM_WITH_NEXT_ARG:
                i += 2
                continue
            if switch is not None:
                i += 1
                continue
            command_args.append(arg)
            i += 1
        if command_args:
            return ' '.join(command_args)
        raise ValueError('no PowerShell code found in command line')

    def _extract_wmic(self, text: str) -> str:
        match = _RE_WMIC_CREATE.match(text)
        if not match:
            raise ValueError('not a recognized WMIC process create command')
        return _strip_outer_quotes(text[match.end():])

    def _extract_cmd(self, text: str) -> str:
        match = _RE_CMD_RUN.match(text)
        if not match:
            raise ValueError('CMD command line missing /c or /k switch')
        return _strip_outer_quotes(text[match.end():])

    def _extract_start(self, argv: list[str]) -> str:
        i = 1
        while i < len(argv):
            arg = argv[i]
            if not arg:
                i += 1
                continue
            if arg.startswith('/'):
                if arg[1:].lower() in _START_SWITCHES_WITH_ARG:
                    i += 2
                    continue
                i += 1
                continue
            if ' ' in arg:
                i += 1
                continue
            return ' '.join(argv[i:])
        raise ValueError('no command found after start')
