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

_PARAM_WITH_NEXT_ARG = {
    'executionpolicy',
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


class ps1arg(Unit):
    """
    Extracts PowerShell code from a powershell.exe command line.

    Parses command lines like the following and extracts the actual PowerShell code:

    - powershell.exe -nop -w 1 -enc BASE64
    - powershell.exe -command "& { ... }"

    The unit handles CRT argument-level escaping (backslash-double-quote for literal quotes) and
    base64-encoded commands. This is useful for analyzing malware samples that contain the full
    command line for powershell.exe, including CRT-level quote escaping that is not valid inside
    PowerShell itself.
    """

    def process(self, data: bytearray):
        text = codecs.decode(data, self.codec, errors='surrogateescape')
        argv = _split_argv(text)
        if not argv:
            raise ValueError('empty command line')
        i = 0
        name = os.path.basename(argv[0]).lower()
        if name in _PS_EXECUTABLE_NAMES or re.fullmatch(
            r'(?i)(?:.*[\\/])?(?:powershell|pwsh)(?:\.exe)?', argv[0]
        ):
            i = 1
        command_args: list[str] = []
        while i < len(argv):
            arg = argv[i]
            if not arg.startswith(('-', '/')):
                command_args.append(arg)
                i += 1
                continue
            switch = _match_switch(arg)
            if switch == 'command':
                i += 1
                result = ' '.join(argv[i:])
                return codecs.encode(
                    result, self.codec, errors='surrogateescape')
            if switch == 'encodedcommand':
                i += 1
                if i >= len(argv):
                    raise ValueError('-EncodedCommand requires an argument')
                blob = argv[i]
                blob += '=' * (-len(blob) % 4)
                raw = base64.b64decode(blob)
                return codecs.decode(raw, 'utf-16-le').encode(self.codec)
            if switch == 'file':
                raise ValueError('-File parameter found; code is in a file, not in the command line')
            if switch is not None and switch in _PARAM_WITH_NEXT_ARG:
                i += 2
                continue
            if switch is not None:
                i += 1
                continue
            command_args.append(arg)
            i += 1
        if command_args:
            result = ' '.join(command_args)
            return codecs.encode(
                result, self.codec, errors='surrogateescape')
        raise ValueError(
            'no PowerShell code found in command line')
