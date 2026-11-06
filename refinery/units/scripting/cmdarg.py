from __future__ import annotations

import base64
import codecs
import io
import ntpath
import re

from typing import NamedTuple

from refinery.lib.scripts.bat import BatchParser, BatchState
from refinery.lib.scripts.bat.model import (
    AstCommand,
    AstPipeline,
    AstSequence,
    EmulatorException,
    MissingVariable,
)
from refinery.lib.scripts.bat.util import cmd_unquote, parse_start_arguments, split_arguments
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


def _split_program(cmdline: str) -> tuple[str, str]:
    """
    Split a command line into the name of the program and the text of its arguments. As when
    Windows locates the program, a name that opens with a double quote ends at the next double
    quote, and any other name ends at the first whitespace.
    """
    if cmdline.startswith('"'):
        program, _, arguments = cmdline[1:].partition('"')
        return program, arguments.lstrip()
    program, *arguments = cmdline.split(None, 1)
    return program, ''.join(arguments)


class _UndefinedVariables(BatchState):
    """
    A command line state in which no variable is defined, so that parsing applies the syntax of
    cmd but leaves every variable reference as written.
    """
    def envar(self, name: str, default: str | None = None):
        if default is None:
            raise MissingVariable
        return default


def _command_as_run(command: str) -> str | None:
    """
    The command line that cmd hands to the program when it runs the given text: its escapes are
    removed and variable references stay as written. The result is `None` unless the text is one
    command, rather than several commands, a pipeline, a block, a control statement, or a command
    with redirected streams.
    """
    try:
        statements = list(BatchParser(command, _UndefinedVariables(cmdline=True)).parse(0))
    except EmulatorException:
        return None
    if len(statements) != 1:
        return None
    if not isinstance(sequence := statements[0], AstSequence) or sequence.tail:
        return None
    if not isinstance(pipeline := sequence.head, AstPipeline) or len(pipeline.parts) != 1:
        return None
    if not isinstance(part := pipeline.parts[0], AstCommand) or part.redirects:
        return None
    return ''.join(part.fragments)


class _Layer(NamedTuple):
    payload: str
    final: bool = False


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


def _executable_name(program: str) -> str:
    return ntpath.basename(program.strip("'")).lower()


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
    (?:/\S+\s+)*
    (?:(?P<quote1>["']?) path    (?P=quote1)\s+)?
       (?P<quote2>["']?) process (?P=quote2)\s+
       (?P<quote3>["']?) call    (?P=quote3)\s+
       (?P<quote4>["']?) create  (?P=quote4)\s*
""")

_RE_CMD_RUN = re.compile(r"""(?ix)
    (?P<switches>(?:/[a-z](?::\w+)?\s*)*?)
    /[ck](?=[\s"])\s*
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

    The program may be given by its full path, also in quotes. Layers are peeled until the
    innermost recognizable payload is reached. This is useful for extracting PowerShell code from
    obfuscated batch files and WMI-based launchers. The command that cmd runs has its escapes
    removed, while variable references are left as written. When that command is a batch script
    with more than one command, the script is the output; it can be emulated with `refinery.bat`.
    """

    def process(self, data: bytearray):
        text = codecs.decode(data, self.codec, errors='surrogateescape')
        final = False
        for _ in range(10):
            if not (text := text.strip()):
                raise ValueError('empty command line')
            if final or (layer := self._dispatch(text)) is None:
                return codecs.encode(text, self.codec, errors='surrogateescape')
            text, final = layer
            self.log_info(F'unwrapped a layer, continuing with: {text}', clip=True)
        raise ValueError('command chain exceeds maximum nesting depth')

    def _dispatch(self, text: str) -> _Layer | None:
        program, arguments = _split_program(text)
        name = _executable_name(program)
        if name in _PS_EXECUTABLE_NAMES:
            return _Layer(self._extract_powershell(_split_argv(arguments)))
        if name in _WMIC_EXECUTABLE_NAMES:
            return _Layer(self._extract_wmic(arguments))
        if name in _CMD_EXECUTABLE_NAMES:
            return self._extract_cmd(arguments)
        if name in _START_EXECUTABLE_NAMES:
            return _Layer(self._extract_start(arguments))
        if program.startswith(('-', '/')):
            return _Layer(self._extract_powershell(_split_argv(text)))
        return None

    def _extract_powershell(self, argv: list[str]) -> str:
        i = 0
        command_args: list[str] = []
        while i < len(argv):
            arg = argv[i]
            if command_args or not arg.startswith(('-', '/')):
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

    def _extract_wmic(self, arguments: str) -> str:
        if not (match := _RE_WMIC_CREATE.match(arguments)):
            raise ValueError('not a recognized WMIC process create command')
        return _strip_outer_quotes(arguments[match.end():])

    def _extract_cmd(self, arguments: str) -> _Layer:
        if not (match := _RE_CMD_RUN.match(arguments)):
            raise ValueError('CMD command line missing /c or /k switch')
        strip = re.search(r'(?i)/s\b', match['switches']) is not None
        executable = BatchState(cmdline=True).names_executable
        command = cmd_unquote(arguments[match.end():], strip, executable)
        if (run := _command_as_run(command)) is None:
            return _Layer(command, final=True)
        return _Layer(run)

    def _extract_start(self, arguments: str) -> str:
        pieces = split_arguments(arguments)
        if (start := parse_start_arguments(pieces)) is None:
            raise ValueError('no command found after start')
        return ''.join(pieces[start.program:])
