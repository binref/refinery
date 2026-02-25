from __future__ import annotations

import itertools
import ntpath
import re
import uuid

from dataclasses import dataclass, field, fields
from enum import Enum
from io import StringIO
from typing import Callable, ClassVar, Generator, Iterable, TypeVar

from refinery.lib.batch.help import HelpOutput
from refinery.lib.batch.model import (
    AbortExecution,
    ArgVarFlags,
    AstCondition,
    AstError,
    AstFor,
    AstForParserMode,
    AstForVariant,
    AstGroup,
    AstIf,
    AstIfCmp,
    AstIfVariant,
    AstLabel,
    AstNode,
    AstPipeline,
    AstSequence,
    AstStatement,
    Ctrl,
    EmulatorException,
    Exit,
    Goto,
    InputLocked,
    InvalidLabel,
    MissingVariable,
)
from refinery.lib.batch.parser import BatchParser
from refinery.lib.batch.state import BatchState, ErrorZero
from refinery.lib.batch.synth import SynCommand, SynNodeBase, synthesize
from refinery.lib.batch.util import batchint, uncaret, unquote
from refinery.lib.deobfuscation import cautious_parse, names_in_expression
from refinery.lib.patterns import indicators
from refinery.lib.types import buf

_T = TypeVar('_T')


def winfnmatch(pattern: str, path: str, cwd: str):
    """
    A function similar to the fnmatch module, but using only Windows wildcards. In Batch, the
    bracket wildcard does not exist.
    """
    parts = re.split('([*?])', pattern)
    regex = StringIO()
    it = iter(parts)
    verbatim = next(it)
    for wildcard in it:
        regex.write(re.escape(verbatim))
        if wildcard == '*':
            regex.write('.*')
        if wildcard == '?':
            regex.write('.')
        verbatim = next(it)
    regex.write(re.escape(verbatim))
    cwd = re.escape(cwd.rstrip('\\'))
    pattern = rF'(?s:{cwd}\\{regex.getvalue()})$'
    return bool(re.match(pattern, path))


def _fuse(*iters):
    with StringIO() as io:
        for it in iters:
            if isinstance(it, str):
                io.write(it)
                continue
            for i in it:
                io.write(i)
        return io.getvalue()


def _onoff(v: str) -> bool:
    vc = v.upper()
    if vc == 'ON':
        return True
    if vc == 'OFF':
        return False
    raise ValueError(v)


class DevNull:
    def getvalue(self):
        return ''

    def __iter__(self):
        return self

    def __next__(self):
        raise StopIteration

    def detach(self):
        raise NotImplementedError

    def readline(self, size: int = -1, /) -> str:
        return ''

    def read(self, size: int | None = -1, /) -> str:
        return ''

    def write(self, s: str, /) -> int:
        return len(s)

    def seek(self, k: int, whence: int = 0, /):
        return

    @property
    def closed(self):
        return True


class Error(str):
    pass


ErrorCannotFindFile = Error('The system cannot find the file specified.')


@dataclass
class IO:
    i: DevNull | StringIO = field(default_factory=StringIO)
    o: DevNull | StringIO = field(default_factory=StringIO)
    e: DevNull | StringIO = field(default_factory=StringIO)

    def __iter__(self):
        yield self.i
        yield self.o
        yield self.e

    def __setitem__(self, k, v):
        if k == 0:
            self.i = v
        elif k == 1:
            self.o = v
        elif k == 2:
            self.e = v
        else:
            raise IndexError(k)

    def __getitem__(self, k):
        if k == 0:
            return self.i
        elif k == 1:
            return self.o
        elif k == 2:
            return self.e
        else:
            raise IndexError(k)


@dataclass
class BatchEmulatorConfig:
    show_nops: bool = False
    show_junk: bool = False
    show_labels: bool = False
    show_sets: bool = False
    show_comments: bool = False
    skip_goto: bool = False
    skip_call: bool = False
    skip_exit: bool = False


class BatchEmulator:

    class _node:
        handlers: ClassVar[dict[
            type[AstNode],
            Callable[[
                BatchEmulator,
                AstNode,
                IO,
                bool,
            ], Generator[SynNodeBase[AstNode] | Error]]
        ]] = {}

        def __init__(self, key: type[AstNode]):
            self.key = key

        def __call__(self, handler):
            self.handlers[self.key] = handler
            return handler

    class _command:
        handlers: ClassVar[dict[
            str,
            Callable[[
                BatchEmulator,
                SynCommand,
                IO,
                bool,
            ], Generator[str, None, int | None] | int | ErrorZero | None]
        ]] = {}

        def __init__(self, key: str):
            self.key = key.upper()

        def __call__(self, handler):
            self.handlers[self.key] = handler
            return handler

    def __init__(
        self,
        data: str | buf | BatchParser,
        state: BatchState | None = None,
        cfg: BatchEmulatorConfig | None = None,
        std: IO | None = None,
    ):
        self.stack = []
        self.parser = BatchParser(data, state)
        self.std = std or IO()
        self.cfg = cfg or BatchEmulatorConfig()
        self.block_labels = set()

    def spawn(self, data: str | buf | BatchParser, state: BatchState | None = None, std: IO | None = None):
        return BatchEmulator(
            data,
            state,
            self.cfg,
            std,
        )

    @property
    def state(self):
        return self.parser.state

    @property
    def environment(self):
        return self.state.environment

    @property
    def delayexpand(self):
        return self.state.delayexpand

    def clone_state(
        self,
        delayexpand: bool | None = None,
        cmdextended: bool | None = None,
        environment: dict | None | ellipsis = ...,
        filename: str | None = None,
    ):
        state = self.state
        if delayexpand is None:
            delayexpand = False
        if cmdextended is None:
            cmdextended = state.cmdextended
        if environment is ...:
            environment = dict(state.environment)
        return BatchState(
            delayexpand,
            cmdextended,
            environment=environment,
            file_system=state.file_system,
            username=state.username,
            hostname=state.hostname,
            now=state.now,
            cwd=state.cwd,
            filename=filename,
        )

    def get_for_variable_regex(self, vars: Iterable[str]):
        return re.compile(RF'%((?:~[fdpnxsatz]*)?)((?:\\$\\w+)?)([{"".join(vars)}])')

    def expand_delayed_variables(self, block: str):
        def expansion(match: re.Match[str]):
            name = match.group(1)
            try:
                return parse(name)
            except MissingVariable:
                _, _, rest = name.partition(':')
                return rest
        parse = self.parser.lexer.parse_env_variable
        return re.sub(r'!([^!\n]*)!', expansion, block)

    def expand_forloop_variables(self, block: str, vars: dict[str, str] | None):
        def expansion(match: re.Match[str]):
            flags = ArgVarFlags.Empty
            for flag in match[1]:
                flags |= ArgVarFlags.FromToken(ord(flag))
            return _vars[match[3]]
        if not vars:
            return block
        _vars = vars
        return self.get_for_variable_regex(vars).sub(expansion, block)

    def contains_for_variable(self, ast: AstNode, vars: Iterable[str]):
        def check(token):
            if isinstance(token, list):
                return any(check(v) for v in token)
            if isinstance(token, dict):
                return any(check(v) for v in token.values())
            if isinstance(token, Enum):
                return False
            if isinstance(token, str):
                return bool(checker(token))
            if isinstance(token, AstNode):
                for tf in fields(token):
                    if tf.name == 'parent':
                        continue
                    if check(getattr(token, tf.name)):
                        return True
            return False
        checker = self.get_for_variable_regex(vars).search
        return check(ast) # type:ignore

    def expand_ast_node(self, ast: _T) -> _T:
        def expand(token):
            if isinstance(token, list):
                return [expand(v) for v in token]
            if isinstance(token, dict):
                return {k: expand(v) for k, v in token.items()}
            if isinstance(token, Enum):
                return token
            if isinstance(token, str):
                if delayexpand:
                    token = self.expand_delayed_variables(token)
                return self.expand_forloop_variables(token, variables)
            if isinstance(token, AstNode):
                new = {}
                for tf in fields(token):
                    value = getattr(token, tf.name)
                    if tf.name != 'parent':
                        value = expand(value)
                    new[tf.name] = value
                return token.__class__(**new)
            return token
        delayexpand = self.delayexpand
        variables = self.state.for_loop_variables
        if not variables and not delayexpand:
            return ast
        return expand(ast) # type:ignore

    def execute_find_or_findstr(self, cmd: SynCommand, std: IO, findstr: bool):
        needles = []
        paths: list[str | ellipsis] = [...]
        flags = {}
        it = iter(cmd.args)
        arg = None
        yield cmd

        for arg in it:
            if not arg.startswith('/'):
                if not findstr and not arg.startswith('"'):
                    return 1
                needles.extend(unquote(arg).split())
                break
            name, has_param, value = arg[1:].partition(':')
            name = name.upper()
            if name in ('OFF', 'OFFLINE'):
                continue
            elif len(name) > 1:
                return 1
            elif name == 'C':
                needles.append(unquote(value))
            elif name == 'F' and findstr:
                if (p := self.state.ingest_file(value)) is None:
                    return 1
                paths.extend(p.splitlines(False))
            elif name == 'G' and findstr:
                if (n := self.state.ingest_file(value)) is None:
                    return 1
                needles.extend(n.splitlines(False))
            elif has_param:
                flags[name] = value
            else:
                flags[name] = True

        valid_flags = 'VNI'
        if findstr:
            valid_flags += 'BELRSXMOPADQ'

        for v in flags:
            if v not in valid_flags:
                return 1

        prefix_filename = False
        state = self.state

        for arg in it:
            pattern = unquote(arg)
            if '*' in pattern or '?' in pattern:
                prefix_filename = True
                for path in state.file_system:
                    if winfnmatch(path, pattern, state.cwd):
                        paths.append(path)
            else:
                paths.append(pattern)

        if len(paths) > 1:
            prefix_filename = True

        for n, needle in enumerate(needles):
            if not findstr or 'L' in flags:
                needle = re.escape(needle)
            if 'X' in flags:
                needle = F'^{needle}$'
            elif 'B' in flags:
                needle = F'^{needle}'
            elif 'E' in flags:
                needle = F'{needle}$'
            needles[n] = needle

        _V = 'V' in flags # noqa; Prints only lines that do not contain a match.
        _P = 'P' in flags # noqa; Skip files with non-printable characters.
        _O = 'O' in flags # noqa; Prints character offset before each matching line.
        _N = 'N' in flags # noqa; Prints the line number before each line that matches.
        _M = 'M' in flags # noqa; Prints only the filename if a file contains a match.

        nothing_found = True
        offset = 0

        for path in paths:
            if path is (...):
                data = std.i.read()
            else:
                data = state.ingest_file(path)
            if data is None:
                return 1
            if _P and not re.fullmatch('[\\s!-~]+', data):
                continue
            for n, line in enumerate(data.splitlines(True), 1):
                for needle in needles:
                    hit = re.search(needle, line)
                    if _V == bool(hit):
                        continue
                    nothing_found = False
                    if not _M:
                        if _O:
                            o = offset + (hit.start() if hit else 0)
                            line = F'{o}:{line}'
                        if _N:
                            line = F'{n}:{line}'
                        if prefix_filename:
                            line = F'{path}:{line}'
                        std.o.write(line)
                    elif path is not (...):
                        std.o.write(path)
                        break
                offset += len(line)

        return int(nothing_found)

    @_command('TYPE')
    def execute_type(self, cmd: SynCommand, std: IO, *_):
        path = cmd.argument_string.strip()
        data = self.state.ingest_file(path)
        if data is None:
            yield ErrorCannotFindFile
            return 1
        else:
            std.o.write(data)
            return 0

    @_command('FIND')
    def execute_find(self, cmd: SynCommand, std: IO, *_):
        return self.execute_find_or_findstr(cmd, std, findstr=False)

    @_command('FINDSTR')
    def execute_findstr(self, cmd: SynCommand, std: IO, *_):
        return self.execute_find_or_findstr(cmd, std, findstr=True)

    @_command('SET')
    def execute_set(self, cmd: SynCommand, std: IO, *_):
        if not (args := cmd.args):
            raise EmulatorException('Empty SET instruction')

        if cmd.verb.upper() != 'SET':
            raise RuntimeError

        # Since variables can be used in GOTO, a SET can be used to change the behavior of a GOTO.
        self.block_labels.clear()

        arithmetic = False
        quote_mode = False
        prompt = None

        it = iter(args)
        tk = next(it)

        if tk.upper() == '/P':
            if std.i.closed:
                prompt = ''
            elif not (prompt := std.i.readline()).endswith('\n'):
                raise InputLocked
            else:
                prompt = prompt.rstrip('\r\n')
            tk = next(it)
        else:
            cmd.junk = not self.cfg.show_sets

        yield cmd

        if tk.upper() == '/A':
            arithmetic = True
            try:
                tk = next(it)
            except StopIteration:
                tk = ''

        args = [tk, *it, *cmd.trailing_spaces]

        if arithmetic:
            def defang(s: str):
                def r(m: re.Match[str]):
                    return F'_{prefix}{ord(m[0]):X}_'
                return re.sub(r'[^-\s()!~*/%+><&^|_\w]', r, s)
            def refang(s: str): # noqa
                def r(m: re.Match[str]):
                    return chr(int(m[1], 16))
                return re.sub(rf'_{prefix}([A-F0-9]+)_', r, s)
            prefix = F'{uuid.uuid4().time_mid:X}'
            namespace = {}
            translate = {}
            value = None
            if not (program := ''.join(args)):
                std.e.write('The syntax of the command is incorrect.\r\n')
                return ErrorZero
            for assignment in program.split(','):
                assignment = assignment.strip()
                if not assignment:
                    std.e.write('Missing operand.\r\n')
                    return ErrorZero
                name, operator, definition = re.split(r'([*+^|/%-&]|<<|>>|)=', assignment, maxsplit=1)
                name = name.upper()
                definition = re.sub(r'\b0([0-7]+)\b', r'0o\1', definition)
                if operator:
                    definition = F'{name}{operator}({definition})'
                definition = defang(definition)
                expression = cautious_parse(definition)
                names = names_in_expression(expression)
                if names.stored or names.others:
                    raise EmulatorException('Arithmetic SET had unexpected variable access.')
                for var in names.loaded:
                    original = refang(name).upper()
                    translate[original] = var
                    if var in namespace:
                        continue
                    try:
                        namespace[var] = batchint(self.environment[original])
                    except (KeyError, ValueError):
                        namespace[var] = 0
                code = compile(expression, filename='[ast]', mode='eval')
                value = eval(code, namespace, {})
                self.environment[name] = str(value)
                namespace[defang(name)] = value
            if value is None:
                std.e.write('The syntax of the command is incorrect.')
                return
            else:
                std.o.write(F'{value!s}\r\n')
        else:
            try:
                eq = args.index(Ctrl.Equals)
            except ValueError:
                assignment = cmd.argument_string
                if assignment.startswith('"'):
                    quote_mode = True
                    assignment, _, unquoted = assignment[1:].rpartition('"')
                    assignment = assignment or unquoted
                else:
                    assignment = ''.join(args)
                name, _, content = assignment.partition('=')
            else:
                with StringIO() as io:
                    for k in range(eq + 1, len(args)):
                        io.write(args[k])
                    content = io.getvalue()
                    name = cmd.args[eq - 1] if eq else ''
            name = name.upper()
            trailing_caret, content = uncaret(content, quote_mode)
            if trailing_caret:
                content = content[:-1]
            if prompt is not None:
                if (qc := content.strip()).startswith('"'):
                    _, _, qc = qc. partition('"') # noqa
                    qc, _, r = qc.rpartition('"') # noqa
                    content = qc or r
                std.o.write(content)
                content = prompt
            if name:
                if content:
                    self.environment[name] = content
                else:
                    self.environment.pop(name, None)

    @_command('CALL')
    def execute_call(self, cmd: SynCommand, std: IO, *_):
        cmdl = cmd.argument_string
        empty, colon, label = cmdl.partition(':')
        if colon and not empty:
            try:
                offset = self.parser.lexer.labels[label.upper()]
            except KeyError as KE:
                raise InvalidLabel(label) from KE
            emu = self.spawn(self.parser, std=std)
        else:
            offset = 0
            path = cmdl.strip()
            code = self.state.ingest_file(path)
            if code is None:
                yield cmd
                return
            state = self.clone_state(environment=self.state.environment, filename=path)
            emu = self.spawn(code, std=std, state=state)
        if self.cfg.skip_call:
            emu.execute(called=True)
        else:
            yield from emu.trace(offset, called=True)

    @_command('SETLOCAL')
    def execute_setlocal(self, cmd: SynCommand, *_):
        yield cmd
        setting = cmd.argument_string.strip().upper()
        delay = {
            'DISABLEDELAYEDEXPANSION': False,
            'ENABLEDELAYEDEXPANSION' : True,
        }.get(setting, self.state.delayexpand)
        cmdxt = {
            'DISABLEEXTENSIONS': False,
            'ENABLEEXTENSIONS' : True,
        }.get(setting, self.state.cmdextended)
        self.state.delayexpand_stack.append(delay)
        self.state.cmdextended_stack.append(cmdxt)
        self.state.environment_stack.append(dict(self.environment))

    @_command('ENDLOCAL')
    def execute_endlocal(self, cmd: SynCommand, *_):
        yield cmd
        if len(self.state.environment_stack) > 1:
            self.state.environment_stack.pop()
            self.state.delayexpand_stack.pop()

    @_command('GOTO')
    def execute_goto(self, cmd: SynCommand, std: IO, *_):
        if self.cfg.skip_goto:
            yield cmd
            return
        it = iter(cmd.args)
        mark = False
        for label in it:
            if not isinstance(label, Ctrl):
                break
            if label == Ctrl.Label:
                mark = True
                for label in it:
                    break
                else:
                    label = ''
                break
        else:
            std.e.write('No batch label specified to GOTO command.\r\n')
            raise AbortExecution
        label, *_ = label.split(maxsplit=1)
        key = label.upper()
        if mark and key == 'EOF':
            raise Exit(int(self.state.ec), False)
        if key not in self.block_labels:
            raise Goto(label)
        else:
            yield Error(F'Infinite Loop detected for label {key}')

    @_command('EXIT')
    def execute_exit(self, cmd: SynCommand, *_):
        it = iter(cmd.args)
        exit = True
        token = 0
        for arg in it:
            if arg.upper() == '/B':
                exit = False
                continue
            token = arg
            break
        try:
            code = int(token)
        except ValueError:
            code = 0
        yield cmd
        if self.cfg.skip_exit:
            return
        raise Exit(code, exit)

    @_command('CHDIR')
    @_command('CD')
    def execute_chdir(self, cmd: SynCommand, *_):
        yield cmd
        self.state.cwd = cmd.argument_string.strip()

    @_command('PUSHD')
    def execute_pushd(self, cmd: SynCommand, *_):
        yield cmd
        self.state.dirstack.append(self.state.cwd)
        self.execute_chdir(cmd)

    @_command('POPD')
    def execute_popd(self, cmd: SynCommand, *_):
        yield cmd
        try:
            self.state.cwd = self.state.dirstack.pop()
        except IndexError:
            pass

    @_command('ECHO')
    def execute_echo(self, cmd: SynCommand, std: IO, in_group: bool):
        cmdl = cmd.argument_string
        mode = cmdl.strip().lower()
        current_state = self.state.echo
        if mode == 'on':
            if self.cfg.show_nops or current_state is False:
                yield cmd
            self.state.echo = True
            return
        if mode == 'off':
            if self.cfg.show_nops or current_state is True:
                yield cmd
            self.state.echo = False
            return
        yield cmd
        if mode:
            if in_group and not cmdl.endswith(' '):
                cmdl += ' '
            std.o.write(F'{cmdl}\r\n')
        else:
            mode = 'on' if self.state.echo else 'off'
            std.o.write(F'ECHO is {mode}.\r\n')

    @_command('CLS')
    def execute_cls(self, cmd: SynCommand, *_):
        yield cmd

    @_command('ERASE')
    @_command('DEL')
    def execute_del(self, cmd: SynCommand, std: IO, *_):
        if not cmd.args:
            yield Error('The syntax of the command is incorrect')
            return 1
        else:
            yield cmd
        flags = {}
        it = iter(cmd.args)
        while (arg := next(it)).startswith('/') and 1 < len(arg):
            flag = arg.upper()
            if flag[:3] == '/A:':
                flags['A'] = flag[3:]
                continue
            flags[flag[1]] = True
        _P = 'P' in flags # Prompts for confirmation before deleting each file.
        _F = 'F' in flags # Force deleting of read-only files.
        _S = 'S' in flags # Delete specified files from all subdirectories.
        _Q = 'Q' in flags # Quiet mode, do not ask if ok to delete on global wildcard
        paths = [arg, *it]
        state = self.state
        cwd = state.cwd
        for pattern in paths:
            for path in list(state.file_system):
                if not winfnmatch(pattern, path, cwd):
                    continue
                if _F:
                    pass
                if _S:
                    pass
                if _Q:
                    pass
                if _P and state.exists_file(pattern):
                    std.o.write(F'{pattern}, Delete (Y/N)? ')
                    decision = None
                    while decision not in ('y', 'n'):
                        confirmation = std.i.readline()
                        if not confirmation.endswith('\n'):
                            raise InputLocked
                        decision = confirmation[:1].lower()
                    if decision == 'n':
                        continue
                state.remove_file(path)
        return 0

    @_command('START')
    def execute_start(self, cmd: SynCommand, std: IO, *_):
        yield cmd
        it = iter(cmd.ast.fragments)
        it = itertools.islice(it, cmd.argument_offset, None)
        title = None
        start = None
        cwd = self.state.cwd
        env = ...
        for arg in it:
            if title is None:
                if '"' not in arg:
                    title = ''
                else:
                    title = unquote(arg)
                    continue
            if arg.isspace():
                continue
            if not arg.startswith('/'):
                start = unquote(arg)
                break
            if (flag := arg.upper()) in ('/NODE', '/AFFINITY', '/MACHINE'):
                next(it)
            elif flag == '/D':
                cwd = next(it)
            elif flag == '/I':
                env = None
        if start and (batch := self.state.ingest_file(start)):
            state = self.clone_state(environment=env)
            state.cwd = cwd
            state.command_line = _fuse(it).strip()
            shell = self.spawn(batch, state, std)
            yield from shell.trace()

    @_command('CMD')
    def execute_cmd(self, cmd: SynCommand, std: IO, *_):
        yield cmd
        it = iter(cmd.ast.fragments)
        command = None
        quiet = False
        strip = False
        codec = 'cp1252'
        delayexpand = None
        cmdextended = None

        for arg in it:
            if arg.isspace() or not arg.startswith('/'):
                continue
            name, _, flag = arg[1:].partition(':')
            flag = flag.upper()
            name = name.upper()
            if name in 'CKR':
                command = _fuse(it)
                break
            elif name == 'Q':
                quiet = True
            elif name == 'S':
                strip = True
            elif name == 'U':
                codec = 'utf-16le'
            elif name == 'E':
                cmdextended = _onoff(flag)
            elif name == 'V':
                delayexpand = _onoff(flag)
        else:
            return 0

        if (stripped := re.search('^\\s*"(.*)"', command)) and (strip
            or command.count('"') != 2
            or re.search('[&<>()@^|]', stripped[1])
            or re.search('\\s', stripped[1]) is None
        ):
            command = stripped[1]

        state = self.clone_state(delayexpand=delayexpand, cmdextended=cmdextended)
        state.codec = codec
        state.echo = not quiet
        shell = self.spawn(command, state, std)
        yield from shell.trace()

    @_command('ARP')
    @_command('AT')
    @_command('ATBROKER')
    @_command('BGINFO')
    @_command('BITSADMIN')
    @_command('CERTUTIL')
    @_command('CLIP')
    @_command('CMSTP')
    @_command('COMPACT')
    @_command('CONTROL')
    @_command('CSCRIPT')
    @_command('CURL')
    @_command('DEFRAG')
    @_command('DISKSHADOW')
    @_command('ESENTUTL')
    @_command('EXPAND')
    @_command('EXPLORER')
    @_command('EXTRAC32')
    @_command('FODHELPER')
    @_command('FORFILES')
    @_command('FTP')
    @_command('HOSTNAME')
    @_command('HOSTNAME')
    @_command('INSTALLUTIL')
    @_command('IPCONFIG')
    @_command('LOGOFF')
    @_command('MAKECAB')
    @_command('MAVINJECT')
    @_command('MOUNTVOL')
    @_command('MSBUILD')
    @_command('MSHTA')
    @_command('MSIEXEC')
    @_command('MSTSC')
    @_command('NET')
    @_command('NET1')
    @_command('NETSH')
    @_command('NSLOOKUP')
    @_command('ODBCCONF')
    @_command('PATHPING')
    @_command('PING')
    @_command('POWERSHELL')
    @_command('PRESENTATIONHOST')
    @_command('PWSH')
    @_command('REG')
    @_command('REGSVR32')
    @_command('ROUTE')
    @_command('RUNDLL32')
    @_command('SCP')
    @_command('SDCLT')
    @_command('SETX')
    @_command('SFTP')
    @_command('SHUTDOWN')
    @_command('SSH')
    @_command('SUBST')
    @_command('SYNCAPPVPUBLISHINGSERVER')
    @_command('SYSTEMINFO')
    @_command('TAR')
    @_command('TELNET')
    @_command('TFTP')
    @_command('TIMEOUT')
    @_command('TRACERT')
    @_command('VSSADMIN')
    @_command('WBADMIN')
    @_command('WHERE')
    @_command('WHOAMI')
    @_command('WINRM')
    @_command('WINRS')
    @_command('WSCRIPT')
    def execute_unimplemented_program(self, cmd: SynCommand, *_):
        yield cmd
        return 0

    @_command('CLS')
    def execute_unimplemented_command_unmodified_ec(self, cmd: SynCommand, *_):
        yield cmd

    @_command('ASSOC')
    @_command('ATTRIB')
    @_command('BCDEDIT')
    @_command('BREAK')
    @_command('CACLS')
    @_command('CHCP')
    @_command('CHKDSK')
    @_command('CHKNTFS')
    @_command('COLOR')
    @_command('COMP')
    @_command('COMPACT')
    @_command('CONVERT')
    @_command('COPY')
    @_command('DATE')
    @_command('DIR')
    @_command('DISKPART')
    @_command('DOSKEY')
    @_command('DRIVERQUERY')
    @_command('FC')
    @_command('FORMAT')
    @_command('FSUTIL')
    @_command('FTYPE')
    @_command('GPRESULT')
    @_command('ICACLS')
    @_command('LABEL')
    @_command('MD')
    @_command('MKDIR')
    @_command('MKLINK')
    @_command('MODE')
    @_command('MORE')
    @_command('MOVE')
    @_command('OPENFILES')
    @_command('PATH')
    @_command('PAUSE')
    @_command('PRINT')
    @_command('PROMPT')
    @_command('RD')
    @_command('RECOVER')
    @_command('REN')
    @_command('RENAME')
    @_command('REPLACE')
    @_command('RMDIR')
    @_command('ROBOCOPY')
    @_command('SC')
    @_command('SCHTASKS')
    @_command('SHIFT')
    @_command('SHUTDOWN')
    @_command('SORT')
    @_command('SUBST')
    @_command('SYSTEMINFO')
    @_command('TASKKILL')
    @_command('TASKLIST')
    @_command('TIME')
    @_command('TITLE')
    @_command('TREE')
    @_command('TYPE')
    @_command('VER')
    @_command('VERIFY')
    @_command('VOL')
    @_command('WMIC')
    @_command('XCOPY')
    def execute_unimplemented_command(self, cmd: SynCommand, *_):
        yield cmd
        return 0

    @_command('REM')
    def execute_rem(self, cmd: SynCommand, *_):
        if self.cfg.show_comments:
            yield cmd

    @_command('HELP')
    def execute_help(self, cmd: SynCommand, std: IO, *_):
        yield cmd
        std.o.write(HelpOutput['HELP'])
        return 0

    def execute_command(self, cmd: SynCommand, std: IO, in_group: bool):
        verb = cmd.verb.upper().strip()
        handler = self._command.handlers.get(verb)

        if handler is None:
            base, ext = ntpath.splitext(verb)
            handler = None
            if any(ext == pe.upper() for pe in self.state.envar('PATHEXT', '').split(';')):
                handler = self._command.handlers.get(base)

        if handler is None:
            if self.state.exists_file(verb):
                self.state.ec = 0
            elif not indicators.winfpath.value.fullmatch(verb):
                if '\uFFFD' in verb or not verb.isprintable():
                    self.state.ec = 9009
                    cmd.junk = True
                else:
                    cmd.junk = not self.cfg.show_junk
            yield cmd
            return

        paths: dict[int, str] = {}

        for src, r in cmd.ast.redirects.items():
            if not 0 <= src <= 2 or (src == 0) != r.is_input:
                continue
            if isinstance((target := r.target), str):
                if target.upper() == 'NUL':
                    std[src] = DevNull()
                else:
                    data = self.state.ingest_file(target)
                    if src == 0:
                        if data is None:
                            yield ErrorCannotFindFile
                            return
                        std.i = StringIO(data)
                    else:
                        if r.is_out_append:
                            buffer = StringIO(data)
                            buffer.seek(0, 2)
                        else:
                            buffer = StringIO()
                        std[src] = buffer
                        paths[src] = target
            elif src == 1 and target == 2:
                std.o = std.e
            elif src == 2 and target == 1:
                std.e = std.o

        if '/?' in cmd.args:
            std.o.write(HelpOutput[verb])
            self.state.ec = 0
            return

        if (result := handler(self, cmd, std, in_group)) is None:
            pass
        elif not isinstance(result, (int, type(ErrorZero))):
            result = (yield from result)

        for k, path in paths.items():
            self.state.create_file(path, std[k].getvalue())

        if result is not None:
            self.state.ec = result

    @_node(AstPipeline)
    def trace_pipeline(self, pipeline: AstPipeline, std: IO, in_group: bool):
        length = len(pipeline.parts)
        streams = IO(*std)
        if length > 1:
            yield synthesize(pipeline)
        for k, part in enumerate(pipeline.parts, 1):
            if k != 1:
                streams.i = streams.o
                streams.i.seek(0)
            if k == length:
                streams.o = std.o
            else:
                streams.o = StringIO()
            if isinstance(part, AstGroup):
                it = self.trace_group(part, streams, in_group)
            else:
                ast = self.expand_ast_node(part)
                cmd = synthesize(ast)
                it = self.execute_command(cmd, streams, in_group)
            yield from it

    @_node(AstSequence)
    def trace_sequence(self, sequence: AstSequence, std: IO, in_group: bool):
        yield from self.trace_statement(sequence.head, std, in_group)
        for cs in sequence.tail:
            if cs.condition == AstCondition.Failure:
                if bool(self.state.ec) is False:
                    continue
            if cs.condition == AstCondition.Success:
                if bool(self.state.ec) is True:
                    continue
            yield from self.trace_statement(cs.statement, std, in_group)

    @_node(AstIf)
    def trace_if(self, _if: AstIf, std: IO, in_group: bool):
        yield synthesize(_if)
        _if = self.expand_ast_node(_if)
        self.block_labels.clear()

        if _if.variant == AstIfVariant.ErrorLevel:
            condition = _if.var_int <= self.state.ec
        elif _if.variant == AstIfVariant.CmdExtVersion:
            condition = _if.var_int <= self.state.extensions_version
        elif _if.variant == AstIfVariant.Exist:
            condition = self.state.exists_file(_if.var_str)
        elif _if.variant == AstIfVariant.Defined:
            condition = _if.var_str.upper() in self.state.environment
        else:
            lhs = _if.lhs
            rhs = _if.rhs
            cmp = _if.cmp
            assert lhs is not None
            assert rhs is not None
            if cmp == AstIfCmp.STR:
                if _if.casefold:
                    if isinstance(lhs, str):
                        lhs = lhs.casefold()
                    if isinstance(rhs, str):
                        rhs = rhs.casefold()
                condition = lhs == rhs
            elif cmp == AstIfCmp.GTR:
                condition = lhs > rhs
            elif cmp == AstIfCmp.GEQ:
                condition = lhs >= rhs
            elif cmp == AstIfCmp.NEQ:
                condition = lhs != rhs
            elif cmp == AstIfCmp.EQU:
                condition = lhs == rhs
            elif cmp == AstIfCmp.LSS:
                condition = lhs < rhs
            elif cmp == AstIfCmp.LEQ:
                condition = lhs <= rhs
            else:
                raise RuntimeError(cmp)
        if _if.negated:
            condition = not condition

        if condition:
            yield from self.trace_sequence(_if.then_do, std, in_group)
        elif (_else := _if.else_do):
            yield from self.trace_sequence(_else, std, in_group)

    @_node(AstFor)
    def trace_for(self, _for: AstFor, std: IO, in_group: bool):
        state = self.state
        cwd = state.cwd
        vars = state.new_forloop()
        body = _for.body
        name = _for.variable
        vars[name] = ''

        if (
            self.contains_for_variable(body, vars)
                or _for.variant != AstForVariant.NumericLoop
                or len(_for.spec) != 1
        ):
            yield synthesize(_for)

        if _for.variant == AstForVariant.FileParsing:
            if _for.mode == AstForParserMode.Command:
                emulator = self.spawn(_for.specline, self.clone_state(filename=state.name))
                yield from emulator.trace()
                lines = emulator.std.o.getvalue().splitlines()
            elif _for.mode == AstForParserMode.Literal:
                lines = _for.spec
            else:
                def lines_from_files():
                    fs = state.file_system
                    for name in _for.spec:
                        for path, content in fs.items():
                            if not winfnmatch(path, name, cwd):
                                continue
                            yield from content.splitlines(False)
                lines = lines_from_files()
            opt = _for.options
            tokens = sorted(opt.tokens)
            split = re.compile('[{}]+'.format(re.escape(opt.delims)))
            count = tokens[-1] + 1 if tokens else 0
            first_variable = ord(name)
            if opt.asterisk:
                tokens.append(count)
            for n, line in enumerate(lines):
                if n < opt.skip:
                    continue
                if opt.comment and line.startswith(opt.comment):
                    continue
                if count:
                    tokenized = split.split(line, maxsplit=count)
                else:
                    tokenized = (line,)
                for k, tok in enumerate(tokens):
                    name = chr(first_variable + k)
                    if not name.isalpha():
                        raise EmulatorException('Ran out of variables in FOR-Loop.')
                    try:
                        vars[name] = tokenized[tok]
                    except IndexError:
                        vars[name] = ''
                yield from self.trace_sequence(body, std, in_group)
        else:
            for entry in _for.spec:
                vars[name] = entry
                yield from self.trace_sequence(body, std, in_group)
        state.end_forloop()

    @_node(AstGroup)
    def trace_group(self, group: AstGroup, std: IO, in_group: bool):
        for sequence in group.fragments:
            yield from self.trace_sequence(sequence, std, True)
        yield synthesize(group)

    @_node(AstLabel)
    def trace_label(self, label: AstLabel, *_):
        if label.comment:
            if self.cfg.show_comments:
                yield synthesize(label)
        else:
            if self.cfg.show_labels:
                yield synthesize(label)
            self.block_labels.add(label.label.upper())

    def trace_statement(self, statement: AstStatement, std: IO, in_group: bool):
        try:
            handler = self._node.handlers[statement.__class__]
        except KeyError:
            raise RuntimeError(statement)
        yield from handler(self, statement, std, in_group)

    def emulate_commands(self, allow_junk=False):
        for syn in self.trace():
            if not isinstance(syn, SynCommand):
                continue
            if not allow_junk and syn.junk:
                continue
            yield str(syn)

    def emulate_to_depth(self, depth: int = 0):
        for syn in self.trace():
            if not isinstance(syn, SynNodeBase):
                continue
            if syn.ast.depth <= depth:
                yield str(syn)

    def emulate(self, offset: int = 0):
        last: AstNode | None = None
        junk: AstNode | None = None
        for syn in self.trace(offset):
            if not isinstance(syn, SynNodeBase):
                continue
            ast = syn.ast
            if isinstance(syn, SynCommand) and syn.junk:
                junk = ast
                continue
            if junk is not None:
                if junk.is_descendant_of(ast):
                    if not last or not last.is_descendant_of(ast):
                        continue
            if last is not None:
                if ast.is_descendant_of(last):
                    # we already synthesized a parent construct, like a FOR loop or IF block
                    continue
                if last.is_descendant_of(ast):
                    # we synthesized a command and no longer need to synthesize an AST node that
                    # wraps it, like a group
                    continue
            if isinstance(ast, AstPipeline):
                if len(ast.parts) == 1:
                    continue
            if last is ast:
                raise RuntimeError('Emulator attempted to synthesize the same command twice.')
            last = ast
            yield str(syn)

    def execute(self, offset: int = 0, called: bool = False):
        for _ in self.trace(offset, called=called):
            pass

    def trace(self, offset: int = 0, called: bool = False):
        if (name := self.state.name):
            self.state.create_file(name, self.parser.lexer.text)
        length = len(self.parser.lexer.code)
        labels = self.parser.lexer.labels

        while offset < length:
            try:
                for sequence in self.parser.parse(offset):
                    if isinstance(sequence, AstError):
                        yield Error(sequence.error)
                        continue
                    yield from self.trace_sequence(sequence, self.std, False)
            except Goto as goto:
                try:
                    offset = labels[goto.label.upper()]
                except KeyError:
                    raise InvalidLabel(goto.label) from goto
                continue
            except Exit as exit:
                self.state.ec = exit.code
                if exit.exit and called:
                    raise
                else:
                    break
            except AbortExecution:
                self.state.ec = 1
                break
            else:
                break
