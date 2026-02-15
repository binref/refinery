from __future__ import annotations

import re
import uuid

from dataclasses import dataclass, field, fields
from enum import Enum
from io import StringIO
from typing import Callable, ClassVar, Generator, TypeVar

from refinery.lib.batch.model import (
    AbortExecution,
    ArgVarFlags,
    AstCondition,
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
    EmulatorException,
    Exit,
    Goto,
    InputLocked,
    InvalidLabel,
    MissingVariable,
)
from refinery.lib.batch.parser import BatchParser
from refinery.lib.batch.state import BatchState
from refinery.lib.batch.synth import SynCommand, SynNodeBase, synthesize
from refinery.lib.batch.util import batchint, uncaret, unquote
from refinery.lib.batch.help import HelpOutput
from refinery.lib.deobfuscation import cautious_parse, names_in_expression
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
            ], Generator[str, None, int | None] | int | None]
        ]] = {}

        def __init__(self, key: str):
            self.key = key

        def __call__(self, handler):
            self.handlers[self.key] = handler
            return handler

    def __init__(
        self,
        data: str | buf | BatchParser,
        state: BatchState | None = None,
        std: IO | None = None,
        show_noops: bool = False,
    ):
        self.stack = []
        self.parser = BatchParser(data, state)
        self.std = std or IO()
        self.show_noops = show_noops

    @property
    def state(self):
        return self.parser.state

    @property
    def environment(self):
        return self.state.environment

    @property
    def delayexpand(self):
        return self.state.delayexpand

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
        return re.sub(
            RF'%((?:~[fdpnxsatz]*)?)((?:\\$\\w+)?)([{"".join(vars)}])', expansion, block)

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

        arithmetic = False
        quote_mode = False
        prompt = None

        it = iter(args)
        tk = next(it)

        if tk.upper() == '/P':
            prompt = std.i.readline()
            if not prompt.endswith('\n'):
                raise InputLocked
            prompt = prompt.rstrip('\r\n')
            tk = next(it)

        if tk.upper() == '/A':
            arithmetic = True
            tk = next(it)

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
            for assignment in ''.join(args).split(','):
                assignment = assignment.strip()
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
        else:
            if (n := len(args)) >= 2 and args[1] == '=':
                name = args[0]
                with StringIO() as rest:
                    for k in range(2, n):
                        rest.write(args[k])
                    content = rest.getvalue()
            elif (assignment := cmd.argument_string).startswith('"'):
                quote_mode = True
                assignment, _, unquoted = assignment[1:].rpartition('"')
                assignment = assignment or unquoted
                name, _, content = assignment.partition('=')
            else:
                name, _, content = ''.join(args).partition('=')
            name = name.upper()
            trailing_caret, content = uncaret(content, quote_mode)
            if trailing_caret:
                content = content[:-1]
            if prompt is not None:
                std.o.write(content)
                self.environment[name] = prompt
            elif not content:
                self.environment.pop(name, None)
            else:
                self.environment[name] = content

    @_command('CALL')
    def execute_call(self, cmd: SynCommand, std: IO, *_):
        cmdl = cmd.argument_string
        empty, colon, label = cmdl.partition(':')
        if colon and not empty:
            try:
                offset = self.parser.lexer.labels[label.upper()]
            except KeyError as KE:
                raise InvalidLabel(label) from KE
            emu = BatchEmulator(self.parser, std=std)
        else:
            offset = 0
            path = cmdl.strip()
            code = self.state.ingest_file(path)
            if code is None:
                yield cmd
                return
            emu = BatchEmulator(code, std=std, state=BatchState(
                environment=self.state.environment,
                file_system=self.state.file_system,
                now=self.state.now,
                cwd=self.state.cwd,
                username=self.state.username,
                hostname=self.state.hostname,
                filename=path,
            ))
        yield from emu.trace(offset, called=True)

    @_command('SETLOCAL')
    def execute_setlocal(self, cmd: SynCommand, *_):
        setting = cmd.argument_string.strip().upper()
        delay = {
            'DISABLEDELAYEDEXPANSION': False,
            'ENABLEDELAYEDEXPANSION' : True,
        }.get(setting, self.state.delayexpand)
        cmdxt = {
            'DISABLEEXTENSIONS': False,
            'ENABLEEXTENSIONS' : True,
        }.get(setting, self.state.ext_setting)
        self.state.delayexpands.append(delay)
        self.state.ext_settings.append(cmdxt)
        self.state.environments.append(dict(self.environment))

    @_command('ENDLOCAL')
    def execute_endlocal(self, *_):
        if len(self.state.environments) > 1:
            self.state.environments.pop()
            self.state.delayexpands.pop()

    @_command('GOTO')
    def execute_goto(self, cmd: SynCommand, std: IO, *_):
        try:
            label, *_ = cmd.argument_string.split(maxsplit=1)
        except ValueError:
            std.e.write('No batch label specified to GOTO command.\r\n')
            raise AbortExecution
        if label.startswith(':'):
            if label.upper() == ':EOF':
                raise Exit(self.state.ec, False)
            label = label[1:]
        raise Goto(label)

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
        raise Exit(code, exit)

    @_command('CHDIR')
    @_command('CD')
    def execute_chdir(self, cmd: SynCommand, *_):
        self.state.cwd = cmd.argument_string.strip()

    @_command('PUSHD')
    def execute_pushd(self, cmd: SynCommand, *_):
        self.state.dirstack.append(self.state.cwd)
        self.execute_chdir(cmd)

    @_command('POPD')
    def execute_popd(self, *_):
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
            if self.show_noops or current_state is False:
                yield cmd
            self.state.echo = True
            return
        if mode == 'off':
            if self.show_noops or current_state is True:
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

    def execute_command(self, cmd: SynCommand, std: IO, in_group: bool):
        verb = cmd.verb.upper().strip()

        try:
            handler = self._command.handlers[verb]
        except KeyError:
            yield cmd
            bogus_command = '\uFFFD' in verb or not verb.isprintable()
            self.state.ec = bogus_command * 9009
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
        elif not isinstance(result, int):
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
                if self.state.ec == 0:
                    continue
            if cs.condition == AstCondition.Success:
                if self.state.ec != 0:
                    continue
            yield from self.trace_statement(cs.statement, std, in_group)

    @_node(AstIf)
    def trace_if(self, _if: AstIf, std: IO, in_group: bool):
        yield synthesize(_if)
        _if = self.expand_ast_node(_if)

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
        yield synthesize(_for)
        state = self.state
        cwd = state.cwd
        vars = state.new_forloop()
        body = _for.body
        name = _for.variable

        if _for.variant == AstForVariant.FileParsing:
            if _for.mode == AstForParserMode.Command:
                emulator = BatchEmulator(_for.specline, BatchState(
                    username=state.username,
                    hostname=state.hostname,
                    now=state.now,
                    cwd=state.cwd,
                    file_system=state.file_system,
                    environment=dict(state.environment),
                    filename=state.name,
                ))
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
            count = tokens[-1] + 1
            first_variable = ord(name)
            if opt.asterisk:
                tokens.append(count)
            for n, line in enumerate(lines):
                if n < opt.skip:
                    continue
                if opt.comment and line.startswith(opt.comment):
                    continue
                tokenized = split.split(line, maxsplit=count)
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
        yield synthesize(group)
        for sequence in group.fragments:
            yield from self.trace_sequence(sequence, std, True)

    @_node(AstLabel)
    def trace_label(self, *_):
        yield from ()

    def trace_statement(self, statement: AstStatement, std: IO, in_group: bool):
        try:
            handler = self._node.handlers[statement.__class__]
        except KeyError:
            raise RuntimeError(statement)
        yield from handler(self, statement, std, in_group)

    def emulate_commands(self):
        for syn in self.trace():
            if isinstance(syn, SynCommand):
                yield str(syn)

    def emulate_to_depth(self, depth: int = 0):
        for syn in self.trace():
            if not isinstance(syn, SynNodeBase):
                continue
            if syn.ast.depth <= depth:
                yield str(syn)

    def emulate(self, offset: int = 0):
        cursor: AstNode | None = None
        for syn in self.trace(offset):
            if not isinstance(syn, SynNodeBase):
                continue
            ast = syn.ast
            if cursor is not None and ast.is_descendant_of(cursor):
                continue
            if isinstance(ast, AstPipeline):
                if len(ast.parts) == 1:
                    continue
            cursor = ast
            yield str(syn)

    def execute(self, offset: int = 0):
        for _ in self.trace(offset):
            pass

    def trace(self, offset: int = 0, called: bool = False):
        if (name := self.state.name):
            self.state.create_file(name, self.parser.lexer.text)
        length = len(self.parser.lexer.code)
        labels = self.parser.lexer.labels

        while offset < length:
            try:
                for sequence in self.parser.parse(offset):
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
