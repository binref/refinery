from __future__ import annotations

import fnmatch
import itertools
import re

from dataclasses import dataclass, field
from io import StringIO
from typing import Callable, ClassVar, Generator

from refinery.lib.batch.model import (
    ArgVarFlags,
    AstCommand,
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
    InvalidLabel,
    MissingVariable,
)
from refinery.lib.batch.parser import BatchParser
from refinery.lib.batch.state import BatchState
from refinery.lib.batch.synth import synthesize, SynCommand
from refinery.lib.batch.util import batchint, uncaret, unquote
from refinery.lib.deobfuscation import cautious_eval_or_default
from refinery.lib.types import buf


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
            ], Generator[str]]
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
    ):
        self.stack = []
        self.parser = BatchParser(data, state)
        self.std = std or IO()

    @property
    def state(self):
        return self.parser.state

    @property
    def environment(self):
        return self.state.environment

    @property
    def delayexpand(self):
        return self.state.delayexpand

    def delay_expand(self, block: str):
        def expansion(match: re.Match[str]):
            name = match.group(1)
            try:
                return parse(name)
            except MissingVariable:
                _, _, rest = name.partition(':')
                return rest
        parse = self.parser.lexer.parse_env_variable
        return re.sub(r'!([^!\n]*)!', expansion, block)

    def for_expand(self, block: str, vars: dict[str, str]):
        def expansion(match: re.Match[str]):
            flags = ArgVarFlags.Empty
            for flag in match[1]:
                flags |= ArgVarFlags.FromToken(ord(flag))
            return vars[match[3]]
        return re.sub(
            RF'%((?:~[fdpnxsatz]*)?)((?:\\$\\w+)?)([{"".join(vars)}])', expansion, block)

    def execute_find_or_findstr(self, cmd: SynCommand, std: IO, findstr: bool):
        needles = []
        paths: list[str | ellipsis] = [...]
        flags = {}
        it = iter(cmd.args)
        arg = None

        for arg in it:
            if not arg.startswith('/'):
                if not findstr and not arg.startswith('"'):
                    self.state.ec = 1
                    return
                needles.extend(unquote(arg).split())
                break
            name, has_param, value = arg[1:].partition(':')
            name = name.upper()
            if name in ('OFF', 'OFFLINE'):
                continue
            elif len(name) > 1:
                self.state.ec = 1
                return
            elif name == 'C':
                needles.append(unquote(value))
            elif name == 'F' and findstr:
                if (p := self.state.ingest_file(value)) is None:
                    self.state.ec = 1
                    return
                paths.extend(p.splitlines(False))
            elif name == 'G' and findstr:
                if (n := self.state.ingest_file(value)) is None:
                    self.state.ec = 1
                    return
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
                self.state.ec = 1
                return

        prefix_filename = False

        for arg in it:
            pattern = unquote(arg)
            if '*' in pattern or '?' in pattern:
                prefix_filename = True
                for path in self.state.file_system:
                    if fnmatch.fnmatch(path, pattern):
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
            if path is ...:
                data = std.i.read()
            else:
                data = self.state.ingest_file(path)
            if data is None:
                self.state.ec = 1
                return
            if _P and not re.fullmatch('[\\s!-~]+', data):
                continue
            for n, line in enumerate(data.splitlines(True), 1):
                for needle in needles:
                    hit = re.match(needle, line)
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
                    else:
                        std.o.write(path)
                        break
                offset += len(line)

        self.state.ec = int(nothing_found)

    @_command('FIND')
    def execute_find(self, cmd: SynCommand, std: IO, *_):
        self.execute_find_or_findstr(cmd, std, findstr=False)

    @_command('FINDSTR')
    def execute_findstr(self, cmd: SynCommand, std: IO, *_):
        self.execute_find_or_findstr(cmd, std, findstr=True)

    @_command('SET')
    def execute_set(self, cmd: SynCommand, std: IO, *_):
        if not (args := cmd.ast.fragments):
            raise EmulatorException('Empty SET instruction')

        if cmd.verb.upper() != 'SET':
            raise RuntimeError

        arithmetic = False
        quote_mode = False

        it = itertools.islice(iter(args), 1, None)

        while (tok := next(it)).isspace():
            continue
        if tok.upper() == '/P':
            raise NotImplementedError('Prompt SET not implemented.')
        if tok.upper() == '/A':
            arithmetic = True
            tok = next(it)

        args = [tok, *it]

        if arithmetic:
            integers = {}
            updated = {}
            assignment = ''.join(args[1:])
            for name, value in self.environment.items():
                try:
                    integers[name] = batchint(value)
                except ValueError:
                    pass
            for assignment in assignment.split(','):
                assignment = assignment.strip()
                name, _, expression = assignment.partition('=')
                expression = cautious_eval_or_default(expression, environment=integers)
                if expression is not None:
                    integers[name] = expression
                    updated[name] = str(expression)
                self.environment.update(updated)
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
            if not content:
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
            target = self.state.ingest_file(cmdl.strip())
            if target is None:
                yield str(cmd)
                return
            emu = BatchEmulator(target, std=std, state=BatchState(
                environment=self.state.environment,
                file_system=self.state.file_system,
                now=self.state.now,
                cwd=self.state.cwd,
                username=self.state.username,
                hostname=self.state.hostname,
                filename=target,
            ))
        yield from emu.emulate(offset, called=True)

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
    def execute_goto(self, cmd: SynCommand, *_):
        label, *_ = cmd.argument_string.split(maxsplit=1)
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
        yield str(cmd)
        if mode == 'on':
            self.state.echo = True
            return
        if mode == 'off':
            self.state.echo = False
            return
        if mode:
            if in_group and not cmdl.endswith(' '):
                cmdl += ' '
            std.o.write(F'{cmdl}\r\n')
        else:
            mode = 'on' if self.state.echo else 'off'
            std.e.write(F'ECHO is {mode}.\r\n')

    def execute_command(self, cmd: SynCommand, std: IO, in_group: bool):
        verb = cmd.verb.upper().strip()

        try:
            handler = self._command.handlers[verb]
        except KeyError:
            yield str(cmd)
            self.state.ec = 0
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

        if (result := handler(self, cmd, std, in_group)) is None:
            pass
        elif not isinstance(result, int):
            result = (yield from result)

        for k, path in paths.items():
            self.state.create_file(path, std[k].getvalue())

        if result is not None:
            self.state.ec = result

    @_node(AstPipeline)
    def emulate_pipeline(self, pipeline: AstPipeline, std: IO, in_group: bool):
        length = len(pipeline.parts)
        streams = IO(*std)
        for k, part in enumerate(pipeline.parts, 1):
            if k != 1:
                streams.i = streams.o
                streams.i.seek(0)
            if k == length:
                streams.o = std.o
            else:
                streams.o = StringIO()
            if isinstance(part, AstGroup):
                yield from self.emulate_group(part, streams, in_group)
            else:
                tokens = iter(part.fragments)
                ast = AstCommand(
                    part.offset,
                    part.silenced,
                    part.redirects,
                )
                if self.delayexpand:
                    tokens = (self.delay_expand(token) for token in tokens)
                if v := self.state.for_loop_variables:
                    tokens = (self.for_expand(token, v) for token in tokens)
                ast.fragments.extend(tokens)
                yield from self.execute_command(synthesize(ast), streams, in_group)

    @_node(AstSequence)
    def emulate_sequence(self, sequence: AstSequence, std: IO, in_group: bool):
        yield from self.emulate_statement(sequence.head, std, in_group)
        for cs in sequence.tail:
            if cs.condition == AstCondition.Failure:
                if self.state.ec == 0:
                    continue
            if cs.condition == AstCondition.Success:
                if self.state.ec != 0:
                    continue
            yield from self.emulate_statement(cs.statement, std, in_group)

    @_node(AstIf)
    def emulate_if(self, _if: AstIf, std: IO, in_group: bool):
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
            yield from self.emulate_sequence(_if.then_do, std, in_group)
        elif (_else := _if.else_do):
            yield from self.emulate_sequence(_else, std, in_group)

    @_node(AstFor)
    def emulate_for(self, _for: AstFor, std: IO, in_group: bool):
        vars = self.state.new_forloop()
        body = _for.body
        name = _for.variable

        if _for.variant == AstForVariant.FileParsing:
            if _for.mode == AstForParserMode.Command:
                return NotImplemented
            if _for.mode == AstForParserMode.Literal:
                lines = _for.spec
            else:
                def lines_from_files():
                    fs = self.state.file_system
                    for name in _for.spec:
                        for path, content in fs.items():
                            if not fnmatch.fnmatch(path, name):
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
                yield from self.emulate_sequence(body, std, in_group)
        else:
            for entry in _for.spec:
                vars[name] = entry
                yield from self.emulate_sequence(_for.body, std, in_group)

    @_node(AstGroup)
    def emulate_group(self, group: AstGroup, std: IO, in_group: bool):
        for sequence in group.fragments:
            yield from self.emulate_sequence(sequence, std, True)

    @_node(AstLabel)
    def emulate_label(self, *_):
        yield from ()

    def emulate_statement(self, statement: AstStatement, std: IO, in_group: bool):
        try:
            handler = self._node.handlers[statement.__class__]
        except KeyError:
            raise RuntimeError(statement)
        yield from handler(self, statement, std, in_group)

    def emulate(self, offset: int = 0, name: str | None = None, command_line: str = '', called: bool = False):
        if name:
            self.state.name = name
        self.state.command_line = command_line
        self.state.create_file(self.state.name, self.parser.lexer.text)
        length = len(self.parser.lexer.code)
        labels = self.parser.lexer.labels

        while offset < length:
            try:
                for sequence in self.parser.parse(offset):
                    yield from self.emulate_sequence(sequence, self.std, False)
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
            else:
                break
