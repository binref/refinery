from __future__ import annotations

import fnmatch
import re

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
    EmulatorCommand,
    EmulatorException,
    Exit,
    Goto,
    InvalidLabel,
    Redirect,
)
from refinery.lib.batch.parser import BatchParser
from refinery.lib.batch.state import BatchState
from refinery.lib.batch.util import batchint, uncaret, unquote
from refinery.lib.deobfuscation import cautious_eval_or_default
from refinery.lib.types import buf


class BatchEmulator:

    class _register:
        handlers: ClassVar[dict[type[AstNode], Callable[[BatchEmulator, AstNode], Generator[str]]]] = {}

        def __init__(self, node_type: type[AstNode]):
            self.node_type = node_type

        def __call__(self, handler):
            self.handlers[self.node_type] = handler
            return handler

    def __init__(self, data: str | buf | BatchParser, state: BatchState | None = None):
        self.stack = []
        self.parser = BatchParser(data, state)

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
            return parse(name)
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

    def execute_set(self, cmd: EmulatorCommand):
        if not (args := cmd.argv):
            raise EmulatorException('Empty SET instruction')

        arithmetic = False
        quote_mode = False

        it = iter(args)

        if next(it).upper() != 'SET':
            raise RuntimeError
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
            if len(args) >= 2 and args[1] == '=':
                name, _, content = args
            elif (assignment := cmd.argument_string).startswith('"'):
                quote_mode = True
                assignment, _, unquoted = assignment[1:].rpartition('"')
                assignment = assignment or unquoted
                name, _, content = assignment.partition('=')
            else:
                name, _, content = ''.join(args).partition('=')
            name = name.upper()
            _, content = uncaret(content, quote_mode)
            if not content:
                self.environment.pop(name, None)
            else:
                self.environment[name] = content

    def execute_command(self, ast_command: AstCommand):
        tokens = iter(ast_command.tokens)
        if self.delayexpand:
            tokens = (self.delay_expand(token) for token in tokens)
        if v := self.state.for_loop_variables:
            tokens = (self.for_expand(token, v) for token in tokens)
        command = EmulatorCommand(tokens)
        verb = command.verb.upper().strip()
        if verb == 'SET':
            self.execute_set(command)
        elif verb == 'GOTO':
            label, *_ = command.argument_string.split(maxsplit=1)
            if label.startswith(':'):
                if label.upper() == ':EOF':
                    raise Exit(self.state.ec, False)
                label = label[1:]
            raise Goto(label)
        elif verb == 'CALL':
            empty, colon, label = command.argument_string.partition(':')
            if empty or not colon:
                raise EmulatorException(F'Invalid CALL label: {label}')
            try:
                offset = self.parser.lexer.labels[label.upper()]
            except KeyError as KE:
                raise InvalidLabel(label) from KE
            emu = BatchEmulator(self.parser)
            yield from emu.emulate(offset, called=True)
        elif verb == 'SETLOCAL':
            setting = command.argument_string.strip().upper()
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
        elif verb == 'ENDLOCAL' and len(self.state.environments) > 1:
            self.state.environments.pop()
            self.state.delayexpands.pop()
        elif verb == 'EXIT':
            it = iter(command.args)
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
        elif verb == 'CD' or verb == 'CHDIR':
            self.state.cwd = command.argument_string
        elif verb == 'PUSHD':
            directory = command.argument_string
            self.state.dirstack.append(self.cwd)
            self.cwd = directory.rstrip()
        elif verb == 'POPD':
            try:
                self.state.cwd = self.state.dirstack.pop()
            except IndexError:
                pass
        elif verb == 'ECHO':
            for io in ast_command.redirects:
                if io.type == Redirect.In:
                    continue
                if isinstance(path := io.target, str):
                    path = unquote(path.lstrip())
                    method = (
                        self.state.append_file
                    ) if io.type == Redirect.OutAppend else (
                        self.state.create_file
                    )
                    method(path, command.argument_string)
                break
            else:
                yield str(command)
        else:
            yield str(command)

    @_register(AstPipeline)
    def emulate_pipeline(self, pipeline: AstPipeline):
        for part in pipeline.parts:
            yield from self.execute_command(part)

    @_register(AstSequence)
    def emulate_sequence(self, sequence: AstSequence):
        yield from self.emulate_statement(sequence.head)
        for cs in sequence.tail:
            if cs.condition == AstCondition.Failure:
                if self.state.ec == 0:
                    continue
            if cs.condition == AstCondition.Success:
                if self.state.ec != 0:
                    continue
            yield from self.emulate_statement(cs.statement)

    @_register(AstIf)
    def emulate_if(self, _if: AstIf):
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
            yield from self.emulate_statement(_if.then_do)
        elif (_else := _if.else_do):
            yield from self.emulate_statement(_else)

    @_register(AstFor)
    def emulate_for(self, _for: AstFor):
        vars = self.state.new_forloop()
        body = _for.body
        name = _for.variable

        if _for.variant == AstForVariant.FileParsing:
            if _for.mode == AstForParserMode.Command:
                return NotImplemented
            if _for.mode == AstForParserMode.Literal:
                lines = _for.strings()
            else:
                def lines_from_files():
                    fs = self.state.file_system
                    for name in _for.strings():
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
                yield from self.emulate_statement(body)
        else:
            for entry in _for.strings():
                vars[name] = entry
                yield from self.emulate_statement(_for.body)

    @_register(AstGroup)
    def emulate_group(self, group: AstGroup):
        for sequence in group.sequences:
            yield from self.emulate_sequence(sequence)

    @_register(AstLabel)
    def emulate_label(self, label: AstLabel):
        yield from ()

    def emulate_statement(self, statement: AstStatement):
        try:
            handler = self._register.handlers[statement.__class__]
        except KeyError:
            raise RuntimeError(statement)
        yield from handler(self, statement)

    def emulate(self, offset: int = 0, name: str | None = None, command_line: str = '', called: bool = False):
        if name:
            self.state.name = name
        self.state.command_line = command_line
        length = len(self.parser.lexer.code)
        labels = self.parser.lexer.labels

        while offset < length:
            try:
                for sequence in self.parser.parse(offset):
                    yield from self.emulate_sequence(sequence)
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
