from __future__ import annotations

import ast
import itertools
import ntpath
import operator
import re
import uuid

from dataclasses import dataclass, field, fields
from enum import Enum
from io import StringIO
from typing import Callable, ClassVar, Generator, Iterable, TypeVar

from refinery.lib.deobfuscation import ExpressionParsingFailure, cautious_parse, names_in_expression
from refinery.lib.patterns import indicators
from refinery.lib.scripts.bat.help import HelpOutput
from refinery.lib.scripts.bat.model import (
    AbortExecution,
    ArgVarFlags,
    AstCommand,
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
from refinery.lib.scripts.bat.parser import BatchParser
from refinery.lib.scripts.bat.state import BatchState, ErrorZero
from refinery.lib.scripts.bat.synth import SynCommand, SynNodeBase, synthesize
from refinery.lib.scripts.bat.util import (
    batchint,
    batchrange,
    findstr_to_regex,
    split_arguments,
    uncaret,
    unquote,
)
from refinery.lib.types import buf

_T = TypeVar('_T')


_IF_OPS = {
    AstIfCmp.STR: operator.__eq__,
    AstIfCmp.EQU: operator.__eq__,
    AstIfCmp.NEQ: operator.__ne__,
    AstIfCmp.LSS: operator.__lt__,
    AstIfCmp.LEQ: operator.__le__,
    AstIfCmp.GTR: operator.__gt__,
    AstIfCmp.GEQ: operator.__ge__,
}


def _seta_mask(value: int) -> int:
    value &= 0xFFFFFFFF
    if value & 0x80000000:
        value -= 0x100000000
    return value


def _seta_div(a: int, b: int) -> int:
    if b == 0:
        raise ZeroDivisionError
    q = abs(a) // abs(b)
    return -q if (a < 0) != (b < 0) else q


_SETA_BINOPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.BitAnd: operator.and_,
    ast.BitOr: operator.or_,
    ast.BitXor: operator.xor,
}


def _seta_eval(node: ast.AST, namespace: dict[str, int]) -> int:
    """
    Evaluate a parsed CMD SET /A expression with the semantics of cmd.exe: arithmetic is
    performed on 32-bit signed integers and division truncates towards zero.
    """
    if isinstance(node, ast.Constant):
        if node.value is None or isinstance(node.value, bool):
            return 0
        if not isinstance(node.value, int):
            raise EmulatorException('Unsupported arithmetic expression.')
        return _seta_mask(node.value)
    if isinstance(node, ast.Name):
        return _seta_mask(int(namespace.get(node.id.upper(), 0)))
    if isinstance(node, ast.UnaryOp):
        value = _seta_eval(node.operand, namespace)
        op = type(node.op)
        if op is ast.USub:
            value = -value
        elif op is ast.Invert:
            value = ~value
        elif op is not ast.UAdd:
            raise EmulatorException('Unsupported arithmetic operator.')
        return _seta_mask(value)
    if isinstance(node, ast.BinOp):
        a = _seta_eval(node.left, namespace)
        b = _seta_eval(node.right, namespace)
        op = type(node.op)
        if op is ast.Div or op is ast.FloorDiv:
            return _seta_mask(_seta_div(a, b))
        if op is ast.Mod:
            return _seta_mask(a - _seta_div(a, b) * b)
        if op is ast.LShift or op is ast.RShift:
            shift = min(b, 64) if b >= 0 else 64
            apply = operator.lshift if op is ast.LShift else operator.rshift
            return _seta_mask(apply(a, shift))
        try:
            apply = _SETA_BINOPS[op]
        except KeyError:
            raise EmulatorException('Unsupported arithmetic operator.')
        return _seta_mask(apply(a, b))
    raise EmulatorException('Unsupported arithmetic expression.')


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
            regex.write(r'[^\\]*')
        if wildcard == '?':
            regex.write(r'[^\\]')
        verbatim = next(it)
    regex.write(re.escape(verbatim))
    cwd = re.escape(cwd.rstrip('\\'))
    pattern = rF'(?si:{cwd}\\{regex.getvalue()})$'
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


def _dequote_set_operand(text: str) -> str:
    """
    Strip one cmd.exe SET-style surrounding quote: everything up to the last quote when the operand
    opens with one, else the tail after it, mirroring the quote handling on the SET assignment path.
    """
    if text.startswith('"'):
        text, _, tail = text[1:].rpartition('"')
        text = text or tail
    return text


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


@dataclass(frozen=True)
class CommandFailure:
    """
    The outcome of a built-in command that failed with a diagnostic. A `_command` handler returns this
    in place of a bare exit code when the failure has a message to print; `execute_command` writes the
    message to the (redirect-aware) error stream and sets the error level. Return it only after the
    command's reconstruction chunk has been yielded, so the deobfuscated output keeps that chunk.
    """
    message: str
    errorlevel: int


MSG_SYNTAX_INCORRECT = 'The syntax of the command is incorrect.'
MSG_MISSING_OPERAND = 'Missing operand.'
MSG_NO_DRIVE = 'The system cannot find the drive specified.'
MSG_NO_PATH = 'The system cannot find the path specified.'
MSG_BAD_SWITCH = 'The filename, directory name, or volume label syntax is incorrect.'


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
            ], Generator[str, None, int | ErrorZero | CommandFailure | None]
                | int | ErrorZero | CommandFailure | None]
        ]] = {}

        def __init__(self, key: str):
            self.key = key.upper()

        def __call__(self, handler):
            if self.key in self.handlers:
                raise RuntimeError(F'Duplicate handler registered for command {self.key}.')
            self.handlers[self.key] = handler
            return handler

    def __init__(
        self,
        data: str | buf | BatchParser,
        state: BatchState | None = None,
        cfg: BatchEmulatorConfig | None = None,
        std: IO | None = None,
    ):
        self.parser = BatchParser(data, state)
        self.std = std or IO()
        self.cfg = cfg or BatchEmulatorConfig()
        self.block_labels = set()
        self.capture = False

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
        filename: str | None | ellipsis = ...,
        cmdline: bool | None = None,
    ):
        state = self.state
        if delayexpand is None:
            delayexpand = state.delayexpand
        if cmdextended is None:
            cmdextended = state.cmdextended
        if cmdline is None:
            cmdline = state.cmdline
        if environment is ...:
            environment = dict(state.environment)
        if filename is ...:
            filename = state.name
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
            cmdline=cmdline,
            context=state.context,
        )

    def get_for_variable_regex(self, vars: Iterable[str]):
        return re.compile(RF'%((?:~[fdpnxsatz]*)?)((?:\\$\\w+)?)([{"".join(vars)}])')

    def expand_delayed_variables(self, block: str):
        def expansion(match: re.Match[str]):
            name = match.group(1)
            if not name:
                return ''
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
        def expand_string(token: str) -> str:
            token = self.expand_forloop_variables(token, variables)
            if delayexpand:
                token = self.expand_delayed_variables(token)
            return token

        def expand_command_fragments(fragments: list[str]) -> list[str]:
            """
            A command whose text was altered by variable substitution is re-split at
            whitespace into verb and arguments; operators in the substituted value
            stay inert. SET commands are exempt: their argument is the whole tail.
            Control fragments never carry substitutions and pass through unchanged.
            """
            pairs = []
            for fragment in fragments:
                if isinstance(fragment, Enum):
                    pairs.append((fragment, fragment))
                    continue
                pairs.append((fragment, expand_string(fragment)))
            if not any(original != expanded for original, expanded in pairs):
                return [expanded for _, expanded in pairs]
            verb = next((expanded for _, expanded in pairs if not expanded.isspace()), '')
            if verb.upper() == 'SET':
                return [expanded for _, expanded in pairs]
            resplit = []
            for original, expanded in pairs:
                if original == expanded:
                    resplit.append(expanded)
                    continue
                pieces = split_arguments(expanded)
                if pieces and not pieces[0].isspace() and pieces[0].upper() == 'SET':
                    tail = expanded[len(pieces[0]):]
                    stripped = tail.lstrip()
                    lead = tail[:len(tail) - len(stripped)]
                    resplit.append(pieces[0])
                    if lead:
                        resplit.append(lead)
                    if stripped:
                        resplit.append(stripped)
                else:
                    resplit.extend(pieces)
            while resplit and isinstance(resplit[0], str) and resplit[0].isspace():
                del resplit[0]
            return resplit

        def expand(token):
            if isinstance(token, list):
                return [expand(v) for v in token]
            if isinstance(token, dict):
                return {k: expand(v) for k, v in token.items()}
            if isinstance(token, Enum):
                return token
            if isinstance(token, str):
                return expand_string(token)
            if isinstance(token, AstNode):
                is_command = isinstance(token, AstCommand)
                new = {}
                for tf in fields(token):
                    value = getattr(token, tf.name)
                    if is_command and tf.name == 'fragments':
                        value = expand_command_fragments(value)
                    elif tf.name != 'parent':
                        value = expand(value)
                    new[tf.name] = value
                return token.__class__(**new)
            return token
        delayexpand = self.delayexpand
        variables = self.state.for_loop_variables
        if not variables and not delayexpand:
            return ast
        return expand(ast) # type:ignore

    def _find_inputs(self, file_args: list[str], glob: bool, std: IO):
        """
        Resolve the input sources for FIND/FINDSTR. With no file arguments the single
        input is standard input, reported with a `None` display name; otherwise each file
        (optionally expanded as a wildcard) yields its resolved content. Returns a list of
        (display_name, data) pairs, or None if an explicit file does not exist.
        """
        if not file_args:
            return [(None, std.i.read())]
        state = self.state
        inputs = []
        for arg in file_args:
            if glob and ('*' in arg or '?' in arg):
                prefix = ntpath.dirname(arg)
                matches = sorted(
                    path for path in state.file_system
                    if winfnmatch(arg, path, state.cwd)
                )
                for path in matches:
                    display = ntpath.join(prefix, ntpath.basename(path))
                    inputs.append((display, state.file_system[path]))
            else:
                data = state.ingest_file(arg)
                if data is None:
                    return None
                inputs.append((arg, data))
        return inputs

    @_command('FINDSTR')
    def execute_findstr(self, cmd: SynCommand, std: IO, *_):
        yield cmd
        needles = []
        file_args = []
        flags = {}
        have_search = False

        for arg in cmd.args:
            if arg.startswith('/'):
                name, has_param, value = arg[1:].partition(':')
                name = name.upper()
                if name in ('OFF', 'OFFLINE'):
                    continue
                if len(name) != 1:
                    return 1
                if name == 'C':
                    needles.append(('/c', unquote(value)))
                    have_search = True
                elif name == 'F':
                    if (p := self.state.ingest_file(unquote(value))) is None:
                        return 1
                    file_args.extend(p.splitlines(False))
                elif name == 'G':
                    if (g := self.state.ingest_file(unquote(value))) is None:
                        return 1
                    needles.extend(('/g', line) for line in g.splitlines(False))
                    have_search = True
                elif has_param:
                    flags[name] = value
                else:
                    flags[name] = True
            elif not have_search:
                needles.extend(('', needle) for needle in unquote(arg).split())
                have_search = True
            else:
                file_args.append(unquote(arg))

        if 'L' in flags and 'R' in flags:
            return CommandFailure('Specify only /L or /R.', 2)
        if not needles:
            return 1
        for v in flags:
            if v not in 'VNIBELRSXMOPADQ':
                return 1

        inputs = self._find_inputs(file_args, True, std)
        if inputs is None:
            return 1

        literal_switch = 'L' in flags
        regex_switch = 'R' in flags
        reflags = re.IGNORECASE if 'I' in flags else 0
        patterns = []
        for origin, needle in needles:
            literal = literal_switch or (origin == '/c' and not regex_switch)
            base = re.escape(needle) if literal else findstr_to_regex(needle)
            if 'X' in flags:
                base = F'^{base}$'
            elif 'B' in flags:
                base = F'^{base}'
            elif 'E' in flags:
                base = F'{base}$'
            patterns.append(re.compile(base, reflags))

        _V = 'V' in flags # noqa; Prints only lines that do not contain a match.
        _P = 'P' in flags # noqa; Skip files with non-printable characters.
        _O = 'O' in flags # noqa; Prints the character offset before each matching line.
        _N = 'N' in flags # noqa; Prints the line number before each line that matches.
        _M = 'M' in flags # noqa; Prints only the filename if a file contains a match.

        wildcard = any('*' in a or '?' in a for a in file_args)
        prefix = bool(file_args) and (wildcard or len(inputs) > 1)
        nothing_found = True

        for display, data in inputs:
            if _P and not re.fullmatch('[\\s!-~]+', data):
                continue
            offset = 0
            for n, line in enumerate(data.splitlines(True), 1):
                line_len = len(line)
                content = line
                for terminator in ('\r\n', '\n', '\r'):
                    if content.endswith(terminator):
                        content = content[:-len(terminator)]
                        break
                matched = any(p.search(content) for p in patterns)
                if matched != _V:
                    nothing_found = False
                    if _M:
                        if display is not None:
                            std.o.write(F'{display}\r\n')
                        break
                    out = line
                    if _O:
                        out = F'{offset}:{out}'
                    if _N:
                        out = F'{n}:{out}'
                    if prefix and display is not None:
                        out = F'{display}:{out}'
                    std.o.write(out)
                offset += line_len

        return int(nothing_found)

    @_command('TYPE')
    def execute_type(self, cmd: SynCommand, std: IO, *_):
        path = unquote(cmd.argument_string.strip())
        data = self.state.ingest_file(path)
        if data is None:
            yield ErrorCannotFindFile
            return 1
        else:
            std.o.write(data)
            return 0

    @_command('FIND')
    def execute_find(self, cmd: SynCommand, std: IO, *_):
        yield cmd
        flags = {}
        search = None
        file_args = []

        for arg in cmd.args:
            if search is None and arg.startswith('/'):
                name = arg[1:].upper()
                if name in ('OFF', 'OFFLINE'):
                    continue
                if name in ('V', 'N', 'I', 'C'):
                    flags[name] = True
                    continue
                return 2
            elif search is None:
                if not arg.startswith('"'):
                    return 2
                search = unquote(arg)
            else:
                file_args.append(unquote(arg))

        if search is None:
            return 2

        inputs = self._find_inputs(file_args, False, std)
        if inputs is None:
            return 1

        _V = 'V' in flags
        _N = 'N' in flags
        _C = 'C' in flags
        casefold = 'I' in flags
        needle = search.casefold() if casefold else search
        total = 0

        for display, data in inputs:
            is_file = display is not None
            if is_file:
                std.o.write(F'\r\n---------- {display.upper()}')
                if not _C:
                    std.o.write('\r\n')
            count = 0
            for n, line in enumerate(data.splitlines(), 1):
                hay = line.casefold() if casefold else line
                contains = bool(needle) and needle in hay
                if contains != _V:
                    count += 1
                    if not _C:
                        std.o.write(F'[{n}]{line}\r\n' if _N else F'{line}\r\n')
            total += count
            if _C:
                std.o.write(F': {count}\r\n' if is_file else F'{count}\r\n')

        return int(total == 0)

    def _set_display(self, std: IO, operand: str) -> CommandFailure | None:
        """
        The SET display command: with no assignment, `SET` lists the environment variables whose name
        starts with the first whitespace token of `operand` (every variable when `operand` is empty),
        leaving the environment and error level untouched. A non-empty operand that matches nothing is
        cmd.exe's `Environment variable <operand> not defined` diagnostic with error level 1.
        """
        operand = _dequote_set_operand(operand)
        tokens = operand.split(None, 1)
        prefix = tokens[0].upper() if tokens else ''
        matches = [
            (name, value)
            for name, value in self.state.display_variables()
            if name.startswith(prefix)
        ]
        if operand and not matches:
            return CommandFailure(F'Environment variable {operand} not defined', 1)
        for name, value in matches:
            std.o.write(F'{name}={value}\r\n')
        return None

    @_command('SET')
    def execute_set(self, cmd: SynCommand, std: IO, in_group=False, piped: bool = False):
        if cmd.verb.upper() != 'SET':
            raise RuntimeError

        # Since variables can be used in GOTO, a SET can be used to change the behavior of a GOTO.
        self.block_labels.clear()

        it = iter(cmd.args)
        tk = next(it, None)
        prompt = None

        if tk is not None and tk.upper() == '/P':
            tk = next(it, None)
            if tk is None:
                yield cmd
                return CommandFailure(MSG_SYNTAX_INCORRECT, 1)
            if std.i.closed:
                prompt = ''
            elif not (prompt := std.i.readline()).endswith('\n'):
                raise InputLocked
            else:
                prompt = prompt.rstrip('\r\n')
        else:
            cmd.junk = not self.cfg.show_sets

        yield cmd

        if tk is not None and tk.upper() == '/A':
            try:
                tk = next(it)
            except StopIteration:
                tk = ''
            args = [tk, *it, *cmd.trailing_spaces]
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
            value = None
            program = ''.join(args)
            if program.startswith('"'):
                program, _, tail = program[1:].rpartition('"')
                program = program or tail
            if not program:
                return CommandFailure(MSG_SYNTAX_INCORRECT, ErrorZero.Val)
            for assignment in program.split(','):
                assignment = assignment.strip()
                if not assignment:
                    return CommandFailure(MSG_MISSING_OPERAND, ErrorZero.Val)
                parts = re.split(r'([-*+^|/%&]|<<|>>|)=', assignment, maxsplit=1)
                if len(parts) == 3:
                    name, operator, definition = parts
                    name = name.strip().upper()
                else:
                    name, operator, definition = '', '', assignment
                definition = re.sub(r'\b0([0-7]+)\b', r'0o\1', definition)
                if operator:
                    definition = F'{name}{operator}({definition})'
                definition = defang(definition)
                try:
                    expression = cautious_parse(definition)
                except ExpressionParsingFailure:
                    return CommandFailure(MSG_MISSING_OPERAND, 1073750989)
                names = names_in_expression(expression)
                if names.stored or names.others:
                    raise EmulatorException('Arithmetic SET had unexpected variable access.')
                for var in names.loaded:
                    key = var.upper()
                    if key in namespace:
                        continue
                    original = refang(var).upper()
                    try:
                        namespace[key] = batchint(self.environment[original])
                    except (KeyError, ValueError):
                        namespace[key] = 0
                try:
                    value = _seta_eval(expression.body, namespace)
                except ZeroDivisionError:
                    return CommandFailure('Divide by zero error.', 1073750993)
                except EmulatorException:
                    return CommandFailure(MSG_MISSING_OPERAND, 1073750989)
                if name:
                    self.environment[name] = str(value)
                    namespace[defang(name).upper()] = value
            if piped or self.capture or self.state.cmdline:
                std.o.write(F'{value!s}\r\n')
            return

        if tk is None:
            return self._set_display(std, '')

        args = [tk, *it, *cmd.trailing_spaces]

        if Ctrl.Equals in args:
            assigns = True
        elif cmd.argument_string.startswith('"'):
            assigns = '=' in _dequote_set_operand(cmd.argument_string)
        else:
            assigns = '=' in ''.join(args)
        if prompt is None and not assigns:
            return self._set_display(std, cmd.argument_string)

        quote_mode = False
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
        if quote_mode:
            trailing_caret, content = uncaret(content, True)
            if trailing_caret:
                content = content[:-1]
        name = name.upper()
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
            self.state.cmdextended_stack.pop()

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
            yield Error(F'Infinite loop detected for label {key}')

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
    def execute_chdir(self, cmd: SynCommand, std: IO, *_):
        yield cmd
        tail = cmd.argument_string.strip()
        drive_switch = False
        while tail[:2].upper() == '/D':
            drive_switch = True
            tail = tail[2:].lstrip()
        if not tail:
            if drive_switch:
                return CommandFailure(MSG_BAD_SWITCH, 1)
            std.o.write(F'{self.state.cwd}\r\n')
            return
        pieces = split_arguments(tail)
        if any(piece.startswith('/') for piece in pieces[1:]):
            return CommandFailure(MSG_NO_PATH, 1)
        target = unquote(tail)
        target_drive = ntpath.splitdrive(target)[0]
        current_drive = ntpath.splitdrive(self.state.cwd)[0]
        if not drive_switch and target_drive and target_drive.upper() != current_drive.upper():
            return
        if not self.state.try_chdir(target):
            return CommandFailure(MSG_NO_DRIVE, 1)

    @_command('PUSHD')
    def execute_pushd(self, cmd: SynCommand, *_):
        yield cmd
        previous = self.state.cwd
        target = cmd.argument_string.strip()
        if target and not self.state.try_chdir(unquote(target)):
            return CommandFailure(MSG_NO_DRIVE, 1)
        self.state.dirstack.append(previous)

    @_command('POPD')
    def execute_popd(self, cmd: SynCommand, *_):
        yield cmd
        try:
            self.state.cwd = self.state.dirstack.pop()
        except IndexError:
            pass

    @_command('ECHO')
    def execute_echo(self, cmd: SynCommand, std: IO, in_group: bool, *_):
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
        arg = None
        while (arg := next(it, None)) is not None:
            if not (arg.startswith('/') and 1 < len(arg)):
                break
            flag = arg.upper()
            if flag[:3] == '/A:':
                flags['A'] = flag[3:]
            else:
                flags[flag[1]] = True
            arg = None
        paths = [unquote(p) for p in (arg, *it) if p is not None]
        if not paths:
            return CommandFailure(MSG_SYNTAX_INCORRECT, 1)
        _P = 'P' in flags # Prompts for confirmation before deleting each file.
        state = self.state
        cwd = state.cwd
        for pattern in paths:
            for path in list(state.file_system):
                if not winfnmatch(pattern, path, cwd):
                    continue
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
        pending = None
        for arg in it:
            if arg.isspace():
                continue
            if pending is not None:
                if pending == '/D':
                    cwd = unquote(arg)
                pending = None
                continue
            if title is None:
                if '"' in arg:
                    title = unquote(arg)
                    continue
                title = ''
            if not arg.startswith('/'):
                start = unquote(arg)
                break
            flag = arg.upper()
            if flag == '/D':
                pending = '/D'
            elif len(flag) > 2 and flag.startswith('/D'):
                cwd = unquote(arg[2:])
            elif flag in ('/NODE', '/AFFINITY', '/MACHINE'):
                pending = flag
            elif flag == '/I':
                env = None
        if start is None or pending is not None:
            return 1
        if start and (batch := self.state.ingest_file(start)):
            state = self.clone_state(environment=env, filename=start, delayexpand=False)
            if not state.try_chdir(cwd):
                return
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
            def _flag():
                if len(arg) > 2 and arg[2] == ':':
                    flag_string = arg[3:]
                else:
                    try:
                        flag_string = next(it)
                    except StopIteration:
                        flag_string = ''
                    else:
                        flag_string = flag_string[1:] if flag_string.startswith(':') else ''
                try:
                    return _onoff(flag_string)
                except ValueError:
                    yield Error(F'Invalid flag in CMD execution: /{name} followed by {flag_string}.')
                    return None

            if arg.isspace() or not arg.startswith('/') or len(arg) < 2:
                continue
            name = arg[1].upper()
            if name in 'CKR':
                command = arg[2:] + _fuse(it)
                break
            elif name == 'Q':
                quiet = True
            elif name == 'S':
                strip = True
            elif name == 'U':
                codec = 'utf-16le'
            elif name == 'E':
                if (cmdextended := (yield from _flag())) is None:
                    return 1
            elif name == 'V':
                if (delayexpand := (yield from _flag())) is None:
                    return 1
        else:
            return 0

        if (
            (stripped := re.search('^\\s*"(.*)"(.*)', command, re.DOTALL))
            and (
                strip
                or command.count('"') != 2
                or stripped[2].strip()
                or re.search('[&<>()@^|]', stripped[1])
                or re.search('\\s', stripped[1]) is None
            )
        ):
            command = stripped[1] + stripped[2]

        state = self.clone_state(
            delayexpand=False if delayexpand is None else delayexpand,
            cmdextended=cmdextended,
            filename=None,
            cmdline=True,
        )
        state.codec = codec
        state.echo = not quiet
        shell = self.spawn(command, state, std)
        for child in shell.trace():
            if not self.cfg.skip_call:
                yield child

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
    @_command('SORT')
    @_command('TASKKILL')
    @_command('TASKLIST')
    @_command('TIME')
    @_command('TITLE')
    @_command('TREE')
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

    def execute_command(self, cmd: SynCommand, std: IO, in_group: bool, piped: bool = False):
        verb = cmd.verb.upper().strip()
        handler = self._command.handlers.get(verb)

        if handler is None:
            base, ext = ntpath.splitext(ntpath.basename(verb))
            handler = None
            if any(ext == pe.upper() for pe in self.state.envar('PATHEXT', '').split(';')):
                handler = self._command.handlers.get(base)

        if handler is None:
            if self.state.exists_file(verb):
                self.state.ec = 0
            elif not indicators.wintpath.value.fullmatch(verb):
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
            if (help_text := HelpOutput.get(verb)) is not None:
                std.o.write(help_text)
            self.state.ec = 0
            return

        if (result := handler(self, cmd, std, in_group, piped)) is None:
            pass
        elif not isinstance(result, (int, ErrorZero, CommandFailure)):
            result = (yield from result)

        if isinstance(result, CommandFailure):
            std.e.write(F'{result.message}\r\n')
            result = result.errorlevel

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
                try:
                    cmd = synthesize(ast)
                except ValueError:
                    continue
                it = self.execute_command(cmd, streams, in_group, length > 1)
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

        if _if.variant in (AstIfVariant.ErrorLevel, AstIfVariant.CmdExtVersion):
            try:
                threshold = batchint(_if.lhs)
            except ValueError:
                std.e.write(F'{_if.lhs} was unexpected at this time.\r\n')
                return
            if _if.variant is AstIfVariant.ErrorLevel:
                condition = threshold <= self.state.ec
            else:
                condition = threshold <= self.state.extensions_version
        elif _if.variant == AstIfVariant.Exist:
            condition = self.state.exists_file(_if.lhs)
        elif _if.variant == AstIfVariant.Defined:
            condition = _if.lhs.upper() in self.state.environment
        else:
            cmp = _if.cmp
            lhs = _if.lhs
            rhs = _if.rhs
            assert rhs is not None
            assert cmp is not None
            numeric = False
            if cmp is not AstIfCmp.STR:
                try:
                    ilh = batchint(lhs)
                    irh = batchint(rhs)
                except (ValueError, IndexError):
                    pass
                else:
                    lhs = ilh
                    rhs = irh
                    numeric = True
            if not numeric and _if.casefold:
                lhs = lhs.casefold()
                rhs = rhs.casefold()
            condition = _IF_OPS[cmp](lhs, rhs)

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
        spec = self.expand_ast_node(_for.spec)
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
                emulator = self.spawn(
                    spec[0], self.clone_state(filename=None, delayexpand=False))
                emulator.capture = True
                yield from emulator.trace()
                lines = emulator.std.o.getvalue().splitlines()
            elif _for.mode == AstForParserMode.Literal:
                lines = spec
            else:
                def lines_from_files():
                    fs = state.file_system
                    for name in spec:
                        for path, content in fs.items():
                            if not winfnmatch(name, path, cwd):
                                continue
                            yield from content.splitlines(False)
                lines = lines_from_files()
            opt = _for.options
            tokens = sorted(opt.tokens)
            count = tokens[-1] + 1 if tokens else 0
            first_variable = ord(name)
            comment = opt.comment
            if comment is None:
                comment = ';'
            if opt.asterisk:
                tokens.append(count)
            split = re.compile(F'[{re.escape(opt.delims)}]+') if opt.delims else None
            for n, line in enumerate(lines):
                if n < opt.skip:
                    continue
                if not line:
                    continue
                stripped = line if split is None else line.lstrip(opt.delims)
                if comment and stripped.startswith(comment):
                    continue
                if split is None:
                    tokenized = [line]
                elif not stripped:
                    if not opt.asterisk:
                        continue
                    tokenized = ['']
                elif opt.asterisk:
                    if count:
                        tokenized = split.split(stripped, count)
                    else:
                        tokenized = [stripped]
                else:
                    tokenized = split.split(stripped, 0)
                if not (tokens and tokens[0] < len(tokenized)):
                    continue
                for k, tok in enumerate(tokens):
                    name = chr(first_variable + k)
                    if not name.isalpha():
                        break
                    try:
                        vars[name] = tokenized[tok]
                    except IndexError:
                        vars[name] = ''
                yield from self.trace_sequence(body, std, in_group)
        elif isinstance(range_spec := _for.spec, batchrange) and range_spec.infinite:
            yield Error(
                F'Infinite loop detected in FOR /L loop ({range_spec.start},{range_spec.step},{range_spec.stop})')
        else:
            for entry in spec:
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
        self.state.count_statement()
        try:
            handler = self._node.handlers[statement.__class__]
        except KeyError:
            raise RuntimeError(statement)
        with self.state.context.descend():
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
            except (InvalidLabel, InputLocked):
                raise
            except EmulatorException as error:
                yield Error(str(error))
                self.state.ec = 1
                break
            except RecursionError:
                yield Error(
                    'The emulation exhausted the available call stack and was aborted, likely '
                    'due to deeply nested or recursive constructs.')
                self.state.ec = 1
                break
            else:
                break
