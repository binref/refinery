from __future__ import annotations

import array
import codecs
import enum
import io
import itertools
import re

from dataclasses import dataclass, field
from typing import Callable, ClassVar, Generator

from refinery.lib.batch.const import (
    AMPERSAND,
    ANGLE_CLOSE,
    ANGLE_OPEN,
    ANGLES,
    ASTERIX,
    AT,
    CARET,
    COLON,
    COMMA,
    DOLLAR,
    EQUALS,
    LINEBREAK,
    NINE,
    PAREN_CLOSE,
    PAREN_OPEN,
    PERCENT,
    PIPE,
    QUOTE,
    SEMICOLON,
    SEPARATORS,
    SLASH,
    WHITESPACE,
    ZERO,
)
from refinery.lib.batch.model import (
    ArgVar,
    ArgVarFlags,
    Ctrl,
    EmulatorException,
    MissingVariable,
    Redirect,
    RedirectIO,
    Token,
    UnexpectedEOF,
    UnexpectedFirstToken,
    UnexpectedToken,
    Word,
)
from refinery.lib.batch.state import BatchState
from refinery.lib.batch.util import batchint, u16, uncaret, unquote
from refinery.lib.types import buf


class Mode(enum.IntEnum):
    Text = 0
    Whitespace = enum.auto()
    Quote = enum.auto()
    Label = enum.auto()
    Gap = enum.auto()
    SetStarted = enum.auto()
    SetRegular = enum.auto()
    SetQuoted = enum.auto()
    VarStarted = enum.auto()
    VarDollar = enum.auto()
    VarColon = enum.auto()


SeparatorMap = {
    AT          : Ctrl.At,
    COLON       : Ctrl.Label,
    COMMA       : Ctrl.Comma,
    PAREN_CLOSE : Ctrl.EndGroup,
    PAREN_OPEN  : Ctrl.NewGroup,
    SEMICOLON   : Ctrl.Semicolon,
}


@dataclass
class BatchLexerCursor:
    offset: int = 0
    modes: list[Mode] = field(default_factory=list)
    token: array.array[int] = field(
        default_factory=lambda: array.array('H'))
    subst_offset: int = 0
    subst_buffer: array.array[int] = field(
        default_factory=lambda: array.array('H'))

    def eof(self, size: int):
        if self.offset < size:
            return False
        return (n := len(self.subst_buffer)) == 0 or self.subst_offset >= n

    def copy(self):
        return self.__class__(
            self.offset,
            list(self.modes),
            array.array('H', self.token),
            self.subst_offset,
            array.array('H', self.subst_buffer)
        )

    @property
    def substituting(self):
        return len(self.subst_buffer) > 0


class BatchLexer:

    labels: dict[str, int]
    code: memoryview

    var_cmdarg: ArgVar | None
    var_resume: int
    var_offset: int
    var_dollar: int

    pending_redirect: RedirectIO | None

    cursor: BatchLexerCursor
    resume: BatchLexerCursor | None

    class _register:
        # A handler is given the current mode and char. It returns a boolean indicating
        # whether or not the character was processed and may be consumed.
        handlers: ClassVar[dict[Mode, Callable[
            [BatchLexer, Mode, int], Generator[Token, None, bool]
        ]]] = {}

        def __init__(self, *modes: Mode):
            self.modes = modes

        def __call__(self, handler):
            for mode in self.modes:
                self.handlers[mode] = handler
            return handler

    def __init__(self, data: str | buf | BatchLexer, state: BatchState | None = None):
        if isinstance(data, BatchLexer):
            if state is not None:
                raise NotImplementedError
            self.text = data.text
            self.code = data.code
            self.labels = data.labels
            self.state = data.state
        else:
            if state is None:
                state = BatchState()
            self.state = state
            self.preparse(data)

    def parse_group(self):
        self.group += 1

    def parse_label(self):
        if (m := self.mode) != Mode.Text or len(self.modes) != 1:
            raise EmulatorException(F'Switching to LABEL while in mode {m.name}')
        self.mode_switch(Mode.Label)

    def parse_gap(self):
        m = self.mode
        if m == Mode.Gap:
            return
        if m != Mode.Text or len(self.modes) != 1:
            raise EmulatorException(F'Switching to GAP while in mode {m.name}')
        self.mode_switch(Mode.Gap)

    def parse_set(self):
        if (m := self.mode) != Mode.Text or len(self.modes) != 1:
            raise EmulatorException(F'Switching to SET while in mode {m.name}')
        self.mode_switch(Mode.SetStarted)

    @property
    def environment(self):
        return self.state.environment

    def parse_arg_variable(self, var: ArgVar):
        """
        %* in a batch script refers to all the arguments (e.g. %1 %2 %3
            %4 %5 ...)
        Substitution of batch parameters (%n) has been enhanced.  You can
        now use the following optional syntax:
            %~1         - expands %1 removing any surrounding quotes (")
            %~f1        - expands %1 to a fully qualified path name
            %~d1        - expands %1 to a drive letter only
            %~p1        - expands %1 to a path only
            %~n1        - expands %1 to a file name only
            %~x1        - expands %1 to a file extension only
            %~s1        - expanded path contains short names only
            %~a1        - expands %1 to file attributes
            %~t1        - expands %1 to date/time of file
            %~z1        - expands %1 to size of file
            %~$PATH:1   - searches the directories listed in the PATH
                           environment variable and expands %1 to the fully
                           qualified name of the first one found.  If the
                           environment variable name is not defined or the
                           file is not found by the search, then this
                           modifier expands to the empty string
        The modifiers can be combined to get compound results:
            %~dp1       - expands %1 to a drive letter and path only
            %~nx1       - expands %1 to a file name and extension only
            %~dp$PATH:1 - searches the directories listed in the PATH
                           environment variable for %1 and expands to the
                           drive letter and path of the first one found.
            %~ftza1     - expands %1 to a DIR like output line
        In the above examples %1 and PATH can be replaced by other
        valid values.  The %~ syntax is terminated by a valid argument
        number.  The %~ modifiers may not be used with %*
        """
        state = self.state

        if (k := var.offset) is (...):
            return state.command_line
        if (j := k - 1) < 0:
            argval = state.name
        elif j < len(args := state.args):
            argval = args[j]
        else:
            return ''

        if var.flags.StripQuotes and argval.startswith('"') and argval.endswith('"'):
            argval = argval[1:-1]
        with io.StringIO() as output:
            if var.flags.StripQuotes:
                ...
            if var.flags.FullPath:
                ...
            if var.flags.DriveLetter:
                ...
            if var.flags.PathOnly:
                ...
            if var.flags.NameOnly:
                ...
            if var.flags.Extension:
                ...
            if var.flags.ShortName:
                ...
            if var.flags.Attributes:
                ...
            if var.flags.DateTime:
                ...
            if var.flags.FileSize:
                ...
            output.write(argval)
            return output.getvalue()

    @property
    def modes(self):
        return self.cursor.modes

    def reset(self, offset: int):
        self.quote = False
        self.caret = False
        self.white = False
        self.separator_count = 2
        self.first_after_gap = True
        self.group = 0
        self.cursor = BatchLexerCursor(offset)
        self.modes.append(Mode.Text)
        self.resume = None
        self.var_resume = -1
        self.var_offset = -1
        self.var_dollar = -1
        self.var_cmdarg = None
        self.pending_redirect = None

    def mode_reset(self):
        del self.modes[1:]

    def mode_finish(self):
        modes = self.modes
        if len(modes) <= 1:
            raise RuntimeError('Trying to exit base mode.')
        self.modes.pop()

    def mode_switch(self, mode: Mode):
        self.modes.append(mode)

    @property
    def mode(self):
        return self.modes[-1]

    @mode.setter
    def mode(self, value: Mode):
        self.modes[-1] = value

    @property
    def substituting(self):
        return self.cursor.substituting

    @property
    def eof(self):
        return (c := self.cursor).offset >= len(self.code) and not c.subst_buffer

    def quick_save(self):
        self.resume = self.cursor.copy()

    def quick_load(self):
        if (resume := self.resume) is None:
            raise RuntimeError
        self.cursor = resume
        self.resume = None

    def current_char(self):
        if not (subst := self.cursor.subst_buffer):
            offset = self.cursor.offset
        else:
            offset = self.cursor.subst_offset
            if offset >= (n := len(subst)):
                offset -= n
                offset += self.cursor.offset
            else:
                return self.cursor.subst_buffer[offset]
        try:
            return self.code[offset]
        except IndexError:
            raise UnexpectedEOF

    def consume_char(self):
        cursor = self.cursor
        if subst := cursor.subst_buffer:
            offset = cursor.subst_offset + 1
            if offset >= len(subst):
                del subst[:]
                cursor.subst_offset = -1
            else:
                cursor.subst_offset = offset
        else:
            offset = cursor.offset + 1
            if offset > len(self.code):
                raise EOFError('Consumed a character beyond EOF.')
            cursor.offset = offset

    def next_char(self):
        self.consume_char()
        return self.current_char()

    def parse_env_variable(self, var: str):
        name, _, modifier = var.partition(':')
        base = self.state.envar(name)
        if not modifier or not base:
            return base
        if '=' in modifier:
            old, _, new = modifier.partition('=')
            kwargs = {}
            if old.startswith('~'):
                old = old[1:]
                kwargs.update(count=1)
            return base.replace(old, new, **kwargs)
        else:
            if not modifier.startswith('~'):
                raise EmulatorException
            offset, _, length = modifier[1:].partition(',')
            offset = batchint(offset)
            if offset < 0:
                offset = max(0, len(base) + offset)
            if length:
                end = offset + batchint(length)
            else:
                end = len(base)
            return base[offset:end]

    def emit_token(self):
        switched = False
        if (buffer := self.cursor.token) and (token := u16(buffer)):
            if (pr := self.pending_redirect):
                pr.target = unquote(token)
                self.pending_redirect = None
                self.mode_switch(Mode.Gap)
                yield pr
                switched = True
            else:
                yield Word(token)
        del buffer[:]
        self.first_after_gap = False
        self.separator_count = 0
        return switched

    def tokens(self, offset: int) -> Generator[Token]:
        self.reset(offset)
        handlers = self._register.handlers
        current_char = self.current_char
        consume_char = self.consume_char
        size = len(self.code)

        while not self.cursor.eof(size):
            c = current_char()
            m = self.mode
            h = handlers[m]
            if (yield from h(self, m, c)):
                consume_char()

        if not self.first_after_gap:
            yield from self.emit_token()

    def check_variable_start(self, char: int):
        if char != PERCENT:
            return False
        if self.cursor.substituting:
            return False
        if self.next_char() == PERCENT:
            self.consume_char()
            self.cursor.token.append(PERCENT)
            return True
        self.mode_switch(Mode.VarStarted)
        self.var_cmdarg = ArgVar()
        self.var_offset = self.cursor.offset
        return True

    def check_line_break(self, mode: Mode, char: int):
        if char != LINEBREAK:
            return False
        if not self.caret:
            # caret is not reset until the next char!
            yield from self.emit_token()
            self.separator_count = 2
            self.white = True
            self.quote = False
            self.mode_reset()
            yield Ctrl.NewLine
        self.consume_char()
        return True

    def check_caret(self, char: int):
        if self.caret:
            self.cursor.token.append(char)
            self.caret = False
            self.consume_char()
            return True
        elif char == CARET:
            self.caret = True
            self.consume_char()
            return True
        else:
            return False

    def check_command_separators(self, char: int):
        if char == PAREN_CLOSE and (g := self.group) > 0:
            yield from self.emit_token()
            yield Ctrl.EndGroup
            self.mode_reset()
            self.consume_char()
            self.group = g - 1
            return True
        elif char == AMPERSAND:
            tok = Ctrl.Ampersand
        elif char == PIPE:
            tok = Ctrl.Pipe
        else:
            return False
        if self.separator_count >= 2:
            raise UnexpectedFirstToken(char)
        yield from self.emit_token()
        self.mode_reset()
        self.consume_char()
        yield tok
        self.separator_count += 1
        return True

    def check_quote_start(self, char: int):
        if char != QUOTE:
            return False
        self.cursor.token.append(char)
        self.mode_switch(Mode.Quote)
        self.caret = False
        self.separator_count = 0
        self.consume_char()
        return True

    def check_redirect_io(self, char: int):
        if char not in ANGLES:
            return False

        output = char != ANGLE_OPEN
        token = self.cursor.token

        if len(token) == 1 and (src := token[0] - ZERO) in range(10):
            del token[:]
            source = src
        else:
            source = int(output)

        char = self.next_char()

        if not output:
            how = Redirect.In
        elif char == ANGLE_CLOSE:
            how = Redirect.OutAppend
            char = self.next_char()
        else:
            how = Redirect.OutCreate

        yield from self.emit_token()

        if char != AMPERSAND:
            self.pending_redirect = RedirectIO(how, source)
            self.mode_switch(Mode.Gap)
        else:
            char = self.next_char()
            if char not in range(ZERO, NINE + 1):
                raise UnexpectedToken(char)
            self.consume_char()
            yield RedirectIO(how, source, char - ZERO)

        return True

    @_register(
        Mode.VarStarted,
        Mode.VarDollar,
        Mode.VarColon,
    )
    def gobble_var(self, mode: Mode, char: int) -> Generator[Token, None, bool]:
        yield from ()

        def done():
            self.mode_finish()
            self.var_cmdarg = None
            self.var_resume = -1
            self.var_offset = -1
            return False

        var_offset = self.var_offset
        var_resume = self.var_resume
        var_cmdarg = self.var_cmdarg
        current = self.cursor.offset
        variable = None

        if self.substituting:
            raise RuntimeError('Nested variable substitution.')

        if char == LINEBREAK:
            if var_resume < 0:
                var_resume = var_offset
            if var_resume < 0:
                raise RuntimeError
            self.cursor.offset = var_resume
            return done()

        if char == PERCENT:
            try:
                var_name = u16(self.code[var_offset:self.cursor.offset])
                variable = u16(self.parse_env_variable(var_name))
            except MissingVariable:
                if var_resume >= 0:
                    self.cursor.offset = var_resume
                self.consume_char()
                return done()

        elif var_cmdarg:
            if ZERO <= char <= NINE:
                var_cmdarg.offset = char - ZERO
                variable = u16(self.parse_arg_variable(var_cmdarg))
            elif char == ASTERIX and var_offset == current:
                var_cmdarg.offset = (...)
                variable = u16(self.parse_arg_variable(var_cmdarg))

        if variable is not None:
            self.consume_char()
            self.cursor.subst_buffer.extend(variable)
            self.cursor.subst_offset = 0
            return done()

        if mode == Mode.VarColon:
            # With a colon, the argument index must follow immediately: %~$PATH:0
            # If there is anything between colon and digit, it is not an argument variable.
            self.var_cmdarg = None
        if mode == Mode.VarDollar:
            if char == COLON:
                if var_cmdarg:
                    var_cmdarg.path = u16(self.code[self.var_dollar:current])
                self.var_resume = current
        if mode == Mode.VarStarted:
            if char == DOLLAR:
                self.var_dollar = current
                self.mode = Mode.VarDollar
                return True
            if char == COLON:
                self.var_cmdarg = None
                self.mode = Mode.VarColon
                self.var_resume = current
                return True
            if not var_cmdarg:
                return True
            try:
                flag = ArgVarFlags.FromToken(char)
            except KeyError:
                self.var_cmdarg = None
                return True
            if flag == ArgVarFlags.StripQuotes and var_cmdarg.flags > 0:
                self.var_cmdarg = None
            elif ArgVarFlags.StripQuotes not in var_cmdarg.flags:
                self.var_cmdarg = None
        return True

    @_register(Mode.Label)
    def gobble_label(self, mode: Mode, char: int) -> Generator[Token, None, bool]:
        if (yield from self.check_line_break(mode, char)):
            return False
        self.cursor.token.append(char)
        return True

    @_register(Mode.Quote)
    def gobble_quote(self, mode: Mode, char: int) -> Generator[Token, None, bool]:
        if (yield from self.check_line_break(mode, char)):
            return False
        if self.check_variable_start(char):
            return False
        self.cursor.token.append(char)
        if char == QUOTE:
            self.mode_finish()
        return True

    @_register(Mode.Whitespace)
    def gobble_whitespace(self, mode: Mode, char: int) -> Generator[Token, None, bool]:
        if char in WHITESPACE:
            self.cursor.token.append(char)
            return True
        self.mode_finish()
        token = self.cursor.token
        yield Word(u16(token))
        del token[:]
        return False

    @_register(Mode.SetQuoted)
    def gobble_quoted_set(self, mode: Mode, char: int) -> Generator[Token, None, bool]:
        if self.check_variable_start(char):
            return False

        if char == QUOTE:
            self.consume_char()
            self.cursor.token.append(QUOTE)
            self.quick_save()
            return False

        if char == LINEBREAK:
            if self.resume is None:
                yield from self.emit_token()
                self.mode_reset()
                yield Ctrl.NewLine
                return True
            elif self.caret:
                self.caret = False
                return True
            else:
                self.quick_load()
                yield from self.emit_token()
                return False

        if char == CARET and self.resume:
            self.caret = not self.caret

        if char in (PIPE, AMPERSAND) and not self.caret and self.resume is not None:
            self.quick_load()
            yield from self.emit_token()
            self.mode_finish()
            # after a quick load, the ending quote was already consumed.
            return False

        self.cursor.token.append(char)
        return True

    @_register(Mode.SetStarted)
    def gobble_set(self, mode: Mode, char: int) -> Generator[Token, None, bool]:
        token = self.cursor.token
        if (yield from self.check_line_break(mode, char)):
            return False
        if char in WHITESPACE:
            yield from self.emit_token()
            token.append(char)
            self.mode_switch(Mode.Whitespace)
            return True
        if char == SLASH and not self.pending_redirect:
            yield from self.emit_token()
            token.append(char)
            return True
        if self.check_variable_start(char):
            return False
        if not token and char == QUOTE:
            self.caret = False
            token.append(char)
            self.mode = Mode.SetQuoted
            return True
        if self.check_caret(char):
            return False
        if char == EQUALS:
            yield from self.emit_token()
            yield Ctrl.Equals
            self.mode = Mode.SetRegular
            return True
        if self.check_quote_start(char):
            return False
        if (yield from self.check_command_separators(char)):
            return False
        if (yield from self.check_redirect_io(char)):
            return False
        token.append(char)
        return True

    def common_token_checks(self, mode: Mode, char: int) -> Generator[Token, None, bool]:
        return (False
            or (yield from self.check_line_break(mode, char))
            or self.check_variable_start(char)
            or self.check_caret(char)
            or self.check_quote_start(char)
            or (yield from self.check_command_separators(char))
            or (yield from self.check_redirect_io(char)))

    @_register(Mode.SetRegular)
    def gobble_set_regular(self, mode: Mode, char: int) -> Generator[Token, None, bool]:
        if (yield from self.common_token_checks(mode, char)):
            return False
        if (pr := self.pending_redirect) and char in WHITESPACE:
            token = self.cursor.token
            self.pending_redirect = None
            pr.target = unquote(u16(token))
            del token[:]
            yield pr
        self.cursor.token.append(char)
        return True

    @_register(Mode.Gap)
    def gobble_gap(self, mode: Mode, char: int) -> Generator[Token, None, bool]:
        yield from ()
        if char in SEPARATORS:
            return True
        self.mode_finish()
        self.first_after_gap = True
        return False

    @_register(Mode.Text)
    def gobble_txt(self, mode: Mode, char: int) -> Generator[Token, None, bool]:
        if (yield from self.common_token_checks(mode, char)):
            return False
        if char in WHITESPACE:
            yield from self.emit_token()
            self.cursor.token.append(char)
            self.mode_switch(Mode.Whitespace)
            return True
        if self.separator_count > 0 and char in SEPARATORS:
            return True
        if char == SLASH and not self.pending_redirect:
            yield from self.emit_token()
        elif char == EQUALS:
            if (yield from self.emit_token()):
                return False
            else:
                yield Ctrl.Equals
                return True
        else:
            try:
                token = SeparatorMap[char]
            except KeyError:
                pass
            else:
                self.separator_count = 0
                if (yield from self.emit_token()):
                    return False
                else:
                    yield token
                    return True
        self.separator_count = 0
        self.cursor.token.append(char)
        return True

    @staticmethod
    def label(text: str):
        parts = re.split('([\x20\t\v])', text.lstrip())
        for k, part in itertools.islice(enumerate(parts), 0, None, 2):
            tq, part = uncaret(part, True)
            if not tq:
                parts[k] = part
                del parts[k + 1:]
                break
            parts[k] = part[:-1]
        return ''.join(parts).upper()

    def preparse(self, text: str | buf):
        self.labels = {}

        if not isinstance(text, str):
            text = codecs.decode(text, 'utf8', errors='replace')

        _tail = text[-10:]
        lines = text.splitlines(keepends=False)
        utf16 = array.array('H')

        if _tail.splitlines() != F'{_tail}\n'.splitlines():
            # the text had a trailing line break, which is swallowed by the splitlines method
            lines.append('')

        for k, line in enumerate(lines):
            if k > 0:
                utf16.append(LINEBREAK)
            encoded = line.encode('utf-16le')
            if not encoded:
                continue
            encoded = memoryview(encoded).cast('H')
            offset = len(utf16)
            prefix = re.search('^@?[\\s]*:', line)
            if prefix:
                p = prefix.end()
                if lb := self.label(u16(encoded[p:])):
                    self.labels.setdefault(lb, offset + p - 1)
            utf16.extend(encoded)

        self.text = text
        self.code = memoryview(utf16)

    if set(_register.handlers) != set(Mode):
        raise NotImplementedError('Not all handlers were implemented.')
