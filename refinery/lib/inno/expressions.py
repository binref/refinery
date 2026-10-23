"""
Setup's boolean expressions, as Inno Setup's `TSimpleExpression` evaluates them: the `Check`
parameter of entries, the yes-or-no directives written as expressions, the `Components`, `Tasks`
and `Languages` parameters, the architecture directives, and the `BeforeInstall` and
`AfterInstall` parameters, which name one function. Setup evaluates while it reads, so a function
runs before a later error in the text is found.
"""
from __future__ import annotations

import enum

from typing import Any, Callable, Generator, NamedTuple

from refinery.lib.inno.delphi.errors import DelphiException
from refinery.lib.inno.emulation import InternalError

Parameter = str | int | bool

Identifier = Callable[[str, list[Parameter]], Generator[Any, Any, bool]]
Expander = Callable[[str], Generator[Any, Any, str]]


class ExpressionError(DelphiException):
    """
    The error that Setup's expression evaluator raises, with Setup's message.
    """


class _Token(enum.IntEnum):
    End = 0
    Open = enum.auto()
    Close = enum.auto()
    Comma = enum.auto()
    Not = enum.auto()
    And = enum.auto()
    Or = enum.auto()
    Identifier = enum.auto()
    String = enum.auto()
    Integer = enum.auto()
    Boolean = enum.auto()


_KEYWORDS = {
    'not'   : _Token.Not,
    'and'   : _Token.And,
    'or'    : _Token.Or,
    'true'  : _Token.Boolean,
    'false' : _Token.Boolean,
}

_LETTERS = frozenset('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_')
_DIGITS = frozenset('0123456789')
_IDENTIFIER = _LETTERS | _DIGITS | {'\\'}
_MAX_PARAMETERS = 10


class Rules(NamedTuple):
    """
    How Setup reads an expression: whether it skips the functions of a branch whose result is
    known, whether identifiers take parameters, whether two identifiers in a row mean `or`, and
    whether the text names one function only.
    """
    lazy: bool
    parameters: bool
    silent_or: bool
    single: bool


CHECK = Rules(lazy=True, parameters=True, silent_or=False, single=False)
"""
The rules of `EvalCheck`: a `Check` parameter and a yes-or-no directive written as an expression.
"""
INSTALL = Rules(lazy=False, parameters=True, silent_or=False, single=True)
"""
The rules of a `BeforeInstall` or `AfterInstall` parameter.
"""
NAMES = Rules(lazy=True, parameters=False, silent_or=True, single=False)
"""
The rules of `EvalExpression`: the `Components`, `Tasks` and `Languages` parameters and the
architecture directives.
"""


class _Reader:

    def __init__(self, text: str, identifier: Identifier, rules: Rules, expand: Expander | None):
        self.text = text
        self.cursor = 0
        self.identifier = identifier
        self.rules = rules
        self.expand = expand
        self.token = _Token.End
        self.value = ''

    def next(self):
        text = self.text
        end = len(text)
        cursor = self.cursor
        while cursor < end and '\x01' <= text[cursor] <= ' ':
            cursor += 1
        if cursor >= end or text[cursor] == '\0':
            self.cursor = cursor
            self.token, self.value = _Token.End, ''
            return
        character = text[cursor]
        if character in '(),':
            self.cursor = cursor + 1
            self.value = character
            self.token = {'(': _Token.Open, ')': _Token.Close, ',': _Token.Comma}[character]
            return
        if character in _LETTERS:
            start = cursor
            cursor += 1
            while cursor < end and text[cursor] in _IDENTIFIER:
                cursor += 1
            self.cursor = cursor
            self.value = word = text[start:cursor]
            self.token = _KEYWORDS.get(word.lower() if word.isascii() else word, _Token.Identifier)
            return
        if character in _DIGITS:
            start = cursor
            cursor += 1
            while cursor < end and text[cursor] in _DIGITS:
                cursor += 1
            self.cursor = cursor
            self.value = text[start:cursor]
            self.token = _Token.Integer
            return
        if character == '\'':
            output = []
            while True:
                cursor += 1
                if cursor >= end or text[cursor] == '\0':
                    raise ExpressionError('Unexpected end of expression while reading string constant')
                character = text[cursor]
                if character in '\n\r':
                    raise ExpressionError('Unterminated string')
                if character == '\'':
                    cursor += 1
                    if cursor >= end or text[cursor] != '\'':
                        break
                output.append(character)
            self.cursor = cursor
            self.value = ''.join(output)
            self.token = _Token.String
            return
        raise ExpressionError(F'Invalid symbol \'{character}\' found')

    def invalid(self, message: str | None = None) -> ExpressionError:
        return ExpressionError(message or F'Invalid token \'{self.value}\' found')

    def parameters(self) -> Generator[Any, Any, list[Parameter]]:
        parameters: list[Parameter] = []
        while self.token in (_Token.Identifier, _Token.String, _Token.Integer, _Token.Boolean):
            if len(parameters) >= _MAX_PARAMETERS:
                raise ExpressionError('Maximum number of parameters exceeded')
            if self.token is _Token.Identifier:
                if self.value.lower() != 'expandconstant':
                    raise ExpressionError('Can only call function "ExpandConstant" within parameter lists')
                self.next()
                if self.token is not _Token.Open:
                    raise self.invalid()
                self.next()
                if self.token is not _Token.String:
                    raise self.invalid()
                value = self.value
                if self.expand is not None:
                    value = yield from self.expand(value)
                parameters.append(value)
                self.next()
                if self.token is not _Token.Close:
                    raise self.invalid()
            elif self.token is _Token.String:
                parameters.append(self.value)
            elif self.token is _Token.Integer:
                parameters.append(_integer(self.value))
            else:
                parameters.append(self.value.lower() == 'true')
            self.next()
            if self.token is not _Token.Comma:
                break
            self.next()
        return parameters

    def identifier_value(self, lazy_branch: bool) -> Generator[Any, Any, bool]:
        name = self.value
        self.next()
        parameters: list[Parameter] = []
        if self.rules.parameters and self.token is _Token.Open:
            self.next()
            parameters = yield from self.parameters()
            if self.token is not _Token.Close:
                raise self.invalid()
            self.next()
        if self.rules.lazy and lazy_branch:
            return True
        return bool((yield from self.identifier(name, parameters)))

    def factor(self, lazy_branch: bool) -> Generator[Any, Any, bool]:
        if self.token is _Token.Open:
            self.next()
            result = yield from self.expression(lazy_branch)
            if self.token is not _Token.Close:
                raise ExpressionError('Invalid token')
            self.next()
            return result
        if self.token is _Token.Not:
            self.next()
            return not (yield from self.factor(lazy_branch))
        if self.token is _Token.Identifier:
            return (yield from self.identifier_value(lazy_branch))
        raise self.invalid()

    def term(self, lazy_branch: bool) -> Generator[Any, Any, bool]:
        result = yield from self.factor(lazy_branch)
        while self.token is _Token.And:
            self.next()
            if not result:
                yield from self.factor(True)
            else:
                result = yield from self.factor(lazy_branch)
        return result

    def expression(self, lazy_branch: bool) -> Generator[Any, Any, bool]:
        result = yield from self.term(lazy_branch)
        while self.token is _Token.Or or self.rules.silent_or and self.token is _Token.Identifier:
            if self.token is _Token.Or:
                self.next()
            if result:
                yield from self.term(True)
            else:
                result = yield from self.term(lazy_branch)
        return result


def _integer(digits: str) -> int:
    """
    Delphi's `StrToInt` of a run of decimal digits, which raises for a value beyond an `Integer`.
    """
    value = int(digits)
    if value > 0x7FFFFFFF:
        raise ExpressionError(F'\'{digits}\' is not a valid integer value')
    return value


def evaluate(
    text: str,
    identifier: Identifier,
    rules: Rules,
    expand: Expander | None = None,
) -> Generator[Any, Any, bool]:
    """
    Evaluates the expression as Setup's `TSimpleExpression.Eval` does: the identifier callback
    gives the value of each name with its parameters, and `expand` gives the value of the constant
    text in an `ExpandConstant` parameter; without it, the text is passed as it is.
    """
    reader = _Reader(text, identifier, rules, expand)
    reader.next()
    if not rules.single:
        result = yield from reader.expression(False)
    else:
        if reader.token is not _Token.Identifier:
            raise reader.invalid()
        result = yield from reader.identifier_value(False)
    if reader.token is not _Token.End:
        raise reader.invalid()
    return result


def decide(text: str, identifier: Callable[[str], bool], rules: Rules = NAMES) -> bool:
    """
    Setup's `EvalExpression`: evaluates an expression whose identifiers run no script, such as the
    architecture directives and the names of components and tasks. Setup raises an error of the
    expression or of an identifier as an internal error.
    """
    def ask(name: str, parameters: list[Parameter]) -> Generator[Any, Any, bool]:
        return identifier(name)
        yield

    evaluation = evaluate(text, ask, rules)
    try:
        next(evaluation)
    except StopIteration as stop:
        return stop.value
    except ExpressionError as error:
        raise InternalError(F'Expression error \'{error}\'') from error
    raise RuntimeError(F'The expression {text!r} asked for more than a value.')
