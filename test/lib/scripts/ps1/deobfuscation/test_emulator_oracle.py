"""
What `refinery.lib.scripts.ps1.deobfuscation.emulator._Ps1Interpreter` computes for an expression,
held against what a real Windows PowerShell 5.1 host printed for the same expression. No host is run
from here: the measurements are the ones already taken and checked in as
`test.lib.scripts.ps1.test_oracle.TYPE_TRANSCRIPTS`, and this module reads them as data.

**The interpreter's currency carries almost no .NET type.** An `Int32` and an `Int64` are the
same Python `int` to it, so the recording says more than the interpreter can answer.
`_CURRENCY` is where that is decided: it names, for each measured .NET type, the one value of the
currency a correct interpreter has to produce, and every type that collapses onto another collapses
there and nowhere else. The two .NET types the interpreter keeps apart from the value it would
otherwise share are `System.Char` and `System.Byte`: it carries a Char as a `_Char`, a `str`
subtype, rather than as the one-character `System.String` it prints as, so that an operation a
String has and a Char does not — a `*` on its left — is refused rather than run; and a Byte as a
`_Byte`, an `int` subtype, so that a fold spelling the value back out writes the width the body
produced rather than the Int32 its magnitude is. What the currency does *not* collapse is `int`
against `float`, `str` and `bool` and `None` against each other: those the currency does spell
apart, the interpreter does produce each of them, and the value that reaches a folded script is one
of them rather than the other — so a mismatch between two of those is a wrong answer and is recorded
as one. A `Decimal` and a `Single` have no counterpart in the currency at all and their rows are
held against nothing, which is why the types that leave the population are pinned by name beside the
population itself.

Two populations, because refusing to answer and answering wrongly are different things and the
deobfuscator only survives one of them. `_measured_rows` is what 5.1 computed a value for, and a
divergence there is a wrong constant folded into the emitted script. `_thrown_rows` is what 5.1
produced no value for, where the only safe answer is to refuse as well: any value at all folds a
constant into a script that has none there, whether 5.1 stepped over the erroring statement and left
`$t` unset or the error stopped the run outright.

Both ledgers hold the *values* rather than prose, and are compared whole. An entry states what 5.1
printed and what the interpreter answered instead, so a failure can be read without leaving this
file; and because the wrong answer is pinned too, a divergence that changes its shape fails as
loudly as one that appears or is fixed.
"""
from __future__ import annotations

import functools
import re
import unittest

from typing import TYPE_CHECKING, Callable, NamedTuple

from test.lib.scripts.ps1.test_oracle import TYPE_TRANSCRIPTS

from refinery.lib.scripts.ps1.deobfuscation.emulator import (
    InvokeExpression,
    _Byte,
    _Char,
    _Ps1Interpreter,
    _Ps1InterpreterError,
)
from refinery.lib.scripts.ps1.model import Ps1AssignmentExpression, Ps1ExpressionStatement
from refinery.lib.scripts.ps1.parser import Ps1Parser

if TYPE_CHECKING:
    from refinery.lib.scripts.ps1.deobfuscation.emulator import _Value

#: The two exceptions every caller of the interpreter catches — `Ps1FunctionEvaluator`,
#: `Ps1ForEachPipeline` and `evaluate_truthy` alike. Anything else escapes into the unit, so it is
#: neither an answer nor a refusal and is not counted as either.
_REFUSALS = (_Ps1InterpreterError, InvokeExpression)

_ROW = re.compile(r'\$t = (?P<expression>.+); Write-Output \(,\$t\); Write-Output \$t')


def _boolean(rendered: str) -> bool:
    return {'True': True, 'False': False}[rendered]


def _null(rendered: str) -> None:
    return {'<null>': None}[rendered]


#: The one value of the interpreter's currency that a measured witness denotes, by the .NET type the
#: recording stamped it with. A type with no entry here takes its rows out of the population rather
#: than being compared against an approximation of itself. A null value's witness names no type at
#: all, which is what the empty key is.
_CURRENCY: dict[str, Callable[[str], _Value]] = {
    'System.Byte'    : _Byte,
    'System.SByte'   : int,
    'System.Int16'   : int,
    'System.UInt16'  : int,
    'System.Int32'   : int,
    'System.UInt32'  : int,
    'System.Int64'   : int,
    'System.UInt64'  : int,
    'System.Double'  : float,
    'System.Boolean' : _boolean,
    'System.Char'    : _Char,
    'System.String'  : str,
    ''               : _null,
}


class _Divergence(NamedTuple):
    measured: _Value
    computed: _Value


class _Coverage(NamedTuple):
    measured: int
    answered: int


#: How many rows of each measured .NET type are held against the interpreter, and how many of those
#: it computes a value for at all. A census rather than a total, so that a type whose rows stop
#: being compared cannot hide behind another type's growth — and a row that turns from an answer
#: into a refusal moves a number here rather than quietly leaving the comparison below.
COVERAGE: dict[str, _Coverage] = {
    ''               : _Coverage(3, 0),
    'System.Boolean' : _Coverage(173, 99),
    'System.Byte'    : _Coverage(5, 5),
    'System.Char'    : _Coverage(8, 6),
    'System.Double'  : _Coverage(40, 21),
    'System.Int16'   : _Coverage(1, 0),
    'System.Int32'   : _Coverage(112, 77),
    'System.Int64'   : _Coverage(27, 20),
    'System.SByte'   : _Coverage(2, 0),
    'System.String'  : _Coverage(65, 24),
    'System.UInt16'  : _Coverage(2, 0),
    'System.UInt32'  : _Coverage(4, 0),
    'System.UInt64'  : _Coverage(2, 0),
}

#: The measured types no value of the currency denotes, and how many rows each takes out of the
#: population. `Decimal` is not a `float` — 5.1 computes it exactly and to a different precision —
#: and `Single` is not one either, so a row carrying one has nothing here to be right about.
TYPES_OUTSIDE_THE_CURRENCY: dict[str, int] = {
    'System.Decimal' : 51,
    'System.Single'  : 1,
}

#: How many measured rows write a collection rather than one value. Such a row's two witnesses
#: disagree by design — writing a collection unrolls it, so the container's type stands on the first
#: line and its elements' on the rest — and the population is the rows whose witnesses agree.
COLLECTION_ROWS: int = 6

#: How many measured rows 5.1 produced no value for, by stepping over the erroring statement or by
#: stopping the run. The population `ANSWERED_THROWS` is drawn from.
THROWING_ROWS: int = 47

#: Where the interpreter computes a value 5.1 did not. Each entry is a constant the deobfuscator
#: folds wrongly into the script it emits.
DIVERGENCES: dict[str, _Divergence] = {
    # A number that leaves the width of its type becomes a Double on 5.1, which is lossy and says
    # so. The interpreter keeps computing in Python integers, which are exact and unbounded, so the
    # answer is a different number written a different way.
    '2147483647 + 1'                     : _Divergence(2147483648.0, 2147483648),
    '-2147483648 / -1'                   : _Divergence(2147483648.0, 2147483648),
    '2147483647 * 2147483647'            : _Divergence(4.61168601413242e+18, 4611686014132420609),
    '512MB * 512MB'                      : _Divergence(2.88230376151712e+17, 288230376151711744),
    '9223372036854775807 + 2'            : _Divergence(9.22337203685478e+18, 9223372036854775809),
    '9223372036854775807L + 1'           : _Divergence(9.22337203685478e+18, 9223372036854775808),
    '9223372036854775807L - -1L'         : _Divergence(9.22337203685478e+18, 9223372036854775808),
    '$true + 9223372036854775807L'       : _Divergence(9.22337203685478e+18, 9223372036854775808),
    '-2147483648 - 9223372036854775807L' : _Divergence(-9.22337203900226e+18, -9223372039002259455),
    '- (-2147483648)'                    : _Divergence(2147483648.0, 2147483648),

    # The left operand decides the operation and the right one is converted to its type, so a
    # number on the left reads whatever stands on the right as a number; a Boolean the operator has
    # no method for falls back to Int32 first, which is why `$true + ''` is 1. The interpreter
    # dispatches on Python's types instead and concatenates.
    "0 + '5'"                            : _Divergence(5, '05'),
    "1 + '5'"                            : _Divergence(6, '15'),
    "5 + '5'"                            : _Divergence(10, '55'),
    "1 + '+5'"                           : _Divergence(6, '1+5'),
    "1 + ' 7 '"                          : _Divergence(8, '1 7 '),
    "1 + '  '"                           : _Divergence(1, '1  '),
    "1 + '1kb'"                          : _Divergence(1025, '11kb'),
    "1 + '1e3'"                          : _Divergence(1001.0, '11e3'),
    "1 + '1.5L'"                         : _Divergence(3, '11.5L'),
    "1 + '2147483648'"                   : _Divergence(2147483649, '12147483648'),
    "1 + '0xFFFFFFFF'"                   : _Divergence(0, '10xFFFFFFFF'),
    "12 + '0xabc'"                       : _Divergence(2760, '120xabc'),
    "$true + ''"                         : _Divergence(1, 'True'),
    '0 + [char]65'                       : _Divergence(65, '0A'),

    # A Char is a number wherever a number is wanted, and its code point is the number, which the
    # cast, index and bitwise paths now read. Subtraction and multiplication still route it through
    # the arithmetic, which reads the one-character string it spells rather than its code point, so
    # `[char]48` reaches them as the numeral zero the string parses to.
    '[char]48 - 0.0'                     : _Divergence(48.0, 0.0),
    '1.5 * [char]48'                     : _Divergence(72.0, 0.0),

    # A Char is as true as the code point it carries, so `[char]0` is false. The interpreter has no
    # Char and holds it as a one-character string, which every non-empty string reads as true.
    '[char]0 -or $false'                 : _Divergence(False, True),
    '$true -and [char]0'                 : _Divergence(False, True),
    '-not [char]0'                       : _Divergence(True, False),

    # An absent value is equal to nothing but another absent value, and orders before every value
    # there is; 5.1 answers both before it converts anything. The interpreter converts first, so the
    # zero and the `$null` meet as numbers and the Boolean and the `$null` meet as Booleans.
    '$null -eq 0'                        : _Divergence(False, True),
    '0 -eq $null'                        : _Divergence(False, True),
    '$null -ne 0'                        : _Divergence(True, False),
    '$null -eq $false'                   : _Divergence(False, True),
    '$false -eq $null'                   : _Divergence(False, True),
    '$null -lt 0'                        : _Divergence(True, False),
    '0 -gt $null'                        : _Divergence(True, False),
    '$false -gt $null'                   : _Divergence(True, False),

    # A Boolean on the left of a comparison converts the right operand to a Boolean, so every truthy
    # value on the right is equal to `$true`. The interpreter compares the Python objects, for which
    # `True` is the number one and nothing else.
    '$true -eq 2'                        : _Divergence(True, False),
    '$true -ne 2'                        : _Divergence(False, True),
    '$true -lt 2'                        : _Divergence(False, True),

    # 5.1 orders two Chars by their code points and compares them for equality ignoring case. The
    # interpreter has no Char and holds both as one-character Python strings, which it orders the
    # way it orders text — case-insensitively — so the two Chars whose order the case decides come
    # out reversed.
    '[char]65 -lt [char]97'              : _Divergence(True, False),
    '[char]97 -lt [char]66'              : _Divergence(False, True),

    # Two texts 5.1 counts equal by collating them rather than by their code points. The
    # interpreter compares the code points, which no expansion of the sharp s reaches.
    "'ss' -eq [char]0x00DF"              : _Divergence(True, False),

    # `-match` is not Python's `re.IGNORECASE`, which folds the long s onto s where .NET does not.
    "'ſ' -match 's'"                     : _Divergence(False, True),

    # A conversion answers inside the width of its target or not at all: a hexadecimal string
    # reaches Int32 as a bit pattern.
    "[int]'0xFFFFFFFF'"                  : _Divergence(-1, 4294967295),

    # `$null` on the left leaves the type to the right operand, so nothing plus a Boolean is that
    # Boolean rather than the number the interpreter converts it to.
    '$null + $true'                      : _Divergence(True, 1),
}

#: Where 5.1 produced no value and the interpreter answered anyway, with the value it answered. Each
#: entry is an expression the host has none for, folded into a constant the script could never hold.
ANSWERED_THROWS: dict[str, _Value] = {
    # A conversion whose source does not fit its target throws. The interpreter answers the
    # oversized number for an integer width and the code point Python allows for a Char, each a
    # value the script could never have held.
    '[int]2147483648'               : 2147483648,
    '[char]65536'                   : chr(65536),

    # A right operand 5.1 reads as the left's number and refuses: an overflowing numeral and a word.
    # The interpreter leaves each a string beside the number and concatenates the two.
    "1 + '1e400'"                   : '11e400',
    "16 + 'file'"                   : '16file',

    # `Convert.ToInt32` reads a based string as unsigned and rejects the sign in front of it.
    "[Convert]::ToInt32('-10', 16)" : -16,

    # A repeat count of four billion is a string .NET will not allocate.
    "'ab' * 0xFFFFFFFF"             : '',
}


class _Measured(NamedTuple):
    """
    A measured row reduced to what the interpreter can be held against: the .NET type 5.1 stamped
    the value with, and that value spelled in the interpreter's currency.
    """
    carried: str
    value: _Value


def _witness(line: str) -> tuple[str, str]:
    kind, carried, rendered = line.split('\t')
    assert kind == 'OUT', line
    return carried, rendered


def _rows() -> dict[str, tuple[str, ...]]:
    """
    Every measured row that assigns one expression to `$t` and writes it twice, keyed by the
    expression. The selection is textual so that it cannot depend on the interpreter it is used to
    test, and a row that stops being selected moves a pinned count rather than dropping out.
    """
    found = {}
    for row, transcript in TYPE_TRANSCRIPTS.items():
        match = _ROW.fullmatch(row)
        if match is not None:
            found[match.group('expression')] = transcript
    return found


def _valued_rows() -> dict[str, tuple[str, ...]]:
    """
    Every measured row whose expression produced a value: its first transcript line is that value on
    the output stream. A row whose expression errored leads with `ERROR` where 5.1 stepped over the
    statement and left `$t` unset, or with `THROW` where the error ended the run before `$t` was
    written twice — both are the absence of a value and belong to `_thrown_rows`.
    """
    return {
        expression: transcript
        for expression, transcript in _rows().items()
        if transcript[0].startswith('OUT\t')
    }


@functools.lru_cache(maxsize=1)
def _measured_rows() -> dict[str, _Measured]:
    """
    Every measured row that carries one value the currency denotes, as that value. A row whose two
    witnesses differ wrote a collection and is not a measurement of one value; a row whose type has
    no entry in `_CURRENCY` is a measurement the currency cannot hold.
    """
    found = {}
    for expression, transcript in _valued_rows().items():
        if expression in _collection_rows():
            continue
        carried, rendered = _witness(transcript[0])
        if carried in _CURRENCY:
            found[expression] = _Measured(carried, _CURRENCY[carried](rendered))
    return found


@functools.lru_cache(maxsize=1)
def _collection_rows() -> tuple[str, ...]:
    return tuple(
        expression
        for expression, transcript in _valued_rows().items()
        if len(transcript) != 2 or transcript[0] != transcript[1]
    )


@functools.lru_cache(maxsize=1)
def _types_outside_the_currency() -> dict[str, int]:
    found: dict[str, int] = {}
    for expression, transcript in _valued_rows().items():
        if expression in _collection_rows():
            continue
        carried, _ = _witness(transcript[0])
        if carried not in _CURRENCY:
            found[carried] = found.get(carried, 0) + 1
    return found


@functools.lru_cache(maxsize=1)
def _thrown_rows() -> tuple[str, ...]:
    """
    Every measured row whose expression produced no value: its first transcript line is the error the
    expression raised rather than a value on the output stream, whether 5.1 stepped over the statement
    or the error ended the run. The interpreter's only safe answer is to refuse each one alike.
    """
    return tuple(
        expression
        for expression, transcript in _rows().items()
        if not transcript[0].startswith('OUT\t')
    )


def _assigned(expression: str):
    """
    The expression as the interpreter meets it in a measured row: the right hand side of the
    assignment the row wrote it in, rather than the same text parsed on its own.
    """
    statement = Ps1Parser(F'$t = {expression}').parse().body[0]
    assert isinstance(statement, Ps1ExpressionStatement), expression
    assignment = statement.expression
    assert isinstance(assignment, Ps1AssignmentExpression), expression
    return assignment.value


class _Outcome(NamedTuple):
    answered: bool
    value: _Value


@functools.lru_cache(maxsize=None)
def _computed(expression: str) -> _Outcome:
    """
    What the interpreter makes of a measured expression, or that it declined to say. Only the two
    exceptions the interpreter's callers catch count as declining; any other one escapes, because a
    caller that does not catch it does not get a refusal from it either.
    """
    try:
        return _Outcome(True, _Ps1Interpreter()._eval(_assigned(expression)))
    except _REFUSALS:
        return _Outcome(False, None)


def _answers() -> dict[str, _Value]:
    return {
        expression: outcome.value
        for expression in _measured_rows()
        if (outcome := _computed(expression)).answered
    }


def _diverges(measured: _Value, computed: _Value) -> bool:
    """
    Whether the interpreter answered something other than the value the host printed. The Python
    type is part of the comparison because the currency spells `1` and `1.0` and `True` and `'1'`
    apart and the deobfuscator writes each of them into the script differently.
    """
    return type(measured) is not type(computed) or measured != computed


def _divergences() -> dict[str, _Divergence]:
    found = {}
    for expression, computed in _answers().items():
        measured = _measured_rows()[expression].value
        if _diverges(measured, computed):
            found[expression] = _Divergence(measured, computed)
    return found


def _answered_throws() -> dict[str, _Value]:
    return {
        expression: outcome.value
        for expression in _thrown_rows()
        if (outcome := _computed(expression)).answered
    }


class TestPs1InterpreterComputesWhatWindowsPowerShellComputed(unittest.TestCase):

    maxDiff = None

    def test_the_value_it_computes_is_the_measured_one_wherever_no_divergence_is_recorded(self):
        for expression, computed in _answers().items():
            if expression in DIVERGENCES:
                continue
            with self.subTest(expression):
                measured = _measured_rows()[expression].value
                self.assertEqual(computed, measured)
                self.assertIs(type(computed), type(measured))

    def test_the_expressions_it_computes_a_different_value_for_are_the_ones_recorded(self):
        self.assertEqual(_divergences(), DIVERGENCES)

    def test_the_rows_held_against_the_recording_are_the_ones_recorded(self):
        measured: dict[str, list[int]] = {}
        for expression, row in _measured_rows().items():
            counted = measured.setdefault(row.carried, [0, 0])
            counted[0] += 1
            counted[1] += _computed(expression).answered
        self.assertEqual(
            {carried: _Coverage(*counted) for carried, counted in measured.items()}, COVERAGE)

    def test_the_measured_types_no_value_of_the_currency_denotes_are_the_ones_recorded(self):
        self.assertEqual(_types_outside_the_currency(), TYPES_OUTSIDE_THE_CURRENCY)

    def test_the_measured_rows_that_write_a_collection_are_as_many_as_recorded(self):
        self.assertEqual(len(_collection_rows()), COLLECTION_ROWS)


class TestPs1InterpreterRefusesWhatWindowsPowerShellRefused(unittest.TestCase):
    """
    An expression a 5.1 host errors on has no value, so an interpreter that produces one has folded a
    constant the script never held — 5.1 either steps over the statement and leaves `$t` unset or
    stops the run. Refusing to answer is the safe outcome and the only correct one here, which is why
    these rows are held apart from the ones that measure a value.
    """

    maxDiff = None

    def test_the_measured_throws_it_answers_anyway_are_the_ones_recorded(self):
        self.assertEqual(_answered_throws(), ANSWERED_THROWS)

    def test_the_measured_throws_are_as_many_as_recorded(self):
        self.assertEqual(len(_thrown_rows()), THROWING_ROWS)


class TestPs1InterpreterRaisesOnlyWhatItsCallersCatch(unittest.TestCase):
    """
    `Ps1FunctionEvaluator`, `Ps1ForEachPipeline` and `evaluate_truthy` each catch
    `_Ps1InterpreterError` and `InvokeExpression` and nothing else, so any other exception leaves
    the interpreter and takes the unit down with it.
    """

    def test_no_measured_expression_raises_anything_else(self):
        escaping = []
        for expression in (*_measured_rows(), *_thrown_rows()):
            try:
                _computed(expression)
            except Exception as error:
                escaping.append(F'{expression!r}: {type(error).__name__}')
        self.assertEqual(escaping, [])
