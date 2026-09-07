"""
What `refinery.lib.scripts.ps1.analysis.values.read` makes of an expression, what
`refinery.lib.scripts.ps1.analysis.values.evaluate` makes of a whole one, what
`refinery.lib.scripts.ps1.analysis.values.apply_unary` makes of a complement, what
`refinery.lib.scripts.ps1.analysis.values.integer_of` and
`refinery.lib.scripts.ps1.analysis.values.collect_integers` hand a caller that wants a number, and
what `refinery.lib.scripts.ps1.analysis.values.render` writes a value back as, each held against
what a real Windows PowerShell 5.1 host made of the same expression. No host is run from here: the
measurements are the ones already taken and checked in, and this module reads them as data, so the
expectations below are the host's rather than ours.
"""
from __future__ import annotations

import dataclasses
import decimal
import inspect
import math
import re
import unittest

from typing import Any, Callable, NamedTuple

from test.lib.scripts.ps1.corpus import (
    BOUNDARIES,
    GRID_WITNESS_GAPS,
    GRID_COMPLETE_BUT_UNREAD,
    GRID_WITNESSES,
    PROBES,
    SNIPPETS,
    SPELLINGS,
    TYPES,
)
from test.lib.scripts.ps1.test_oracle import TYPE_TRANSCRIPTS

from refinery.lib.scripts.ps1.analysis.values import (
    ALWAYS,
    INFINITY,
    MAYBE,
    NEVER,
    NOTHING,
    NULL,
    UNKNOWN,
    Ps1Constant,
    Ps1Fact,
    Ps1Outcome,
    Ps1Typed,
    _coerced_numeral,
    _stamped,
    apply,
    apply_unary,
    candidate_types,
    collect_byte_array,
    collect_integers,
    convert,
    evaluate,
    fact_of,
    integer_of,
    is_truthy,
    make_string_literal,
    read,
    render,
    resolve_expression_type,
    type_of,
    text_of,
    read_operand,
)
from refinery.lib.scripts.ps1.analysis.world import Ps1TypeWorld
from refinery.lib.scripts.ps1.analysis.worldflow import Ps1WorldReach
from refinery.lib.scripts.ps1.ast import in_evaluation_order, string_value
from refinery.lib.scripts.ps1.data import (
    OperatorOutcome,
    binary_outcome,
    conversion_outcome,
    operand_witnesses,
    resolve_type,
)
from refinery.lib.scripts.ps1.dotnet import Ps1TypeName
from refinery.lib.scripts.ps1.model import (
    Expression,
    Ps1ArrayExpression,
    Ps1ArrayLiteral,
    Ps1AssignmentExpression,
    Ps1BinaryExpression,
    Ps1CastExpression,
    Ps1ExpandableHereString,
    Ps1ExpandableString,
    Ps1ExpressionStatement,
    Ps1HereString,
    Ps1IntegerLiteral,
    Ps1ParenExpression,
    Ps1StringLiteral,
    Ps1TypeExpression,
    Ps1UnaryExpression,
)
from refinery.lib.scripts.ps1.parser import Ps1Parser
from refinery.lib.scripts.ps1.synth import Ps1Synthesizer

_ROW_PATTERN = re.compile(
    r'\$t = (?P<expression>.+); Write-Output \(,\$t\); Write-Output \$t'
)

#: What counts as a single numeric literal in a measured row. The selection is textual on purpose:
#: it has to be independent of the parser it is used to test, or a lexer that stopped reading a
#: spelling would quietly withdraw the row that measures it instead of failing on it.
_NUMERAL = re.compile(r'[-+]?\(?[0-9][0-9a-zA-Z_.+-]*\)?')


def _type(name: str) -> Ps1TypeName:
    resolved = resolve_type(name)
    assert resolved is not None, name
    return resolved


INT32 = _type('System.Int32')
INT64 = _type('System.Int64')
STRING = _type('System.String')
CHAR = _type('System.Char')
BYTE = _type('System.Byte')
SBYTE = _type('System.SByte')
UINT16 = _type('System.UInt16')
UINT32 = _type('System.UInt32')
BOOLEAN = _type('System.Boolean')
DOUBLE = _type('System.Double')
DECIMAL = _type('System.Decimal')
OBJECT_ARRAY = _type('System.Object[]')


def _boolean(rendered: str) -> bool:
    """
    The Boolean a host printed. Those two spellings are the only ones it prints, and a third is a
    `KeyError` rather than a truth value read out of the length of a word.
    """
    return {'True': True, 'False': False}[rendered]


#: How the Python payload of a fact is spelled for each .NET type a measured row carries. A type no
#: entry covers is a `KeyError` naming it rather than a comparison against a value read the wrong
#: way round. A Char and a String are spelled alike on purpose: what tells the two apart is the
#: `Ps1TypeName` a fact is stamped with, never the Python object it holds.
_PAYLOADS: dict[str, Callable[[str], int | float | bool | decimal.Decimal | str]] = {
    'System.Int32'   : int,
    'System.Int64'   : int,
    'System.Decimal' : decimal.Decimal,
    'System.Double'  : float,
    'System.Byte'    : int,
    'System.SByte'   : int,
    'System.Int16'   : int,
    'System.UInt16'  : int,
    'System.UInt32'  : int,
    'System.UInt64'  : int,
    'System.Boolean' : _boolean,
    'System.Char'    : str,
    'System.String'  : str,
}


def _transcript(expression: str, witness: str = '$t') -> tuple[str, ...]:
    """
    What a 5.1 host printed for the measured row that assigns `expression` to `$t` and then prints
    `$t` whole and `witness`. A row this module asks for and the corpus does not hold is a
    `KeyError` naming it: nothing here may run a host, so a case has to be measured in
    `test.lib.scripts.ps1.corpus` before it can be asked about.
    """
    row = F'$t = {expression}; Write-Output (,$t); Write-Output {witness}'
    return TYPE_TRANSCRIPTS[row]


def _printed(line: str) -> tuple[str, str]:
    """
    The type a transcript line's value carried and the text the host rendered it as.
    """
    kind, carried, rendered = line.split('\t')
    assert kind == 'OUT', line
    return carried, rendered


def _throws(transcript: tuple[str, ...]) -> bool:
    """
    Whether a host produced no value for the row: its first line is the error the expression raised
    rather than a value on the output stream, whether 5.1 stepped over the erroring statement and
    left `$t` unset or the error stopped the run.
    """
    return not transcript[0].startswith('OUT\t')


def _measured(expression: str) -> tuple[str, str]:
    """
    The .NET type and the rendered value a host printed for `expression`. Both witnesses name the
    type — the first for `$t` wrapped in a one-element array and unrolled back out of it, the
    second for `$t` written directly — and a row whose two witnesses disagree is not a measurement
    of one value.
    """
    wrapped, printed = _transcript(expression)
    stamp, reported = _printed(wrapped)
    carried, rendered = _printed(printed)
    assert (stamp, reported) == (carried, rendered), (wrapped, printed)
    return carried, rendered


def _measured_fact(expression: str) -> Ps1Fact:
    name, rendered = _measured(expression)
    return Ps1Constant(_type(name), _PAYLOADS[name](rendered))


def _measured_count(expression: str) -> tuple[str, int]:
    """
    The container type and the element count a host printed for an array shape. Such a row prints
    `$t.Count` as its second witness, because printing the array itself prints its elements and
    never says how many there are.
    """
    wrapped, counted = _transcript(expression, '$t.Count')
    container, _ = _printed(wrapped)
    counter, rendered = _printed(counted)
    assert counter == 'System.Int32', counted
    return container, int(rendered)


def _measured_shape(expression: str) -> tuple[Ps1TypeName, int]:
    container, count = _measured_count(expression)
    return _type(container), count


def _measured_rendering(expression: str) -> tuple[str, str]:
    """
    The container type a host stamped a collection with and the text it wrote the collection as.
    Writing one writes its elements, so this is the witness that says what they are: an element
    that is itself a collection is written as `System.Object[]` rather than as its contents.
    """
    wrapped, _ = _transcript(expression, '$t.Count')
    return _printed(wrapped)


def _measured_elements(expression: str) -> tuple[Ps1Fact, ...]:
    """
    The facts a host printed for the elements of a collection. Writing a collection out unrolls it,
    so every line after the first witness is one element under the type it carried.
    """
    transcript = _transcript(expression)
    elements: list[Ps1Fact] = []
    for line in transcript[1:]:
        name, rendered = _printed(line)
        elements.append(Ps1Constant(_type(name), _PAYLOADS[name](rendered)))
    return tuple(elements)


def _numeral_rows() -> dict[str, tuple[str, ...]]:
    rows: dict[str, tuple[str, ...]] = {}
    for row, transcript in TYPE_TRANSCRIPTS.items():
        match = _ROW_PATTERN.fullmatch(row)
        if match is None:
            continue
        expression = match.group('expression')
        if _NUMERAL.fullmatch(expression):
            rows[expression] = transcript
    return rows


_NUMERAL_ROWS = _numeral_rows()

#: The fact a 5.1 host pins each measured numeral spelling to.
MEASURED: dict[str, Ps1Fact] = {
    expression: _measured_fact(expression)
    for expression, transcript in _NUMERAL_ROWS.items()
    if not _throws(transcript)
}

#: The measured spellings 5.1 itself has no value for. It reports NumericConstantTooLarge for a
#: hexadecimal literal that fills neither width, and reads a digit group broken by an underscore as
#: a command name, because 5.1 has no digit separator.
REFUSED: tuple[str, ...] = tuple(
    expression for expression, transcript in _NUMERAL_ROWS.items() if _throws(transcript)
)

#: Measured spellings `read` refuses although the host pins each to a value: a unary minus over a
#: parenthesized literal is an operator over a value, so reaching past the parenthesis to the numeral
#: would report its width without its sign. `evaluate` applies the operator and answers the width the
#: parenthesis decides — `-(2147483648)` stays the Int64 it negates, `-(2147483647)` the Int32.
UNANSWERED: tuple[str, ...] = (
    '-(2147483648)',
    '-(2147483647)',
)

DECIDED: tuple[str, ...] = tuple(
    expression for expression in MEASURED if expression not in UNANSWERED
)


def _slot(expression: str) -> Expression:
    """
    The right hand side of `$t = <expression>`, which is the slot every measured row puts its
    expression in.
    """
    statement = Ps1Parser(F'$t = {expression}').parse().body[0]
    assert isinstance(statement, Ps1ExpressionStatement)
    assignment = statement.expression
    assert isinstance(assignment, Ps1AssignmentExpression)
    value = assignment.value
    assert isinstance(value, Expression), expression
    return value


def _read(expression: str) -> Ps1Fact:
    """
    The fact `read` answers for a measured row's expression.
    """
    return read(_slot(expression))


def _evaluated(expression: str) -> Ps1Outcome:
    """
    The outcome `evaluate` answers for a measured row's expression, which is the one call a caller
    holding the whole tree of it makes.
    """
    return evaluate(_slot(expression))


def _elements(fact: Ps1Fact) -> tuple[Ps1Fact, ...]:
    """
    The element facts an array constant carries.
    """
    assert isinstance(fact, Ps1Constant), fact
    payload = fact.payload
    assert isinstance(payload, tuple), payload
    return payload


def _payload(fact: Ps1Fact) -> object:
    """
    The Python object a constant carries, which is everything a caller whose currency is a payload
    holds of the value: the type stamped beside it stays behind.
    """
    assert isinstance(fact, Ps1Constant), fact
    return fact.payload


def _read_shape(expression: str) -> tuple[Ps1TypeName | None, int]:
    fact = _read(expression)
    return type_of(fact), len(_elements(fact))


def _spelled(fact: Ps1Fact) -> str:
    """
    The source text a fact is written back as, which is what a caller putting the value into a
    script emits. A fact that names a value always has one, so nothing to write is a broken
    contract here rather than a case to be handled.
    """
    node = render(fact)
    assert node is not None, fact
    return Ps1Synthesizer().convert(node)


#: What counts as a cast in a measured row: the type an accelerator names in brackets, and the
#: operand written against it. The selection is textual for the same reason the numeral one is, and
#: an operand may not open with a colon, so that a read of a static member — `[double]::NaN` — is
#: not taken for a value cast to `Double`.
#:
#: A text match alone is not enough, because the pattern is greedy where the language is not:
#: `[byte]1 -shl 4` matches it with the operand `1 -shl 4`, which is a different expression from
#: the one the host was asked about — the cast binds to the `1` and the shift is applied after. So
#: the match is confirmed against the parse, which is the only thing that knows the precedence.
_CAST = re.compile(r'\[(?P<target>[A-Za-z0-9_]+)\](?P<operand>[^:].*)')

#: A row that measures `-as` instead. `X -as [T]` and `[T]X` are different expressions and the
#: corpus measures both, so the two have to be told apart before either is read as an expectation.
_AS = re.compile(r'(?P<operand>.+) -as \[(?P<target>[A-Za-z0-9_]+)\]')


class _Cast(NamedTuple):
    """
    The two halves of a measured cast, as the row spells them.
    """
    target: str
    operand: str


def _converts(expression: str, operator: str | None) -> bool:
    """
    Whether the whole of `expression` is the conversion the pattern took it for: a cast when
    `operator` is `None`, and otherwise a binary application of that operator.

    A row that does not parse is not caught: every measured row is PowerShell a host ran, so one
    the parser refuses is a defect to be seen rather than a row to be quietly dropped from the
    selection.
    """
    statements = [
        node for node in Ps1Parser(expression).parse().walk()
        if isinstance(node, Ps1ExpressionStatement)
    ]
    if len(statements) != 1:
        return False
    root = statements[0].expression
    if operator is None:
        return isinstance(root, Ps1CastExpression)
    return isinstance(root, Ps1BinaryExpression) and root.operator.lower() == operator


def _rows(pattern: re.Pattern[str], operator: str | None = None) -> dict[str, _Cast]:
    matched: dict[str, _Cast] = {}
    for row in TYPE_TRANSCRIPTS:
        outer = _ROW_PATTERN.fullmatch(row)
        if outer is None:
            continue
        expression = outer.group('expression')
        inner = pattern.fullmatch(expression)
        if inner is not None and _converts(expression, operator):
            matched[expression] = _Cast(inner.group('target'), inner.group('operand'))
    return matched


CAST_ROWS = _rows(_CAST)
AS_ROWS = _rows(_AS, '-as')

#: The measured casts a host answered by throwing, which are therefore the rows that have no value
#: to be held against.
THROWN: tuple[str, ...] = tuple(
    expression for expression in CAST_ROWS if _throws(_transcript(expression))
)

#: The measured casts whose value the domain declines to compute, under the reason `convert`
#: documents for each. Every row here is one a host printed a value for, so an entry states that
#: the domain answers less than the host does — deliberately, because the rule that would produce
#: the value is one no measurement covers, and a .NET rule guessed at is a wrong answer that looks
#: like a right one.
DECLINED: dict[str, tuple[str, ...]] = {
    'a String spelling 5.1 reads by two rules that disagree with each other': (
        "[int]'1e3'",
        "[int]'1,000'",
    ),
    'a String whose target throws for reasons `convert` does not see': (
        "[double]'1.5'",
        "[double]'1,5'",
    ),
    'a collection joins on $OFS, which only a run decides': (
        "[string]('a', 'b')",
    ),
    'a Single is a width nothing here computes in': (
        '[single]1.5',
    ),
    'an operand naming no value, so the cast is given nothing to convert': (
        '[bool](0.0 / 0.0)',
    ),
}

DECLINED_CASTS: tuple[str, ...] = tuple(
    expression for group in DECLINED.values() for expression in group
)

#: The declined casts that name no type either, because the *operand* names no value and so the
#: conversion is never reached. `_evaluated_cast` falls back to the target's own column for those,
#: and `_cast_names` answers only where the whole column names one type — which it does not for
#: `System.Boolean`, although a host converts every value to one and throws for none. An entry is a
#: **defect**: the type is one the domain could name and does not.
UNREAD_OPERANDS: tuple[str, ...] = (
    '[bool](0.0 / 0.0)',
)

#: The corpus rows where the readers below name a type and `evaluate` names a different one, which
#: the agreement law would otherwise forbid outright. An entry is a **defect**, not a tolerance: it
#: is listed so that the law keeps its full strength everywhere else and a second disagreement fails
#: here rather than joining a silence.
#:
#: `resolve_expression_type` and `candidate_types` answer a cast with the type its *name* resolves
#: to, and `[array]` is the one accelerator where that is not the type the cast produces:
#: `System.Array` is abstract and has no instance, so `[array]5` is a `System.Object[]` — measured,
#: and recorded that way in the conversion grid, which is where `evaluate` reads it.
#: `analysis.values._from_conversion_cell` already documents the exception; the two name-reading
#: entries do not consult it. Fixing it means a cast's type coming from the measured cell rather
#: than from the spelling, for every target and not just this one.
READER_DISAGREEMENTS: tuple[str, ...] = (
    '$t = [array]5; Write-Output (,$t); Write-Output $t.Count',
)

#: The measured casts whose operand is itself a cast, which is how the language spells a value of a
#: type it has no literal for. They are the round trip the domain has to make inside one expression:
#: the inner cast is read as the value it spells, and the outer one converts that.
NESTED_CASTS: tuple[str, ...] = (
    '[int][char]65',
    '[int][char]48',
)

#: Every measured way a script spells a collection, each of which the corpus counts the elements
#: of. Both operators are here on the same parts, because the point of measuring them is that they
#: build different arrays out of them.
COLLECTION_SHAPES: tuple[str, ...] = (
    '@()',
    ', 1',
    ',(1, 2)',
    '(1, 2), 3',
    '@(@(1, 2))',
    '@((1, 2))',
    '@(@(1, 2), 3)',
)

#: The .NET types whose values are integers. This is a fact about the framework rather than about
#: the code under test: each of these is a whole number held in a fixed number of bits, and every
#: other type a measured row carries is either a number that is not one — a `System.Double` or a
#: `System.Decimal` — or not a number at all. What makes the distinction load-bearing is that 5.1
#: reaches a number from any of them, so a caller wanting one from a `System.Boolean` or a
#: `System.String` is asking for a *conversion*, which is a rule of its own with a rounding and a
#: parsing question in it.
INTEGER_TYPES: frozenset[str] = frozenset((
    'System.Byte',
    'System.SByte',
    'System.Int16',
    'System.UInt16',
    'System.Int32',
    'System.UInt32',
    'System.Int64',
    'System.UInt64',
))

#: The measured casts whose target is a type 5.1 spells no literal for. Each expression is
#: therefore the only way a value of that type can be written back into a script, and the host
#: stamped the row with the type and the value that spelling produces.
CAST_SPELLINGS: tuple[str, ...] = (
    '[byte]5',
    '[sbyte]-5',
    '[int16]7',
    '[uint16]7',
    '[uint32]7',
    '[uint64]7',
    '[uint64]18446744073709551615',
    '[char]0',
    '[char]65',
    '[char]65535',
)


def _converted(expression: str) -> Ps1Outcome:
    """
    What `convert` makes of a measured cast row: the type the row names as its target, applied to
    the fact `read` makes of the operand it is written against.
    """
    row = CAST_ROWS[expression]
    return convert(_read(row.operand), _type(row.target))


#: A measured row that assigns an expression to `$t` and writes it. The second witness is optional
#: here where the other harvests require it, because a row whose value is `$null` has only the
#: first: writing `$null` writes nothing at all, so there would be no second line to measure.
_OPERATION_ROW = re.compile(
    r'\$t = (?P<expression>.+?); Write-Output \(,\$t\)(?:; Write-Output \$t)?'
)


def _application(expression: str) -> Ps1BinaryExpression | None:
    """
    The one binary operator a measured expression applies, or `None` where it applies none. This
    selection is by the parse where the numeral and cast harvests select on the text, because what
    reads an operator row is a fold and a fold sees the parse; a row that stops being selected is
    caught by the count rather than by the shape of the selection.
    """
    statement = Ps1Parser(F'$t = {expression}').parse().body[0]
    if not isinstance(statement, Ps1ExpressionStatement):
        return None
    assignment = statement.expression
    if not isinstance(assignment, Ps1AssignmentExpression):
        return None
    applied = assignment.value
    return applied if isinstance(applied, Ps1BinaryExpression) else None


def _operation_rows() -> dict[str, tuple[str, ...]]:
    rows: dict[str, tuple[str, ...]] = {}
    for row, transcript in TYPE_TRANSCRIPTS.items():
        match = _OPERATION_ROW.fullmatch(row)
        if match is None:
            continue
        expression = match.group('expression')
        if _application(expression) is not None:
            rows[expression] = transcript
    return rows


#: Every measured operation, keyed by the expression the row applies its operator in.
OPERATION_ROWS: dict[str, tuple[str, ...]] = _operation_rows()

#: The measured operations a 5.1 host answered by throwing, which are therefore the rows that have
#: no value to be held against.
THROWN_OPERATIONS: tuple[str, ...] = tuple(
    expression for expression, transcript in OPERATION_ROWS.items() if _throws(transcript)
)


def _measured_operation(expression: str) -> tuple[str, str]:
    """
    The .NET type and the rendered value a host printed for a measured operation, read from the
    `(,$t)` witness, which is the one witness every row has.
    """
    return _printed(OPERATION_ROWS[expression][0])


def _witnessed_fact(measured: tuple[str, str]) -> Ps1Fact:
    """
    The fact a host printed, from the type and the text one of its witnesses carried. A witness that
    reports no type and `<null>` is `$null`, which is a value the expression produced rather than a
    sign that it produced none.
    """
    name, rendered = measured
    if (name, rendered) == ('', '<null>'):
        return NULL
    return Ps1Constant(_type(name), _PAYLOADS[name](rendered))


def _measured_operation_fact(expression: str) -> Ps1Fact:
    return _witnessed_fact(_measured_operation(expression))


def _applied(expression: str) -> Ps1Outcome:
    """
    What `apply` makes of a measured operation: the operator the row spells, over the facts
    `read_operand` makes of the two operands it stands between. This is the call
    `refinery.lib.scripts.ps1.deobfuscation.folding` makes for the same expression, so what is
    answered here is what that pass sees.

    `read_operand` and not `read`, because an operand of an operator is not read the way the same
    numeral is read standing alone: 5.1 folds a constant expression in its parser and a `Decimal`
    numeral reaching that fold loses the places it has nothing to hold. `'x' + 1.0d` is `x1` while
    `$t = 1.0d` is `1.0`, both measured, so a step composed out of `read` would answer a value no
    host prints and the law that `evaluate` agrees with its steps would be quantified over the
    wrong step.
    """
    applied = _application(expression)
    assert applied is not None, expression
    return apply(
        applied.operator.lower(), read_operand(applied.left), read_operand(applied.right))


#: The measured operations the domain answers with the exact value a host printed for them. Each is
#: a fold the constant folding pass performs, so this list is what says a fold was not lost.
PINNED_OPERATIONS: tuple[str, ...] = (
    "'a' + 1.5",
    "'x' + (1.0d)",
    "'x' + 0.0d",
    "'x' + 1.000d",
    "'x' + 1.00d",
    "'x' + 1.0d",
    "'x' + 1.100d",
    "'x' + 1.2300d",
    "'x' + 10.0d",
    "'x' + 2.0d",
    '1.000d + 0d',
    '1.00d + 0d',
    '1.0d * 1d',
    '1.0d + 2.0d',
    '1.0d - 0d',
    '1.0d / 1d',
    '1.100d + 0d',
    '1.10d + 0d',
    '1.500d + 1.500d',
    '2.50d + 0d',
    '$null -gt -5',
    '$null -le -5',
    '$null -lt -5',
    '$true - 1.5',
    "$true -eq '0'",
    '$true -gt 2',
    '$true -lt 2',
    "'1000' -eq 1e3d",
    "'a' + 1e3d",
    "'x' + 1.10d",
    '1.0d + 0d',
    '1.0d - $true',
    '2 * [char]48',
    '79228162514264337593543950335d + 0d',
    "[char]48 - '1'",
    "[char]48 -eq '0'",
    '[char]48 -eq 48',
    '[char]65 -ceq [char]97',
    '[char]65 -eq [char]97',
    '[char]65 -lt [char]97',
    '[char]97 -lt [char]66',
    '$null -eq $null',
    "$null -eq ''",
    '$null -eq 0',
    '$null -lt 1',
    "'' -eq $null",
    "'' -eq '0'",
    "'' -eq 0",
    "'0' -eq 0",
    "'1.0' -eq 1",
    "'A' -ceq 'a'",
    "'A' -ieq 'a'",
    '0 -eq $null',
    "0 -eq '0'",
    '1 -ceq 1',
    "1 -eq '1.0'",
    '$null -eq $false',
    '$null -ne $null',
    '$null -ne 0',
    '$null -ge 1',
    '$null -gt 1',
    '$null -le 1',
    '$null -lt 0',
    "$null -lt ''",
    "$null -lt 'abc'",
    '$false -eq $null',
    '$false -gt $null',
    '$true -eq $null',
    '0 -gt $null',
    '1 -ge $null',
    '1 -gt $null',
    '1 -le $null',
    '1 -lt $null',
    '1 -ne $null',
    "'' -gt $null",
    "'abc' -lt $null",
    '$false -eq 0',
    '$false -lt 5',
    '$true -eq 1',
    '$true -eq 2',
    "$true -eq ''",
    "$true -eq 'abc'",
    "$true -ge 'abc'",
    '$true -gt $false',
    '$true -ne 2',
    '2 -eq $true',
    "'abc' -eq $true",
    "'10' -ne 10",
    "10 -ne '10'",
    '$null + $true',
    "$null + 'abc'",
    '$null + 1.5d',
    '$null + [char]65',
    '$false + 1',
    '$true * 1.5d',
    '$true + $true',
    "$true + ''",
    '$true + 1',
    '$true + 1.5',
    '$true - 1',
    '$true -band 1',
    '$true -bxor $false',
    '$true / 1',
    '1 + $true',
    '1 - $true',
    '2 * $true',
    "'10' -band 6",
    "'1e400' + 1",
    "'5' - 1",
    "'5' / 2",
    "0 + '5'",
    "1 + '  '",
    "1 + ' 7 '",
    "1 + '+5'",
    "1 + '0xFFFFFFFF'",
    "1 + '1.5L'",
    "1 + '1e3'",
    "1 + '1kb'",
    "1 + '2147483648'",
    "1 + '5'",
    "1 - '5'",
    "12 + '0xabc'",
    "5 + '5'",
    '0 + [char]65',
    '1.5 * [char]48',
    '[char]48 - 0.0',
    '[char]48 -band [byte]255',
    '[char]48 -bxor [char]48',
    '[char]65 -bxor 32',
    '-1 * [uint64]1',
    '-1 -band [uint32]1',
    '-2147483648 % -1',
    '-2147483648 - 9223372036854775807L',
    '-2147483648 / -1',
    '1L -shl 64',
    '0xFFFFFFFF -bxor 0x5A',
    '0xFFFFFFFF + 0',
    '0xFFFFFFFFFFFFFFFF + 0',
    '1kb + 0',
    '1L + 0',
    '10d + 0',
    '10 - $null',
    '$null + 5',
    '$null - 5',
    '$null -band 1',
    '$null * 1',
    '2147483647 + 1',
    '100000000000000d * 100000000000000d',
    '1.2345678901234567890123456789d + 0d',
    '1.50d + 1.50d',
    '1d / 3d',
    '79228162514264337593543950334d + 1d',
    '79228162514264337593543950335d - 1d',
    '79228162514264337593543950335d * 1d',
    '79228162514264337593543950335d / 1d',
    '-2147483647 - 1',
    '10 -ne 20',
    "'5' + 5",
    "'a' + $null",
    "'a' + $true",
    "'a' + $false",
    "'a' + 1.50d",
    "'a' + -1.50d",
    "'a' + 0.5d",
    "'a' + 1L",
    "'a' + 79228162514264337593543950335d",
    "'a' + [char]65",
    "'a' + [uint64]18446744073709551615",
)

#: A measured join beside the measured cast of the same value to String. `+` with a text on its left
#: appends the text its right operand writes, so the two rows of a pair ask one question twice and
#: an answer that is right at one of them and wrong at the other is not one answer.
JOINED_AGAINST_ITS_TEXT: tuple[tuple[str, str], ...] = (
    ("'a' + $true", '[string]$true'),
    ("'a' + $false", '[string]$false'),
    ("'a' + 1L", '[string]1L'),
    ("'a' + 1.50d", '[string]1.50d'),
    ("'a' + 0.5d", '[string]0.5d'),
    ("'a' + -1.50d", '[string]-1.50d'),
    ("'a' + 79228162514264337593543950335d", '[string]79228162514264337593543950335d'),
    ("'a' + [uint64]18446744073709551615", '[string][uint64]18446744073709551615'),
)

#: The six comparisons, in each of the three ways one may be spelled: bare, `-c` for a comparison
#: that minds case and `-i` for one that ignores it. Written out rather than harvested off the
#: language tables, so that a spelling the lexer stopped reading takes rows out of the population
#: below and is caught there rather than shrinking it quietly.
COMPARISON_OPERATORS: frozenset[str] = frozenset(
    F'-{case}{name}'
    for name in ('eq', 'ne', 'lt', 'le', 'gt', 'ge')
    for case in ('', 'c', 'i')
)


def _is_comparison(expression: str) -> bool:
    applied = _application(expression)
    return applied is not None and applied.operator.lower() in COMPARISON_OPERATORS


#: Every measured operation that applies one of them, selected by the parse so that a comparison
#: measured after this was written is one the laws over it are quantified over too.
COMPARISON_ROWS: tuple[str, ...] = tuple(
    expression for expression in OPERATION_ROWS if _is_comparison(expression)
)

#: The measured comparisons the domain settles a Boolean for, grouped by what settles them. 5.1
#: reads the operand on the *left* to decide what kind of comparison happens and converts the other
#: one into it, except that an absent operand on either side is settled before any conversion — so
#: the group a row is in is a claim about the language and not about the values in it.
DECIDED_COMPARISONS: dict[str, tuple[str, ...]] = {
    'a text on the left, so the right operand is read as text': (
        "'' -eq 0",
        "'' -eq '0'",
        "'0' -eq 0",
        "'1.0' -eq 1",
        "'10' -ne 10",
        "'A' -ceq 'a'",
        "'A' -ieq 'a'",
        "'abc' -eq $true",
        "'1000' -eq 1e3d",
    ),
    'a number on the left, so the right operand is read as a number': (
        '10 -ne 20',
        '1 -ceq 1',
        "0 -eq '0'",
        "1 -eq '1.0'",
        "10 -ne '10'",
        '2 -eq $true',
    ),
    'a Boolean on the left, so the right operand is read as a truth': (
        '$true -eq 1',
        '$true -eq 2',
        "$true -eq ''",
        "$true -eq 'abc'",
        "$true -ge 'abc'",
        '$true -gt $false',
        '$true -ne 2',
        '$false -eq 0',
        '$false -lt 5',
        "$true -eq '0'",
        '$true -gt 2',
        '$true -lt 2',
    ),
    'an absent operand on one side, so the two are compared by presence': (
        '$null -eq $null',
        '$null -ne $null',
        '$null -eq $false',
        '$null -eq 0',
        "$null -eq ''",
        '$null -ne 0',
        '$null -ge 1',
        '$null -gt 1',
        '$null -le 1',
        '$null -lt 0',
        '$null -lt 1',
        "$null -lt ''",
        "$null -lt 'abc'",
        '$true -eq $null',
        '$false -eq $null',
        '$false -gt $null',
        '0 -eq $null',
        '0 -gt $null',
        '1 -ge $null',
        '1 -gt $null',
        '1 -le $null',
        '1 -lt $null',
        '1 -ne $null',
        "'' -eq $null",
        "'' -gt $null",
        "'abc' -lt $null",
        '$null -gt -5',
        '$null -le -5',
        '$null -lt -5',
    ),
    'a Char on the left, so an equality reads the right operand as a character': (
        "[char]48 -eq '0'",
        '[char]48 -eq 48',
        '[char]65 -eq [char]97',
        '[char]65 -ceq [char]97',
        '[char]65 -lt [char]97',
        '[char]97 -lt [char]66',
    ),
}

DECIDED_COMPARISON_ROWS: tuple[str, ...] = tuple(
    expression for group in DECIDED_COMPARISONS.values() for expression in group
)

#: The measured comparisons the domain settles no value for. Refusing is allowed — ordering two
#: texts is a culture's question, and ordering a number against a text may abort.
#: Answering one of them differently from a host is not allowed. An entry leaving this tuple is an
#: answer gained and one joining it an answer lost, so neither can happen without this being
#: rewritten.
UNDECIDED_COMPARISONS: tuple[str, ...] = (
    "'10' -lt '9'",
    "'10' -lt 9",
    "'10' -ge 9",
    "'10' -cle '9'",
    "'B' -gt 'a'",
    "'B' -cgt 'a'",
    "'B' -igt 'a'",
    "10 -lt '9'",
    "10 -ge '9'",
    "1 -lt '5'",
    "1 -eq 'abc'",
    "1 -ne 'abc'",
    "'10' -gt 9",
    "'10' -le '9'",
    "'2' -lt '10'",
    "'ss' -eq [char]0x00DF",
    "[char]0x00DF -eq 'ss'",
)

#: The measured comparisons against a collection on the left, which 5.1 answers with the elements
#: that match the right operand rather than with a truth: `10, 20, 30 -eq 20` is the one-element
#: collection `20` and `@(1, 2) -eq $null` is the empty one. The domain settles the same collection,
#: so these are decided rather than refused, but the host printed the members and not a fact this
#: module reconstructs — so the type is pinned here and the value beside the fold, in
#: `test.lib.scripts.ps1.deobfuscation.test_value_domain`.
FILTERED_COMPARISONS: tuple[str, ...] = (
    '10, 20, 30 -eq 20',
    '10, 20, 30, 20, 10 -ne 20',
    '@(1, 2) -eq $null',
)

#: The measured Decimal literals at the extremes of the type. A `System.Decimal` is a 96 bit
#: coefficient with a scale of at most 28, so `2**96 - 1` is the largest magnitude it holds and
#: carries the 29 significant digits the type is worth; the other three are that magnitude at a
#: scale of one, its negative, and 29 significant digits at the widest scale.
WIDEST_DECIMAL_LITERALS: tuple[str, ...] = (
    '79228162514264337593543950335d',
    '-79228162514264337593543950335d',
    '7922816251426433759354395033.5d',
    '1.2345678901234567890123456789d',
)

#: The measured Decimal arithmetic the domain answers, at magnitudes and scales Python's default
#: 28 digit context cannot hold. `79228162514264337593543950334d + 1d` lands exactly on the largest
#: value the type holds and `1.50d + 1.50d` keeps the scale both addends were written with.
EXACT_DECIMAL_OPERATIONS: tuple[str, ...] = (
    '10d + 0',
    '100000000000000d * 100000000000000d',
    '1.2345678901234567890123456789d + 0d',
    '1.50d + 1.50d',
    '79228162514264337593543950334d + 1d',
    '79228162514264337593543950335d - 1d',
    '79228162514264337593543950335d * 1d',
)

#: The measured Decimal divisions, which are asked about separately from the other operations
#: because a quotient is the one that need not be exact: `1d / 3d` is rounded onto the places the
#: type has, where `79228162514264337593543950335d / 1d` is answered whole.
DECIMAL_DIVISIONS: tuple[str, ...] = (
    '1d / 3d',
    '79228162514264337593543950335d / 1d',
)

#: The measured cast of a Decimal to String, which is where the scale a value was written with
#: becomes text.
DECIMAL_TEXTS: tuple[str, ...] = (
    '[string]1.50d',
    '[string]0.5d',
    '[string]-1.50d',
    '[string]10d',
)

#: Decimal literals that spell one number at more than one scale, each of which the corpus measures
#: the cast to String of. The type keeps the places a value was written with, so `1.0d` and `1.00d`
#: are one number and two values, and a host writes the one `1.0` and the other `1.00`.
SCALED_DECIMALS: tuple[str, ...] = (
    '1.0d',
    '1.00d',
    '1.000d',
    '1.10d',
    '1.100d',
)

#: The precisions the questions about a Decimal are asked under. 28 is Python's default and the
#: others stand for what anything else sharing the process may set it to: one digit, a handful, and
#: more than the type has.
DECIMAL_PRECISIONS: tuple[int, ...] = (1, 5, 28, 60)


def _digits(fact: Ps1Fact) -> str | None:
    """
    The digits a fact writes its value with, or `None` where it names no value. The two outcomes are
    spelled apart because they are different outcomes, and the digits are read off the payload
    rather than compared as numbers: `Decimal('3.00')` and `Decimal('3')` are equal and are not the
    same text, and the scale a Decimal carries is exactly what its rows measure.
    """
    return str(_payload(fact)) if isinstance(fact, Ps1Constant) else None


def _complement(expression: str) -> Ps1UnaryExpression | None:
    """
    The complement a measured expression applies, or `None` where it applies none. Selected by the
    parse and by the operator, because a measured row that writes a unary minus — `- 2147483648`,
    with the space that keeps the sign out of the numeral — is a different question.
    """
    statement = Ps1Parser(F'$t = {expression}').parse().body[0]
    if not isinstance(statement, Ps1ExpressionStatement):
        return None
    assignment = statement.expression
    if not isinstance(assignment, Ps1AssignmentExpression):
        return None
    applied = assignment.value
    if not isinstance(applied, Ps1UnaryExpression) or applied.operator.lower() != '-bnot':
        return None
    return applied


def _complement_rows() -> dict[str, tuple[str, ...]]:
    rows: dict[str, tuple[str, ...]] = {}
    for row, transcript in TYPE_TRANSCRIPTS.items():
        match = _OPERATION_ROW.fullmatch(row)
        if match is None:
            continue
        expression = match.group('expression')
        if _complement(expression) is not None:
            rows[expression] = transcript
    return rows


#: Every measured complement, keyed by the expression the row writes it in.
COMPLEMENT_ROWS: dict[str, tuple[str, ...]] = _complement_rows()

#: The measured complements a 5.1 host answered by throwing.
THROWN_COMPLEMENTS: tuple[str, ...] = tuple(
    expression for expression, transcript in COMPLEMENT_ROWS.items() if _throws(transcript)
)


def _complemented(expression: str) -> Ps1Outcome:
    """
    What `apply_unary` makes of a measured complement, asked exactly as
    `refinery.lib.scripts.ps1.deobfuscation.folding` asks it: the operator the row spells, over the
    fact `read` makes of the operand it stands before.
    """
    applied = _complement(expression)
    assert applied is not None, expression
    return apply_unary(applied.operator, read(applied.operand))


def _complement_operand(expression: str) -> Expression | None:
    """
    The operand a measured complement stands before.
    """
    applied = _complement(expression)
    assert applied is not None, expression
    return applied.operand


def _measured_complement(expression: str) -> tuple[str, str]:
    """
    The .NET type and the rendered value a host printed for a measured complement.
    """
    return _printed(COMPLEMENT_ROWS[expression][0])


def _measured_complement_fact(expression: str) -> Ps1Fact:
    return _witnessed_fact(_measured_complement(expression))


def _negation(expression: str) -> Ps1UnaryExpression | None:
    """
    The unary minus a measured expression applies, or `None` where it applies none. The parse
    decides it, as it does for a complement, and here that is the whole selection: a minus written
    against a numeral is part of the numeral, so `-5` is a literal and only `- 5` is an operator.
    """
    statement = Ps1Parser(F'$t = {expression}').parse().body[0]
    if not isinstance(statement, Ps1ExpressionStatement):
        return None
    assignment = statement.expression
    if not isinstance(assignment, Ps1AssignmentExpression):
        return None
    applied = assignment.value
    if not isinstance(applied, Ps1UnaryExpression) or applied.operator != '-':
        return None
    return applied


def _negation_rows() -> dict[str, tuple[str, ...]]:
    rows: dict[str, tuple[str, ...]] = {}
    for row, transcript in TYPE_TRANSCRIPTS.items():
        match = _OPERATION_ROW.fullmatch(row)
        if match is None:
            continue
        expression = match.group('expression')
        if _negation(expression) is not None:
            rows[expression] = transcript
    return rows


#: Every measured negation, keyed by the expression the row writes it in.
NEGATION_ROWS: dict[str, tuple[str, ...]] = _negation_rows()

#: The measured negations a 5.1 host answered by throwing.
THROWN_NEGATIONS: tuple[str, ...] = tuple(
    expression for expression, transcript in NEGATION_ROWS.items() if _throws(transcript)
)

#: The measured negation a host printed to fewer digits than the value carries: 5.1 writes a Double
#: as fifteen significant figures and the negated UInt64 maximum has twenty. What such a row
#: measures is the widening, so the type is what the value is held against.
ABBREVIATED_NEGATIONS: tuple[str, ...] = ('- [uint64]18446744073709551615',)


def _negated(expression: str) -> Ps1Outcome:
    """
    What `apply_unary` makes of a measured negation, asked exactly as
    `refinery.lib.scripts.ps1.deobfuscation.folding` asks it: the operator the row spells, over the
    fact `read` makes of the operand it stands before.
    """
    applied = _negation(expression)
    assert applied is not None, expression
    return apply_unary(applied.operator, read(applied.operand))


def _negated_as_subtraction(expression: str) -> Ps1Outcome:
    """
    What the same negation comes to when it is asked as the subtraction 5.1 compiles it into: `-`
    over an Int32 zero and the fact `read` makes of the operand the minus stands before.
    """
    applied = _negation(expression)
    assert applied is not None, expression
    return apply('-', Ps1Constant(INT32, 0), read(applied.operand))


def _measured_negation(expression: str) -> tuple[str, str]:
    """
    The .NET type and the rendered value a host printed for a measured negation.
    """
    return _printed(NEGATION_ROWS[expression][0])


def _measured_negation_fact(expression: str) -> Ps1Fact:
    return _witnessed_fact(_measured_negation(expression))


def _coerced(text: str) -> Ps1Fact:
    """
    The number a String computes as where an operator wants one, which keeps the type the numeral
    written inside it spells. A text this reader answers nothing for is a broken selection here
    rather than a case to pass over: every one of `NEGATED_STRINGS` spells a number 5.1 reads.
    """
    coerced = _coerced_numeral(Ps1Constant(STRING, text))
    assert coerced is not None, text
    return coerced


def _sign_of(fact: Ps1Fact) -> float:
    """
    The sign a floating payload carries, which is the only thing that tells `+0.0` from `-0.0`: the
    two compare equal, so a negation that produced the other one is invisible to `==`.
    """
    payload = _payload(fact)
    assert isinstance(payload, float), payload
    return math.copysign(1.0, payload)


#: The String operands a negation is asked over. Between them they spell a number of every width
#: 5.1 reads out of a String — the `L` suffix over an integer and over a real, two decimals no Int32
#: holds, a binary multiplier, a real, an exponent and the `D` suffix — and the last four spell one
#: an Int32 does hold, so that a width kept and a width lost are told apart.
NEGATED_STRINGS: tuple[str, ...] = (
    '5L',
    '1.5L',
    '2147483648',
    '3000000000',
    '5gb',
    '1.5',
    '1e3',
    '5d',
    '5',
    '1kb',
    '0xabc',
    '',
)

#: Two magnitudes at the widest a .NET `System.Decimal` reaches. Such a value is a 96 bit integer
#: scaled by a power of ten, so `2**96 - 1` is the largest it holds at scale zero and carries the 29
#: significant digits the type is worth; the second is those same digits at a scale of one. Python
#: keeps 28 by default and rounds every `decimal` result to whatever `decimal.getcontext().prec`
#: says, so either magnitude comes back a different number from arithmetic that consults it.
WIDEST_DECIMALS: tuple[decimal.Decimal, ...] = (
    decimal.Decimal((1 << 96) - 1),
    decimal.Decimal(F'{(1 << 96) - 1}E-1'),
)


#: The shapes a measured row settles an expression's truth in. They are one question written down
#: several ways: `[bool] $x` prints the Boolean the conversion produced, `if ($x)` prints the branch
#: that same conversion selected, each of the three logical operators prints the truth of the
#: operand that decides it, and `-not $x` prints the opposite of it.
_BOOLEAN_CAST_ROW = re.compile(
    r'\$t = (?P<expression>\[bool\](?P<condition>.+))'
    r'; Write-Output \(,\$t\); Write-Output \$t'
)
_BRANCH_ROW = re.compile(
    r"\$t = (?P<expression>if \((?P<condition>.+)\) \{ 'yes' \} else \{ 'no' \})"
    r'; Write-Output \(,\$t\); Write-Output \$t'
)
_AND_TRUE_ROW = re.compile(
    r'\$t = (?P<expression>(?P<condition>.+) -and \$true)'
    r'; Write-Output \(,\$t\); Write-Output \$t'
)
_OR_FALSE_ROW = re.compile(
    r'\$t = (?P<expression>(?P<condition>.+) -or \$false)'
    r'; Write-Output \(,\$t\); Write-Output \$t'
)
_TRUE_AND_ROW = re.compile(
    r'\$t = (?P<expression>\$true -and (?P<condition>.+))'
    r'; Write-Output \(,\$t\); Write-Output \$t'
)
_NEGATION_ROW = re.compile(
    r'\$t = (?P<expression>-not (?P<condition>.+))'
    r'; Write-Output \(,\$t\); Write-Output \$t'
)

#: Each shape with whether the Boolean it prints is the condition's own truth or its negation.
_TRUTH_SHAPES: tuple[tuple[re.Pattern[str], bool], ...] = (
    (_BOOLEAN_CAST_ROW, False),
    (_BRANCH_ROW, False),
    (_AND_TRUE_ROW, False),
    (_OR_FALSE_ROW, False),
    (_TRUE_AND_ROW, False),
    (_NEGATION_ROW, True),
)

#: What the branch a host ran says about the condition it ran on. A rendering neither name covers
#: is a `KeyError` naming it rather than a truth read out of a word this does not know.
_BRANCH_TAKEN = {'yes': True, 'no': False}


def _truth_rows() -> dict[str, dict[str, bool]]:
    """
    What every measured row that settles a condition's truth says that truth is, keyed by the
    condition and then by the expression the row writes it in. A condition several shapes settle is
    kept once per shape rather than collapsed, so that the shapes can be held against each other:
    the truth a row carries is read through the shape it was written in, and a shape read the wrong
    way round would otherwise put a host's own answer into the expectations upside down.
    """
    rows: dict[str, dict[str, bool]] = {}
    for row in TYPE_TRANSCRIPTS:
        for pattern, negated in _TRUTH_SHAPES:
            match = pattern.fullmatch(row)
            if match is None:
                continue
            expression = match.group('expression')
            settled = rows.setdefault(match.group('condition'), {})
            settled[expression] = _measured_truth(expression) != negated
    return rows


def _measured_truth(expression: str) -> bool:
    """
    What a host counted a measured expression as, read out of whichever witness its row prints.
    """
    carried, rendered = _measured(expression)
    return _boolean(rendered) if carried == 'System.Boolean' else _BRANCH_TAKEN[rendered]


#: Every measured row that settles a truth, by the condition it settles and the expression it is
#: written in.
TRUTH_ROWS: dict[str, dict[str, bool]] = _truth_rows()

#: The truth a 5.1 host counted each measured condition as, taken from one of its rows. Which one
#: does not matter where the shapes agree, and that they agree is itself measured rather than
#: assumed.
TRUTHS: dict[str, bool] = {
    condition: next(iter(settled.values())) for condition, settled in TRUTH_ROWS.items()
}

#: The measured conditions this has to settle rather than refuse: a string, an empty string, a
#: number, zero and `$null`. A module that answered nothing at all would agree with every host
#: there is, so the agreement above is held over these too.
PLAIN_CONDITIONS: tuple[str, ...] = ("'a'", "''", "'0'", '1', '0', '$null')

#: The measured conditions the domain names no truth for. A NaN is the whole of it: a host counts
#: `0.0 / 0.0` true, and the domain names the Double it is and no value of one. A condition that
#: leaves this tuple is a truth gained and one that joins it is a truth lost, so neither can happen
#: without this being rewritten.
UNSETTLED_CONDITIONS: tuple[str, ...] = ('(0.0 / 0.0)',)

#: A measured condition beside the collection of one holding it. The two are counted apart by a
#: host, which is what says that what a one-element collection makes of its element is not what a
#: condition makes of the same value.
ELEMENT_PAIRS: tuple[tuple[str, str], ...] = (
    ('[char]0', '(,[char]0)'),
    ('(,@())', '(,(,@()))'),
)


#: The measured operations whose result a host printed to fewer digits than the value has: 5.1
#: writes a Double as fifteen significant figures, and `512MB * 512MB` is 2 to the 58th exactly.
#: What such a row measures is the widening, so the type is what the value is held against.
#: The measured operations the domain answers with a value the host did not print. Empty, and the
#: partition below is what keeps it so: an operation whose fold stops matching its measurement has
#: to be written here before the suite passes again, which is a diff saying that a wrong constant is
#: now being emitted rather than a number quietly moving.
#:
#: It held the parse-time `Decimal` fold until `read_operand` was written. 5.1 folds a constant
#: expression in its parser and a numeral reaching that fold loses the places it has nothing to hold
#: — `'x' + 1.00d` is `x1` where `'x' + 1.100d` is `x1.100`, and it is the *operand* that loses them
#: and not the result, which is why `1.500d + 1.500d` is `3.000`.
MISFOLDED_OPERATIONS: dict[str, str] = {}

ABBREVIATED_OPERATIONS: tuple[str, ...] = (
    '$true + 9223372036854775807L',
    '0 - [uint64]18446744073709551615',
    '1 + [uint64]18446744073709551615',
    '1 / [uint64]18446744073709551615',
    '2147483647 * 2147483647',
    '2147483647 * [uint32]4294967295',
    '9223372036854775807L + 1',
    '9223372036854775807L - -1L',
    '[uint64]18446744073709551615 + 1',
    '512MB * 512MB',
    '9223372036854775807 + 2',
)

#: The binary operators the grid was captured for: the five arithmetic, the three bitwise, the two
#: shifts and the six comparisons.
GRID_OPERATORS: tuple[str, ...] = (
    '+',
    '-',
    '*',
    '/',
    '%',
    '-band',
    '-bor',
    '-bxor',
    '-shl',
    '-shr',
    '-eq',
    '-ne',
    '-lt',
    '-le',
    '-gt',
    '-ge',
)

#: The operand types a cell may be read as a fact over: every type the capture used as an operand,
#: less the ones a `GRID_WITNESS_GAPS` row convicts, and less the ones measured complete that the
#: domain does not read anyway.
SPANNED_TYPES: frozenset[str] = (
    frozenset(GRID_WITNESSES) - frozenset(GRID_WITNESS_GAPS) - GRID_COMPLETE_BUT_UNREAD)

#: The conversion cells every witness of their source threw for. The capture recorded no type at
#: all for a `[char]` of a Decimal or of a Single, so there is nothing in either cell for a cast
#: over a source the witnesses fall short of to keep.
EVERY_WITNESS_THREW: tuple[tuple[str, str], ...] = (
    ('System.Char', 'System.Decimal'),
    ('System.Char', 'System.Single'),
)


def _grid_operand(name: str) -> Ps1Fact:
    """
    A fact of the grid's operand type `name` that pins no value, so that the cell it indexes is the
    only place an answer about it could come from. The `System.Void` row is `$null`'s — the corpus
    lists `$null` as the witness it was captured from — and there is no value of that type for a
    `Ps1Typed` to stand for.
    """
    return NULL if name == 'System.Void' else Ps1Typed(_type(name))


def _cell(operator: str, left: str | Ps1TypeName, right: str | Ps1TypeName) -> OperatorOutcome:
    """
    The grid cell an operator and two operand types index. A cell the grid does not cover raises
    here, naming what was asked for, rather than reaching an expectation as `None`: a question the
    grid stopped answering has to fail where it is asked and say which question it was.
    """
    cell = binary_outcome(operator, left, right)
    if cell is None:
        raise KeyError(F'the grid has no cell for {left} {operator} {right}')
    return cell


def _cast_cell(target: str | Ps1TypeName, source: str | Ps1TypeName) -> OperatorOutcome:
    """
    The conversion cell a target and a source type index, read the way `_cell` reads a binary one.
    """
    cell = conversion_outcome(target, source)
    if cell is None:
        raise KeyError(F'the grid has no cell for [{target}] of {source}')
    return cell


def _recorded(cell: OperatorOutcome) -> tuple[str, ...]:
    """
    A grid cell spelled the way `GRID_WITNESS_GAPS` spells one: the types it was observed to
    produce, with `throw` and `null` beside them where it was observed to do either, sorted so that
    the shipped cell and the recorded one can be compared.
    """
    names = [str(one) for one in cell.types]
    if cell.may_throw:
        names.append('throw')
    if cell.may_be_null:
        names.append('null')
    return tuple(sorted(names))


def _generalisations(fact: Ps1Fact) -> tuple[Ps1Fact, ...]:
    """
    The facts that say strictly less about the same value: that it carries the type it carries,
    where it carries one, and that nothing at all is known about it.
    """
    carried = type_of(fact)
    return (UNKNOWN,) if carried is None else (Ps1Typed(carried), UNKNOWN)


#: One operand of each type the domain builds facts of, which is what the questions below about
#: generalising an operand are asked over. A zero of each numeric kind is here because the divisor
#: is what decides whether a division throws, and the three kinds do not agree about it.
OPERANDS: tuple[Ps1Fact, ...] = (
    NULL,
    MEASURED['0xFF'],
    MEASURED['1L'],
    MEASURED['10d'],
    MEASURED['1.5'],
    Ps1Constant(INT32, 0),
    Ps1Constant(INT64, 0),
    Ps1Constant(DECIMAL, decimal.Decimal(0)),
    Ps1Constant(DOUBLE, 0.0),
    Ps1Constant(BOOLEAN, True),
    Ps1Constant(CHAR, 'A'),
    Ps1Constant(STRING, 'abc'),
)

#: A division and a remainder by a zero of each numeric kind, as the type it is written in, the
#: value divided and the zero it is divided by.
ZERO_DIVISIONS: tuple[tuple[Ps1TypeName, Ps1Fact, Ps1Fact], ...] = (
    (INT32, Ps1Constant(INT32, 5), Ps1Constant(INT32, 0)),
    (DECIMAL, Ps1Constant(DECIMAL, decimal.Decimal(5)), Ps1Constant(DECIMAL, decimal.Decimal(0))),
    (DOUBLE, Ps1Constant(DOUBLE, 1.5), Ps1Constant(DOUBLE, 0.0)),
)


#: Every corpus table that holds PowerShell expressions, deduplicated and in a stable order. What
#: `evaluate` promises is a claim about every expression a script can contain, so the questions
#: about it below are asked of the population these tables are rather than of cases picked here: a
#: contract that only survives the examples its author thought of is not the contract.
CORPUS_SOURCES: tuple[str, ...] = tuple(dict.fromkeys((
    *TYPES,
    *BOUNDARIES,
    *SNIPPETS.values(),
    *PROBES,
    *SPELLINGS,
)))


class _Site(NamedTuple):
    """
    One expression the corpus contains, carrying the source it stands in so that a disagreement is
    reported as the script it was found in rather than as a node with no context.
    """
    source: str
    node: Expression


def _corpus_sites() -> tuple[_Site, ...]:
    sites: list[_Site] = []
    for source in CORPUS_SOURCES:
        for node in in_evaluation_order(Ps1Parser(source).parse()):
            if isinstance(node, Expression):
                sites.append(_Site(source, node))
    return tuple(sites)


#: Every expression the corpus writes, which is the population the agreements below quantify over.
SITES: tuple[_Site, ...] = _corpus_sites()

#: The world a typing question is asked in. It is closed, so that a command name still denotes what
#: the collected metadata says: an open world types nothing at all, and an agreement over it would
#: hold because neither side answers rather than because they answer alike.
CLOSED_WORLD = Ps1WorldReach(Ps1TypeWorld(True, frozenset()))


class _Numeral(NamedTuple):
    """
    A corpus site where the literal node reports a number of its own and `evaluate` names a value:
    the spelling as it was written, the number the node reports for it, and the fact the domain
    names.
    """
    raw: str
    reported: int
    named: Ps1Constant


def _numeral_node(expression: str) -> Ps1IntegerLiteral:
    """
    The numeral node a spelling parses to, for the assertions that hold the number a *node* reports
    against the value the domain names. The node's own reading is weaker on purpose — see
    `refinery.lib.scripts.ps1.model.Ps1IntegerLiteral`.
    """
    node = _slot(expression)
    assert isinstance(node, Ps1IntegerLiteral), expression
    return node


def _corpus_numerals() -> tuple[_Numeral, ...]:
    numerals: list[_Numeral] = []
    for site in SITES:
        literal = site.node
        fact = evaluate(literal).value
        if not isinstance(literal, Ps1IntegerLiteral) or not isinstance(fact, Ps1Constant):
            continue
        numerals.append(_Numeral(literal.raw, literal.value, fact))
    return tuple(numerals)


NUMERALS: tuple[_Numeral, ...] = _corpus_numerals()

#: The corpus spellings whose literal node reports a number 5.1 did not print for them. A
#: hexadecimal literal that fills its width names a bit pattern rather than a magnitude, and a
#: decimal too wide for any integer type is a Double: the node reads the digits, and `MEASURED`
#: holds what a host made of the same ones.
MISREAD_SPELLINGS: tuple[str, ...] = (
    '0xFFFFFFFF',
    '0xFFFFFFFFFFFFFFFF',
    '100000000000000000000000000000000',
)

#: Every target the shipped conversion grid holds a column for, written out rather than read off
#: the resource so that a column added or withdrawn fails here instead of quietly changing what a
#: cast of a value nothing is known about is answered with.
CONVERSION_TARGETS: tuple[str, ...] = (
    'array',
    'bool',
    'byte',
    'char',
    'decimal',
    'double',
    'int',
    'int16',
    'long',
    'sbyte',
    'single',
    'string',
    'uint16',
    'uint32',
    'uint64',
)


def _operator_of(expression: str) -> str:
    """
    The operator a measured operation writes, in the case the row spells it.
    """
    applied = _application(expression)
    assert applied is not None, expression
    return applied.operator


def _cased(expression: str, case: Callable[[str], str]) -> Ps1Outcome:
    """
    What `evaluate` answers for a measured operation whose operator is written in `case`. The case
    is changed on the parsed operator rather than in the source text, so that nothing else about the
    row can change along with it.
    """
    applied = _application(expression)
    assert applied is not None, expression
    return evaluate(dataclasses.replace(applied, operator=case(applied.operator)))


def _element_payloads(fact: Ps1Fact) -> list[object]:
    """
    What each element of an array fact holds. An element that names no value stands for itself, so
    that comparing the list against collected bytes fails on it rather than passing it over.
    """
    return [one.payload if isinstance(one, Ps1Constant) else one for one in _elements(fact)]


class _Collected(NamedTuple):
    """
    A corpus site the byte-array reader answers for and `evaluate` names an array at: the bytes the
    reader collected out of it, and what each element of that array holds.
    """
    source: str
    collected: bytes
    payloads: list[object]


def _corpus_byte_arrays() -> tuple[_Collected, ...]:
    rows: list[_Collected] = []
    for site in SITES:
        collected = collect_byte_array(site.node)
        fact = evaluate(site.node).value
        if collected is None or not isinstance(fact, Ps1Constant):
            continue
        if not isinstance(fact.payload, tuple):
            continue
        rows.append(_Collected(site.source, collected, _element_payloads(fact)))
    return tuple(rows)


BYTE_ARRAYS: tuple[_Collected, ...] = _corpus_byte_arrays()


def _names_a_value(fact: Ps1Fact) -> bool:
    """
    Whether a fact names a value rather than a bound on one. `$null` is one: it is what an absent
    value *is*, and not the absence of knowledge about it.
    """
    return fact is NULL or isinstance(fact, Ps1Constant)


class _Step(NamedTuple):
    """
    A corpus cast or operator, with what the one-step reader answers over the facts its operands
    come to and what the whole expression is answered with. `consultable` is whether the step could
    be asked at all: `convert` and `apply` both read a grid indexed by the operand's type, and an
    operand that names no type indexes no row in it.
    """
    source: str
    kind: str
    consultable: bool
    step: Ps1Outcome
    answered: Ps1Outcome


def _operand_of(node) -> Ps1Outcome:
    """
    What an operand of an operator comes to, which is `evaluate` over it except where `read_operand`
    reads a numeral standing there differently from the same numeral standing alone. The step and
    the whole have to be asked about the same operand or the law below compares two expressions.
    """
    folded = read_operand(node)
    return Ps1Outcome(NEVER, folded) if folded is not UNKNOWN else evaluate(node)


def _corpus_steps() -> tuple[_Step, ...]:
    steps: list[_Step] = []
    for site in SITES:
        node = site.node
        if isinstance(node, Ps1CastExpression):
            target = resolve_type(node.type_name)
            if target is None:
                continue
            operand = evaluate(node.operand)
            steps.append(_Step(
                site.source,
                'cast',
                operand.value is not UNKNOWN,
                convert(operand.value, target),
                evaluate(node),
            ))
        elif isinstance(node, Ps1BinaryExpression):
            left = _operand_of(node.left)
            right = _operand_of(node.right)
            steps.append(_Step(
                site.source,
                'operator',
                UNKNOWN not in (left.value, right.value),
                apply(node.operator, left.value, right.value),
                evaluate(node),
            ))
    return tuple(steps)


STEPS: tuple[_Step, ...] = _corpus_steps()


class _Array(NamedTuple):
    """
    A corpus array and what `evaluate` makes of it: whether the array names a value, and whether
    every element it holds does.
    """
    source: str
    named: bool
    elements_named: bool


def _corpus_arrays() -> tuple[_Array, ...]:
    arrays: list[_Array] = []
    for site in SITES:
        if not isinstance(site.node, (Ps1ArrayLiteral, Ps1ArrayExpression)):
            continue
        fact = evaluate(site.node).value
        payload = fact.payload if isinstance(fact, Ps1Constant) else None
        elements = payload if isinstance(payload, tuple) else ()
        arrays.append(
            _Array(site.source, _names_a_value(fact), all(_names_a_value(one) for one in elements)))
    return tuple(arrays)


ARRAYS: tuple[_Array, ...] = _corpus_arrays()


class _Spelled(NamedTuple):
    """
    A corpus site the tree's string reader answers a text for and `evaluate` names a fact at.
    """
    source: str
    text: str
    named: Ps1Fact


def _corpus_strings() -> tuple[_Spelled, ...]:
    rows: list[_Spelled] = []
    for site in SITES:
        text = string_value(site.node)
        fact = evaluate(site.node).value
        if text is None or fact is UNKNOWN:
            continue
        rows.append(_Spelled(site.source, text, fact))
    return tuple(rows)


STRINGS: tuple[_Spelled, ...] = _corpus_strings()


class TestPs1MeasuredNumerals(unittest.TestCase):
    """
    A numeric literal's spelling decides its .NET type as much as its digits do, and every
    expectation here is what a 5.1 host printed for that spelling.
    """

    def test_every_numeral_the_corpus_measures_is_selected(self):
        self.assertEqual(
            len(_NUMERAL_ROWS), 44, 'a measured numeral was added or withdrawn')
        self.assertEqual(sorted(REFUSED), ['0xFFFFFFFFFFFFFFFFF', '1_0'])
        self.assertEqual(
            sorted(set(UNANSWERED) - set(MEASURED)), [], 'a spelling named here is not measured')

    def test_every_measured_numeral_reads_as_the_fact_the_host_printed(self):
        for expression in DECIDED:
            with self.subTest(expression):
                self.assertEqual(_read(expression), MEASURED[expression])

    def test_a_numeral_5_1_cannot_read_is_not_read_here_either(self):
        """
        Our lexer accepts both of these and hands the domain a number for each: the seventeen
        hexadecimal digits as an arbitrary-width integer, and the underscored group as ten. 5.1 has
        no value for either, so a fact here would be one no run of the script can produce.
        """
        for expression in REFUSED:
            with self.subTest(expression):
                self.assertEqual(_read(expression), UNKNOWN)

    def test_a_numeral_the_domain_does_not_read_is_refused_rather_than_guessed(self):
        for expression in UNANSWERED:
            with self.subTest(expression):
                self.assertEqual(_read(expression), UNKNOWN)

    def test_a_negated_parenthesized_literal_keeps_the_width_of_the_literal_it_negates(self):
        """
        `-2147483648` is one literal that fits an Int32, while `-(2147483648)` negates the Int64
        literal `2147483648` and stays an Int64 — the same value under two types. A `-` glued to the
        numeral is part of it and `read` answers it; a `-` over a parenthesized literal is an
        operator, which `read` refuses because reaching past the parenthesis would report the
        literal's width without its sign. `evaluate` applies the operator and answers the width the
        parenthesis decides.
        """
        self.assertEqual(_read('-2147483648'), MEASURED['-2147483648'])
        for expression in ('-(2147483648)', '-(2147483647)'):
            with self.subTest(expression):
                self.assertEqual(_read(expression), UNKNOWN)
                self.assertEqual(_evaluated(expression).value, MEASURED[expression])

    def test_a_real_with_a_long_suffix_is_the_rounded_int64_the_host_prints(self):
        """
        5.1 prints Int64 2 for both `1.5L` and `2.5L`, which is the half-to-even rounding of a cast
        rather than a refusal to read the spelling.
        """
        for expression in ('1.5L', '2.5L'):
            with self.subTest(expression):
                self.assertEqual(_read(expression), MEASURED[expression])

    def test_the_same_printed_value_under_two_spellings_is_two_different_facts(self):
        """
        The host prints 255 for `0xFF` and for `0xFFL`, and 1.5 for `1.5` and for `1.5d`, and stamps
        each pair with two different types. A domain that carried the value alone could not tell the
        members of a pair apart, and every operation whose result type follows its operands' would
        then answer for the wrong one.
        """
        by_value: dict[str, dict[str, str]] = {}
        for expression in DECIDED:
            name, rendered = _measured(expression)
            by_value.setdefault(rendered, {})[name] = expression
        collisions = {
            rendered: spellings for rendered, spellings in by_value.items() if len(spellings) > 1
        }
        self.assertEqual(sorted(collisions), ['-1', '1', '1.5', '1024', '255'])
        for rendered, spellings in collisions.items():
            with self.subTest(rendered):
                facts = {_read(expression) for expression in spellings.values()}
                self.assertEqual(len(facts), len(spellings))


class TestPs1FactLattice(unittest.TestCase):

    def test_nothing_known_and_no_value_are_different_facts(self):
        self.assertNotEqual(UNKNOWN, NULL)
        self.assertIsNone(type_of(UNKNOWN))
        self.assertIsNone(type_of(NULL))

    def test_a_variable_the_source_does_not_pin_is_unknown_while_the_null_literal_is_null(self):
        self.assertEqual(_read('$x'), UNKNOWN)
        self.assertEqual(_read('$null'), NULL)

    def test_type_of_reads_the_type_of_a_typed_fact_and_of_a_constant(self):
        self.assertEqual(type_of(Ps1Typed(CHAR)), CHAR)
        self.assertEqual(type_of(Ps1Constant(CHAR, 'A')), CHAR)

    def test_a_char_and_a_string_carrying_equal_payloads_are_different_facts(self):
        """
        5.1 answers `[char]65 -is [char]` True and `'A' -is [char]` False, prints 66 for
        `1 + [char]65` and throws on `1 + 'A'`, and refuses to replicate a Char where it replicates
        a String. Both carry the same `'A'`, so only the type they are stamped with tells them
        apart.
        """
        self.assertNotEqual(Ps1Constant(CHAR, 'A'), Ps1Constant(STRING, 'A'))
        self.assertNotEqual(type_of(Ps1Constant(CHAR, 'A')), type_of(Ps1Constant(STRING, 'A')))

    def test_a_fact_is_a_value_so_one_read_twice_is_one_fact(self):
        self.assertEqual(_read('0xFF'), _read('0xFF'))
        self.assertEqual(len({_read('0xFF'), _read('0xFF'), _read('0xFFL')}), 2)


class TestPs1WhatCountsAsAnInteger(unittest.TestCase):
    """
    The number a caller wanting an integer is handed. Every site that used to take one off a literal
    node asks here instead, so a value this answered wrongly would be an index, a repeat count, a
    range bound, a format argument, a conversion base and a loop bound all at once.

    Two things settle it, and both are the host's: the type it stamped the value with, and the
    digits it printed. A type outside `INTEGER_TYPES` is a value 5.1 reaches a number *from*, by a
    conversion with a rounding or a parsing rule in it, and never a number this may hand back.
    """

    def _integer_rows(self) -> dict[str, Ps1Fact]:
        """
        Every measured value whose spelling the domain reads: the numerals, and the casts that are
        the only way to write a value of a type no literal spells.
        """
        rows = {expression: MEASURED[expression] for expression in DECIDED}
        rows.update({
            expression: _measured_fact(expression) for expression in CAST_SPELLINGS
        })
        return rows

    def test_a_measured_value_the_host_stamped_an_integer_type_is_the_number_it_printed(self):
        rows = {
            expression: fact for expression, fact in self._integer_rows().items()
            if str(type_of(fact)) in INTEGER_TYPES
        }
        self.assertEqual(len(rows), 29)
        self.assertEqual(
            {expression: integer_of(fact) for expression, fact in rows.items()},
            {expression: int(_measured(expression)[1]) for expression in rows},
        )

    def test_a_measured_value_of_any_other_type_names_no_integer(self):
        others = {
            expression: fact for expression, fact in self._integer_rows().items()
            if str(type_of(fact)) not in INTEGER_TYPES
        }
        self.assertEqual(
            sorted({str(type_of(fact)) for fact in others.values()}),
            ['System.Char', 'System.Decimal', 'System.Double'],
        )
        self.assertEqual(
            {expression: integer_of(fact) for expression, fact in others.items()},
            {expression: None for expression in others},
        )

    def test_a_hexadecimal_numeral_that_fills_its_width_is_the_negative_number_it_names(self):
        """
        The whole point of asking the domain: the digits of `0xFFFFFFFF` spell 4294967295 and the
        value is -1, so a caller reading the digits and a caller reading the value differ by
        4294967296 at every site that takes an integer.
        """
        self.assertEqual(_measured('0xFFFFFFFF'), ('System.Int32', '-1'))
        self.assertEqual(_measured('0xFFFFFFFFFFFFFFFF'), ('System.Int64', '-1'))
        self.assertEqual(_measured('0xFF'), ('System.Int32', '255'))
        self.assertEqual(integer_of(MEASURED['0xFFFFFFFF']), -1)
        self.assertEqual(integer_of(MEASURED['0xFFFFFFFFFFFFFFFF']), -1)
        self.assertEqual(integer_of(MEASURED['0xFF']), 255)
        self.assertEqual(_numeral_node('0xFFFFFFFF').value, 0xFFFFFFFF)

    def test_a_value_5_1_only_converts_to_a_number_is_not_read_as_one(self):
        """
        Each of these reaches a number on 5.1 and is not one: measured, `[int]$null` is 0,
        `[int]$true` is 1, `[int]'5'` is 5, `[int][char]65` is 65, `[int]1.5` is 2 and `[int]10d`
        is 10. Two of those round rather than truncate and one parses text, so a caller that read
        the payload of any of them would be picking a conversion rule of its own.
        """
        self.assertEqual(
            {
                cast: _measured(cast) for cast in (
                    '[int]$null',
                    '[int]$true',
                    "[int]'5'",
                    '[int][char]65',
                    '[int]1.5',
                    '[int]10d',
                )
            },
            {
                '[int]$null'    : ('System.Int32', '0'),
                '[int]$true'    : ('System.Int32', '1'),
                "[int]'5'"      : ('System.Int32', '5'),
                '[int][char]65' : ('System.Int32', '65'),
                '[int]1.5'      : ('System.Int32', '2'),
                '[int]10d'      : ('System.Int32', '10'),
            },
        )
        operands = (
            '$null',
            '$true',
            "'5'",
            '[char]65',
            '1.5',
            '10d',
        )
        self.assertEqual(
            {expression: integer_of(_read(expression)) for expression in operands},
            {expression: None for expression in operands},
        )

    def test_a_fact_that_names_no_value_names_no_integer(self):
        self.assertIsNone(integer_of(UNKNOWN))
        self.assertIsNone(integer_of(Ps1Typed(INT32)))


class TestPs1CollectedIntegers(unittest.TestCase):
    """
    The integers a caller reading a command's arguments gets. A scalar is a list of one, because
    PowerShell binds one value and a collection of one to the same parameter; an array is what its
    elements name; and one element that is no integer refuses the whole list rather than being
    dropped from it, since a list shorter than the script wrote is a different argument.
    """

    def test_a_scalar_is_a_list_of_one_and_an_array_is_its_elements(self):
        self.assertEqual(
            {
                expression: collect_integers(_slot(expression)) for expression in (
                    '0xFF',
                    '[byte]5',
                    '@()',
                    '@(1, 2)',
                    '1, 2',
                    '@(1kb)',
                )
            },
            {
                '0xFF'     : [255],
                '[byte]5'  : [5],
                '@()'      : [],
                '@(1, 2)'  : [1, 2],
                '1, 2'     : [1, 2],
                '@(1kb)'   : [1024],
            },
        )

    def test_an_element_that_fills_its_width_is_collected_as_the_negative_it_is(self):
        self.assertEqual(_measured('0xFFFFFFFF'), ('System.Int32', '-1'))
        self.assertEqual(collect_integers(_slot('@(0xFFFFFFFF, 2)')), [-1, 2])

    def test_one_element_that_is_no_integer_refuses_the_whole_list(self):
        for expression in (
            '@(1, 1.5)',
            "@(1, '2')",
            '@(1, $null)',
            '@(1, $true)',
            '@(1, [char]65)',
            '@(1, 10d)',
            '@(1, $x)',
        ):
            with self.subTest(expression):
                self.assertIsNone(collect_integers(_slot(expression)))

    def test_a_number_no_byte_holds_is_no_byte_array(self):
        """
        Measured, `[byte]-1` and `[byte]300` both throw rather than wrapping, so a list holding
        either is not one 5.1 would bind to a byte array — and `0xFFFFFFFF` is exactly the first of
        those, written in a way that looks like the second.
        """
        self.assertEqual(_throws(_transcript('[byte]-1')), True)
        self.assertEqual(_throws(_transcript('[byte]300')), True)
        self.assertEqual(collect_byte_array(_slot('@(0x41, 0xFF)')), b'A\xff')
        self.assertIsNone(collect_byte_array(_slot('@(0x41, 0xFFFFFFFF)')))
        self.assertIsNone(collect_byte_array(_slot('@(0x41, 300)')))


class TestPs1Outcome(unittest.TestCase):

    def test_the_refusal_names_no_value_and_claims_no_absence_of_a_throw(self):
        self.assertEqual(NOTHING, Ps1Outcome(MAYBE, UNKNOWN))
        self.assertIsNone(type_of(NOTHING.value))

    def test_an_outcome_carries_a_type_and_a_possible_throw_at_once(self):
        outcome = Ps1Outcome(MAYBE, Ps1Typed(INT32))
        self.assertEqual(outcome, (MAYBE, Ps1Typed(INT32)))
        self.assertEqual(type_of(outcome.value), INT32)
        self.assertTrue(outcome.may_throw)
        self.assertFalse(outcome.certainly_throws)

    def test_the_two_readings_of_the_throw_axis_project_from_the_one_field(self):
        self.assertEqual(
            [(o.may_throw, o.certainly_throws) for o in (
                Ps1Outcome(NEVER, UNKNOWN),
                Ps1Outcome(MAYBE, UNKNOWN),
                Ps1Outcome(ALWAYS, UNKNOWN),
            )],
            [(False, False), (True, False), (True, True)],
        )


class TestPs1LiteralFacts(unittest.TestCase):

    def test_a_string_literal_reads_as_the_string_it_spells(self):
        self.assertEqual(_read("'abc'"), Ps1Constant(STRING, 'abc'))
        self.assertEqual(_read('"abc"'), Ps1Constant(STRING, 'abc'))

    def test_a_here_string_reads_as_the_text_between_its_delimiters(self):
        source = inspect.cleandoc("""
            @'
            abc
            '@
        """)
        self.assertEqual(_read(source), Ps1Constant(STRING, 'abc'))

    def test_the_boolean_variables_read_as_booleans_in_any_casing(self):
        self.assertEqual(_read('$true'), Ps1Constant(BOOLEAN, True))
        self.assertEqual(_read('$TRUE'), Ps1Constant(BOOLEAN, True))
        self.assertEqual(_read('$false'), Ps1Constant(BOOLEAN, False))

    def test_a_parenthesis_around_a_literal_reads_through_to_the_literal(self):
        self.assertEqual(_read('(0xFF)'), MEASURED['0xFF'])
        self.assertEqual(_read('((1kb))'), MEASURED['1kb'])


class TestPs1StringSpelling(unittest.TestCase):

    def test_multiline_string_emitted_as_here_string(self):
        node = make_string_literal('line1\nline2')
        self.assertIsInstance(node, Ps1HereString)
        self.assertEqual(node.value, 'line1\nline2')
        self.assertIn("@'\n", node.raw)
        node2 = make_string_literal('no newlines')
        self.assertIsInstance(node2, Ps1StringLiteral)

    def test_make_string_literal_avoids_herestring_breakout(self):
        # A value with a line beginning with the here-string terminator `'@` must not be emitted as
        # a here-string, or it would close the string early; a safe multi-line value still may.
        unsafe = make_string_literal("a\n'@\nb")
        self.assertNotIsInstance(unsafe, Ps1HereString)
        safe = make_string_literal('a\nb')
        self.assertIsInstance(safe, Ps1HereString)


class TestPs1ValueSpelling(unittest.TestCase):
    """
    What `render` writes a fact back as. A value always has a spelling — a literal where 5.1 has
    one for its type, the cast of a decimal numeral where it does not — so a caller holding a
    value never has to choose between leaving the source alone and writing something else.
    Nothing to write is therefore reserved for a fact that names no value.
    """

    def test_only_a_fact_that_names_no_value_is_left_unwritten(self):
        self.assertIsNone(render(UNKNOWN))
        self.assertIsNone(render(Ps1Typed(INT32)))
        self.assertIsNone(render(Ps1Typed(OBJECT_ARRAY)))
        self.assertEqual(_spelled(NULL), '$Null')
        self.assertEqual(_read('$Null'), NULL)

    def test_a_fact_written_and_read_back_is_the_fact_it_was(self):
        facts = [MEASURED[expression] for expression in DECIDED]
        facts.extend(_read(spelling) for spelling in COLLECTION_SHAPES)
        facts.extend(_read(spelling) for spelling in (
            "'abc'",
            "''",
            '$True',
            '$False',
            '$Null',
            "'a', 1",
        ))
        for fact in facts:
            with self.subTest(repr(fact)):
                self.assertEqual(_read(_spelled(fact)), fact)

    def test_a_spelling_read_and_written_back_is_the_spelling_it_was(self):
        for spelling in (
            "'abc'",
            '255',
            '-1',
            '1024L',
            '10d',
            '1.5',
            '$True',
            '$False',
            '$Null',
            '@()',
            "'a', 1",
            ',(1, 2)',
        ):
            with self.subTest(spelling):
                self.assertEqual(_spelled(_read(spelling)), spelling)

    def test_a_numeral_carries_the_suffix_that_pins_its_type_and_no_other(self):
        """
        5.1 has two numeric literal suffixes: `L` names an Int64 and `d` a Decimal. An integer
        numeral written without one is an Int32 and a real without one a Double, so those two are
        written bare.
        """
        self.assertEqual(_spelled(Ps1Constant(INT32, 7)), '7')
        self.assertEqual(_spelled(Ps1Constant(INT64, 1)), '1L')
        self.assertEqual(_spelled(Ps1Constant(DECIMAL, decimal.Decimal(10))), '10d')
        self.assertEqual(_spelled(Ps1Constant(DOUBLE, 1.5)), '1.5')
        self.assertEqual(
            [MEASURED['007'], MEASURED['1L'], MEASURED['10d'], MEASURED['1.5']],
            [
                Ps1Constant(INT32, 7),
                Ps1Constant(INT64, 1),
                Ps1Constant(DECIMAL, decimal.Decimal(10)),
                Ps1Constant(DOUBLE, 1.5),
            ],
        )

    def test_a_value_of_a_type_no_literal_spells_is_written_as_the_cast_the_host_measured(self):
        self.assertEqual(sorted(set(CAST_SPELLINGS) - set(CAST_ROWS)), [])
        self.assertEqual(
            {expression: _spelled(_measured_fact(expression)) for expression in CAST_SPELLINGS},
            {expression: expression for expression in CAST_SPELLINGS},
        )

    def test_the_cast_a_value_is_written_as_reads_back_as_that_value(self):
        """
        A cast is how the language spells a value of a type it has no literal for, so it is a
        spelling `read` has to invert or nothing this module writes out could be read in again.
        What says each spelling names the right value is the host, which stamped `[byte]5` a Byte 5.
        """
        for expression in CAST_SPELLINGS:
            with self.subTest(expression):
                self.assertEqual(_read(expression), _measured_fact(expression))
        self.assertEqual(_measured('[byte]5'), ('System.Byte', '5'))

    def test_a_char_and_a_one_character_string_are_not_written_alike(self):
        """
        Measured, `[char]65` is a Char and `'A'` a String: the two answer `-is [char]` differently,
        carry different methods and reach different numbers under `[int]`. One spelling for both
        would erase that at the one point where a value re-enters a script.
        """
        self.assertEqual(_measured('[char]65'), ('System.Char', 'A'))
        self.assertEqual(_spelled(Ps1Constant(CHAR, 'A')), '[char]65')
        self.assertEqual(_spelled(Ps1Constant(STRING, 'A')), "'A'")
        self.assertEqual(_read("'A'"), Ps1Constant(STRING, 'A'))

    def test_the_boolean_values_are_written_as_the_variables_that_hold_them(self):
        self.assertEqual(_spelled(Ps1Constant(BOOLEAN, True)), '$True')
        self.assertEqual(_spelled(Ps1Constant(BOOLEAN, False)), '$False')

    def test_a_double_that_no_literal_and_no_cast_reaches_is_left_unwritten(self):
        for payload in (INFINITY, -INFINITY, float('nan')):
            with self.subTest(payload):
                self.assertIsNone(render(Ps1Constant(DOUBLE, payload)))
        self.assertEqual(_spelled(MEASURED['100000000000000000000000000000000']), '1e+32')

    def test_a_collection_holds_each_element_under_the_type_the_host_printed_for_it(self):
        fact = _read("'a', 1")
        self.assertEqual(_elements(fact), _measured_elements("'a', 1"))
        self.assertEqual(_spelled(fact), "'a', 1")

    def test_the_array_operator_writes_the_empty_collection_and_no_other(self):
        """
        `@(...)` unrolls the collection it is handed, so writing a one-element collection with it
        would hand back what was inside instead: measured, `,(1, 2)` holds one element and
        `@((1, 2))` holds two. The comma operator is what writes every non-empty collection.
        """
        self.assertEqual(_measured_count('@()'), ('System.Object[]', 0))
        self.assertEqual(_measured_count(',(1, 2)'), ('System.Object[]', 1))
        self.assertEqual(_measured_count('@((1, 2))'), ('System.Object[]', 2))
        self.assertEqual(_spelled(_read('@()')), '@()')
        self.assertEqual(_spelled(_read(',(1, 2)')), ',(1, 2)')
        self.assertNotEqual(_read(',(1, 2)'), _read('@((1, 2))'))

    def test_a_collection_is_written_by_what_it_holds_and_not_by_how_it_was_spelled(self):
        """
        `@(@(1, 2))` and `@((1, 2))` are both the two-element collection `1, 2`, and `@(@(1, 2), 3)`
        is the two-element one whose first element is a collection. Each is written back as what it
        holds, which is a different spelling from the one it was read from and the same value.
        """
        self.assertEqual(_spelled(_read('@(@(1, 2))')), '1, 2')
        self.assertEqual(_spelled(_read('@((1, 2))')), '1, 2')
        self.assertEqual(_spelled(_read('@(@(1, 2), 3)')), '(1, 2), 3')
        for expression in ('@(@(1, 2))', '@((1, 2))', '@(@(1, 2), 3)'):
            with self.subTest(expression):
                self.assertEqual(
                    _read_shape(_spelled(_read(expression))), _measured_shape(expression))

    def test_a_collection_holding_a_value_with_no_spelling_is_not_written_shorter(self):
        self.assertIsNone(render(Ps1Constant(OBJECT_ARRAY, (Ps1Constant(INT32, 1), UNKNOWN))))
        self.assertEqual(_spelled(Ps1Constant(OBJECT_ARRAY, (Ps1Constant(INT32, 1),))), ',1')

    def test_a_string_value_is_written_as_a_literal_that_reads_back_as_it(self):
        for value in ('abc', '', "it's", 'a"b', 'a`b', 'a$b', 'a\nb', 'a\tb', "a\n'@\nb"):
            with self.subTest(value):
                self.assertEqual(
                    _read(_spelled(Ps1Constant(STRING, value))), Ps1Constant(STRING, value))


class TestPs1ArrayFacts(unittest.TestCase):
    """
    The two ways of writing a collection do not build the same array out of the same parts. The
    comma operator takes each operand whole; `@(...)` collects what a pipeline hands it, and a
    pipeline unrolls a collection one level on the way. Every expectation here is the length a 5.1
    host counted.
    """

    def test_a_measured_array_shape_reads_as_an_object_array_of_the_measured_length(self):
        self.assertEqual(
            {expression: _read_shape(expression) for expression in COLLECTION_SHAPES},
            {expression: _measured_shape(expression) for expression in COLLECTION_SHAPES},
        )

    def test_the_comma_operator_takes_its_operand_whole_where_the_array_operator_unrolls_it(self):
        """
        Measured, `,(1, 2)` counts one element and `@((1, 2))` counts two out of the same parts, so
        the collection `@(...)` was handed is not the one it built. Reading the two alike would let
        a caller lose or gain a level of nesting without anything in the answer saying so.
        """
        self.assertEqual(_measured_count(',(1, 2)'), ('System.Object[]', 1))
        self.assertEqual(_measured_count('@((1, 2))'), ('System.Object[]', 2))
        self.assertNotEqual(_read(',(1, 2)'), _read('@((1, 2))'))
        self.assertEqual(_read(',(1, 2)'), Ps1Constant(OBJECT_ARRAY, (_read('1, 2'),)))
        self.assertEqual(_read('@((1, 2))'), _read('1, 2'))

    def test_the_array_operator_unrolls_the_value_a_statement_produced_and_not_what_was_in_it(self):
        """
        `@(@(1, 2), 3)` and `(1, 2), 3` are written by the host alike — two elements, the first of
        them an `Object[]` — so the unrolling happened once, to the collection the statement
        produced, and did not reach into the collection that was inside it.
        """
        self.assertEqual(
            _measured_rendering('@(@(1, 2), 3)'), ('System.Object[]', 'System.Object[] 3'))
        self.assertEqual(
            _measured_rendering('(1, 2), 3'), _measured_rendering('@(@(1, 2), 3)'))
        self.assertEqual(_read('@(@(1, 2), 3)'), _read('(1, 2), 3'))
        self.assertEqual(
            [type_of(element) for element in _elements(_read('@(@(1, 2), 3)'))],
            [OBJECT_ARRAY, INT32],
        )

    def test_a_collection_the_array_operator_unrolled_holds_what_was_inside_it(self):
        self.assertEqual(_measured_count('@(@(1, 2))'), ('System.Object[]', 2))
        self.assertEqual(_read('@(@(1, 2))'), _read('1, 2'))
        self.assertEqual(_read('@(@(1, 2))'), _read('@((1, 2))'))

    def test_an_array_literal_carries_the_fact_of_each_element(self):
        self.assertEqual(
            _read('0xFF, 1kb'),
            Ps1Constant(OBJECT_ARRAY, (MEASURED['0xFF'], MEASURED['1kb'])),
        )

    def test_an_array_whose_element_is_not_pinned_is_not_read_as_a_shorter_array(self):
        self.assertNotIsInstance(_read('0xFF, $x'), Ps1Constant)


class TestPs1ReadOnlyReadsTheSource(unittest.TestCase):
    """
    `read` answers what the source pins and evaluates nothing, so an expression whose value only a
    run produces is refused however well known that value is. A guess here would be worse than no
    answer: the ledger's Char rows are all one erasure, and a Char answered as a one-character
    String changes what `1 + $t` and `$t * 3` do.
    """

    def test_an_expression_whose_value_only_an_evaluation_produces_is_refused(self):
        for expression in (
            "[int]'27'",
            '[int](1 + 2)',
            "'AB'.Length",
            "5 + '5'",
            "'ABC'[0]",
            '"a$b"',
            '@{ a = 1 }',
            'Get-Date',
        ):
            with self.subTest(expression):
                self.assertEqual(_read(expression), UNKNOWN)

    def test_reading_nothing_at_all_is_unknown(self):
        self.assertEqual(read(None), UNKNOWN)
        self.assertEqual(read(Ps1ParenExpression()), UNKNOWN)


class TestPs1ADoubleQuotedStringIsPinnedOnlyWhereEveryPartIsText(unittest.TestCase):
    """
    A double-quoted string whose parts are all literal text spells the text it holds and runs
    nothing to produce it, which is the shape a pass leaves behind once it has written a constant
    into an expansion. One part that still interpolates makes the whole string a value only a run
    names, and a string missing that part is a different string, so nothing is pinned at all.
    """

    def _spelled_by(self, *parts: str) -> list[Expression]:
        return [Ps1StringLiteral(value=part, raw=F"'{part}'") for part in parts]

    def test_a_string_of_text_alone_is_pinned_to_the_text_its_parts_spell(self):
        self.assertEqual(
            read(Ps1ExpandableString(parts=self._spelled_by('value: ', 'SECRET', ' end'))),
            Ps1Constant(STRING, 'value: SECRET end'),
        )

    def test_a_here_string_of_text_alone_is_pinned_the_same_way(self):
        self.assertEqual(
            read(Ps1ExpandableHereString(parts=self._spelled_by('a\n', 'b'))),
            Ps1Constant(STRING, 'a\nb'),
        )

    def test_a_string_with_one_part_that_is_not_text_is_pinned_to_nothing(self):
        for expression in ('"a$b"', '"$x"', '"a$(1)b"', '"$(1)"', '"${env:Temp}\\x"'):
            with self.subTest(expression):
                self.assertEqual(_read(expression), UNKNOWN)

    def test_a_string_the_parser_wrote_as_one_literal_is_pinned_to_that_literal(self):
        self.assertEqual(_read('"abc"'), Ps1Constant(STRING, 'abc'))
        self.assertEqual(_read('"a`nb"'), Ps1Constant(STRING, 'a\nb'))


class TestPs1AComputedPayloadNamesTheValueItsPythonKindDecides(unittest.TestCase):
    """
    `fact_of` is `read`'s counterpart for a caller holding a value it computed rather than one it
    found written down. A payload carries no .NET type, so the value it names is the one its Python
    kind decides and never the one it was made from: what a caller loses by holding a payload is
    exactly the difference between the two, and it is stated here rather than assumed.
    """

    def test_a_number_takes_the_width_an_unsuffixed_numeral_takes(self):
        self.assertEqual(fact_of(7), MEASURED['007'])
        self.assertEqual(fact_of(2147483648), MEASURED['2147483648'])
        self.assertEqual(fact_of(9223372036854775808), MEASURED['9223372036854775808'])
        self.assertEqual(fact_of(1.5), MEASURED['1.5'])

    def test_a_boolean_is_a_boolean_although_python_carries_it_as_an_integer(self):
        self.assertEqual(fact_of(True), Ps1Constant(BOOLEAN, True))
        self.assertEqual(fact_of(False), Ps1Constant(BOOLEAN, False))
        self.assertNotEqual(fact_of(True), fact_of(1))

    def test_a_python_none_is_the_null_value(self):
        self.assertEqual(fact_of(None), NULL)
        self.assertEqual(fact_of(None), _read('$Null'))

    def test_a_one_character_string_is_a_string_and_never_a_char(self):
        self.assertEqual(_measured('[char]65'), ('System.Char', 'A'))
        self.assertEqual(fact_of('A'), _read("'A'"))
        self.assertNotEqual(fact_of('A'), _measured_fact('[char]65'))

    def test_a_sequence_names_the_collection_of_what_its_elements_name(self):
        self.assertEqual(fact_of([1, 'a']), _read("1, 'a'"))
        self.assertEqual(fact_of(()), _read('@()'))
        self.assertEqual(fact_of([[1, 2], 3]), _read('(1, 2), 3'))

    def test_an_object_no_powershell_value_stands_behind_names_nothing(self):
        for payload in (b'abc', {'a': 1}, decimal.Decimal('1.5'), object()):
            with self.subTest(repr(payload)):
                self.assertEqual(fact_of(payload), UNKNOWN)

    def test_a_number_no_numeral_spells_names_nothing(self):
        """
        An infinity is a Double a run can hold and no source text can write down, so naming it here
        would hand a caller a value it cannot put back into the script it came out of.
        """
        for payload in (INFINITY, -INFINITY):
            with self.subTest(repr(payload)):
                self.assertEqual(fact_of(payload), UNKNOWN)

    def test_a_value_whose_type_its_payload_carries_is_named_back_unchanged(self):
        for spelling in ('007', '2147483648', '1.5', '0xFFFFFFFF', '0xFFFFFFFFL'):
            with self.subTest(spelling):
                self.assertEqual(fact_of(_payload(MEASURED[spelling])), MEASURED[spelling])

    def test_a_value_whose_type_its_payload_left_behind_is_named_back_as_another(self):
        self.assertEqual(fact_of(_payload(_read('[byte]5'))), Ps1Constant(INT32, 5))
        self.assertEqual(fact_of(_payload(_read('[char]65'))), Ps1Constant(STRING, 'A'))
        self.assertEqual(fact_of(_payload(MEASURED['1L'])), Ps1Constant(INT32, 1))
        self.assertEqual(fact_of(_payload(MEASURED['1.5d'])), UNKNOWN)

    def test_a_named_value_is_written_and_read_back_as_the_value_it_named(self):
        for payload in (None, True, 7, 2147483648, 1.5, 'abc', 'A', [1, 'a'], ()):
            with self.subTest(repr(payload)):
                self.assertEqual(_read(_spelled(fact_of(payload))), fact_of(payload))


class TestPs1AComputedValueIsStampedOnlyByAnArmThatNamesItsKind(unittest.TestCase):
    """
    `analysis.values._stamped` is the guard `apply` and `convert` route every value a kernel
    computed through, and it dispatches on the payload's Python kind: a `bool`, an `int`, a
    `Decimal`, a `str` and a `float` each have an arm, and the value is reported only under a type
    the measured cell recorded. A payload of any other kind is therefore the one thing it must
    refuse, since stamping it would report a value under a type it does not have — which is what a
    trailing `Double` arm did to everything that reached it.
    """

    #: A cell recording a type for every arm, and the array type as well, so that a refusal below is
    #: the guard declining to stamp a payload rather than the candidates withholding a type from it.
    CANDIDATES = frozenset({BOOLEAN, INT32, DECIMAL, DOUBLE, STRING, OBJECT_ARRAY})

    def test_a_payload_of_a_kind_no_arm_names_is_refused(self):
        """
        The guard has to fail closed for a kind nothing names, because stamping one would report a
        value under a type it does not have. A `set` stands for that here — it is a payload no fact
        carries and no kernel returns, so reaching the refusal is the whole of what it tests.
        """
        unnamed: Any = {1, 2}
        self.assertEqual(_stamped(unnamed, self.CANDIDATES), UNKNOWN)

    def test_a_collection_is_stamped_only_where_the_cell_recorded_the_array_type(self):
        """
        A tuple of facts is the payload an array constant carries, and the kernel returns one for
        `@(1, 2) + 5`. It is stamped like every other kind: under the array type when the cell
        recorded it, and refused when the cell did not, so the arm is licensed by the measurement
        rather than by being written.
        """
        collection: Any = (Ps1Constant(INT32, 1), Ps1Constant(INT32, 2))
        self.assertEqual(
            _stamped(collection, self.CANDIDATES), Ps1Constant(OBJECT_ARRAY, collection))
        self.assertEqual(_stamped(collection, self.CANDIDATES - {OBJECT_ARRAY}), UNKNOWN)

    def test_a_payload_of_each_kind_an_arm_names_is_stamped_from_the_same_candidates(self):
        self.assertEqual(_stamped(True, self.CANDIDATES), Ps1Constant(BOOLEAN, True))
        self.assertEqual(_stamped(5, self.CANDIDATES), Ps1Constant(INT32, 5))
        self.assertEqual(
            _stamped(decimal.Decimal('1.5'), self.CANDIDATES),
            Ps1Constant(DECIMAL, decimal.Decimal('1.5')),
        )
        self.assertEqual(_stamped('A', self.CANDIDATES), Ps1Constant(STRING, 'A'))
        self.assertEqual(_stamped(1.5, self.CANDIDATES), Ps1Constant(DOUBLE, 1.5))


class TestPs1MeasuredCasts(unittest.TestCase):
    """
    What `[target] value` produces, held against what a 5.1 host printed for the same cast. Each
    row is answered exactly as the host answered it or declined, and the failure this class exists
    to catch is the third thing: a value, a type, or an absence of a throw that the host did not
    produce.
    """

    def test_every_cast_the_corpus_measures_is_selected(self):
        self.assertEqual(len(CAST_ROWS), 115, 'a measured cast was added or withdrawn')
        self.assertEqual(sorted(set(DECLINED_CASTS) - set(CAST_ROWS)), [])
        self.assertEqual(sorted(set(DECLINED_CASTS) & set(THROWN)), [])

    def test_a_measured_cast_the_domain_pins_is_pinned_to_the_fact_the_host_printed(self):
        pinned = {
            expression: _converted(expression)
            for expression in CAST_ROWS
            if expression not in THROWN
            and isinstance(_converted(expression).value, Ps1Constant)
        }
        self.assertEqual(
            pinned,
            {
                expression: Ps1Outcome(NEVER, _measured_fact(expression))
                for expression in pinned
            },
        )

    def test_the_measured_casts_whose_value_is_declined_are_exactly_the_documented_ones(self):
        declined = [
            expression for expression in CAST_ROWS
            if expression not in THROWN
            and not isinstance(_converted(expression).value, Ps1Constant)
        ]
        self.assertEqual(sorted(declined), sorted(DECLINED_CASTS))

    def test_a_declined_cast_still_carries_the_type_the_host_reported(self):
        """
        A number the domain does not compute is still a value of the type the host stamped it with,
        and every declined cast whose operand is read has that type in the grid: `[int]'0x10'` is an
        Int32 whether or not this can say that .NET reads those digits as sixteen.
        """
        for expression in sorted(set(DECLINED_CASTS) - set(UNREAD_OPERANDS)):
            with self.subTest(expression):
                name, _ = _measured(expression)
                self.assertEqual(_converted(expression).value, Ps1Typed(_type(name)))

    def test_a_cast_over_an_unread_operand_names_no_type_only_where_recorded(self):
        unnamed = [
            expression for expression in DECLINED_CASTS
            if _converted(expression).value is UNKNOWN
        ]
        self.assertEqual(sorted(unnamed), sorted(UNREAD_OPERANDS))

    def test_a_cast_of_a_cast_reaches_the_value_the_host_printed(self):
        """
        The host prints 65 for `[int][char]65` and 48 for `[int][char]48`. The inner cast is how the
        language spells a Char, so `read` names the Char and the outer conversion has an operand to
        work from: a Char is a number to `[int]`, where the one-character String it used to be
        spelled as parses its digits instead.
        """
        for expression in NESTED_CASTS:
            with self.subTest(expression):
                self.assertEqual(
                    _converted(expression), Ps1Outcome(NEVER, _measured_fact(expression)))

    def test_a_cast_the_host_threw_on_pins_no_value_and_reports_the_throw(self):
        """
        5.1 throws rather than wrapping where a value does not fit its target, and rather than
        yielding zero for a String that spells no number. A row where the domain sees the throw for
        itself names no value at all; one where it declines the spelling keeps the type its cell
        names — an Int32, or it throws — and that type is not a claim that a value came out.

        The throw axis is `ALWAYS` for every row the domain proves throws for the operand in hand: a
        value the target's width or range cannot hold, and a String the invariant coercion cannot
        read (`'abc'`, `'1_0'`, `'0b1010'`, `'0o17'`, `'1kb'`). Three rows the host throws on the
        domain still only *may* throw here, because it declines them soundly rather than proving
        them: an exponent String (`[byte]'1e3'`, whose overflow it does not compute), an
        all-whitespace one (`[int]'   '`, which is not the empty String it converts to zero), and
        `[byte](200 * 2)`, whose operand is an operator `read` does not fold, so `convert` is handed
        an unknown — `evaluate`, which folds the 400, proves that one (see the evaluate twin below).
        """
        self.assertEqual(
            {expression: _converted(expression) for expression in THROWN},
            {
                '[byte]300'       : Ps1Outcome(ALWAYS, UNKNOWN),
                '[byte]-1'        : Ps1Outcome(ALWAYS, UNKNOWN),
                '[byte]400'       : Ps1Outcome(ALWAYS, UNKNOWN),
                '[byte](200 * 2)' : Ps1Outcome(MAYBE, UNKNOWN),
                '[int]2147483648' : Ps1Outcome(ALWAYS, UNKNOWN),
                '[char]65536'     : Ps1Outcome(ALWAYS, UNKNOWN),
                '[char]-1'        : Ps1Outcome(ALWAYS, UNKNOWN),
                "[byte]'-1'"      : Ps1Outcome(ALWAYS, UNKNOWN),
                "[byte]'0x100'"   : Ps1Outcome(ALWAYS, UNKNOWN),
                "[char]'AB'"      : Ps1Outcome(ALWAYS, UNKNOWN),
                "[char]''"        : Ps1Outcome(ALWAYS, UNKNOWN),
                "[int]'abc'"      : Ps1Outcome(ALWAYS, Ps1Typed(INT32)),
                "[int]'   '"      : Ps1Outcome(MAYBE, Ps1Typed(INT32)),
                "[int]'1_0'"      : Ps1Outcome(ALWAYS, Ps1Typed(INT32)),
                "[int]'0b1010'"   : Ps1Outcome(ALWAYS, Ps1Typed(INT32)),
                "[int]'0o17'"     : Ps1Outcome(ALWAYS, Ps1Typed(INT32)),
                "[int]'1kb'"      : Ps1Outcome(ALWAYS, Ps1Typed(INT32)),
                "[byte]'1e3'"     : Ps1Outcome(MAYBE, Ps1Typed(BYTE)),
            },
        )

    def test_a_row_that_measures_as_is_not_a_cast_and_is_no_expectation_here(self):
        """
        A conversion that cannot be made yields `$null` for `-as` and throws for a cast, measured:
        the corpus prints `<null>` for `300 -as [byte]` where `[byte]300` throws. An `-as` row read
        as a cast's expectation would pin `convert` to `$null` for exactly the operands where the
        two expressions differ.
        """
        self.assertEqual(
            sorted(AS_ROWS), ["'abc' -as [int]", '300 -as [byte]', '5 -as [long]'])
        self.assertEqual(sorted(set(AS_ROWS) & set(CAST_ROWS)), [])
        self.assertEqual(_measured('300 -as [byte]'), ('', '<null>'))
        self.assertEqual(_throws(_transcript('[byte]300')), True)


class TestPs1CharConversions(unittest.TestCase):
    """
    A Char is the one value no literal spells, so every measured cast over one is a row `convert`
    has to be asked for directly. It is also the erasure the fact layer exists to undo: 65 and `A`
    are one Char under two casts, and a Char answered as a one-character String changes what
    `1 + $t` and `$t * 3` do.
    """

    def test_a_char_casts_to_the_number_and_to_the_text_the_host_printed(self):
        """
        Measured, `[int][char]65` is Int32 65 and `[string][char]65` is `A`.
        """
        self.assertEqual(
            convert(Ps1Constant(CHAR, 'A'), INT32), Ps1Outcome(NEVER, Ps1Constant(INT32, 65)))
        self.assertEqual(
            convert(Ps1Constant(CHAR, 'A'), STRING), Ps1Outcome(NEVER, Ps1Constant(STRING, 'A')))

    def test_a_char_reaches_no_target_the_corpus_does_not_measure(self):
        """
        The corpus measures a Char cast to Int32, to String and to Boolean, and to nothing else.
        What `[double][char]65` is remains a .NET rule no row records, so there the type the grid
        names is the whole answer and the value is left where the measurement left it.
        """
        self.assertEqual(convert(Ps1Constant(CHAR, 'A'), DOUBLE).value, Ps1Typed(DOUBLE))
        self.assertEqual(convert(Ps1Constant(CHAR, 'A'), DECIMAL).value, Ps1Typed(DECIMAL))


class TestPs1CastsThatReadAString(unittest.TestCase):
    """
    A String is the one source a cast reads by parsing rather than by arithmetic, and 5.1 parses it
    by more than one rule. Each question below is asked twice — of the transcript the row was
    measured in and of the domain — so the two can only agree by both agreeing with the host.
    """

    def test_a_hexadecimal_string_is_the_bit_pattern_the_target_width_holds(self):
        """
        The digits are read at the width of the target rather than at the width the number needs, so
        the same eight bits are 128 in a Byte and -128 in an SByte.
        """
        self.assertEqual(_measured("[byte]'0x80'"), ('System.Byte', '128'))
        self.assertEqual(_measured("[sbyte]'0x80'"), ('System.SByte', '-128'))
        self.assertEqual(_measured("[uint16]'0xFFFF'"), ('System.UInt16', '65535'))
        self.assertEqual(_measured("[int]'0xFFFFFFFF'"), ('System.Int32', '-1'))
        self.assertEqual(_converted("[byte]'0x80'"), Ps1Outcome(NEVER, Ps1Constant(BYTE, 128)))
        self.assertEqual(_converted("[sbyte]'0x80'"), Ps1Outcome(NEVER, Ps1Constant(SBYTE, -128)))
        self.assertEqual(
            _converted("[uint16]'0xFFFF'"), Ps1Outcome(NEVER, Ps1Constant(UINT16, 65535)))
        self.assertEqual(
            _converted("[int]'0xFFFFFFFF'"), Ps1Outcome(NEVER, Ps1Constant(INT32, -1)))

    def test_a_hexadecimal_string_the_target_width_does_not_hold_throws(self):
        self.assertEqual(_throws(_transcript("[byte]'0x100'")), True)
        self.assertEqual(_converted("[byte]'0x100'"), Ps1Outcome(ALWAYS, UNKNOWN))

    def test_a_decimal_string_carries_a_sign_where_a_hexadecimal_one_carries_a_pattern(self):
        """
        `[byte]'-1'` throws where `[byte]'0x80'` is 128, so a decimal spelling is a magnitude that
        has to fit and never a width to be filled.
        """
        self.assertEqual(_throws(_transcript("[byte]'-1'")), True)
        self.assertEqual(_measured("[int]'+7'"), ('System.Int32', '7'))
        self.assertEqual(_converted("[byte]'-1'"), Ps1Outcome(ALWAYS, UNKNOWN))
        self.assertEqual(_converted("[int]'+7'"), Ps1Outcome(NEVER, Ps1Constant(INT32, 7)))

    def test_a_string_spelling_a_half_is_rounded_to_the_even_neighbour(self):
        """
        Both rows are exactly halfway and neither rounds upwards: 7.5 is 8 and 2.5 is 2.
        """
        self.assertEqual(_measured("[int]'7.5'"), ('System.Int32', '8'))
        self.assertEqual(_measured("[int]'2.5'"), ('System.Int32', '2'))
        self.assertEqual(_converted("[int]'7.5'"), Ps1Outcome(NEVER, Ps1Constant(INT32, 8)))
        self.assertEqual(_converted("[int]'2.5'"), Ps1Outcome(NEVER, Ps1Constant(INT32, 2)))

    def test_the_empty_string_is_a_zero_and_a_string_of_spaces_is_not(self):
        """
        Space around a number is stripped and a String of nothing but space is not the empty one:
        `[int]' 5 '` is 5, `[int]''` is 0, and `[int]'   '` throws.
        """
        self.assertEqual(_measured("[int]''"), ('System.Int32', '0'))
        self.assertEqual(_measured("[int]' 5 '"), ('System.Int32', '5'))
        self.assertEqual(_throws(_transcript("[int]'   '")), True)
        self.assertEqual(_converted("[int]''"), Ps1Outcome(NEVER, Ps1Constant(INT32, 0)))
        self.assertEqual(_converted("[int]' 5 '"), Ps1Outcome(NEVER, Ps1Constant(INT32, 5)))
        self.assertEqual(_converted("[int]'   '"), Ps1Outcome(MAYBE, Ps1Typed(INT32)))

    def test_a_string_is_true_by_holding_characters_rather_than_by_what_they_spell(self):
        self.assertEqual(_measured("[bool]'0'"), ('System.Boolean', 'True'))
        self.assertEqual(_measured("[bool]'a'"), ('System.Boolean', 'True'))
        self.assertEqual(_measured("[bool]''"), ('System.Boolean', 'False'))
        self.assertEqual(_converted("[bool]'0'"), Ps1Outcome(NEVER, Ps1Constant(BOOLEAN, True)))
        self.assertEqual(_converted("[bool]'a'"), Ps1Outcome(NEVER, Ps1Constant(BOOLEAN, True)))
        self.assertEqual(_converted("[bool]''"), Ps1Outcome(NEVER, Ps1Constant(BOOLEAN, False)))

    def test_a_one_character_string_is_that_char_and_every_other_length_throws(self):
        """
        The empty String is where the targets part: it is a zero to `[int]` and a throw to `[char]`.
        """
        self.assertEqual(_measured("[char]'A'"), ('System.Char', 'A'))
        self.assertEqual(_throws(_transcript("[char]'AB'")), True)
        self.assertEqual(_throws(_transcript("[char]''")), True)
        self.assertEqual(_converted("[char]'A'"), Ps1Outcome(NEVER, Ps1Constant(CHAR, 'A')))
        self.assertEqual(_converted("[char]'AB'"), Ps1Outcome(ALWAYS, UNKNOWN))
        self.assertEqual(_converted("[char]''"), Ps1Outcome(ALWAYS, UNKNOWN))

    def test_a_cast_to_string_is_the_string_it_was_handed(self):
        self.assertEqual(_measured("[string]'foo'"), ('System.String', 'foo'))
        self.assertEqual(
            _converted("[string]'foo'"), Ps1Outcome(NEVER, Ps1Constant(STRING, 'foo')))

    def test_a_spelling_two_targets_read_apart_is_declined_by_both(self):
        """
        Measured, `'1e3'` is 1000 to `[int]` and a throw to `[byte]`, so no one rule reads the
        exponent and a value computed under either would be the wrong answer under the other.
        """
        self.assertEqual(_measured("[int]'1e3'"), ('System.Int32', '1000'))
        self.assertEqual(_throws(_transcript("[byte]'1e3'")), True)
        self.assertEqual(_converted("[int]'1e3'"), Ps1Outcome(MAYBE, Ps1Typed(INT32)))
        self.assertEqual(_converted("[byte]'1e3'"), Ps1Outcome(MAYBE, Ps1Typed(BYTE)))

    def test_a_spelling_only_python_reads_as_a_number_is_no_number_here(self):
        """
        A digit separator and a binary prefix are Python's numerals and not 5.1's: measured, both
        rows throw, so a module that read them with Python's own parser would answer 10 twice.
        """
        self.assertEqual(_throws(_transcript("[int]'1_0'")), True)
        self.assertEqual(_throws(_transcript("[int]'0b1010'")), True)
        self.assertEqual(_converted("[int]'1_0'"), Ps1Outcome(ALWAYS, Ps1Typed(INT32)))
        self.assertEqual(_converted("[int]'0b1010'"), Ps1Outcome(ALWAYS, Ps1Typed(INT32)))


class TestPs1ConvertRefusals(unittest.TestCase):
    """
    A cast reads its type from the grid and its value from a kernel, and the two axes fail apart:
    where the kernel has no rule the type still stands, and where the grid has no cell there is no
    answer at all.
    """

    def test_a_fact_that_is_not_a_value_is_never_converted_into_one(self):
        """
        A value known only by its type is looked up in the grid and not computed from, so a cast of
        a Double nothing pins is an Int32 whose number is unanswered, and a fact that names no type
        at all indexes no cell and answers nothing. `$null` is neither of those: it is the value an
        absent one *is*, and every target converts it as that target's own zero.
        """
        self.assertEqual(convert(UNKNOWN, INT32), NOTHING)
        self.assertEqual(convert(Ps1Typed(DOUBLE), INT32).value, Ps1Typed(INT32))
        self.assertEqual(convert(NULL, INT32), Ps1Outcome(NEVER, Ps1Constant(INT32, 0)))

    def test_a_cast_the_grid_does_not_cover_is_refused_rather_than_assumed(self):
        """
        The grid holds the targets the capture measured, and `System.DateTime` is not one of them. A
        cast to a type nothing measured produces no fact: neither the identity nor a nearest rule is
        an answer that was ever observed.
        """
        self.assertEqual(convert(Ps1Constant(INT32, 5), _type('System.DateTime')), NOTHING)

    def test_a_double_is_not_carried_into_a_decimal_by_python(self):
        """
        `[decimal]` of a Double converts by the digits the value is written with, where Python's
        `Decimal` of a `float` carries the binary expansion instead — `Decimal(1.1)` begins
        1.10000000000000008. Nothing measures the cast, so the type is the answer and the number is
        not.
        """
        self.assertEqual(convert(Ps1Constant(DOUBLE, 1.5), DECIMAL).value, Ps1Typed(DECIMAL))


class TestPs1OutcomeIsWeakOnBothAxes(unittest.TestCase):
    """
    An outcome's two fields are read in the same direction: `may_throw` is `False` only where the
    domain claims the operation *cannot* throw, exactly as `UNKNOWN` is the value of one that names
    none. So an answer about operands the domain knows less about may lose a value and may gain a
    throw, and never the other way round — a throw that a *weaker* premise takes away is one no
    measurement ever removed.
    """

    def test_an_operand_nothing_is_known_about_leaves_both_axes_unclaimed(self):
        unclaimed = Ps1Outcome(MAYBE, UNKNOWN)
        for operator in GRID_OPERATORS:
            for fact in OPERANDS:
                with self.subTest(F'{fact!r} {operator}'):
                    self.assertEqual(apply(operator, UNKNOWN, fact), unclaimed)
                    self.assertEqual(apply(operator, fact, UNKNOWN), unclaimed)
        for target in (INT32, DOUBLE, STRING, CHAR, BOOLEAN, DECIMAL):
            with self.subTest(str(target)):
                self.assertEqual(convert(UNKNOWN, target), unclaimed)

    def test_generalising_a_divisor_does_not_take_away_the_throw_it_had(self):
        """
        Division by a zero divisor is where the two axes came apart: the domain proves the throw for
        the concrete pair it is handed — a certain throw — and an answer for a divisor it knows less
        about must not weaken that to *safe*. `Ps1Outcome(NEVER, UNKNOWN)` reads as safe to the
        folding pass, which folds an outcome that cannot throw; a generalised divisor keeps at least
        `MAYBE`, never `NEVER`.
        """
        five = Ps1Constant(INT32, 5)
        zero = Ps1Constant(INT32, 0)
        self.assertEqual(apply('/', five, zero), Ps1Outcome(ALWAYS, UNKNOWN))
        self.assertEqual(apply('/', five, Ps1Typed(INT32)), Ps1Outcome(MAYBE, UNKNOWN))
        self.assertEqual(apply('/', five, UNKNOWN), Ps1Outcome(MAYBE, UNKNOWN))
        self.assertEqual(apply('/', Ps1Typed(INT32), zero), Ps1Outcome(MAYBE, UNKNOWN))
        self.assertEqual(apply('%', five, zero), Ps1Outcome(ALWAYS, UNKNOWN))
        self.assertEqual(apply('%', five, UNKNOWN), Ps1Outcome(MAYBE, UNKNOWN))

    def test_generalising_an_operand_never_takes_away_a_throw(self):
        """
        Wherever the domain reports a possible throw, it reports one for every pair that says less
        about the same two values. Nothing narrows the premise: a throw reported for operands the
        domain knows exactly is a throw it has grounds for, and an answer that has *fewer* grounds
        cannot be the one that clears the operation.
        """
        for operator in GRID_OPERATORS:
            for left in OPERANDS:
                for right in OPERANDS:
                    if not apply(operator, left, right).may_throw:
                        continue
                    for wider in _generalisations(left):
                        with self.subTest(F'{wider!r} {operator} {right!r}'):
                            self.assertEqual(apply(operator, wider, right).may_throw, True)
                    for wider in _generalisations(right):
                        with self.subTest(F'{left!r} {operator} {wider!r}'):
                            self.assertEqual(apply(operator, left, wider).may_throw, True)

    def test_generalising_the_operand_of_a_cast_the_host_threw_on_keeps_the_throw(self):
        for expression in THROWN:
            row = CAST_ROWS[expression]
            operand = _read(row.operand)
            target = _type(row.target)
            asked = [operand, *_generalisations(operand)]
            with self.subTest(expression):
                self.assertEqual(
                    [convert(fact, target).may_throw for fact in asked], [True] * len(asked))


class TestPs1ZeroDivisors(unittest.TestCase):
    """
    Dividing by a zero is not one operation with one answer, and which answer it has is measured
    rather than reasoned about: the `/` and `%` cells over Int32 and over Decimal each recorded a
    throw, and the ones over Double recorded none although `0.0` is one of the values the capture
    divided by. A domain that raised for every zero would be claiming a throw on the one axis a
    caller acts on, with nothing that ever observed one.
    """

    def test_a_zero_divisor_throws_exactly_where_the_capture_recorded_a_throw(self):
        expected = {
            ('/', 'System.Int32')   : True,
            ('/', 'System.Decimal') : True,
            ('/', 'System.Double')  : False,
            ('%', 'System.Int32')   : True,
            ('%', 'System.Decimal') : True,
            ('%', 'System.Double')  : False,
        }
        self.assertEqual(
            {
                (operator, str(kind)): _cell(operator, kind, kind).may_throw
                for operator in ('/', '%')
                for kind, _, _ in ZERO_DIVISIONS
            },
            expected,
        )
        self.assertEqual(
            {
                (operator, str(kind)): apply(operator, dividend, zero).may_throw
                for operator in ('/', '%')
                for kind, dividend, zero in ZERO_DIVISIONS
            },
            expected,
        )

    def test_a_float_divided_by_zero_names_no_value_and_no_throw(self):
        """
        What a host produces there is an infinity, which is a value this domain deliberately does
        not carry — so the answer names the Double the cell records and no number, and a fold is
        refused for want of a value rather than by a throw that was never observed.
        """
        for operator in ('/', '%'):
            with self.subTest(operator):
                outcome = apply(
                    operator, Ps1Constant(DOUBLE, 1.5), Ps1Constant(DOUBLE, 0.0))
                self.assertEqual(outcome, Ps1Outcome(NEVER, Ps1Typed(DOUBLE)))
                self.assertIsNone(render(outcome.value))


class TestPs1MeasuredOperators(unittest.TestCase):
    """
    What `left <operator> right` produces, held against what a 5.1 host printed for the same
    expression. `apply` is asked here exactly as the folding pass asks it, so what this class
    formalizes is which measured operations a script is rewritten by and to what — and the failure
    it exists to catch is an answer the host did not produce.
    """

    def test_every_measured_operation_is_selected(self):
        self.assertEqual(
            len(OPERATION_ROWS), 293, 'a measured operation was added or withdrawn')
        self.assertEqual(sorted(set(PINNED_OPERATIONS) - set(OPERATION_ROWS)), [])
        self.assertEqual(sorted(set(ABBREVIATED_OPERATIONS) - set(OPERATION_ROWS)), [])
        self.assertEqual(sorted(set(FILTERED_COMPARISONS) - set(OPERATION_ROWS)), [])
        self.assertEqual(
            sorted(THROWN_OPERATIONS),
            [
                '$null -band [uint32]1',
                "$true * '1'",
                '$true * 2',
                '$true + 1.0d',
                '$true - 1.0d',
                '$true / 1.0d',
                "'1_0' -band 15",
                "'ab' * 0xFFFFFFFF",
                "1 + '1e400'",
                "1 -gt 'abc'",
                "1 -lt 'abc'",
                "16 + 'file'",
                '1d / 0d',
                '79228162514264337593543950335d + 1d',
                '79228162514264337593543950335d - -1d',
                "[char]48 * '1'",
                '[char]48 * 2',
                '[decimal]::MaxValue + 1',
            ],
        )

    def test_a_measured_operation_the_domain_pins_is_pinned_to_the_fact_the_host_printed(self):
        self.assertEqual(
            {expression: _applied(expression) for expression in PINNED_OPERATIONS},
            {
                expression: Ps1Outcome(NEVER, _measured_operation_fact(expression))
                for expression in PINNED_OPERATIONS
            },
        )

    def test_the_measured_operations_a_fold_rewrites_are_the_ones_it_has_a_value_for(self):
        """
        The folding pass rewrites an outcome that cannot throw and names a value with a spelling.
        Reading a cell more carefully costs none of those, because a value the kernel computed is
        answered on the kernel's own evidence and never asks whether the cell's witnesses reached
        far enough.
        """
        rewritten = [
            expression for expression in OPERATION_ROWS
            if not _applied(expression).may_throw
            and render(_applied(expression).value) is not None
        ]
        self.assertEqual(
            sorted(rewritten),
            sorted(
                PINNED_OPERATIONS
                + ABBREVIATED_OPERATIONS
                + FILTERED_COMPARISONS
                + tuple(MISFOLDED_OPERATIONS)
            ),
        )

    def test_every_operation_recorded_as_folded_wrongly_still_is(self):
        """
        The ledger only ratchets in one direction on its own: the partition above stops a new wrong
        fold being added silently, and this stops a fixed one being left behind, so an entry here
        can only leave by the defect leaving with it.
        """
        self.assertEqual(
            {
                expression: text_of(_applied(expression).value)
                for expression in MISFOLDED_OPERATIONS
            },
            MISFOLDED_OPERATIONS,
        )
        self.assertEqual(
            {
                expression: text_of(_measured_operation_fact(expression)) == folded
                for expression, folded in MISFOLDED_OPERATIONS.items()
            },
            {expression: False for expression in MISFOLDED_OPERATIONS},
        )

    def test_no_measured_operation_is_answered_with_a_type_the_host_did_not_print(self):
        """
        A cell records what some values did, so a type read out of one is a claim about every
        value. `1 + '2147483648'` is where the two come apart: the host printed an Int64 that the
        cell an Int32 and a String index does not carry.
        """
        named = {
            expression: type_of(_applied(expression).value)
            for expression in OPERATION_ROWS
            if type_of(_applied(expression).value) is not None
        }
        self.assertEqual(
            named,
            {
                expression: _type(_measured_operation(expression)[0])
                for expression in named
            },
        )

    def test_an_operation_the_host_threw_on_is_left_with_nothing_to_fold_to(self):
        self.assertEqual(
            {
                expression: (
                    _applied(expression).may_throw, render(_applied(expression).value))
                for expression in THROWN_OPERATIONS
            },
            {expression: (True, None) for expression in THROWN_OPERATIONS},
        )

    def test_an_overflow_the_host_widened_is_answered_as_the_double_it_produced(self):
        """
        The digits a host printed for these two are fewer than the value carries, so the type is
        what the row measures: a domain computing in Python's unbounded integers would report the
        exact sum under an integer type the host never produced.
        """
        self.assertEqual(
            {
                expression: (
                    _applied(expression).may_throw, type_of(_applied(expression).value))
                for expression in ABBREVIATED_OPERATIONS
            },
            {
                expression: (False, _type(_measured_operation(expression)[0]))
                for expression in ABBREVIATED_OPERATIONS
            },
        )


class TestPs1MeasuredComplement(unittest.TestCase):
    """
    What `-bnot operand` produces, held against what a 5.1 host printed for the same expression.
    The width the bits are complemented at is not the operand's own type: measured, a Byte, a Char,
    a Boolean and a Decimal all complement to an Int32, an Int64 to an Int64 and a UInt32 to a
    UInt32. So the answer cannot be the complement of whatever number the operand's node reported,
    and the two questions the domain has to keep apart are which width and which number.
    """

    def test_every_measured_complement_is_selected(self):
        self.assertEqual(
            len(COMPLEMENT_ROWS), 13, 'a measured complement was added or withdrawn')
        self.assertEqual(sorted(THROWN_COMPLEMENTS), ["-bnot 'abc'"])

    def test_a_measured_complement_the_domain_pins_is_pinned_to_the_fact_the_host_printed(self):
        pinned = {
            expression: _complemented(expression)
            for expression in COMPLEMENT_ROWS
            if isinstance(_complemented(expression).value, Ps1Constant)
        }
        self.assertEqual(
            pinned,
            {
                expression: Ps1Outcome(NEVER, _measured_complement_fact(expression))
                for expression in pinned
            },
        )

    def test_the_measured_complements_the_domain_leaves_unpinned_are_two(self):
        self.assertEqual(
            sorted(
                expression for expression in COMPLEMENT_ROWS
                if not isinstance(_complemented(expression).value, Ps1Constant)
            ),
            ["-bnot 'abc'", '-bnot 3000000000.0'],
        )

    def test_a_hexadecimal_operand_that_fills_its_width_is_complemented_as_the_negative_it_is(self):
        """
        `0xFFFFFFFF` is the Int32 -1 and its complement is 0, where the complement of the magnitude
        those digits spell would be -4294967296. The two are the same eight digits, so only the
        spelling rule tells them apart.
        """
        self.assertEqual(_measured('0xFFFFFFFF'), ('System.Int32', '-1'))
        self.assertEqual(_measured_complement('-bnot 0xFFFFFFFF'), ('System.Int32', '0'))
        self.assertEqual(_measured_complement('-bnot 0xFF'), ('System.Int32', '-256'))
        self.assertEqual(
            _complemented('-bnot 0xFFFFFFFF'), Ps1Outcome(NEVER, Ps1Constant(INT32, 0)))
        self.assertEqual(_complemented('-bnot 0xFF'), Ps1Outcome(NEVER, Ps1Constant(INT32, -256)))

    def test_a_narrow_operand_widens_where_a_wide_one_keeps_its_width(self):
        """
        Measured, the complement of a Byte 5 is an Int32 and not a Byte, the complement of an Int64
        is an Int64, and the complement of a UInt32 is a UInt32 — which is where the unsigned width
        shows, since 4294967288 is the same bits as -8 and not the same number.
        """
        self.assertEqual(_measured_complement('-bnot [byte]5'), ('System.Int32', '-6'))
        self.assertEqual(_measured_complement('-bnot 1L'), ('System.Int64', '-2'))
        self.assertEqual(
            _measured_complement('-bnot [uint32]7'), ('System.UInt32', '4294967288'))
        self.assertEqual(_complemented('-bnot [byte]5'), Ps1Outcome(NEVER, Ps1Constant(INT32, -6)))
        self.assertEqual(_complemented('-bnot 1L'), Ps1Outcome(NEVER, Ps1Constant(INT64, -2)))
        self.assertEqual(
            _complemented('-bnot [uint32]7'),
            Ps1Outcome(NEVER, Ps1Constant(UINT32, 4294967288)),
        )

    def test_an_operand_that_is_no_integer_is_complemented_at_what_converting_it_reaches(self):
        """
        None of these is a number of a width, and each still has one answer: measured, `[int]1.5`
        is 2 and `-bnot 1.5` is -3, `[int]$null` is 0 and `-bnot $null` is -1, `[int]'5'` is 5 and
        `-bnot '5'` is -6, `[int][char]65` is 65 and `-bnot [char]65` is -66. The conversion is what
        the operator is defined over, so the domain has to convert rather than refuse.
        """
        self.assertEqual(
            {
                expression: (_measured(cast), _measured_complement(expression))
                for expression, cast in (
                    ('-bnot 1.5', '[int]1.5'),
                    ('-bnot $null', '[int]$null'),
                    ("-bnot '5'", "[int]'5'"),
                    ('-bnot [char]65', '[int][char]65'),
                    ('-bnot $true', '[int]$true'),
                )
            },
            {
                '-bnot 1.5'      : (('System.Int32', '2'), ('System.Int32', '-3')),
                '-bnot $null'    : (('System.Int32', '0'), ('System.Int32', '-1')),
                "-bnot '5'"      : (('System.Int32', '5'), ('System.Int32', '-6')),
                '-bnot [char]65' : (('System.Int32', '65'), ('System.Int32', '-66')),
                '-bnot $true'    : (('System.Int32', '1'), ('System.Int32', '-2')),
            },
        )
        self.assertEqual(
            {
                expression: _complemented(expression)
                for expression in (
                    '-bnot 1.5',
                    '-bnot $null',
                    "-bnot '5'",
                    '-bnot [char]65',
                    '-bnot $true',
                )
            },
            {
                '-bnot 1.5'      : Ps1Outcome(NEVER, Ps1Constant(INT32, -3)),
                '-bnot $null'    : Ps1Outcome(NEVER, Ps1Constant(INT32, -1)),
                "-bnot '5'"      : Ps1Outcome(NEVER, Ps1Constant(INT32, -6)),
                '-bnot [char]65' : Ps1Outcome(NEVER, Ps1Constant(INT32, -66)),
                '-bnot $true'    : Ps1Outcome(NEVER, Ps1Constant(INT32, -2)),
            },
        )

    def test_the_width_a_real_complements_at_follows_its_value_and_not_its_type(self):
        """
        Measured, `-bnot 1.5` is an Int32 and `-bnot 3000000000.0` a UInt32, both over a Double. So
        the width is settled by the magnitude, and a rule keyed on the operand's type alone would
        answer the second one -3000000001 under a type the host never printed. The domain has no
        rule for that width and names nothing, which costs a fold and states nothing false.
        """
        self.assertEqual(_measured_complement('-bnot 1.5'), ('System.Int32', '-3'))
        self.assertEqual(
            _measured_complement('-bnot 3000000000.0'), ('System.UInt32', '1294967295'))
        self.assertEqual(_complemented('-bnot 1.5'), Ps1Outcome(NEVER, Ps1Constant(INT32, -3)))
        self.assertEqual(_complemented('-bnot 3000000000.0'), NOTHING)

    def test_a_complement_the_host_threw_on_names_no_value_and_reports_the_throw(self):
        """
        Measured, `-bnot 'abc'` throws where `-bnot '5'` is -6, so what a String complements to is
        decided by whether the conversion succeeds and never by the length of the text.
        """
        self.assertEqual(
            {expression: _complemented(expression) for expression in THROWN_COMPLEMENTS},
            {expression: Ps1Outcome(MAYBE, UNKNOWN) for expression in THROWN_COMPLEMENTS},
        )
        self.assertEqual(_throws(_transcript("[int]'abc'")), True)

    def test_no_measured_complement_is_answered_with_a_type_the_host_did_not_print(self):
        named = {
            expression: type_of(_complemented(expression).value)
            for expression in COMPLEMENT_ROWS
            if type_of(_complemented(expression).value) is not None
        }
        self.assertEqual(
            named,
            {
                expression: _type(_measured_complement(expression)[0])
                for expression in named
            },
        )

    def test_an_operand_nothing_is_known_about_leaves_both_axes_unclaimed(self):
        for operand in (UNKNOWN, Ps1Typed(INT32), Ps1Typed(DOUBLE), Ps1Typed(STRING)):
            with self.subTest(repr(operand)):
                self.assertEqual(apply_unary('-bnot', operand), Ps1Outcome(MAYBE, UNKNOWN))

    def test_a_measured_complement_is_answered_the_same_however_its_operator_is_cased(self):
        self.assertEqual(
            {
                expression: apply_unary('-BNOT', read(_complement_operand(expression)))
                for expression in COMPLEMENT_ROWS
            },
            {expression: _complemented(expression) for expression in COMPLEMENT_ROWS},
        )

    def test_an_operator_this_does_not_answer_is_refused_rather_than_complemented(self):
        """
        `-not` negates a truth value, so an answer here for it would be the complement handed to an
        expression that does not take one: measured, `-bnot 0xFF` is -256 while `-not 0xFF` is
        `$False`. Unary minus is left out because it is answered rather than refused, from a grid
        of its own — see `TestPs1MeasuredNegation`.
        """
        for operator in ('-not', '!', '+', '-bxor', '-join'):
            with self.subTest(operator):
                self.assertEqual(apply_unary(operator, MEASURED['0xFF']), NOTHING)


class TestPs1MeasuredNegation(unittest.TestCase):
    """
    What `- operand` produces, held against what a 5.1 host printed for the same expression. The
    result type is not the operand's own and not the width its value needs either: measured, a Byte
    and a Char negate to an Int32, a UInt32 and the Int32 with no positive counterpart to a Double,
    and a String is read as a number first. So the answer is read off the measured grid, and what a
    rule written out here would cost is a type no run of the script produces.
    """

    def test_every_measured_negation_is_selected(self):
        self.assertEqual(len(NEGATION_ROWS), 32, 'a measured negation was added or withdrawn')
        self.assertEqual(sorted(THROWN_NEGATIONS), ["- 'abc'", '- @()'])
        self.assertEqual(sorted(set(ABBREVIATED_NEGATIONS) - set(NEGATION_ROWS)), [])

    def test_a_measured_negation_the_domain_pins_is_pinned_to_the_fact_the_host_printed(self):
        pinned = {
            expression: _negated(expression)
            for expression in NEGATION_ROWS
            if expression not in ABBREVIATED_NEGATIONS
            and isinstance(_negated(expression).value, Ps1Constant)
        }
        self.assertEqual(
            pinned,
            {
                expression: Ps1Outcome(NEVER, _measured_negation_fact(expression))
                for expression in pinned
            },
        )

    def test_the_measured_negations_the_domain_leaves_unpinned_are_the_throws(self):
        """
        Every negation a host answered is one the domain names a value for, and the two it leaves
        are the two the host refused as well.
        """
        self.assertEqual(
            sorted(
                expression for expression in NEGATION_ROWS
                if not isinstance(_negated(expression).value, Ps1Constant)
            ),
            sorted(THROWN_NEGATIONS),
        )

    def test_a_negation_the_host_threw_on_names_no_value_and_reports_the_throw(self):
        # Both name no value; the axis parts them by whether the domain proves the throw. `- 'abc'`
        # is the compiled `0 - 'abc'`, whose String coercion the invariant reader rejects — a certain
        # throw — while `- @()` is a MethodNotFound the domain declines rather than proves.
        self.assertEqual(
            {expression: _negated(expression) for expression in THROWN_NEGATIONS},
            {
                "- 'abc'": Ps1Outcome(ALWAYS, UNKNOWN),
                '- @()': Ps1Outcome(MAYBE, UNKNOWN),
            },
        )

    def test_no_measured_negation_is_answered_with_a_type_the_host_did_not_print(self):
        named = {
            expression: type_of(_negated(expression).value)
            for expression in NEGATION_ROWS
            if type_of(_negated(expression).value) is not None
        }
        self.assertEqual(
            named,
            {expression: _type(_measured_negation(expression)[0]) for expression in named},
        )

    def test_a_negation_printed_to_fewer_digits_is_answered_under_the_type_it_was_printed_with(self):
        self.assertEqual(
            {
                expression: (_negated(expression).may_throw, type_of(_negated(expression).value))
                for expression in ABBREVIATED_NEGATIONS
            },
            {
                expression: (False, _type(_measured_negation(expression)[0]))
                for expression in ABBREVIATED_NEGATIONS
            },
        )

    def test_an_operand_nothing_is_known_about_leaves_both_axes_unclaimed(self):
        for operand in (UNKNOWN, Ps1Typed(INT32), Ps1Typed(DOUBLE), Ps1Typed(STRING)):
            with self.subTest(repr(operand)):
                self.assertEqual(apply_unary('-', operand), NOTHING)

    def test_a_negation_is_the_subtraction_from_an_int32_zero_it_is_compiled_into(self):
        """
        5.1 compiles `- x` into a binary subtraction from an Int32 zero and has no unary arm for it
        at all, so the unary answer and the binary one are one answer, over every operand a host was
        measured negating.
        """
        self.assertEqual(
            {expression: _negated(expression) for expression in NEGATION_ROWS},
            {expression: _negated_as_subtraction(expression) for expression in NEGATION_ROWS},
        )

    def test_a_string_operand_negates_at_the_width_the_numeral_inside_it_takes(self):
        """
        A String is read as a number before it is negated, and that number takes the width its own
        spelling asks for rather than the Int32 an unsuffixed numeral would take. `_coerced_numeral`
        is the reader that answers the same question where a binary operator wants a number out of
        a String, so a negation typed by the String itself disagrees with it.
        """
        negated = {
            text: apply_unary('-', Ps1Constant(STRING, text)) for text in NEGATED_STRINGS
        }
        self.assertEqual(
            {text: type_of(outcome.value) for text, outcome in negated.items()},
            {text: type_of(_coerced(text)) for text in NEGATED_STRINGS},
        )
        self.assertEqual(
            negated,
            {
                text: apply('-', Ps1Constant(INT32, 0), Ps1Constant(STRING, text))
                for text in NEGATED_STRINGS
            },
        )

    def test_a_decimal_at_the_widest_magnitude_negates_exactly_under_any_decimal_context(self):
        """
        Python rounds every `decimal` result to `decimal.getcontext().prec`, which is 28 by default
        and which anything else sharing the process may set to anything at all. A `System.Decimal`
        carries 29 significant digits, so a negation reached through that arithmetic hands back a
        different number from the one it was given — under the default context as much as under a
        narrower one, and a host changes no digit of a value it negates.
        """
        for precision in (1, 28, 60):
            for value in WIDEST_DECIMALS:
                negated = decimal.Decimal(F'-{value}')
                with self.subTest(precision=precision, value=str(value)):
                    with decimal.localcontext() as context:
                        context.prec = precision
                        answered = apply_unary('-', Ps1Constant(DECIMAL, value))
                        restored = apply_unary('-', Ps1Constant(DECIMAL, negated))
                    self.assertEqual(answered, Ps1Outcome(NEVER, Ps1Constant(DECIMAL, negated)))
                    self.assertEqual(restored, Ps1Outcome(NEVER, Ps1Constant(DECIMAL, value)))

    def test_a_floating_zero_negates_to_the_zero_a_subtraction_from_zero_produces(self):
        """
        IEEE-754 subtraction under round to nearest answers `0 - 0.0` and `0 - -0.0` with `+0.0`
        alike, and 5.1 compiles the unary minus into exactly that subtraction. Python's own minus
        answers `-0.0` for the first of the two, and a comparison counts the two zeros equal, so
        what is read here is the sign they carry.
        """
        for operand in (0.0, -0.0):
            with self.subTest(repr(operand)):
                answered = apply_unary('-', Ps1Constant(DOUBLE, operand))
                self.assertEqual(answered, Ps1Outcome(NEVER, Ps1Constant(DOUBLE, 0.0)))
                self.assertEqual(_sign_of(answered.value), 1.0)
                self.assertEqual(
                    _sign_of(apply('-', Ps1Constant(INT32, 0), Ps1Constant(DOUBLE, operand)).value),
                    1.0,
                )


class TestPs1MeasuredTruth(unittest.TestCase):
    """
    What `is_truthy` answers, held against what a host counted the same expression as. Refusing is
    always allowed and a disagreement never is: every caller of it drops a branch or a loop on the
    answer, so a truth that is not the host's is a script rewritten into a different one. The
    question is asked of every condition the corpus settles rather than of a list chosen here, so a
    row measured after this was written is one this is quantified over too.

    `- '0'` is the expression that makes this a measurement rather than a rule. A minus sign in
    front of a String converts the String to a number, so the text `'0'` is true while the Int32 it
    negates to is false, and a host measured over `if (- '0')` ran the else branch.
    """

    def test_a_measured_condition_this_answers_is_answered_the_truth_the_host_counted(self):
        answers = {condition: is_truthy(_slot(condition)) for condition in TRUTHS}
        answered = {
            condition: truth for condition, truth in answers.items() if truth is not None
        }
        self.assertEqual(len(TRUTHS), 52, 'a measured truth was added or withdrawn')
        self.assertEqual(answered, {condition: TRUTHS[condition] for condition in answered})

    def test_a_condition_whose_truth_is_its_own_value_is_answered_rather_than_refused(self):
        self.assertEqual(
            {condition: is_truthy(_slot(condition)) for condition in PLAIN_CONDITIONS},
            {condition: TRUTHS[condition] for condition in PLAIN_CONDITIONS},
        )

    def test_every_shape_a_condition_was_measured_in_counted_it_the_same_way(self):
        self.assertEqual(
            TRUTH_ROWS,
            {
                condition: {expression: TRUTHS[condition] for expression in settled}
                for condition, settled in TRUTH_ROWS.items()
            },
        )

    def test_the_measured_conditions_this_names_no_truth_for_are_the_ones_written_down(self):
        self.assertEqual(
            sorted(condition for condition in TRUTHS if is_truthy(_slot(condition)) is None),
            sorted(UNSETTLED_CONDITIONS),
        )


class TestPs1ACollectionOfOneCountsItsElementByARuleOfItsOwn(unittest.TestCase):
    """
    A collection counts as true by how many elements it holds, and a collection of exactly one asks
    what is inside it — but not the question a condition asks of that same value. Measured,
    `[char]0` is false where `(,[char]0)` is true, and `(,@())` is false where `(,(,@()))` is true:
    the rule inside has no Char arm, so every Char is true to it, and it answers a collection by
    whether it holds anything rather than by asking itself again.

    One rule shared between the two depths would therefore get one member of each pair wrong,
    whichever of the two rules it was.
    """

    def test_a_measured_value_and_the_collection_of_one_holding_it_are_counted_apart(self):
        for element, holding in ELEMENT_PAIRS:
            with self.subTest(holding):
                self.assertEqual(TRUTHS[holding], not TRUTHS[element])
                self.assertEqual(is_truthy(_slot(element)), TRUTHS[element])
                self.assertEqual(is_truthy(_slot(holding)), TRUTHS[holding])

    def test_an_element_that_names_no_value_leaves_the_collection_uncounted(self):
        """
        The rule 5.1 uses inside a one-element collection ends in *otherwise true*, so a copy of it
        would answer true for an element it knows nothing about. `@() + (0 -shl $true)` builds
        exactly that: a collection of one whose element carries a type and no value.
        """
        self.assertEqual(
            _evaluated('@() + (0 -shl $true)'),
            Ps1Outcome(NEVER, Ps1Constant(OBJECT_ARRAY, (Ps1Typed(INT32),))),
        )
        self.assertEqual(
            convert(Ps1Constant(OBJECT_ARRAY, (Ps1Typed(INT32),)), BOOLEAN),
            Ps1Outcome(MAYBE, Ps1Typed(BOOLEAN)),
        )
        self.assertIsNone(is_truthy(_slot('@() + (0 -shl $true)')))


class TestPs1TruthRefusesWhateverEitherStepMayThrowOn(unittest.TestCase):
    """
    Reaching a value and making a Boolean of it are two steps, and either may throw. The second does
    not carry the first: `$null * [int]'abc'` is a definite `$null`, which converts to `$False` and
    cannot throw doing so, while reaching that `$null` is a multiplication a host never finishes.
    A caller told it is false prunes the branch and deletes the throw with it.
    """

    def test_a_definite_value_that_may_throw_on_the_way_to_it_is_counted_as_nothing(self):
        self.assertEqual(_throws(_transcript("[int]'abc'")), True)
        self.assertEqual(_evaluated("$null * [int]'abc'"), Ps1Outcome(ALWAYS, NULL))
        self.assertEqual(convert(NULL, BOOLEAN), Ps1Outcome(NEVER, Ps1Constant(BOOLEAN, False)))
        self.assertIsNone(is_truthy(_slot("$null * [int]'abc'")))

    def test_a_condition_the_host_threw_on_is_counted_as_nothing(self):
        self.assertEqual(
            {expression: is_truthy(_slot(expression)) for expression in THROWN_NEGATIONS},
            {expression: None for expression in THROWN_NEGATIONS},
        )


class TestPs1PlusIsDecidedByItsLeftOperand(unittest.TestCase):
    """
    `+` either adds or joins text, and which it does is settled by the operand written on its left.
    Measured, `[char]65 + 1` is the String `A1` while `1 + [char]65` is the number 66, and `'A' + 1`
    joins where `1 + 'A'` throws — so the same two values in the other order are a different value
    of a different type, and one order refuses operands the other accepts.
    """

    def test_a_char_and_a_number_join_in_one_order_and_not_in_the_other(self):
        self.assertEqual(
            TYPE_TRANSCRIPTS["Write-Output ([char]65 + 1); Write-Output ('A' + 1)"][0],
            'OUT\tSystem.String\tA1',
        )
        self.assertEqual(
            TYPE_TRANSCRIPTS["Write-Output (1 + [char]65); Write-Output (1 + 'A')"][0],
            'OUT\tSystem.Int32\t66',
        )
        self.assertEqual(
            apply('+', Ps1Constant(CHAR, 'A'), Ps1Constant(INT32, 1)),
            Ps1Outcome(NEVER, Ps1Constant(STRING, 'A1')),
        )
        self.assertEqual(
            apply('+', Ps1Constant(INT32, 1), Ps1Constant(CHAR, 'A')),
            Ps1Outcome(NEVER, Ps1Constant(INT32, 66)),
        )

    def test_two_chars_join_into_the_two_character_string_the_host_printed(self):
        self.assertEqual(
            TYPE_TRANSCRIPTS["Write-Output ([char]114 + [char]53); Write-Output ('r' + '5')"],
            ('OUT\tSystem.String\tr5', 'OUT\tSystem.String\tr5'),
        )
        self.assertEqual(
            apply('+', Ps1Constant(CHAR, 'r'), Ps1Constant(CHAR, '5')),
            Ps1Outcome(NEVER, Ps1Constant(STRING, 'r5')),
        )

    def test_nothing_but_a_string_or_a_char_on_the_left_is_answered_with_a_join(self):
        """
        Measured, `1 + 'A'` throws, `1 + [char]65` is 66 and `5 + '5'` is 10: a number on the left
        never joins text, whatever stands on the right of it.

        `$null` is excluded because it is not joining: a null left operand is answered with the
        right operand exactly as it stands, so `$null + 'abc'` is that String and `$null + [char]65`
        is a **Char** rather than the one-character String a join would have made of it. Both
        measured.
        """
        joining = {
            type_of(left)
            for left in OPERANDS
            for right in OPERANDS
            if left is not NULL and type_of(apply('+', left, right).value) == STRING
        }
        self.assertEqual(
            sorted(str(one) for one in joining), ['System.Char', 'System.String'])
        self.assertEqual(
            apply('+', NULL, Ps1Constant(CHAR, 'A')), Ps1Outcome(NEVER, Ps1Constant(CHAR, 'A')))

    def test_what_a_join_appends_is_what_a_cast_of_the_right_operand_to_string_names(self):
        """
        Measured, `'a' + $true` is `aTrue` and `[string]$true` is `True`, so a join asks its right
        operand the question a cast to String asks. `$null` is the one operand where the two are
        spelled apart: it appends nothing and is no String.
        """
        head = Ps1Constant(STRING, 'a')
        for right in OPERANDS:
            with self.subTest(repr(right)):
                joined = apply('+', head, right).value
                converted = convert(right, STRING).value
                if right is NULL:
                    self.assertEqual(joined, head)
                elif isinstance(converted, Ps1Constant):
                    self.assertEqual(joined, Ps1Constant(STRING, F'a{converted.payload}'))
                else:
                    self.assertEqual(joined, UNKNOWN)

    def test_a_decimal_is_joined_with_the_digits_it_was_written_with(self):
        """
        `1.50d` and `1.5d` are one number under two spellings, and the text a join appends is the
        one that was written: measured, `'a' + 1.50d` is `a1.50`.
        """
        self.assertEqual(_measured("'a' + 1.50d"), ('System.String', 'a1.50'))
        self.assertEqual(_applied("'a' + 1.50d"), Ps1Outcome(NEVER, Ps1Constant(STRING, 'a1.50')))

    def test_a_right_operand_whose_text_only_a_session_settles_is_not_joined(self):
        """
        Measured, `'a' + @(1, 2)` is `a1 2`, and that text is not one this module can write: a
        collection is separated by `$OFS`, which only a run settles. So the join names no value rather
        than the sum an arithmetic reading would have made of it.
        """
        self.assertEqual(_measured("'a' + @(1, 2)"), ('System.String', 'a1 2'))
        self.assertEqual(_applied("'a' + @(1, 2)"), NOTHING)

    def test_a_numeral_left_operand_joins_a_double_as_text_and_not_as_a_sum(self):
        """
        Measured, `'5' + 5` is the String `55` and `'a' + 1.5` is `a1.5`: a numeral spelled inside the
        left operand is text like any other and never an addend, and a Double on the right is appended
        as its text. Composing the two, `'5' + 1.5` is the String `51.5`, where reading it as
        arithmetic would make the Double `6.5`, a value and a type no run of the script produces.
        """
        self.assertEqual(_measured("'5' + 5"), ('System.String', '55'))
        self.assertEqual(_measured("'a' + 1.5"), ('System.String', 'a1.5'))
        self.assertEqual(_applied("'5' + 1.5"), Ps1Outcome(NEVER, Ps1Constant(STRING, '51.5')))

    def test_a_right_operand_whose_text_is_written_here_is_joined_all_the_same(self):
        self.assertEqual(_applied("'5' + 5"), Ps1Outcome(NEVER, Ps1Constant(STRING, '55')))
        self.assertEqual(_applied('[char]65 + 1'), Ps1Outcome(NEVER, Ps1Constant(STRING, 'A1')))


class TestPs1AComparisonIsDecidedByItsLeftOperand(unittest.TestCase):
    """
    A comparison does not compare two values of one kind. The operand written on the *left* settles
    what kind of comparison happens and the other one is read into it, so the same two values in the
    other order are a different question with a different answer: measured, `'10' -lt 9` is True and
    `10 -lt '9'` is False, because the first orders the texts `10` and `9` and the second the
    numbers. An absent operand is settled ahead of all of it, by presence rather than by conversion.

    A comparison folds into a Boolean and a Boolean decides a branch, so a comparison answered the
    way 5.1 does not answer it is a script rewritten into a different script. Refusing to answer one
    is always allowed.
    """

    def test_every_measured_comparison_is_decided_refused_or_one_the_host_aborted_on(self):
        self.assertEqual(len(COMPARISON_ROWS), 84, 'a measured comparison was added or withdrawn')
        self.assertEqual(
            sorted(COMPARISON_ROWS),
            sorted(
                DECIDED_COMPARISON_ROWS
                + UNDECIDED_COMPARISONS
                + FILTERED_COMPARISONS
                + tuple(row for row in COMPARISON_ROWS if row in THROWN_OPERATIONS)
            ),
        )
        self.assertEqual(
            sorted(row for row in COMPARISON_ROWS if row in THROWN_OPERATIONS),
            ["1 -gt 'abc'", "1 -lt 'abc'"],
        )

    def test_a_comparison_this_decides_is_the_boolean_the_host_printed(self):
        self.assertEqual(
            {expression: _applied(expression) for expression in DECIDED_COMPARISON_ROWS},
            {
                expression: Ps1Outcome(NEVER, _measured_operation_fact(expression))
                for expression in DECIDED_COMPARISON_ROWS
            },
        )

    def test_a_comparison_this_does_not_decide_names_no_value_rather_than_a_guess(self):
        """
        A comparison this does not settle is answered with a bound on its value — the `System.Boolean`
        its cell names, or nothing where that cell may throw — and never with a value, because a type
        is a bound and only a value is folded.
        """
        self.assertEqual(
            {
                expression: _applied(expression).value
                for expression in UNDECIDED_COMPARISONS
                if _names_a_value(_applied(expression).value)
            },
            {},
        )

    def test_no_measured_comparison_is_counted_a_truth_the_host_did_not_print(self):
        """
        `is_truthy` is what an `if` over a comparison asks, and it composes two steps that each may
        refuse — so it is asked here as well as `apply`, over every measured comparison including
        the two a host aborted on.

        A comparison against a collection is left out: it produces the members that match and not a
        Boolean, so the host printed no truth for it to be held against. Its `if` reads the truth of
        that collection, which is what `is_truthy` over a collection is measured against elsewhere.
        """
        counted = {
            expression: is_truthy(_slot(expression))
            for expression in COMPARISON_ROWS
            if expression not in FILTERED_COMPARISONS and is_truthy(_slot(expression)) is not None
        }
        self.assertEqual(
            counted,
            {
                expression: _boolean(_measured_operation(expression)[1])
                for expression in counted
            },
        )
        self.assertEqual(sorted(counted), sorted(DECIDED_COMPARISON_ROWS))

    def test_the_same_two_values_compare_as_text_one_way_round_and_as_numbers_the_other(self):
        """
        Ordering the texts `10` and `9` puts `10` first where ordering the numbers puts `9` first,
        and the text `1.0` is not the text `1` where the number 1.0 is the number 1. So each pair
        below is one operator over one pair of values, and answers the opposite of its mirror.
        """
        self.assertEqual(
            {
                expression: _measured_operation(expression)[1] for expression in (
                    "'10' -lt 9",
                    "10 -lt '9'",
                    "'10' -ge 9",
                    "10 -ge '9'",
                    "'1.0' -eq 1",
                    "1 -eq '1.0'",
                )
            },
            {
                "'10' -lt 9"  : 'True',
                "10 -lt '9'"  : 'False',
                "'10' -ge 9"  : 'False',
                "10 -ge '9'"  : 'True',
                "'1.0' -eq 1" : 'False',
                "1 -eq '1.0'" : 'True',
            },
        )
        self.assertEqual(
            _applied("'1.0' -eq 1"), Ps1Outcome(NEVER, Ps1Constant(BOOLEAN, False)))
        self.assertEqual(
            _applied("1 -eq '1.0'"), Ps1Outcome(NEVER, Ps1Constant(BOOLEAN, True)))

    def test_a_boolean_on_the_left_asks_whether_the_right_operand_is_true_and_not_whether_it_is_one(
        self,
    ):
        self.assertEqual(
            {
                expression: _measured_operation(expression)[1] for expression in (
                    '$true -eq 2',
                    '2 -eq $true',
                    "$true -eq 'abc'",
                    "'abc' -eq $true",
                    "$true -eq ''",
                )
            },
            {
                '$true -eq 2'     : 'True',
                '2 -eq $true'     : 'False',
                "$true -eq 'abc'" : 'True',
                "'abc' -eq $true" : 'False',
                "$true -eq ''"    : 'False',
            },
        )
        self.assertEqual(
            _applied('$true -eq 2'), Ps1Outcome(NEVER, Ps1Constant(BOOLEAN, True)))
        self.assertEqual(
            _applied('2 -eq $true'), Ps1Outcome(NEVER, Ps1Constant(BOOLEAN, False)))

    def test_an_absent_operand_is_settled_by_presence_rather_than_converted_to_the_other_side(self):
        """
        A `$null` converted into the type standing opposite it would be a zero against a number, the
        empty text against a text and `$false` against a Boolean, and each of those three compares
        *equal* to what it was converted from. Measured, all three are greater than `$null` and none
        of them equals it, so the conversion never happens.
        """
        self.assertEqual(
            {
                expression: _measured_operation(expression)[1] for expression in (
                    '0 -gt $null',
                    "'' -gt $null",
                    '$false -gt $null',
                    '$false -eq $null',
                    '$null -lt 0',
                    "$null -lt ''",
                    '$null -eq $false',
                )
            },
            {
                '0 -gt $null'      : 'True',
                "'' -gt $null"     : 'True',
                '$false -gt $null' : 'True',
                '$false -eq $null' : 'False',
                '$null -lt 0'      : 'True',
                "$null -lt ''"     : 'True',
                '$null -eq $false' : 'False',
            },
        )
        self.assertEqual(
            _applied('$false -gt $null'), Ps1Outcome(NEVER, Ps1Constant(BOOLEAN, True)))
        self.assertEqual(
            _applied('$false -eq $null'), Ps1Outcome(NEVER, Ps1Constant(BOOLEAN, False)))

    def test_the_case_sensitive_spelling_of_a_comparison_is_a_different_question(self):
        self.assertEqual(
            {
                expression: _measured_operation(expression)[1] for expression in (
                    "'A' -ceq 'a'",
                    "'A' -ieq 'a'",
                )
            },
            {
                "'A' -ceq 'a'" : 'False',
                "'A' -ieq 'a'" : 'True',
            },
        )
        self.assertEqual(
            _applied("'A' -ceq 'a'"), Ps1Outcome(NEVER, Ps1Constant(BOOLEAN, False)))
        self.assertEqual(
            _applied("'A' -ieq 'a'"), Ps1Outcome(NEVER, Ps1Constant(BOOLEAN, True)))


class TestPs1TheDecimalTypeKeepsItsDigits(unittest.TestCase):
    """
    A `System.Decimal` is a 96 bit coefficient with a scale of at most 28, so it carries 29
    significant digits and keeps the trailing zeros it was written with. Python's `decimal` carries
    both and rounds the result of every *operation* to `decimal.getcontext().prec`, which is 28 by
    default and which anything else sharing the process may set to anything at all. So an answer
    that consults the context is one that changes with what some other library did, and 5.1 changes
    no digit of a value it was handed.

    Every expectation below is read out of the digits a host printed rather than out of a
    `decimal.Decimal` built here, because two of those compare equal while writing different text:
    `Decimal('3.00') == Decimal('3')`, and only one of them is what `1.50d + 1.50d` produces.
    """

    #: The negation a Decimal at the widest magnitude is measured under.
    NEGATION = '- 79228162514264337593543950335d'

    def _measured_digits(self) -> dict[str, str]:
        """
        The digits a host printed for every Decimal subject: the literals it read, the arithmetic it
        computed, the negation it took and the text it cast each of them to.
        """
        return {
            **{expression: _measured(expression)[1] for expression in WIDEST_DECIMAL_LITERALS},
            **{
                expression: _measured_operation(expression)[1]
                for expression in EXACT_DECIMAL_OPERATIONS
            },
            **{expression: _measured(expression)[1] for expression in DECIMAL_TEXTS},
            self.NEGATION: _measured_negation(self.NEGATION)[1],
        }

    def _answered_digits(self) -> dict[str, str | None]:
        return {
            **{expression: _digits(_read(expression)) for expression in WIDEST_DECIMAL_LITERALS},
            **{
                expression: _digits(_applied(expression).value)
                for expression in EXACT_DECIMAL_OPERATIONS
            },
            **{
                expression: _digits(_converted(expression).value)
                for expression in DECIMAL_TEXTS
            },
            self.NEGATION: _digits(_negated(self.NEGATION).value),
        }

    def test_a_decimal_literal_at_the_extremes_of_the_type_is_typed_a_decimal(self):
        self.assertEqual(
            {str(type_of(_read(expression))) for expression in WIDEST_DECIMAL_LITERALS},
            {'System.Decimal'},
        )

    def test_reading_negating_computing_and_writing_a_decimal_are_the_digits_the_host_printed(self):
        self.assertEqual(self._answered_digits(), self._measured_digits())

    def test_none_of_those_moves_with_the_precision_python_is_set_to(self):
        answered = {}
        for precision in DECIMAL_PRECISIONS:
            with decimal.localcontext() as context:
                context.prec = precision
                for expression, digits in self._answered_digits().items():
                    answered[precision, expression] = digits
        self.assertEqual(
            answered,
            {
                (precision, expression): digits
                for precision in DECIMAL_PRECISIONS
                for expression, digits in self._measured_digits().items()
            },
        )

    def test_dividing_two_decimals_does_not_move_with_it_either(self):
        """
        Refusing under a precision is allowed, which is why what is collected here is the digits
        that are not the host's rather than every answer.
        """
        wrong = {}
        for precision in DECIMAL_PRECISIONS:
            with decimal.localcontext() as context:
                context.prec = precision
                computed = {
                    expression: _digits(_applied(expression).value)
                    for expression in DECIMAL_DIVISIONS
                }
            for expression, digits in computed.items():
                if digits is not None and digits != _measured_operation(expression)[1]:
                    wrong[precision, expression] = digits
        self.assertEqual(wrong, {})


class TestPs1TheScaleOfADecimalIsPartOfTheValue(unittest.TestCase):
    """
    A `System.Decimal` carries the places it was written with, so one number written at two scales
    is two values: a host writes `1.0d` as `1.0` and `1.00d` as `1.00`, and the domain writes each
    back as the literal it was read from. A caller that puts a fact in a set or keys a dictionary by
    one — which is how `refinery.lib.scripts.ps1.deobfuscation.constants` decides whether
    re-assigning a variable changes what it holds — therefore has to see as many values here as the
    host writes texts.
    """

    def _measured_texts(self) -> dict[str, str]:
        """
        The text a host wrote each of those literals as, read off the cast to String that measures
        it.
        """
        return {spelling: _measured(F'[string]{spelling}')[1] for spelling in SCALED_DECIMALS}

    def test_a_host_writes_each_of_those_scales_as_its_own_text(self):
        self.assertEqual(self._measured_texts(), {
            '1.0d'   : '1.0',
            '1.00d'  : '1.00',
            '1.000d' : '1.000',
            '1.10d'  : '1.10',
            '1.100d' : '1.100',
        })

    @unittest.expectedFailure
    def test_each_of_those_scales_is_a_fact_of_its_own(self):
        """
        Ledgered rather than fixed: a fact carries its Decimal as a `decimal.Decimal`, and two of
        those compare equal and hash alike where they differ only in scale, so the five values
        collapse into the two numbers they are written from.
        """
        distinct = {_read(spelling) for spelling in SCALED_DECIMALS}
        self.assertEqual(sorted(_spelled(fact) for fact in distinct), sorted(SCALED_DECIMALS))


class TestPs1TheTextAValueWrites(unittest.TestCase):
    """
    Two questions with one answer: what `[string]` makes of a value, and what a `+` with a text on
    its left appends. Measured, `'a' + <value>` is `a` followed by exactly what `[string] <value>`
    writes, so a value whose text is got wrong is wrong at both.
    """

    def test_a_join_appends_exactly_the_text_a_cast_to_string_writes(self):
        self.assertEqual(
            {join: _measured_operation(join)[1] for join, _ in JOINED_AGAINST_ITS_TEXT},
            {join: F'a{_measured(cast)[1]}' for join, cast in JOINED_AGAINST_ITS_TEXT},
        )
        self.assertEqual(
            {join: _applied(join) for join, _ in JOINED_AGAINST_ITS_TEXT},
            {
                join: Ps1Outcome(NEVER, Ps1Constant(STRING, F'a{_measured(cast)[1]}'))
                for join, cast in JOINED_AGAINST_ITS_TEXT
            },
        )
        self.assertEqual(
            {cast: _converted(cast) for _, cast in JOINED_AGAINST_ITS_TEXT},
            {cast: Ps1Outcome(NEVER, _measured_fact(cast)) for _, cast in JOINED_AGAINST_ITS_TEXT},
        )

    def test_a_cast_to_string_writes_the_scale_a_decimal_was_written_with(self):
        """
        `1.50d` and `1.5d` are one number written two ways, and only the first writes `1.50`. A
        Decimal carried as its numeric value alone, or normalized on the way in, could write only
        one of the two.
        """
        self.assertEqual(
            {expression: _measured(expression) for expression in DECIMAL_TEXTS},
            {
                '[string]1.50d'  : ('System.String', '1.50'),
                '[string]0.5d'   : ('System.String', '0.5'),
                '[string]-1.50d' : ('System.String', '-1.50'),
                '[string]10d'    : ('System.String', '10'),
            },
        )
        self.assertEqual(
            {expression: _converted(expression) for expression in DECIMAL_TEXTS},
            {
                expression: Ps1Outcome(NEVER, _measured_fact(expression))
                for expression in DECIMAL_TEXTS
            },
        )

    def test_a_char_writes_its_one_character_and_a_boolean_the_name_of_its_truth(self):
        self.assertEqual(_measured_operation("'a' + [char]65"), ('System.String', 'aA'))
        self.assertEqual(_measured('[string]$true'), ('System.String', 'True'))
        self.assertEqual(_measured('[string]$false'), ('System.String', 'False'))
        self.assertEqual(
            _applied("'a' + [char]65"), Ps1Outcome(NEVER, Ps1Constant(STRING, 'aA')))
        self.assertEqual(
            _converted('[string]$true'), Ps1Outcome(NEVER, Ps1Constant(STRING, 'True')))
        self.assertEqual(
            _converted('[string]$false'), Ps1Outcome(NEVER, Ps1Constant(STRING, 'False')))


class TestPs1AnOperandShapeTheHostAbortsOnIsNeverGivenAValue(unittest.TestCase):
    """
    There are operand shapes 5.1 raises on rather than producing a value, and each of them is a
    place a script stops. A value answered for one of those is folded into the emitted script, and
    what comes out runs on where the original could not — so none of them may be answered, whatever
    the answer would have been.
    """

    def test_every_operation_the_host_aborted_on_names_no_value_and_reports_the_throw(self):
        outcomes = {expression: _evaluated(expression) for expression in THROWN_OPERATIONS}
        self.assertTrue(all(o.value is UNKNOWN and o.may_throw for o in outcomes.values()))

    def test_the_operations_the_domain_proves_throw_are_the_value_precise_ones(self):
        """
        A throw the host took is `ALWAYS` exactly where the domain reaches it value-precisely — a
        decimal overflow, a division by zero, and a String an integer coercion certainly rejects.
        The rest are proven throws the domain declines (an unread multiplier, an infinite double, a
        collection repeat, a Boolean product), so they stay `MAYBE`: kept as possible throws, never
        claimed as certain.
        """
        certain = sorted(
            expression for expression in THROWN_OPERATIONS
            if _evaluated(expression).certainly_throws
        )
        self.assertEqual(certain, sorted((
            "'1_0' -band 15",
            '16 + \'file\'',
            '1d / 0d',
            '79228162514264337593543950335d + 1d',
            '79228162514264337593543950335d - -1d',
        )))

    def test_no_condition_the_host_aborted_on_is_counted_true_or_false(self):
        self.assertEqual(
            {expression: is_truthy(_slot(expression)) for expression in THROWN_OPERATIONS},
            {expression: None for expression in THROWN_OPERATIONS},
        )

    def test_ordering_a_number_against_a_text_that_spells_none_aborts_where_equality_does_not(self):
        """
        The same two operands, one operator apart: equality answers False without reading `abc` as a
        number and ordering cannot, so `1 -eq 'abc'` is a value and `1 -lt 'abc'` is the end of the
        script. The domain refuses both, which is allowed; answering the ordering would not be.
        """
        compared = ("1 -lt 'abc'", "1 -gt 'abc'", "1 -eq 'abc'", "1 -ne 'abc'")
        self.assertEqual(
            {expression: _throws(_transcript(expression)) for expression in compared},
            {
                "1 -lt 'abc'" : True,
                "1 -gt 'abc'" : True,
                "1 -eq 'abc'" : False,
                "1 -ne 'abc'" : False,
            },
        )
        self.assertEqual(_measured_operation("1 -eq 'abc'"), ('System.Boolean', 'False'))
        self.assertEqual(
            {expression: _applied(expression) for expression in compared},
            {expression: NOTHING for expression in compared},
        )

    def test_a_decimal_that_leaves_its_range_or_is_divided_by_zero_aborts(self):
        """
        `79228162514264337593543950334d + 1d` lands exactly on the largest value the type holds and
        is a number; one more than that, and a subtraction that reaches the same place, are not.
        """
        computed = (
            '79228162514264337593543950334d + 1d',
            '79228162514264337593543950335d + 1d',
            '79228162514264337593543950335d - -1d',
            '1d / 0d',
        )
        self.assertEqual(
            {expression: _throws(_transcript(expression)) for expression in computed},
            {
                '79228162514264337593543950334d + 1d'  : False,
                '79228162514264337593543950335d + 1d'  : True,
                '79228162514264337593543950335d - -1d' : True,
                '1d / 0d'                              : True,
            },
        )
        self.assertEqual(
            {expression: _applied(expression) for expression in computed[1:]},
            {expression: Ps1Outcome(ALWAYS, UNKNOWN) for expression in computed[1:]},
        )
        self.assertEqual(
            str(_payload(_applied(computed[0]).value)), _measured_operation(computed[0])[1])


class TestPs1CellsTheWitnessesReach(unittest.TestCase):
    """
    A grid cell records what some values were observed to do, which is a lower bound. Reading one
    as what the operation *produces* is a claim about every value, and the operand types the
    shipped witnesses reach every outcome of are the ones that claim was measured to survive over.
    `test.lib.scripts.ps1.corpus.GRID_WITNESS_GAPS` carries the cell that convicts each of the
    others, so what an exclusion costs is a cell rather than a worry.
    """

    def test_the_operand_types_an_answered_cell_stands_on_are_the_ones_reached(self):
        answered = {
            (operator, left, right)
            for operator in GRID_OPERATORS
            for left in GRID_WITNESSES
            for right in GRID_WITNESSES
            if apply(operator, _grid_operand(left), _grid_operand(right)) != NOTHING
        }
        self.assertEqual(
            sorted({name for _, left, right in answered for name in (left, right)}),
            sorted(SPANNED_TYPES),
        )

    def test_the_cell_a_witness_gap_convicts_is_not_answered_from(self):
        """
        Each gap row is one cell measured twice: what the shipped grid records over its witnesses,
        and what the operand type really produces there. The first is what an answer would come
        from and the second is why it may not.
        """
        for name, row in GRID_WITNESS_GAPS.items():
            operator, left, right, recorded, produced = row
            with self.subTest(name):
                self.assertEqual(_recorded(_cell(operator, left, right)), recorded)
                self.assertNotEqual(recorded, produced)
                self.assertEqual(
                    apply(operator, _grid_operand(left), _grid_operand(right)), NOTHING)

    def test_the_type_ledger_contradicts_the_cell_a_string_operand_indexes(self):
        """
        What an addition does to a string is decided by which string, and the ledger holds one the
        capture never wrote out: measured, `1 + '2147483648'` is an Int64, which is a type the cell
        an Int32 and a String index does not carry at all.

        The domain answers it anyway, and that is the point. The type comes from promoting the two
        operands — the string coerced to the numeral it spells, which is an Int64 — and not from
        the cell, so an answer the measurement never wrote down is still the one the host gives.
        """
        self.assertEqual(_measured("1 + '2147483648'"), ('System.Int64', '2147483649'))
        self.assertEqual(
            sorted(str(one) for one in _cell('+', INT32, STRING).types),
            ['System.Double', 'System.Int32'],
        )
        self.assertEqual(
            _applied("1 + '2147483648'"),
            Ps1Outcome(NEVER, Ps1Constant(INT64, 2147483649)),
        )

    def test_a_cell_over_operands_the_witnesses_reach_is_still_the_answer(self):
        """
        Measured, `$null * 1` really is `$null` — a value the operation produced and not a sign
        that it produced none — and `$null` is the witness the grid's `System.Void` row was
        captured from.
        """
        self.assertEqual(_measured_operation_fact('$null * 1'), NULL)
        self.assertEqual(apply('*', NULL, Ps1Typed(INT32)), Ps1Outcome(NEVER, NULL))
        self.assertEqual(_cell('-band', INT32, INT32).single_type, INT32)
        self.assertEqual(
            apply('-band', Ps1Typed(INT32), Ps1Typed(INT32)), Ps1Outcome(NEVER, Ps1Typed(INT32)))


class TestPs1SpanRestsOnTheShippedGrid(unittest.TestCase):
    """
    Which cells may be read as a fact was measured against the resource this repository ships, by
    capturing the whole grid a second time over the extremes the shipped witness list is missing.
    No test can re-run that, so the witness list is a ratchet: a regenerated resource has to fail
    here rather than leave the measurement standing on a capture it was not made from.
    """

    def test_the_shipped_grid_carries_the_witnesses_the_span_was_measured_from(self):
        self.assertEqual(operand_witnesses(), GRID_WITNESSES)

    def test_every_operand_type_the_grid_was_captured_over_is_reached_or_convicted(self):
        self.assertEqual(sorted(set(GRID_WITNESS_GAPS) - set(GRID_WITNESSES)), [])
        self.assertEqual(sorted(GRID_COMPLETE_BUT_UNREAD - set(GRID_WITNESSES)), [])
        self.assertEqual(sorted(GRID_COMPLETE_BUT_UNREAD & set(GRID_WITNESS_GAPS)), [])
        self.assertEqual(
            sorted(SPANNED_TYPES | frozenset(GRID_WITNESS_GAPS) | GRID_COMPLETE_BUT_UNREAD),
            sorted(GRID_WITNESSES))

    def test_the_cell_a_gap_row_names_is_one_the_type_it_convicts_is_an_operand_of(self):
        for name, row in GRID_WITNESS_GAPS.items():
            operator, left, right, _, _ = row
            with self.subTest(name):
                self.assertIn(name, (left, right))
                self.assertIsNotNone(binary_outcome(operator, left, right))

    def test_every_operator_the_span_is_read_over_has_a_grid_of_its_own(self):
        covered = {
            operator: binary_outcome(operator, INT32, INT32) is not None
            for operator in GRID_OPERATORS
        }
        self.assertEqual(covered, {operator: True for operator in GRID_OPERATORS})


class TestPs1CastNamesItsTargetWhereAnOperatorNamesNothing(unittest.TestCase):
    """
    A cast differs from an operator in exactly one way here: what a cast produces is settled by the
    type that was written, where what an operator produces is settled by its operands' values as
    much as by their types. So over a source the witnesses fall short of, a cast still names the
    target and loses only what the witnesses were the evidence for, while an operator over the same
    operand is left with nothing to say at all.
    """

    def test_a_cast_from_a_source_the_witnesses_fall_short_of_still_names_its_target(self):
        answers = {
            (target, source): convert(_grid_operand(source), _type(target))
            for source in GRID_WITNESS_GAPS
            for target in GRID_WITNESSES
            if conversion_outcome(target, source) is not None
        }
        self.assertEqual(len(answers), 75, 'a conversion cell was added or withdrawn')
        self.assertEqual(
            {cell: answer for cell, answer in answers.items() if cell not in EVERY_WITNESS_THREW},
            {
                cell: Ps1Outcome(MAYBE, Ps1Typed(_type(cell[0])))
                for cell in answers
                if cell not in EVERY_WITNESS_THREW
            },
        )
        self.assertEqual(
            {cell: answers[cell] for cell in EVERY_WITNESS_THREW},
            {cell: Ps1Outcome(MAYBE, UNKNOWN) for cell in EVERY_WITNESS_THREW},
        )

    def test_such_a_cast_no_longer_claims_that_it_cannot_throw(self):
        """
        The cell for a `[string]` of a Char recorded no throw, which is a lower bound in the same
        way its type is: the three characters the capture wrote out are not every character. The
        type is what a cast produces or throws trying, so it stands where the silence does not.
        """
        self.assertEqual(_cast_cell(STRING, CHAR).may_throw, False)
        self.assertEqual(convert(Ps1Typed(CHAR), STRING), Ps1Outcome(MAYBE, Ps1Typed(STRING)))

    def test_an_operator_over_the_same_source_is_left_without_an_answer(self):
        """
        Measured, `[int]'1e3'` is Int32 1000 and `1 + '1e3'` is Double 1001, so the two read the
        same String by different rules and reach different types doing it, and both are answered
        here by the rule that belongs to them: the cast converts to the type it names, and the
        operator re-reads the string as the numeral it spells and promotes over that.
        """
        self.assertEqual(_measured("[int]'1e3'"), ('System.Int32', '1000'))
        self.assertEqual(_converted("[int]'1e3'"), Ps1Outcome(MAYBE, Ps1Typed(INT32)))
        self.assertEqual(_measured("1 + '1e3'"), ('System.Double', '1001'))
        self.assertEqual(_applied("1 + '1e3'"), Ps1Outcome(NEVER, Ps1Constant(DOUBLE, 1001.0)))


class TestPs1EvaluateComposesTheOneStepReaders(unittest.TestCase):
    """
    `read`, `convert` and `apply` each answer about one step, and `evaluate` is those put together
    over a whole expression: a literal is what the source pins, a cast is a conversion of what its
    operand comes to, an operator an application over both of its, an array its elements and a
    parenthesis its inner. What that buys a caller is measured rather than described — the rows
    whose operand is itself an expression are exactly the ones a single step has nothing to say
    about, and they are answered here with the value a 5.1 host printed.
    """

    def test_a_literal_evaluates_to_the_fact_the_host_printed_for_it(self):
        self.assertEqual(
            {expression: _evaluated(expression) for expression in DECIDED},
            {expression: Ps1Outcome(NEVER, MEASURED[expression]) for expression in DECIDED},
        )

    def test_a_measured_cast_is_answered_as_the_single_step_answers_it(self):
        composed = {
            expression: _evaluated(expression)
            for expression in CAST_ROWS
            if _read(CAST_ROWS[expression].operand) is not UNKNOWN
        }
        self.assertEqual(len(composed), 113)
        self.assertEqual(
            composed, {expression: _converted(expression) for expression in composed})

    def test_a_cast_of_a_cast_is_the_value_the_host_printed(self):
        self.assertEqual(
            {expression: _evaluated(expression) for expression in NESTED_CASTS},
            {
                expression: Ps1Outcome(NEVER, _measured_fact(expression))
                for expression in NESTED_CASTS
            },
        )
        self.assertEqual(
            {expression: _converted(expression) for expression in NESTED_CASTS},
            {expression: _evaluated(expression) for expression in NESTED_CASTS},
        )

    def test_a_measured_operation_is_answered_as_the_single_step_answers_it(self):
        composed = {
            expression: _evaluated(expression)
            for expression in OPERATION_ROWS
            if _applied(expression).value is not UNKNOWN
        }
        self.assertEqual(len(composed), 196)
        self.assertEqual(
            composed, {expression: _applied(expression) for expression in composed})

    def test_an_operation_over_an_operation_is_the_value_the_host_printed(self):
        self.assertEqual(_applied('10 - $null + 3'), NOTHING)
        self.assertEqual(
            _evaluated('10 - $null + 3'),
            Ps1Outcome(NEVER, _measured_operation_fact('10 - $null + 3')),
        )

    def test_a_parenthesis_is_worth_what_it_encloses(self):
        self.assertEqual(_read('([int]1.5)'), UNKNOWN)
        self.assertEqual(
            _evaluated('([int]1.5)'), Ps1Outcome(NEVER, _measured_fact('[int]1.5')))
        self.assertEqual(_evaluated('(([int]1.5))'), _evaluated('([int]1.5)'))

    def test_an_array_holds_what_each_of_its_elements_comes_to(self):
        self.assertEqual(_read('[int]1.5, 007'), UNKNOWN)
        self.assertEqual(
            _evaluated('[int]1.5, 007'),
            Ps1Outcome(
                NEVER,
                Ps1Constant(OBJECT_ARRAY, (_measured_fact('[int]1.5'), MEASURED['007'])),
            ),
        )

    def test_the_typing_a_caller_supplies_reaches_every_operand_recursed_into(self):
        """
        5.1 prints an Int32 for `'AB'.Length`, and the grid records one for an Int32 `-band` an
        Int32. Nothing in these sources types `$s`, so the typing the caller passed in is the only
        way any of them is answered at all: through a parenthesis and through either side of an
        operator, since a step that dropped it would answer for one operand and not for the next.

        An array is where it reaches and nothing is named all the same, which is not a gap in the
        threading: a typing yields a bound on a value and never a value, and an array is a value
        only where every element is one.
        """
        self.assertEqual(_measured("'AB'.Length"), ('System.Int32', '2'))
        self.assertEqual(_cell('-band', INT32, INT32).single_type, INT32)
        reached = (
            '$s.Length',
            '(($s.Length))',
            '$s.Length -band $s.Length',
        )
        self.assertEqual(
            {expression: _evaluated(expression) for expression in reached},
            {expression: NOTHING for expression in reached},
        )
        self.assertEqual(
            {
                expression: evaluate(_slot(expression), lambda var: STRING)
                for expression in reached
            },
            {expression: Ps1Outcome(MAYBE, Ps1Typed(INT32)) for expression in reached},
        )
        self.assertEqual(evaluate(_slot('$s.Length, 1'), lambda var: STRING), NOTHING)


class TestPs1EvaluateComposesACastOfAStringWithAJoin(unittest.TestCase):
    """
    None of these expressions is a measured row: each writes two measured steps against each other,
    and what it comes to follows from what a host printed for either. `[int]'0x10'` is Int32 16 and
    `'5' + 5` is the String `55`, so `'v' + [int]'0x10'` is `v16` and nothing else — while a step
    the host threw on and a step whose spelling is declined each leave the whole expression with no
    value, one of them with a throw the domain saw for itself.
    """

    def test_a_join_over_a_cast_of_a_string_is_the_text_the_two_steps_come_to(self):
        self.assertEqual(_measured("[int]'0x10'"), ('System.Int32', '16'))
        self.assertEqual(_measured("'5' + 5"), ('System.String', '55'))
        self.assertEqual(
            _evaluated("'v' + [int]'0x10'"), Ps1Outcome(NEVER, Ps1Constant(STRING, 'v16')))

    def test_a_cast_over_a_join_reads_the_text_the_join_produced(self):
        self.assertEqual(_measured("[int]'5'"), ('System.Int32', '5'))
        self.assertEqual(_evaluated("[int]('1' + '0')"), Ps1Outcome(NEVER, Ps1Constant(INT32, 10)))

    def test_a_step_the_host_threw_on_leaves_the_join_with_a_throw_and_no_value(self):
        # The cast throws when 5.1 evaluates it, before the eager `+`, so the whole join is a
        # certain throw — where the declined-spelling twin below only *may* throw.
        self.assertEqual(_throws(_transcript("[char]'AB'")), True)
        self.assertEqual(_evaluated("'x' + [char]'AB'"), Ps1Outcome(ALWAYS, UNKNOWN))

    def test_a_step_whose_spelling_is_declined_leaves_the_join_with_no_value(self):
        self.assertEqual(_measured("[int]'1e3'"), ('System.Int32', '1000'))
        self.assertEqual(_evaluated("'x' + [int]'1e3'"), Ps1Outcome(MAYBE, UNKNOWN))


class TestPs1EvaluateAgreesOrRefuses(unittest.TestCase):
    """
    The contract, quantified over the PowerShell the corpus holds rather than over cases chosen
    here: for an expression another reader in this code base answers, `evaluate` answers the same
    thing or names nothing at all. Refusing is always allowed; a third answer never is, because two
    readers of one script that disagree make the pass consulting both unsound whichever is right.

    Each question below counts the expressions it compared, so that a reader which stopped
    answering fails here instead of leaving its agreement to hold over nothing.
    """

    def test_an_expression_the_source_pins_evaluates_to_exactly_what_it_pins(self):
        compared = [site for site in SITES if read(site.node) is not UNKNOWN]
        self.assertEqual(len(compared), 2917)
        self.assertEqual(
            [
                site.source for site in compared
                if evaluate(site.node) != Ps1Outcome(NEVER, read(site.node))
            ],
            [],
        )

    def test_no_expression_carries_one_type_here_and_another_in_the_single_type_reader(self):
        compared = [
            site for site in SITES
            if resolve_expression_type(site.node) is not None
            and type_of(evaluate(site.node).value) is not None
        ]
        self.assertEqual(len(compared), 2957)
        self.assertEqual(
            [
                site.source for site in compared
                if resolve_expression_type(site.node) != type_of(evaluate(site.node).value)
            ],
            sorted(READER_DISAGREEMENTS),
        )

    def test_a_type_named_here_is_one_the_candidate_set_holds(self):
        compared = [
            site for site in SITES
            if candidate_types(site.node, CLOSED_WORLD)
            and type_of(evaluate(site.node).value) is not None
        ]
        self.assertEqual(len(compared), 2957)
        self.assertEqual(
            [
                site.source for site in compared
                if type_of(evaluate(site.node).value)
                not in candidate_types(site.node, CLOSED_WORLD)
            ],
            sorted(READER_DISAGREEMENTS),
        )

    def test_a_string_the_tree_reader_spells_is_the_string_named_here(self):
        self.assertEqual(len(STRINGS), 1698)
        self.assertEqual(
            [row.source for row in STRINGS if row.named != Ps1Constant(STRING, row.text)], [])

    def test_the_bytes_the_array_reader_collects_are_the_numbers_the_elements_name(self):
        self.assertEqual(len(BYTE_ARRAYS), 116)
        self.assertEqual(
            [row.source for row in BYTE_ARRAYS if list(row.collected) != row.payloads], [])

    def test_a_literal_node_and_the_domain_read_one_spelling_as_one_number(self):
        """
        The two come apart only where 5.1 does: the node reads the digits it was written with, and
        the host printed something else for exactly three of the corpus spellings.
        """
        self.assertEqual(len(NUMERALS), 524)
        self.assertEqual(
            sorted({one.raw for one in NUMERALS if one.named.payload != one.reported}),
            sorted(MISREAD_SPELLINGS),
        )
        self.assertEqual(
            [_numeral_node(expression).value for expression in MISREAD_SPELLINGS],
            [0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 10 ** 32],
        )
        self.assertEqual(
            {expression: _evaluated(expression) for expression in MISREAD_SPELLINGS},
            {
                expression: Ps1Outcome(NEVER, MEASURED[expression])
                for expression in MISREAD_SPELLINGS
            },
        )

    def test_a_node_that_is_not_an_expression_names_nothing(self):
        statement = Ps1Parser('if ($a) { 1 }').parse().body[0]
        self.assertEqual(evaluate(statement), NOTHING)
        self.assertEqual(evaluate(None), NOTHING)


class TestPs1EvaluateIsNoStrongerThanItsSteps(unittest.TestCase):
    """
    A composition may refuse where its parts answer, and may not answer where they refuse. So for
    every cast and every operator the corpus writes, the fact the whole expression is answered with
    is the fact the one-step reader named over what its operands came to.

    The one exception is a step that cannot be asked at all: `convert` and `apply` both read a grid
    indexed by the operand's type, and an operand that names no type indexes no row in it. There a
    cast still names its target, which is a bound on a value and never one.
    """

    def test_a_step_that_can_be_consulted_is_the_whole_answer(self):
        consulted = [step for step in STEPS if step.consultable]
        self.assertEqual(len(consulted), 555)
        self.assertEqual(
            [step.source for step in consulted if step.answered.value != step.step.value], [])

    def test_only_a_cast_names_anything_where_its_step_cannot_be_consulted(self):
        unconsulted = [step for step in STEPS if not step.consultable]
        self.assertEqual(len(unconsulted), 34)
        self.assertEqual(
            [step.source for step in unconsulted if _names_a_value(step.answered.value)], [])
        self.assertEqual(
            sorted({
                step.kind for step in unconsulted if step.answered.value is not UNKNOWN
            }),
            ['cast'],
        )

    def test_an_array_names_a_value_only_where_every_element_is_one(self):
        """
        A `Ps1Constant` says the value is exactly this, so a collection that named one while holding
        an element that names only a type would be claiming what it does not have. There is nothing
        weaker to fall back on either: an array shorter than the script builds is a different value.
        """
        named = [row for row in ARRAYS if row.named]
        self.assertEqual(len(named), 158)
        self.assertEqual([row.source for row in named if not row.elements_named], [])

    def test_an_element_that_names_only_a_type_leaves_the_array_unknown(self):
        # The element is a certain throw the domain proves, but the array collapses to *nothing*
        # rather than carrying that up: an element naming only a type is not a value, so the array
        # is unknown and its own certainty is not established here (a sound miss, not a wrong claim).
        self.assertEqual(_evaluated("[int]'abc'"), Ps1Outcome(ALWAYS, Ps1Typed(INT32)))
        self.assertEqual(_evaluated("([int]'abc'), 1"), NOTHING)
        self.assertEqual(
            _evaluated('$null, 1'),
            Ps1Outcome(NEVER, Ps1Constant(OBJECT_ARRAY, (NULL, Ps1Constant(INT32, 1)))),
        )


class TestPs1EvaluateCarriesAThrowUp(unittest.TestCase):
    """
    An operand that may throw makes the expression consuming it one that may throw, whatever the
    operation does with the value: the expression is what a script runs, and producing the operand
    is part of running it. So does an operand nothing is known about, because `Ps1Outcome` reads its
    two fields in one direction and not knowing is not a claim of safety.
    """

    def test_no_expression_is_cleared_of_a_throw_one_it_consumes_may_take(self):
        compared = [
            (site, child)
            for site in SITES
            for child in site.node.children()
            if isinstance(child, Expression) and evaluate(child).may_throw
        ]
        self.assertEqual(len(compared), 2336)
        self.assertEqual(
            [site.source for site, _ in compared if not evaluate(site.node).may_throw], [])

    def test_an_operand_the_host_threw_on_makes_the_operation_one_that_may_throw(self):
        """
        5.1 throws for `[int]'abc'`, and neither operation below can throw over the fact that cast
        leaves behind: the grid records one type and no throw for an Int32 `-band` an Int32 and for
        a `[string]` of an Int32. So the throw is the operand's, carried up — the operand certainly
        throws, both operators evaluate it eagerly, and each expression is therefore a certain throw
        that keeps the result type the surviving step would have named.
        """
        self.assertEqual(_throws(_transcript("[int]'abc'")), True)
        thrown = _evaluated("[int]'abc'")
        self.assertEqual(thrown, Ps1Outcome(ALWAYS, Ps1Typed(INT32)))
        self.assertEqual(
            apply('-band', thrown.value, Ps1Constant(INT32, 1)), Ps1Outcome(NEVER, Ps1Typed(INT32)))
        self.assertEqual(_evaluated("[int]'abc' -band 1"), Ps1Outcome(ALWAYS, Ps1Typed(INT32)))
        self.assertEqual(convert(thrown.value, STRING), Ps1Outcome(NEVER, Ps1Typed(STRING)))
        self.assertEqual(_evaluated("[string]([int]'abc')"), Ps1Outcome(ALWAYS, Ps1Typed(STRING)))

    def test_an_operand_nothing_is_known_about_leaves_the_expression_able_to_throw(self):
        for expression in ('$x -band 1', '1 -band $x', '[int]$x', '$x, 1', '($x)'):
            with self.subTest(expression):
                self.assertEqual(_evaluated(expression).may_throw, True)

    def test_an_answer_that_names_no_value_never_claims_it_cannot_throw(self):
        self.assertEqual(
            [site.source for site in SITES if evaluate(site.node) == Ps1Outcome(NEVER, UNKNOWN)],
            [],
        )


class TestPs1EvaluateNamesACastsTarget(unittest.TestCase):
    """
    A cast names its target whatever it is handed, because naming one is what a cast is: `[int] $x`
    is an Int32 or it throws. The one target that does not is read off the grid rather than assumed
    — `[array]` is the only column the capture recorded a value passing through as `$null`, so it is
    the only one that names no type.
    """

    def test_the_grid_holds_a_column_over_every_source_for_every_target_named_here(self):
        self.assertEqual(
            {
                target: [
                    source for source in GRID_WITNESSES
                    if conversion_outcome(target, source) is None
                ]
                for target in CONVERSION_TARGETS
            },
            {target: [] for target in CONVERSION_TARGETS},
        )
        self.assertEqual(
            sorted({row.target for row in CAST_ROWS.values()} - set(CONVERSION_TARGETS)), [])

    def test_the_one_target_a_value_passes_through_names_no_type(self):
        passing = [
            target for target in CONVERSION_TARGETS
            if any(_cast_cell(target, source).may_be_null for source in GRID_WITNESSES)
        ]
        self.assertEqual(passing, ['array'])
        self.assertEqual(_evaluated('[array]$x'), NOTHING)
        self.assertEqual(_evaluated('[array]$null'), Ps1Outcome(NEVER, NULL))

    def test_every_other_target_is_named_over_a_value_nothing_is_known_about(self):
        named = {
            target: _evaluated(F'[{target}]$x')
            for target in CONVERSION_TARGETS
            if target != 'array'
        }
        self.assertEqual(
            named,
            {target: Ps1Outcome(MAYBE, Ps1Typed(_type(target))) for target in named},
        )

    def test_a_target_the_grid_never_measured_names_nothing(self):
        self.assertIsNone(conversion_outcome('datetime', 'System.Int32'))
        self.assertEqual(_evaluated('[datetime]$x'), NOTHING)

    def test_a_cast_the_host_threw_on_keeps_what_convert_made_of_the_value_in_hand(self):
        """
        The operand of each of these is pinned by the source, so the grid has a row for it and the
        conversion is settled there rather than by the target: the ones the domain sees the throw of
        name no value at all, which is more than *a Byte or a throw* would have said, and the ones
        whose spelling it declines keep the type their cell names beside the throw. Naming the
        target is for the other case, where the operand names no type and there is no row to read.
        """
        self.assertEqual(
            {expression: _evaluated(expression) for expression in THROWN},
            {
                '[byte]300'       : Ps1Outcome(ALWAYS, UNKNOWN),
                '[byte]-1'        : Ps1Outcome(ALWAYS, UNKNOWN),
                '[byte]400'       : Ps1Outcome(ALWAYS, UNKNOWN),
                '[byte](200 * 2)' : Ps1Outcome(ALWAYS, UNKNOWN),
                '[int]2147483648' : Ps1Outcome(ALWAYS, UNKNOWN),
                '[char]65536'     : Ps1Outcome(ALWAYS, UNKNOWN),
                '[char]-1'        : Ps1Outcome(ALWAYS, UNKNOWN),
                "[byte]'-1'"      : Ps1Outcome(ALWAYS, UNKNOWN),
                "[byte]'0x100'"   : Ps1Outcome(ALWAYS, UNKNOWN),
                "[char]'AB'"      : Ps1Outcome(ALWAYS, UNKNOWN),
                "[char]''"        : Ps1Outcome(ALWAYS, UNKNOWN),
                "[int]'abc'"      : Ps1Outcome(ALWAYS, Ps1Typed(INT32)),
                "[int]'   '"      : Ps1Outcome(MAYBE, Ps1Typed(INT32)),
                "[int]'1_0'"      : Ps1Outcome(ALWAYS, Ps1Typed(INT32)),
                "[int]'0b1010'"   : Ps1Outcome(ALWAYS, Ps1Typed(INT32)),
                "[int]'0o17'"     : Ps1Outcome(ALWAYS, Ps1Typed(INT32)),
                "[int]'1kb'"      : Ps1Outcome(ALWAYS, Ps1Typed(INT32)),
                "[byte]'1e3'"     : Ps1Outcome(MAYBE, Ps1Typed(BYTE)),
            },
        )
        # `evaluate` and `convert` over the read operand agree on every row but one: the operand of
        # `[byte](200 * 2)` is an operator `read` does not fold, so `convert` is handed an unknown
        # and only *may* throw, where `evaluate` folds the 400 and proves the throw.
        folds_only_under_evaluate = '[byte](200 * 2)'
        self.assertEqual(
            {e: _evaluated(e) for e in THROWN if e != folds_only_under_evaluate},
            {e: _converted(e) for e in THROWN if e != folds_only_under_evaluate},
        )
        self.assertEqual(_evaluated(folds_only_under_evaluate), Ps1Outcome(ALWAYS, UNKNOWN))
        self.assertEqual(_converted(folds_only_under_evaluate), Ps1Outcome(MAYBE, UNKNOWN))
        self.assertEqual(_evaluated('[byte]$x'), Ps1Outcome(MAYBE, Ps1Typed(BYTE)))


class TestPs1EvaluateRefusesATypeLiteral(unittest.TestCase):
    """
    `[int]` written as a value is not an Int32. `resolve_expression_type` answers `System.Int32` for
    it because what asks that function is a member lookup, and the type a literal *names* is what a
    lookup needs; the value one *is* is a `System.RuntimeType`, which no measurement here covers.
    This is the one place `evaluate` deliberately says less than the other reader.
    """

    def test_every_type_literal_the_corpus_writes_is_refused_here_and_typed_there(self):
        literals = [site for site in SITES if isinstance(site.node, Ps1TypeExpression)]
        self.assertEqual(len(literals), 33)
        self.assertEqual([site.source for site in literals if evaluate(site.node) != NOTHING], [])
        self.assertEqual(
            [site.source for site in literals if resolve_expression_type(site.node) is None], [])

    def test_a_type_literal_is_not_a_value_of_the_type_it_names(self):
        for source, name in (
            ('[int]', 'System.Int32'),
            ('[string]', 'System.String'),
            ('[byte]', 'System.Byte'),
        ):
            with self.subTest(source):
                self.assertEqual(_evaluated(source), NOTHING)
                self.assertEqual(resolve_expression_type(_slot(source)), _type(name))

    def test_an_operator_that_consumes_a_type_literal_is_refused_with_it(self):
        """
        `-as` takes one as its right operand, and a conversion that cannot be made yields `$null`
        there where a cast throws: measured, `300 -as [byte]` is `$null` and `[byte]300` throws. A
        Byte answered here would be the cast's answer given to a different expression.
        """
        self.assertEqual(_measured('300 -as [byte]'), ('', '<null>'))
        self.assertEqual(
            {expression: _evaluated(expression) for expression in AS_ROWS},
            {expression: NOTHING for expression in AS_ROWS},
        )


class TestPs1NumeralTypesAreReadFromTheSpelling(unittest.TestCase):
    """
    How wide a numeral is written decides its type and only the spelling knows: `1L` is an Int64,
    `2147483648` an Int64, `9223372036854775808` a Decimal and `1e3` a Double, every one of them
    measured. `resolve_expression_type` is what a member read on such a literal resolves against, so
    a numeral answered `System.Int32` there resolved the read against a type the value never had.
    """

    def test_a_measured_numeral_is_typed_by_the_type_the_host_stamped_it_with(self):
        self.assertEqual(
            {expression: resolve_expression_type(_slot(expression)) for expression in DECIDED},
            {expression: type_of(MEASURED[expression]) for expression in DECIDED},
        )

    def test_a_numeral_no_int32_holds_is_not_typed_as_one(self):
        wider = (
            '1L',
            '2147483648',
            '9223372036854775808',
            '1e3',
            '100000000000000000000000000000000',
        )
        self.assertEqual(
            sorted({_measured(expression)[0] for expression in wider}),
            ['System.Decimal', 'System.Double', 'System.Int64'],
        )
        self.assertEqual(
            {
                expression: str(resolve_expression_type(_slot(expression)))
                for expression in wider
            },
            {expression: _measured(expression)[0] for expression in wider},
        )

    def test_a_spelling_the_domain_will_not_read_is_typed_by_nobody(self):
        for expression in REFUSED + UNANSWERED:
            with self.subTest(expression):
                self.assertIsNone(resolve_expression_type(_slot(expression)))


class TestPs1OperatorCaseDoesNotChangeTheAnswer(unittest.TestCase):
    """
    PowerShell's operators are case-insensitive, and a caller holds whatever case the script wrote.
    The fact a measured row is answered with is the host's, so it has to be the answer for either
    spelling of the same operator: a fold lost to a capital letter is a fold lost.
    """

    def test_a_measured_operation_is_answered_the_same_in_either_case(self):
        lettered = [
            expression for expression in OPERATION_ROWS
            if any(character.isalpha() for character in _operator_of(expression))
        ]
        self.assertEqual(len(lettered), 158)
        self.assertEqual(
            {expression: _cased(expression, str.upper) for expression in lettered},
            {expression: _cased(expression, str.lower) for expression in lettered},
        )

    def test_a_pinned_operation_is_pinned_however_its_operator_is_cased(self):
        pinned = [
            expression for expression in PINNED_OPERATIONS
            if any(character.isalpha() for character in _operator_of(expression))
        ]
        self.assertEqual(
            {expression: _cased(expression, str.upper) for expression in pinned},
            {
                expression: Ps1Outcome(NEVER, _measured_operation_fact(expression))
                for expression in pinned
            },
        )

    def test_the_grid_answers_alike_however_an_operator_is_cased(self):
        for operator in GRID_OPERATORS:
            if not any(character.isalpha() for character in operator):
                continue
            for left in OPERANDS:
                for right in OPERANDS:
                    with self.subTest(F'{left!r} {operator} {right!r}'):
                        self.assertEqual(
                            apply(operator.upper(), left, right), apply(operator, left, right))


if __name__ == '__main__':
    unittest.main()
