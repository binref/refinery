from __future__ import annotations

import dataclasses
import decimal
import inspect
import math
import re
import unittest

from typing import Any, Callable, NamedTuple

from test import backlog, opportunity
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
ARRAY = _type('System.Array')


def _boolean(rendered: str) -> bool:
    return {'True': True, 'False': False}[rendered]


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
    row = F'$t = {expression}; Write-Output (,$t); Write-Output {witness}'
    return TYPE_TRANSCRIPTS[row]


def _printed(line: str) -> tuple[str, str]:
    kind, carried, rendered = line.split('\t')
    assert kind == 'OUT', line
    return carried, rendered


def _throws(transcript: tuple[str, ...]) -> bool:
    return not transcript[0].startswith('OUT\t')


def _measured(expression: str) -> tuple[str, str]:
    wrapped, printed = _transcript(expression)
    stamp, reported = _printed(wrapped)
    carried, rendered = _printed(printed)
    assert (stamp, reported) == (carried, rendered), (wrapped, printed)
    return carried, rendered


def _measured_fact(expression: str) -> Ps1Fact:
    name, rendered = _measured(expression)
    return Ps1Constant(_type(name), _PAYLOADS[name](rendered))


def _measured_count(expression: str) -> tuple[str, int]:
    wrapped, counted = _transcript(expression, '$t.Count')
    container, _ = _printed(wrapped)
    counter, rendered = _printed(counted)
    assert counter == 'System.Int32', counted
    return container, int(rendered)


def _measured_shape(expression: str) -> tuple[Ps1TypeName, int]:
    container, count = _measured_count(expression)
    return _type(container), count


def _measured_rendering(expression: str) -> tuple[str, str]:
    wrapped, _ = _transcript(expression, '$t.Count')
    return _printed(wrapped)


def _measured_elements(expression: str) -> tuple[Ps1Fact, ...]:
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

MEASURED: dict[str, Ps1Fact] = {
    expression: _measured_fact(expression)
    for expression, transcript in _NUMERAL_ROWS.items()
    if not _throws(transcript)
}

REFUSED: tuple[str, ...] = tuple(
    expression for expression, transcript in _NUMERAL_ROWS.items() if _throws(transcript)
)

UNANSWERED: tuple[str, ...] = (
    '-(2147483648)',
    '-(2147483647)',
)

ROUNDED: tuple[str, ...] = (
    '0.50000000000000000000000000001d',
    '9.9999999999999999999999999999d',
)

DECIDED: tuple[str, ...] = tuple(
    expression
    for expression in MEASURED
    if expression not in UNANSWERED and expression not in ROUNDED
)


def _slot(expression: str) -> Expression:
    statement = Ps1Parser(F'$t = {expression}').parse().body[0]
    assert isinstance(statement, Ps1ExpressionStatement)
    assignment = statement.expression
    assert isinstance(assignment, Ps1AssignmentExpression)
    value = assignment.value
    assert isinstance(value, Expression), expression
    return value


def _read(expression: str) -> Ps1Fact:
    return read(_slot(expression))


def _evaluated(expression: str) -> Ps1Outcome:
    return evaluate(_slot(expression))


def _elements(fact: Ps1Fact) -> tuple[Ps1Fact, ...]:
    assert isinstance(fact, Ps1Constant), fact
    payload = fact.payload
    assert isinstance(payload, tuple), payload
    return payload


def _payload(fact: Ps1Fact) -> object:
    assert isinstance(fact, Ps1Constant), fact
    return fact.payload


def _read_shape(expression: str) -> tuple[Ps1TypeName | None, int]:
    fact = _read(expression)
    return type_of(fact), len(_elements(fact))


def _spelled(fact: Ps1Fact) -> str:
    node = render(fact)
    assert node is not None, fact
    return Ps1Synthesizer().convert(node)


_CAST = re.compile(r'\[(?P<target>[A-Za-z0-9_]+)\](?P<operand>[^:].*)')

_AS = re.compile(r'(?P<operand>.+) -as \[(?P<target>[A-Za-z0-9_]+)\]')


class _Cast(NamedTuple):
    target: str
    operand: str


def _converts(expression: str, operator: str | None) -> bool:
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

THROWN: tuple[str, ...] = tuple(
    expression for expression in CAST_ROWS if _throws(_transcript(expression))
)

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

UNREAD_OPERANDS: tuple[str, ...] = (
    '[bool](0.0 / 0.0)',
)

NESTED_CASTS: tuple[str, ...] = (
    '[int][char]65',
    '[int][char]48',
)

COLLECTION_SHAPES: tuple[str, ...] = (
    '@()',
    ', 1',
    ',(1, 2)',
    '(1, 2), 3',
    '@(@(1, 2))',
    '@((1, 2))',
    '@(@(1, 2), 3)',
)

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
    row = CAST_ROWS[expression]
    return convert(_read(row.operand), _type(row.target))


_OPERATION_ROW = re.compile(
    r'\$t = (?P<expression>.+?); Write-Output \(,\$t\)(?:; Write-Output \$t)?'
)


def _application(expression: str) -> Ps1BinaryExpression | None:
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


OPERATION_ROWS: dict[str, tuple[str, ...]] = _operation_rows()

THROWN_OPERATIONS: tuple[str, ...] = tuple(
    expression for expression, transcript in OPERATION_ROWS.items() if _throws(transcript)
)


def _measured_operation(expression: str) -> tuple[str, str]:
    return _printed(OPERATION_ROWS[expression][0])


def _witnessed_fact(measured: tuple[str, str]) -> Ps1Fact:
    name, rendered = measured
    if (name, rendered) == ('', '<null>'):
        return NULL
    return Ps1Constant(_type(name), _PAYLOADS[name](rendered))


def _measured_operation_fact(expression: str) -> Ps1Fact:
    return _witnessed_fact(_measured_operation(expression))


def _applied(expression: str) -> Ps1Outcome:
    applied = _application(expression)
    assert applied is not None, expression
    return apply(
        applied.operator.lower(), read_operand(applied.left), read_operand(applied.right))


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
    '1d / 0.1d',
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

COMPARISON_OPERATORS: frozenset[str] = frozenset(
    F'-{case}{name}'
    for name in ('eq', 'ne', 'lt', 'le', 'gt', 'ge')
    for case in ('', 'c', 'i')
)


def _is_comparison(expression: str) -> bool:
    applied = _application(expression)
    return applied is not None and applied.operator.lower() in COMPARISON_OPERATORS


COMPARISON_ROWS: tuple[str, ...] = tuple(
    expression for expression in OPERATION_ROWS if _is_comparison(expression)
)

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

FILTERED_COMPARISONS: tuple[str, ...] = (
    '10, 20, 30 -eq 20',
    '10, 20, 30, 20, 10 -ne 20',
    '@(1, 2) -eq $null',
)

WIDEST_DECIMAL_LITERALS: tuple[str, ...] = (
    '79228162514264337593543950335d',
    '-79228162514264337593543950335d',
    '7922816251426433759354395033.5d',
    '1.2345678901234567890123456789d',
)

EXACT_DECIMAL_OPERATIONS: tuple[str, ...] = (
    '10d + 0',
    '100000000000000d * 100000000000000d',
    '1.2345678901234567890123456789d + 0d',
    '1.50d + 1.50d',
    '79228162514264337593543950334d + 1d',
    '79228162514264337593543950335d - 1d',
    '79228162514264337593543950335d * 1d',
)

DECIMAL_DIVISIONS: tuple[str, ...] = (
    '1d / 3d',
    '1d / 0.1d',
    '79228162514264337593543950335d / 1d',
)

DECIMAL_TEXTS: tuple[str, ...] = (
    '[string]1.50d',
    '[string]0.5d',
    '[string]-1.50d',
    '[string]10d',
)

SCALED_DECIMALS: tuple[str, ...] = (
    '1.0d',
    '1.00d',
    '1.000d',
    '1.10d',
    '1.100d',
)

DECIMAL_PRECISIONS: tuple[int, ...] = (1, 5, 28, 60)


def _digits(fact: Ps1Fact) -> str | None:
    return str(_payload(fact)) if isinstance(fact, Ps1Constant) else None


def _complement(expression: str) -> Ps1UnaryExpression | None:
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


COMPLEMENT_ROWS: dict[str, tuple[str, ...]] = _complement_rows()

THROWN_COMPLEMENTS: tuple[str, ...] = tuple(
    expression for expression, transcript in COMPLEMENT_ROWS.items() if _throws(transcript)
)


def _complemented(expression: str) -> Ps1Outcome:
    applied = _complement(expression)
    assert applied is not None, expression
    return apply_unary(applied.operator, read(applied.operand))


def _complement_operand(expression: str) -> Expression | None:
    applied = _complement(expression)
    assert applied is not None, expression
    return applied.operand


def _measured_complement(expression: str) -> tuple[str, str]:
    return _printed(COMPLEMENT_ROWS[expression][0])


def _measured_complement_fact(expression: str) -> Ps1Fact:
    return _witnessed_fact(_measured_complement(expression))


def _negation(expression: str) -> Ps1UnaryExpression | None:
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


NEGATION_ROWS: dict[str, tuple[str, ...]] = _negation_rows()

THROWN_NEGATIONS: tuple[str, ...] = tuple(
    expression for expression, transcript in NEGATION_ROWS.items() if _throws(transcript)
)

ABBREVIATED_NEGATIONS: tuple[str, ...] = ('- [uint64]18446744073709551615',)


def _negated(expression: str) -> Ps1Outcome:
    applied = _negation(expression)
    assert applied is not None, expression
    return apply_unary(applied.operator, read_operand(applied.operand))


def _negated_as_subtraction(expression: str) -> Ps1Outcome:
    applied = _negation(expression)
    assert applied is not None, expression
    return apply('-', Ps1Constant(INT32, 0), read_operand(applied.operand))


def _measured_negation(expression: str) -> tuple[str, str]:
    return _printed(NEGATION_ROWS[expression][0])


def _measured_negation_fact(expression: str) -> Ps1Fact:
    return _witnessed_fact(_measured_negation(expression))


def _coerced(text: str) -> Ps1Fact:
    coerced = _coerced_numeral(Ps1Constant(STRING, text))
    assert coerced is not None, text
    return coerced


def _sign_of(fact: Ps1Fact) -> float:
    payload = _payload(fact)
    assert isinstance(payload, float), payload
    return math.copysign(1.0, payload)


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

WIDEST_DECIMALS: tuple[decimal.Decimal, ...] = (
    decimal.Decimal((1 << 96) - 1),
    decimal.Decimal(F'{(1 << 96) - 1}E-1'),
)


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

_TRUTH_SHAPES: tuple[tuple[re.Pattern[str], bool], ...] = (
    (_BOOLEAN_CAST_ROW, False),
    (_BRANCH_ROW, False),
    (_AND_TRUE_ROW, False),
    (_OR_FALSE_ROW, False),
    (_TRUE_AND_ROW, False),
    (_NEGATION_ROW, True),
)

_BRANCH_TAKEN = {'yes': True, 'no': False}


def _truth_rows() -> dict[str, dict[str, bool]]:
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
    carried, rendered = _measured(expression)
    return _boolean(rendered) if carried == 'System.Boolean' else _BRANCH_TAKEN[rendered]


TRUTH_ROWS: dict[str, dict[str, bool]] = _truth_rows()

TRUTHS: dict[str, bool] = {
    condition: next(iter(settled.values())) for condition, settled in TRUTH_ROWS.items()
}

PLAIN_CONDITIONS: tuple[str, ...] = ("'a'", "''", "'0'", '1', '0', '$null')

ELEMENT_PAIRS: tuple[tuple[str, str], ...] = (
    ('[char]0', '(,[char]0)'),
    ('(,@())', '(,(,@()))'),
)


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

SPANNED_TYPES: frozenset[str] = (
    frozenset(GRID_WITNESSES) - frozenset(GRID_WITNESS_GAPS) - GRID_COMPLETE_BUT_UNREAD)

EVERY_WITNESS_THREW: tuple[tuple[str, str], ...] = (
    ('System.Char', 'System.Decimal'),
    ('System.Char', 'System.Single'),
)

THROWS_THE_WITNESSES_MISSED: dict[str, tuple[str, str]] = {
    '[sbyte][char]200'       : ('System.SByte', 'System.Char'),
    '[int16][char]40000'     : ('System.Int16', 'System.Char'),
    '[sbyte][single]200'     : ('System.SByte', 'System.Single'),
    '[int16][single]40000'   : ('System.Int16', 'System.Single'),
    '[int][single]3e10'      : ('System.Int32', 'System.Single'),
    '[long][single]1e19'     : ('System.Int64', 'System.Single'),
    '[decimal][single]::NaN' : ('System.Decimal', 'System.Single'),
}


def _grid_operand(name: str) -> Ps1Fact:
    return NULL if name == 'System.Void' else Ps1Typed(_type(name))


def _cell(operator: str, left: str | Ps1TypeName, right: str | Ps1TypeName) -> OperatorOutcome:
    cell = binary_outcome(operator, left, right)
    if cell is None:
        raise KeyError(F'the grid has no cell for {left} {operator} {right}')
    return cell


def _cast_cell(target: str | Ps1TypeName, source: str | Ps1TypeName) -> OperatorOutcome:
    cell = conversion_outcome(target, source)
    if cell is None:
        raise KeyError(F'the grid has no cell for [{target}] of {source}')
    return cell


def _recorded(cell: OperatorOutcome) -> tuple[str, ...]:
    names = [str(one) for one in cell.types]
    if cell.may_throw:
        names.append('throw')
    if cell.may_be_null:
        names.append('null')
    return tuple(sorted(names))


def _generalisations(fact: Ps1Fact) -> tuple[Ps1Fact, ...]:
    carried = type_of(fact)
    return (UNKNOWN,) if carried is None else (Ps1Typed(carried), UNKNOWN)


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

ZERO_DIVISIONS: tuple[tuple[Ps1TypeName, Ps1Fact, Ps1Fact], ...] = (
    (INT32, Ps1Constant(INT32, 5), Ps1Constant(INT32, 0)),
    (DECIMAL, Ps1Constant(DECIMAL, decimal.Decimal(5)), Ps1Constant(DECIMAL, decimal.Decimal(0))),
    (DOUBLE, Ps1Constant(DOUBLE, 1.5), Ps1Constant(DOUBLE, 0.0)),
)


CORPUS_SOURCES: tuple[str, ...] = tuple(dict.fromkeys((
    *TYPES,
    *BOUNDARIES,
    *SNIPPETS.values(),
    *PROBES,
    *SPELLINGS,
)))


class _Site(NamedTuple):
    source: str
    node: Expression


def _corpus_sites() -> tuple[_Site, ...]:
    sites: list[_Site] = []
    for source in CORPUS_SOURCES:
        for node in in_evaluation_order(Ps1Parser(source).parse()):
            if isinstance(node, Expression):
                sites.append(_Site(source, node))
    return tuple(sites)


SITES: tuple[_Site, ...] = _corpus_sites()

CLOSED_WORLD = Ps1WorldReach(Ps1TypeWorld(True, frozenset()))


class _Numeral(NamedTuple):
    raw: str
    reported: int
    named: Ps1Constant


def _numeral_node(expression: str) -> Ps1IntegerLiteral:
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

MISREAD_SPELLINGS: tuple[str, ...] = (
    '0xFFFFFFFF',
    '0xFFFFFFFFFFFFFFFF',
    '100000000000000000000000000000000',
)

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
    applied = _application(expression)
    assert applied is not None, expression
    return applied.operator


def _cased(expression: str, case: Callable[[str], str]) -> Ps1Outcome:
    applied = _application(expression)
    assert applied is not None, expression
    return evaluate(dataclasses.replace(applied, operator=case(applied.operator)))


def _element_payloads(fact: Ps1Fact) -> list[object]:
    return [one.payload if isinstance(one, Ps1Constant) else one for one in _elements(fact)]


class _Collected(NamedTuple):
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
    return fact is NULL or isinstance(fact, Ps1Constant)


def _an_array_cast_evaluated_as_the_object_array_it_builds(node: Expression) -> bool:
    return (
        isinstance(node, Ps1CastExpression)
        and resolve_type(node.type_name) == ARRAY
        and type_of(evaluate(node).value) == OBJECT_ARRAY
    )


class _Step(NamedTuple):
    source: str
    kind: str
    consultable: bool
    step: Ps1Outcome
    answered: Ps1Outcome


def _operand_of(node) -> Ps1Outcome:
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

    def test_every_numeral_the_corpus_measures_is_selected(self):
        self.assertEqual(
            len(_NUMERAL_ROWS), 49, 'a measured numeral was added or withdrawn')
        self.assertEqual(
            sorted(REFUSED), ['0xFFFFFFFFFFFFFFFFF', '1_0', '79228162514264337593543950336d'])
        self.assertEqual(
            sorted(set(UNANSWERED) - set(MEASURED)), [], 'a spelling named here is not measured')
        self.assertEqual(
            sorted(set(ROUNDED) - set(MEASURED)), [], 'a spelling named here is not measured')

    def test_every_measured_numeral_reads_as_the_fact_the_host_printed(self):
        for expression in DECIDED:
            with self.subTest(expression):
                self.assertEqual(_read(expression), MEASURED[expression])

    def test_a_numeral_5_1_cannot_read_is_not_read_here_either(self):
        for expression in REFUSED:
            with self.subTest(expression):
                self.assertEqual(_read(expression), UNKNOWN)

    def test_the_rounded_measured_numerals_are_the_only_unread_ones(self):
        self.assertEqual(
            sorted(
                expression for expression in MEASURED if _read(expression) is UNKNOWN
            ),
            sorted(ROUNDED + UNANSWERED),
        )

    def test_a_negated_parenthesized_literal_keeps_the_width_of_the_literal_it_negates(self):
        self.assertEqual(_read('-2147483648'), MEASURED['-2147483648'])
        for expression in ('-(2147483648)', '-(2147483647)'):
            with self.subTest(expression):
                self.assertEqual(_read(expression), UNKNOWN)
                self.assertEqual(_evaluated(expression).value, MEASURED[expression])

    def test_a_real_with_a_long_suffix_is_the_rounded_int64_the_host_prints(self):
        for expression in ('1.5L', '2.5L'):
            with self.subTest(expression):
                self.assertEqual(_read(expression), MEASURED[expression])

    def test_the_same_printed_value_under_two_spellings_is_two_different_facts(self):
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
        self.assertNotEqual(Ps1Constant(CHAR, 'A'), Ps1Constant(STRING, 'A'))
        self.assertNotEqual(type_of(Ps1Constant(CHAR, 'A')), type_of(Ps1Constant(STRING, 'A')))

    def test_a_fact_is_a_value_so_one_read_twice_is_one_fact(self):
        self.assertEqual(_read('0xFF'), _read('0xFF'))
        self.assertEqual(len({_read('0xFF'), _read('0xFF'), _read('0xFFL')}), 2)


class TestPs1WhatCountsAsAnInteger(unittest.TestCase):

    def _integer_rows(self) -> dict[str, Ps1Fact]:
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
        self.assertEqual(_measured('0xFFFFFFFF'), ('System.Int32', '-1'))
        self.assertEqual(_measured('0xFFFFFFFFFFFFFFFF'), ('System.Int64', '-1'))
        self.assertEqual(_measured('0xFF'), ('System.Int32', '255'))
        self.assertEqual(integer_of(MEASURED['0xFFFFFFFF']), -1)
        self.assertEqual(integer_of(MEASURED['0xFFFFFFFFFFFFFFFF']), -1)
        self.assertEqual(integer_of(MEASURED['0xFF']), 255)
        self.assertEqual(_numeral_node('0xFFFFFFFF').value, 0xFFFFFFFF)

    def test_a_value_5_1_only_converts_to_a_number_is_not_read_as_one(self):
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
        unsafe = make_string_literal("a\n'@\nb")
        self.assertNotIsInstance(unsafe, Ps1HereString)
        safe = make_string_literal('a\nb')
        self.assertIsInstance(safe, Ps1HereString)


class TestPs1ValueSpelling(unittest.TestCase):

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
        for expression in CAST_SPELLINGS:
            with self.subTest(expression):
                self.assertEqual(_read(expression), _measured_fact(expression))
        self.assertEqual(_measured('[byte]5'), ('System.Byte', '5'))

    def test_a_char_and_a_one_character_string_are_not_written_alike(self):
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
        self.assertEqual(_measured_count('@()'), ('System.Object[]', 0))
        self.assertEqual(_measured_count(',(1, 2)'), ('System.Object[]', 1))
        self.assertEqual(_measured_count('@((1, 2))'), ('System.Object[]', 2))
        self.assertEqual(_spelled(_read('@()')), '@()')
        self.assertEqual(_spelled(_read(',(1, 2)')), ',(1, 2)')
        self.assertNotEqual(_read(',(1, 2)'), _read('@((1, 2))'))

    def test_a_collection_is_written_by_what_it_holds_and_not_by_how_it_was_spelled(self):
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

    def test_a_measured_array_shape_reads_as_an_object_array_of_the_measured_length(self):
        self.assertEqual(
            {expression: _read_shape(expression) for expression in COLLECTION_SHAPES},
            {expression: _measured_shape(expression) for expression in COLLECTION_SHAPES},
        )

    def test_the_comma_operator_takes_its_operand_whole_where_the_array_operator_unrolls_it(self):
        self.assertEqual(_measured_count(',(1, 2)'), ('System.Object[]', 1))
        self.assertEqual(_measured_count('@((1, 2))'), ('System.Object[]', 2))
        self.assertNotEqual(_read(',(1, 2)'), _read('@((1, 2))'))
        self.assertEqual(_read(',(1, 2)'), Ps1Constant(OBJECT_ARRAY, (_read('1, 2'),)))
        self.assertEqual(_read('@((1, 2))'), _read('1, 2'))

    def test_the_array_operator_unrolls_the_value_a_statement_produced_and_not_what_was_in_it(self):
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

    CANDIDATES = frozenset({BOOLEAN, INT32, DECIMAL, DOUBLE, STRING, OBJECT_ARRAY})

    def test_a_payload_of_a_kind_no_arm_names_is_refused(self):
        unnamed: Any = {1, 2}
        self.assertEqual(_stamped(unnamed, self.CANDIDATES), UNKNOWN)

    def test_a_collection_is_stamped_only_where_the_cell_recorded_the_array_type(self):
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

    def test_no_measured_cast_is_declined_beyond_the_documented_ones(self):
        declined = {
            expression for expression in CAST_ROWS
            if expression not in THROWN
            and not isinstance(_converted(expression).value, Ps1Constant)
        }
        self.assertEqual(sorted(declined - set(DECLINED_CASTS)), [])

    @opportunity
    def test_a_measured_cast_is_declined_only_over_an_unread_operand_or_a_join_on_ofs(self):
        declined = [
            expression for expression in CAST_ROWS
            if expression not in THROWN
            and not isinstance(_converted(expression).value, Ps1Constant)
        ]
        undecided = DECLINED['a collection joins on $OFS, which only a run decides']
        self.assertEqual(sorted(declined), sorted(undecided + UNREAD_OPERANDS))

    def test_a_declined_cast_still_carries_the_type_the_host_reported(self):
        for expression in sorted(set(DECLINED_CASTS) - set(UNREAD_OPERANDS)):
            with self.subTest(expression):
                name, _ = _measured(expression)
                self.assertEqual(type_of(_converted(expression).value), _type(name))

    def test_a_cast_of_a_cast_reaches_the_value_the_host_printed(self):
        for expression in NESTED_CASTS:
            with self.subTest(expression):
                self.assertEqual(
                    _converted(expression), Ps1Outcome(NEVER, _measured_fact(expression)))

    def test_a_cast_the_host_threw_on_names_no_value(self):
        self.assertEqual(
            {expression: _names_a_value(_converted(expression).value) for expression in THROWN},
            {expression: False for expression in THROWN},
        )

    def test_a_thrown_cast_certainly_throws_except_over_an_operation_a_blank_or_an_exponent(self):
        excepted = ('[byte](200 * 2)', "[int]'   '", "[byte]'1e3'")
        certain = {
            expression: _converted(expression).certainly_throws
            for expression in THROWN
            if expression not in excepted
        }
        self.assertEqual(certain, {expression: True for expression in certain})

    def test_a_row_that_measures_as_is_not_a_cast_and_is_no_expectation_here(self):
        self.assertEqual(
            sorted(AS_ROWS), ["'abc' -as [int]", '300 -as [byte]', '5 -as [long]'])
        self.assertEqual(sorted(set(AS_ROWS) & set(CAST_ROWS)), [])
        self.assertEqual(_measured('300 -as [byte]'), ('', '<null>'))
        self.assertEqual(_throws(_transcript('[byte]300')), True)


class TestPs1CharConversions(unittest.TestCase):

    def test_a_char_casts_to_the_number_and_to_the_text_the_host_printed(self):
        self.assertEqual(
            convert(Ps1Constant(CHAR, 'A'), INT32), Ps1Outcome(NEVER, Ps1Constant(INT32, 65)))
        self.assertEqual(
            convert(Ps1Constant(CHAR, 'A'), STRING), Ps1Outcome(NEVER, Ps1Constant(STRING, 'A')))

    def test_a_char_reaches_no_target_the_corpus_does_not_measure(self):
        self.assertEqual(convert(Ps1Constant(CHAR, 'A'), DOUBLE).value, Ps1Typed(DOUBLE))
        self.assertEqual(convert(Ps1Constant(CHAR, 'A'), DECIMAL).value, Ps1Typed(DECIMAL))


class TestPs1CastsThatReadAString(unittest.TestCase):

    def test_a_hexadecimal_string_is_the_bit_pattern_the_target_width_holds(self):
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
        self.assertEqual(_throws(_transcript("[byte]'-1'")), True)
        self.assertEqual(_measured("[int]'+7'"), ('System.Int32', '7'))
        self.assertEqual(_converted("[byte]'-1'"), Ps1Outcome(ALWAYS, UNKNOWN))
        self.assertEqual(_converted("[int]'+7'"), Ps1Outcome(NEVER, Ps1Constant(INT32, 7)))

    def test_a_string_spelling_a_half_is_rounded_to_the_even_neighbour(self):
        self.assertEqual(_measured("[int]'7.5'"), ('System.Int32', '8'))
        self.assertEqual(_measured("[int]'2.5'"), ('System.Int32', '2'))
        self.assertEqual(_converted("[int]'7.5'"), Ps1Outcome(NEVER, Ps1Constant(INT32, 8)))
        self.assertEqual(_converted("[int]'2.5'"), Ps1Outcome(NEVER, Ps1Constant(INT32, 2)))

    @opportunity
    def test_the_empty_string_is_a_zero_and_a_string_of_spaces_is_not(self):
        self.assertEqual(_measured("[int]''"), ('System.Int32', '0'))
        self.assertEqual(_measured("[int]' 5 '"), ('System.Int32', '5'))
        self.assertEqual(_throws(_transcript("[int]'   '")), True)
        self.assertEqual(_converted("[int]''"), Ps1Outcome(NEVER, Ps1Constant(INT32, 0)))
        self.assertEqual(_converted("[int]' 5 '"), Ps1Outcome(NEVER, Ps1Constant(INT32, 5)))
        self.assertTrue(_converted("[int]'   '").certainly_throws)

    def test_a_string_is_true_by_holding_characters_rather_than_by_what_they_spell(self):
        self.assertEqual(_measured("[bool]'0'"), ('System.Boolean', 'True'))
        self.assertEqual(_measured("[bool]'a'"), ('System.Boolean', 'True'))
        self.assertEqual(_measured("[bool]''"), ('System.Boolean', 'False'))
        self.assertEqual(_converted("[bool]'0'"), Ps1Outcome(NEVER, Ps1Constant(BOOLEAN, True)))
        self.assertEqual(_converted("[bool]'a'"), Ps1Outcome(NEVER, Ps1Constant(BOOLEAN, True)))
        self.assertEqual(_converted("[bool]''"), Ps1Outcome(NEVER, Ps1Constant(BOOLEAN, False)))

    def test_a_one_character_string_is_that_char_and_every_other_length_throws(self):
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

    @opportunity
    def test_an_exponent_string_is_a_number_to_int_and_a_throw_to_byte(self):
        self.assertEqual(_measured("[int]'1e3'"), ('System.Int32', '1000'))
        self.assertEqual(_throws(_transcript("[byte]'1e3'")), True)
        self.assertEqual(_converted("[int]'1e3'"), Ps1Outcome(NEVER, Ps1Constant(INT32, 1000)))
        self.assertTrue(_converted("[byte]'1e3'").certainly_throws)

    def test_a_spelling_only_python_reads_as_a_number_is_no_number_here(self):
        self.assertEqual(_throws(_transcript("[int]'1_0'")), True)
        self.assertEqual(_throws(_transcript("[int]'0b1010'")), True)
        self.assertEqual(_converted("[int]'1_0'"), Ps1Outcome(ALWAYS, Ps1Typed(INT32)))
        self.assertEqual(_converted("[int]'0b1010'"), Ps1Outcome(ALWAYS, Ps1Typed(INT32)))


class TestPs1ConvertRefusals(unittest.TestCase):

    def test_a_fact_that_is_not_a_value_is_never_converted_into_one(self):
        self.assertEqual(convert(UNKNOWN, INT32), NOTHING)
        self.assertEqual(convert(Ps1Typed(DOUBLE), INT32).value, Ps1Typed(INT32))
        self.assertEqual(convert(NULL, INT32), Ps1Outcome(NEVER, Ps1Constant(INT32, 0)))

    def test_a_cast_the_grid_does_not_cover_is_refused_rather_than_assumed(self):
        self.assertEqual(convert(Ps1Constant(INT32, 5), _type('System.DateTime')), NOTHING)

    def test_a_double_is_not_carried_into_a_decimal_by_python(self):
        converted = convert(Ps1Constant(DOUBLE, 1.1), DECIMAL).value
        self.assertIn(converted, (Ps1Typed(DECIMAL), Ps1Constant(DECIMAL, decimal.Decimal('1.1'))))


class TestPs1OutcomeIsWeakOnBothAxes(unittest.TestCase):

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
        five = Ps1Constant(INT32, 5)
        zero = Ps1Constant(INT32, 0)
        self.assertEqual(apply('/', five, zero), Ps1Outcome(ALWAYS, UNKNOWN))
        self.assertEqual(apply('%', five, zero), Ps1Outcome(ALWAYS, UNKNOWN))
        for operator, left, right in (
            ('/', five, Ps1Typed(INT32)),
            ('/', five, UNKNOWN),
            ('/', Ps1Typed(INT32), zero),
            ('%', five, UNKNOWN),
        ):
            with self.subTest(F'{left!r} {operator} {right!r}'):
                self.assertTrue(apply(operator, left, right).may_throw)

    def test_generalising_an_operand_never_takes_away_a_throw(self):
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
        for operator in ('/', '%'):
            with self.subTest(operator):
                outcome = apply(
                    operator, Ps1Constant(DOUBLE, 1.5), Ps1Constant(DOUBLE, 0.0))
                self.assertEqual(outcome, Ps1Outcome(NEVER, Ps1Typed(DOUBLE)))
                self.assertIsNone(render(outcome.value))


class TestPs1MeasuredOperators(unittest.TestCase):

    def test_every_measured_operation_is_selected(self):
        self.assertEqual(
            len(OPERATION_ROWS), 294, 'a measured operation was added or withdrawn')
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

    def test_a_fold_rewrites_every_pinned_operation_and_to_no_value_the_host_did_not_print(self):
        rewritten = {
            expression for expression in OPERATION_ROWS
            if not _applied(expression).may_throw
            and render(_applied(expression).value) is not None
        }
        pinned = set(PINNED_OPERATIONS + ABBREVIATED_OPERATIONS + FILTERED_COMPARISONS)
        self.assertEqual(sorted(pinned - rewritten), [])
        compared = rewritten - set(ABBREVIATED_OPERATIONS) - set(FILTERED_COMPARISONS)
        self.assertEqual(
            {expression: _applied(expression).value for expression in compared},
            {expression: _measured_operation_fact(expression) for expression in compared},
        )

    def test_no_measured_operation_is_answered_with_a_type_the_host_did_not_print(self):
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

    def test_every_measured_complement_is_pinned_except_the_throw_and_a_real_beyond_int32(self):
        self.assertEqual(
            sorted(
                expression for expression in COMPLEMENT_ROWS
                if expression not in THROWN_COMPLEMENTS
                and expression != '-bnot 3000000000.0'
                and not isinstance(_complemented(expression).value, Ps1Constant)
            ),
            [],
        )

    def test_a_hexadecimal_operand_that_fills_its_width_is_complemented_as_the_negative_it_is(self):
        self.assertEqual(_measured('0xFFFFFFFF'), ('System.Int32', '-1'))
        self.assertEqual(_measured_complement('-bnot 0xFFFFFFFF'), ('System.Int32', '0'))
        self.assertEqual(_measured_complement('-bnot 0xFF'), ('System.Int32', '-256'))
        self.assertEqual(
            _complemented('-bnot 0xFFFFFFFF'), Ps1Outcome(NEVER, Ps1Constant(INT32, 0)))
        self.assertEqual(_complemented('-bnot 0xFF'), Ps1Outcome(NEVER, Ps1Constant(INT32, -256)))

    def test_a_narrow_operand_widens_where_a_wide_one_keeps_its_width(self):
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

    @opportunity
    def test_the_width_a_real_complements_at_follows_its_value_and_not_its_type(self):
        self.assertEqual(_measured_complement('-bnot 1.5'), ('System.Int32', '-3'))
        self.assertEqual(
            _measured_complement('-bnot 3000000000.0'), ('System.UInt32', '1294967295'))
        self.assertEqual(_complemented('-bnot 1.5'), Ps1Outcome(NEVER, Ps1Constant(INT32, -3)))
        self.assertEqual(
            _complemented('-bnot 3000000000.0'),
            Ps1Outcome(NEVER, Ps1Constant(UINT32, 1294967295)),
        )

    def test_a_complement_the_host_threw_on_names_no_value(self):
        self.assertEqual(
            {
                expression: _names_a_value(_complemented(expression).value)
                for expression in THROWN_COMPLEMENTS
            },
            {expression: False for expression in THROWN_COMPLEMENTS},
        )

    @opportunity
    def test_a_complement_the_host_threw_on_certainly_throws(self):
        self.assertEqual(_throws(_transcript("[int]'abc'")), True)
        self.assertEqual(
            {
                expression: _complemented(expression).certainly_throws
                for expression in THROWN_COMPLEMENTS
            },
            {expression: True for expression in THROWN_COMPLEMENTS},
        )

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

    def test_an_operand_whose_type_does_not_decide_the_result_leaves_both_axes_unclaimed(self):
        for operand in (UNKNOWN, Ps1Typed(DOUBLE), Ps1Typed(STRING)):
            with self.subTest(repr(operand)):
                self.assertEqual(apply_unary('-bnot', operand), Ps1Outcome(MAYBE, UNKNOWN))

    def test_complementing_an_int32_of_unknown_value_names_an_int32_or_nothing(self):
        self.assertIn(apply_unary('-bnot', Ps1Typed(INT32)).value, (UNKNOWN, Ps1Typed(INT32)))

    def test_a_measured_complement_is_answered_the_same_however_its_operator_is_cased(self):
        self.assertEqual(
            {
                expression: apply_unary('-BNOT', read(_complement_operand(expression)))
                for expression in COMPLEMENT_ROWS
            },
            {expression: _complemented(expression) for expression in COMPLEMENT_ROWS},
        )

    def test_an_operator_this_does_not_answer_is_refused_rather_than_complemented(self):
        for operator in ('-not', '!', '+', '-bxor', '-join'):
            with self.subTest(operator):
                self.assertEqual(apply_unary(operator, MEASURED['0xFF']), NOTHING)


class TestPs1MeasuredNegation(unittest.TestCase):

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
        self.assertEqual(
            sorted(
                expression for expression in NEGATION_ROWS
                if not isinstance(_negated(expression).value, Ps1Constant)
            ),
            sorted(THROWN_NEGATIONS),
        )

    def test_a_negation_the_host_threw_on_names_no_value(self):
        self.assertEqual(
            {
                expression: _names_a_value(_negated(expression).value)
                for expression in THROWN_NEGATIONS
            },
            {expression: False for expression in THROWN_NEGATIONS},
        )

    def test_a_negation_of_a_text_that_spells_no_number_certainly_throws(self):
        self.assertTrue(_negated("- 'abc'").certainly_throws)

    @opportunity
    def test_a_negation_of_an_empty_array_certainly_throws(self):
        self.assertTrue(_negated('- @()').certainly_throws)

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

    def test_an_operand_whose_type_does_not_decide_the_result_leaves_both_axes_unclaimed(self):
        for operand in (UNKNOWN, Ps1Typed(STRING)):
            with self.subTest(repr(operand)):
                self.assertEqual(apply_unary('-', operand), NOTHING)

    def test_negating_an_unknown_int32_names_no_type_as_its_minimum_negates_to_a_double(self):
        self.assertEqual(_measured_negation('- 5'), ('System.Int32', '-5'))
        self.assertEqual(_measured_negation('- (-2147483648)'), ('System.Double', '2147483648'))
        self.assertEqual(apply_unary('-', Ps1Typed(INT32)).value, UNKNOWN)

    def test_negating_a_double_of_unknown_value_names_a_double_or_nothing(self):
        self.assertIn(apply_unary('-', Ps1Typed(DOUBLE)).value, (UNKNOWN, Ps1Typed(DOUBLE)))

    def test_a_negation_is_the_subtraction_from_an_int32_zero_it_is_compiled_into(self):
        self.assertEqual(
            {expression: _negated(expression) for expression in NEGATION_ROWS},
            {expression: _negated_as_subtraction(expression) for expression in NEGATION_ROWS},
        )

    def test_a_string_operand_negates_at_the_width_the_numeral_inside_it_takes(self):
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

    def test_every_measured_condition_except_nan_is_answered_a_truth(self):
        self.assertEqual(
            sorted(
                condition for condition in TRUTHS
                if condition != '(0.0 / 0.0)' and is_truthy(_slot(condition)) is None
            ),
            [],
        )

    @opportunity
    def test_a_nan_condition_is_counted_true(self):
        self.assertEqual(TRUTHS['(0.0 / 0.0)'], True)
        self.assertEqual(is_truthy(_slot('(0.0 / 0.0)')), True)


class TestPs1ACollectionOfOneCountsItsElementByARuleOfItsOwn(unittest.TestCase):

    def test_a_measured_value_and_the_collection_of_one_holding_it_are_counted_apart(self):
        for element, holding in ELEMENT_PAIRS:
            with self.subTest(holding):
                self.assertEqual(TRUTHS[holding], not TRUTHS[element])
                self.assertEqual(is_truthy(_slot(element)), TRUTHS[element])
                self.assertEqual(is_truthy(_slot(holding)), TRUTHS[holding])

    def test_an_element_that_names_no_value_leaves_the_collection_uncounted(self):
        uncounted = Ps1Constant(OBJECT_ARRAY, (Ps1Typed(INT32),))
        self.assertFalse(_names_a_value(convert(uncounted, BOOLEAN).value))


class TestPs1TruthRefusesWhateverEitherStepMayThrowOn(unittest.TestCase):

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
        self.assertEqual(_measured("'a' + 1.50d"), ('System.String', 'a1.50'))
        self.assertEqual(_applied("'a' + 1.50d"), Ps1Outcome(NEVER, Ps1Constant(STRING, 'a1.50')))

    def test_a_right_operand_whose_text_only_a_session_settles_is_not_joined(self):
        self.assertEqual(_measured("'a' + @(1, 2)"), ('System.String', 'a1 2'))
        self.assertEqual(_applied("'a' + @(1, 2)"), NOTHING)

    def test_a_numeral_left_operand_joins_a_double_as_text_and_not_as_a_sum(self):
        self.assertEqual(_measured("'5' + 5"), ('System.String', '55'))
        self.assertEqual(_measured("'a' + 1.5"), ('System.String', 'a1.5'))
        self.assertEqual(_applied("'5' + 1.5"), Ps1Outcome(NEVER, Ps1Constant(STRING, '51.5')))

    def test_a_right_operand_whose_text_is_written_here_is_joined_all_the_same(self):
        self.assertEqual(_applied("'5' + 5"), Ps1Outcome(NEVER, Ps1Constant(STRING, '55')))
        self.assertEqual(_applied('[char]65 + 1'), Ps1Outcome(NEVER, Ps1Constant(STRING, 'A1')))


class TestPs1AComparisonIsDecidedByItsLeftOperand(unittest.TestCase):

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

    def test_a_comparison_this_does_not_decide_names_no_value_rather_than_a_guess(self):
        self.assertEqual(
            {
                expression: _applied(expression).value
                for expression in UNDECIDED_COMPARISONS
                if _names_a_value(_applied(expression).value)
            },
            {},
        )

    def test_a_comparison_this_decides_is_the_boolean_the_host_printed(self):
        self.assertEqual(
            {expression: _applied(expression) for expression in DECIDED_COMPARISON_ROWS},
            {
                expression: Ps1Outcome(NEVER, _measured_operation_fact(expression))
                for expression in DECIDED_COMPARISON_ROWS
            },
        )

    def test_no_measured_comparison_is_counted_a_truth_the_host_did_not_print(self):
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

    def test_a_comparison_this_decides_is_counted_the_truth_the_host_printed(self):
        self.assertEqual(
            {expression: is_truthy(_slot(expression)) for expression in DECIDED_COMPARISON_ROWS},
            {
                expression: _boolean(_measured_operation(expression)[1])
                for expression in DECIDED_COMPARISON_ROWS
            },
        )

    def test_the_same_two_values_compare_as_text_one_way_round_and_as_numbers_the_other(self):
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

    NEGATION = '- 79228162514264337593543950335d'

    def _measured_digits(self) -> dict[str, str]:
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

    def _measured_texts(self) -> dict[str, str]:
        return {spelling: _measured(F'[string]{spelling}')[1] for spelling in SCALED_DECIMALS}

    def test_a_host_writes_each_of_those_scales_as_its_own_text(self):
        self.assertEqual(self._measured_texts(), {
            '1.0d'   : '1.0',
            '1.00d'  : '1.00',
            '1.000d' : '1.000',
            '1.10d'  : '1.10',
            '1.100d' : '1.100',
        })

    def test_each_of_those_scales_is_a_fact_of_its_own(self):
        distinct = {_read(spelling) for spelling in SCALED_DECIMALS}
        self.assertEqual(sorted(_spelled(fact) for fact in distinct), sorted(SCALED_DECIMALS))


class TestPs1AFactIsSpelledAsTheTypeHoldsIt(unittest.TestCase):

    def test_a_quotient_spelled_with_an_exponent_is_the_coefficient_the_type_holds(self):
        self.assertEqual(
            _applied('1d / 0.1d'),
            Ps1Outcome(NEVER, Ps1Constant(DECIMAL, decimal.Decimal('10'))),
        )

    def test_a_product_whose_raw_scale_passes_the_places_the_type_has_is_held_at_them(self):
        held = decimal.Decimal('1.0000000000000000000000000000')
        self.assertEqual(
            apply('*', Ps1Constant(DECIMAL, held), Ps1Constant(DECIMAL, held)),
            Ps1Outcome(NEVER, Ps1Constant(DECIMAL, held)),
        )


class TestPs1TheTextAValueWrites(unittest.TestCase):

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

    def test_every_operation_the_host_aborted_on_names_no_value_and_reports_the_throw(self):
        self.assertEqual(
            {
                expression: (
                    _names_a_value(_evaluated(expression).value),
                    _evaluated(expression).may_throw,
                )
                for expression in THROWN_OPERATIONS
            },
            {expression: (False, True) for expression in THROWN_OPERATIONS},
        )

    def test_no_operation_the_host_printed_a_value_for_is_proven_to_throw(self):
        self.assertEqual(
            sorted(
                expression for expression in OPERATION_ROWS
                if expression not in THROWN_OPERATIONS and _evaluated(expression).certainly_throws
            ),
            [],
        )

    def test_a_decimal_overflow_a_zero_divisor_and_a_non_numeric_text_are_proven_to_throw(self):
        proven = (
            "'1_0' -band 15",
            "16 + 'file'",
            '1d / 0d',
            '79228162514264337593543950335d + 1d',
            '79228162514264337593543950335d - -1d',
        )
        self.assertEqual(sorted(set(proven) - set(THROWN_OPERATIONS)), [])
        self.assertEqual(
            {expression: _evaluated(expression).certainly_throws for expression in proven},
            {expression: True for expression in proven},
        )

    @opportunity
    def test_every_operation_the_host_threw_on_is_proven_to_throw(self):
        self.assertEqual(
            {
                expression: _evaluated(expression).certainly_throws
                for expression in THROWN_OPERATIONS
            },
            {expression: True for expression in THROWN_OPERATIONS},
        )

    def test_no_condition_the_host_aborted_on_is_counted_true_or_false(self):
        self.assertEqual(
            {expression: is_truthy(_slot(expression)) for expression in THROWN_OPERATIONS},
            {expression: None for expression in THROWN_OPERATIONS},
        )

    @opportunity
    def test_ordering_a_number_against_a_text_that_spells_none_aborts_where_equality_does_not(self):
        orderings = ("1 -lt 'abc'", "1 -gt 'abc'")
        equalities = ("1 -eq 'abc'", "1 -ne 'abc'")
        self.assertEqual(
            {expression: _throws(_transcript(expression)) for expression in orderings + equalities},
            {
                "1 -lt 'abc'" : True,
                "1 -gt 'abc'" : True,
                "1 -eq 'abc'" : False,
                "1 -ne 'abc'" : False,
            },
        )
        self.assertEqual(_measured_operation("1 -eq 'abc'"), ('System.Boolean', 'False'))
        self.assertEqual(_measured_operation("1 -ne 'abc'"), ('System.Boolean', 'True'))
        self.assertEqual(
            {expression: _applied(expression).certainly_throws for expression in orderings},
            {expression: True for expression in orderings},
        )
        self.assertEqual(
            {expression: _applied(expression) for expression in equalities},
            {
                "1 -eq 'abc'" : Ps1Outcome(NEVER, Ps1Constant(BOOLEAN, False)),
                "1 -ne 'abc'" : Ps1Outcome(NEVER, Ps1Constant(BOOLEAN, True)),
            },
        )

    def test_a_decimal_that_leaves_its_range_or_is_divided_by_zero_aborts(self):
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
        for name, row in GRID_WITNESS_GAPS.items():
            operator, left, right, recorded, produced = row
            with self.subTest(name):
                self.assertEqual(_recorded(_cell(operator, left, right)), recorded)
                self.assertNotEqual(recorded, produced)
                self.assertEqual(
                    apply(operator, _grid_operand(left), _grid_operand(right)), NOTHING)

    def test_the_type_ledger_contradicts_the_cell_a_string_operand_indexes(self):
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
        self.assertEqual(_measured_operation_fact('$null * 1'), NULL)
        self.assertEqual(apply('*', NULL, Ps1Typed(INT32)), Ps1Outcome(NEVER, NULL))
        self.assertEqual(_cell('-band', INT32, INT32).single_type, INT32)
        self.assertEqual(
            apply('-band', Ps1Typed(INT32), Ps1Typed(INT32)), Ps1Outcome(NEVER, Ps1Typed(INT32)))


class TestPs1SpanRestsOnTheShippedGrid(unittest.TestCase):

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

    def test_a_cast_from_a_source_the_witnesses_fall_short_of_still_names_its_target(self):
        answers = {
            (target, source): convert(_grid_operand(source), _type(target)).value
            for source in GRID_WITNESS_GAPS
            for target in GRID_WITNESSES
            if conversion_outcome(target, source) is not None
        }
        self.assertEqual(len(answers), 75, 'a conversion cell was added or withdrawn')
        self.assertEqual(
            {cell: answer for cell, answer in answers.items() if cell not in EVERY_WITNESS_THREW},
            {
                cell: Ps1Typed(_type(cell[0]))
                for cell in answers
                if cell not in EVERY_WITNESS_THREW
            },
        )
        self.assertEqual(
            {cell: _names_a_value(answers[cell]) for cell in EVERY_WITNESS_THREW},
            {cell: False for cell in EVERY_WITNESS_THREW},
        )

    def test_a_byte_cast_from_a_source_the_witnesses_fall_short_of_may_throw(self):
        self.assertEqual(
            {
                source: convert(_grid_operand(source), BYTE).may_throw
                for source in GRID_WITNESS_GAPS
            },
            {source: True for source in GRID_WITNESS_GAPS},
        )

    def test_a_cast_the_host_throws_on_from_a_source_the_witnesses_fall_short_of_may_throw(self):
        self.assertEqual(
            {
                measured: convert(_grid_operand(source), _type(target)).may_throw
                for measured, (target, source) in THROWS_THE_WITNESSES_MISSED.items()
            },
            dict.fromkeys(THROWS_THE_WITNESSES_MISSED, True),
        )

    @opportunity
    def test_a_cast_of_a_char_to_string_cannot_throw(self):
        self.assertEqual(_cast_cell(STRING, CHAR).may_throw, False)
        self.assertEqual(convert(Ps1Typed(CHAR), STRING), Ps1Outcome(NEVER, Ps1Typed(STRING)))

    @opportunity
    def test_a_cast_and_an_operator_read_the_same_string_by_different_rules(self):
        self.assertEqual(_measured("[int]'1e3'"), ('System.Int32', '1000'))
        self.assertEqual(_converted("[int]'1e3'"), Ps1Outcome(NEVER, Ps1Constant(INT32, 1000)))
        self.assertEqual(_measured("1 + '1e3'"), ('System.Double', '1001'))
        self.assertEqual(_applied("1 + '1e3'"), Ps1Outcome(NEVER, Ps1Constant(DOUBLE, 1001.0)))


class TestPs1EvaluateComposesTheOneStepReaders(unittest.TestCase):

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
        self.assertEqual(len(composed), 197)
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

    def test_a_join_over_a_cast_of_a_string_is_the_text_the_two_steps_come_to(self):
        self.assertEqual(_measured("[int]'0x10'"), ('System.Int32', '16'))
        self.assertEqual(_measured("'5' + 5"), ('System.String', '55'))
        self.assertEqual(
            _evaluated("'v' + [int]'0x10'"), Ps1Outcome(NEVER, Ps1Constant(STRING, 'v16')))

    def test_a_cast_over_a_join_reads_the_text_the_join_produced(self):
        self.assertEqual(_measured("[int]'5'"), ('System.Int32', '5'))
        self.assertEqual(_evaluated("[int]('1' + '0')"), Ps1Outcome(NEVER, Ps1Constant(INT32, 10)))

    def test_a_step_the_host_threw_on_leaves_the_join_with_a_throw_and_no_value(self):
        self.assertEqual(_throws(_transcript("[char]'AB'")), True)
        self.assertEqual(_evaluated("'x' + [char]'AB'"), Ps1Outcome(ALWAYS, UNKNOWN))

    def test_a_join_over_a_cast_of_an_exponent_string_names_no_text_but_the_number_it_spells(self):
        self.assertIn(
            _evaluated("'x' + [int]'1e3'").value,
            (UNKNOWN, Ps1Typed(STRING), Ps1Constant(STRING, 'x1000')),
        )

    @opportunity
    def test_a_join_over_a_cast_of_an_exponent_string_is_the_text_of_the_number_it_spells(self):
        self.assertEqual(_measured("[int]'1e3'"), ('System.Int32', '1000'))
        self.assertEqual(
            _evaluated("'x' + [int]'1e3'"), Ps1Outcome(NEVER, Ps1Constant(STRING, 'x1000'))
        )


class TestPs1EvaluateAgreesOrRefuses(unittest.TestCase):

    def test_an_expression_the_source_pins_evaluates_to_exactly_what_it_pins(self):
        compared = [site for site in SITES if read(site.node) is not UNKNOWN]
        self.assertEqual(len(compared), 2961)
        self.assertEqual(
            [
                site.source for site in compared
                if evaluate(site.node) != Ps1Outcome(NEVER, read(site.node))
            ],
            [],
        )

    def test_only_an_array_cast_has_one_type_here_and_another_in_the_single_type_reader(self):
        compared = [
            site for site in SITES
            if resolve_expression_type(site.node) is not None
            and type_of(evaluate(site.node).value) is not None
        ]
        self.assertEqual(len(compared), 2996)
        self.assertEqual(
            [
                site.source for site in compared
                if resolve_expression_type(site.node) != type_of(evaluate(site.node).value)
                and not _an_array_cast_evaluated_as_the_object_array_it_builds(site.node)
            ],
            [],
        )

    def test_a_type_named_here_is_one_the_candidate_set_holds_but_for_an_array_cast(self):
        compared = [
            site for site in SITES
            if candidate_types(site.node, CLOSED_WORLD)
            and type_of(evaluate(site.node).value) is not None
        ]
        self.assertEqual(len(compared), 2996)
        self.assertEqual(
            [
                site.source for site in compared
                if type_of(evaluate(site.node).value)
                not in candidate_types(site.node, CLOSED_WORLD)
                and not _an_array_cast_evaluated_as_the_object_array_it_builds(site.node)
            ],
            [],
        )

    def test_an_array_cast_is_evaluated_as_the_object_array_it_builds(self):
        self.assertEqual(_measured_rendering('[array]5'), ('System.Object[]', '5'))
        self.assertEqual(type_of(_evaluated('[array]5').value), OBJECT_ARRAY)

    @backlog
    def test_an_array_cast_is_typed_as_the_object_array_it_builds_by_the_readers_of_its_name(self):
        self.assertEqual(resolve_expression_type(_slot('[array]5')), OBJECT_ARRAY)
        self.assertIn(OBJECT_ARRAY, candidate_types(_slot('[array]5'), CLOSED_WORLD))

    def test_a_string_the_tree_reader_spells_is_the_string_named_here(self):
        self.assertEqual(len(STRINGS), 1731)
        self.assertEqual(
            [row.source for row in STRINGS if row.named != Ps1Constant(STRING, row.text)], [])

    def test_the_bytes_the_array_reader_collects_are_the_numbers_the_elements_name(self):
        self.assertEqual(len(BYTE_ARRAYS), 116)
        self.assertEqual(
            [row.source for row in BYTE_ARRAYS if list(row.collected) != row.payloads], [])

    def test_a_literal_node_and_the_domain_read_one_spelling_as_one_number(self):
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

    def test_a_step_that_can_be_consulted_is_the_whole_answer(self):
        consulted = [step for step in STEPS if step.consultable]
        self.assertEqual(len(consulted), 555)
        self.assertEqual(
            [step.source for step in consulted if step.answered.value != step.step.value], [])

    def test_only_a_cast_names_anything_where_its_step_cannot_be_consulted(self):
        unconsulted = [step for step in STEPS if not step.consultable]
        self.assertEqual(len(unconsulted), 38)
        self.assertEqual(
            [step.source for step in unconsulted if _names_a_value(step.answered.value)], [])
        self.assertEqual(
            sorted({
                step.kind for step in unconsulted if step.answered.value is not UNKNOWN
            }),
            ['cast'],
        )

    def test_an_array_names_a_value_only_where_every_element_is_one(self):
        named = [row for row in ARRAYS if row.named]
        self.assertEqual(len(named), 159)
        self.assertEqual([row.source for row in named if not row.elements_named], [])

    def test_an_element_that_names_only_a_type_leaves_the_array_unknown(self):
        self.assertEqual(_evaluated("[int]'abc'"), Ps1Outcome(ALWAYS, Ps1Typed(INT32)))
        self.assertFalse(_names_a_value(_evaluated("([int]'abc'), 1").value))
        self.assertEqual(
            _evaluated('$null, 1'),
            Ps1Outcome(NEVER, Ps1Constant(OBJECT_ARRAY, (NULL, Ps1Constant(INT32, 1)))),
        )

    @opportunity
    def test_an_array_holding_an_element_that_certainly_throws_certainly_throws(self):
        self.assertTrue(_evaluated("([int]'abc'), 1").certainly_throws)


class TestPs1EvaluateCarriesAThrowUp(unittest.TestCase):

    def test_no_expression_is_cleared_of_a_throw_one_it_consumes_may_take(self):
        compared = [
            (site, child)
            for site in SITES
            for child in site.node.children()
            if isinstance(child, Expression) and evaluate(child).may_throw
        ]
        self.assertEqual(len(compared), 2406)
        self.assertEqual(
            [site.source for site, _ in compared if not evaluate(site.node).may_throw], [])

    def test_an_operand_the_host_threw_on_makes_the_operation_one_that_may_throw(self):
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

    def test_a_cast_the_host_threw_on_evaluates_to_no_value(self):
        self.assertEqual(
            {expression: _names_a_value(_evaluated(expression).value) for expression in THROWN},
            {expression: False for expression in THROWN},
        )

    def test_a_thrown_cast_evaluates_to_a_certain_throw_except_over_a_blank_or_an_exponent(self):
        excepted = ("[int]'   '", "[byte]'1e3'")
        certain = {
            expression: _evaluated(expression).certainly_throws
            for expression in THROWN
            if expression not in excepted
        }
        self.assertEqual(certain, {expression: True for expression in certain})


class TestPs1EvaluateRefusesATypeLiteral(unittest.TestCase):

    def test_every_type_literal_the_corpus_writes_is_refused_here_and_typed_there(self):
        literals = [site for site in SITES if isinstance(site.node, Ps1TypeExpression)]
        self.assertEqual(len(literals), 43)
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
        self.assertEqual(_measured('300 -as [byte]'), ('', '<null>'))
        self.assertEqual(
            {expression: _evaluated(expression) for expression in AS_ROWS},
            {expression: NOTHING for expression in AS_ROWS},
        )


class TestPs1NumeralTypesAreReadFromTheSpelling(unittest.TestCase):

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

    def test_a_spelling_5_1_cannot_read_is_typed_by_nobody(self):
        for expression in REFUSED:
            with self.subTest(expression):
                self.assertIsNone(resolve_expression_type(_slot(expression)))

    def test_a_negated_parenthesized_literal_is_typed_by_nobody_or_as_the_host_typed_it(self):
        for expression in ('-(2147483648)', '-(2147483647)'):
            with self.subTest(expression):
                self.assertIn(
                    resolve_expression_type(_slot(expression)),
                    (None, type_of(MEASURED[expression])),
                )


class TestPs1OperatorCaseDoesNotChangeTheAnswer(unittest.TestCase):

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
