from __future__ import annotations

import re
import unittest
import unittest.mock

from typing import NamedTuple

from refinery.lib.scripts.ps1.deobfuscation import _folds, deobfuscate
from refinery.lib.scripts.ps1.model import (
    Ps1AssignmentExpression,
    Ps1CommandInvocation,
    Ps1ExpressionStatement,
)
from refinery.lib.scripts.ps1.parser import Ps1Parser
from refinery.lib.scripts.ps1.synth import Ps1Synthesizer

from test.lib.scripts.ps1 import corpus, dispatch
from test.lib.scripts.ps1.corpus import oracle_corpus
from test.lib.scripts.ps1.deobfuscation.fold_expectations import (
    NOT_YET_SIMPLIFIED,
    SIMPLIFIED,
    Emptied,
    Expectation,
    KeptAsWritten,
    Simplified,
)
from test.lib.scripts.ps1.test_dispatch import DISPATCH_TRANSCRIPTS
from test.lib.scripts.ps1.test_oracle import (
    BEHAVIOUR_DEFECTS,
    DEFECTS,
    TYPE_DEFECTS,
    TYPE_TRANSCRIPTS,
)


def _unchanged(row: str) -> str:
    return Ps1Synthesizer().convert(Ps1Parser(row).parse())


def _rewritten(row: str) -> str:
    ast = Ps1Parser(row).parse()
    deobfuscate(ast)
    return Ps1Synthesizer().convert(ast)


class Census(NamedTuple):
    outputs: dict[str, str]
    errors: dict[str, str]


def census() -> Census:
    outputs = {}
    errors = {}
    for row in oracle_corpus():
        try:
            outputs[row] = _rewritten(row)
        except Exception as error:
            errors[row] = F'{type(error).__name__}: {error}'
    return Census(outputs, errors)


_TYPES = frozenset(corpus.TYPES)

_STORED_AND_WRITTEN = re.compile(r'\$t = .*; Write-Output \(,\$t\); Write-Output \$t', re.DOTALL)


def _stores_a_command_call(row: str) -> bool:
    statement = Ps1Parser(row).parse().body[0]
    return (
        isinstance(statement, Ps1ExpressionStatement)
        and isinstance(statement.expression, Ps1AssignmentExpression)
        and isinstance(statement.expression.value, Ps1CommandInvocation)
    )


def _type_rule(row: str) -> Simplified | None:
    if row not in _TYPES or not _STORED_AND_WRITTEN.fullmatch(row):
        return None
    transcript = TYPE_TRANSCRIPTS.get(row, ())
    if not transcript or any(line.startswith('THROW') for line in transcript):
        return None
    if _stores_a_command_call(row):
        return None
    return Simplified(keeps=('Write-Output', 'Write-Output'), lacks=('$t = ', '(,$t)'))


def _spelling_of_the_raise_that_ends_the_run(
    program: tuple[dispatch.Statement, ...],
    preference: dispatch.Preference,
    on: frozenset[int],
) -> str:
    leaving: list[dispatch.Statement] = []

    def witness(site: dispatch.Statement, outcome: dispatch.Outcome, target: object) -> None:
        if outcome is dispatch.Outcome.LEAVES:
            leaving.append(site)

    dispatch.run(program, preference, on, witness)
    (site,) = leaving
    return "throw 'x'" if isinstance(site, dispatch.Throw) else '[int]'


def _dispatch_rule(name: str) -> Simplified:
    program, preference, on = dispatch.ANCHORS[name]
    transcript = DISPATCH_TRANSCRIPTS[name]
    statements = list(dispatch.statements(program))
    marks = {statement.name for statement in statements if isinstance(statement, dispatch.Mark)}
    values = {statement.value for statement in statements if isinstance(statement, dispatch.Set)}
    keeps = []
    for written in dict.fromkeys(transcript.split(' ')):
        if written in marks:
            keeps.append(F"Write-Host '{written}'")
        elif written in values:
            keeps.append(F"'{written}'")
    if transcript.endswith(dispatch.Event.THREW.value):
        keeps.append(_spelling_of_the_raise_that_ends_the_run(program, preference, on))
    return Simplified(keeps=tuple(keeps), lacks=('$p = ', '$p['))


def _dispatch_rules() -> dict[str, Simplified]:
    return {
        dispatch.render(program, preference, on): _dispatch_rule(name)
        for name, (program, preference, on) in dispatch.ANCHORS.items()
        if name in DISPATCH_TRANSCRIPTS
    }


_DEFECTIVE = frozenset({*BEHAVIOUR_DEFECTS, *TYPE_DEFECTS, *DEFECTS})


def expectations() -> dict[str, Expectation]:
    dispatched = _dispatch_rules()
    expected: dict[str, Expectation] = {}
    for row in oracle_corpus():
        if row in _DEFECTIVE:
            continue
        if row in SIMPLIFIED:
            expected[row] = SIMPLIFIED[row]
        elif row in dispatched:
            expected[row] = dispatched[row]
        elif (rule := _type_rule(row)) is not None:
            expected[row] = rule
    return expected


class TestPs1EverySimplificationTheCorpusExpectsIsMade(unittest.TestCase):

    def test_each_corpus_script_deobfuscates_keeps_what_it_must_and_simplifies_as_expected(self):
        taken = census()
        outputs = taken.outputs
        expected = {row: rule for row, rule in expectations().items() if row in outputs}
        with self.subTest('every corpus script deobfuscates without an error'):
            self.assertEqual(taken.errors, {})
        with self.subTest('no output loses what its script has to keep'):
            lost = [row for row, rule in expected.items() if not rule.kept_by(outputs[row], row)]
            self.assertEqual(sorted(lost), [])
        with self.subTest('every expected simplification is made except the ones not made yet'):
            short = [row for row, rule in expected.items() if not rule.met_by(outputs[row], row)]
            self.assertEqual(sorted(short), sorted(NOT_YET_SIMPLIFIED))

    def test_no_expectation_but_one_kept_as_written_is_met_by_its_script_left_unchanged(self):
        met = [
            row for row, rule in expectations().items()
            if not isinstance(rule, KeptAsWritten) and rule.met_by(_unchanged(row), row)
        ]
        self.assertEqual(sorted(met), [])

    def test_every_expectation_kept_as_written_rejects_its_script_without_its_last_statement(self):
        met = []
        for row, rule in expectations().items():
            if not isinstance(rule, KeptAsWritten):
                continue
            shortened = Ps1Parser(row).parse()
            shortened.body.pop()
            if rule.met_by(Ps1Synthesizer().convert(shortened), row):
                met.append(row)
        self.assertEqual(sorted(met), [])

    def test_no_expectation_accepts_an_empty_output_unless_it_expects_one(self):
        met = [
            row for row, rule in expectations().items()
            if not isinstance(rule, Emptied) and rule.met_by('', row)
        ]
        self.assertEqual(sorted(met), [])

    def test_every_text_an_expectation_keeps_is_in_its_script(self):
        missing = [
            row for row, rule in expectations().items()
            if not rule.kept_by(_unchanged(row), row)
        ]
        self.assertEqual(sorted(missing), [])

    def test_no_text_an_expectation_gains_is_in_its_script_already(self):
        present = []
        for row, rule in expectations().items():
            if not isinstance(rule, Simplified):
                continue
            unchanged = _unchanged(row)
            present.extend(
                (row, text) for text in dict.fromkeys(rule.gains)
                if unchanged.count(text) >= rule.gains.count(text)
            )
        self.assertEqual(sorted(present), [])

    def test_every_hand_written_expectation_is_for_a_corpus_script(self):
        self.assertEqual(sorted(set(SIMPLIFIED) - set(oracle_corpus())), [])

    def test_no_hand_written_expectation_is_for_a_script_the_tool_is_known_to_rewrite_wrongly(self):
        self.assertEqual(sorted(set(SIMPLIFIED) & _DEFECTIVE), [])

    def test_no_folding_pass_stands_in_the_way_of_a_simplification_the_other_passes_make(self):
        missing = {row: rule for row, rule in expectations().items() if row in NOT_YET_SIMPLIFIED}
        for transformer in _folds:
            with self.subTest(switched_off=transformer.__name__):
                with unittest.mock.patch.object(transformer, 'visit', lambda self, node: None):
                    made = [
                        row for row, rule in missing.items() if rule.met_by(_rewritten(row), row)
                    ]
                self.assertEqual(made, [])
