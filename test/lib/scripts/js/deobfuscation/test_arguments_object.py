from __future__ import annotations

import inspect
import unittest

from typing import Mapping, NamedTuple

from test import opportunity
from test.lib.scripts.js.analysis.differential import behavior, node_executable

from refinery.units.scripting.djs import djs


class _Row(NamedTuple):
    printed: str
    text: str


class _StandingRow(NamedTuple):
    printed: str
    standing: str
    folded: str


_AN_ADMITTED_OBJECT_ANSWERS: dict[str, _Row] = {
    'function f() { return arguments.length; } console.log(f(1, 2));': _Row(
        '2\n', 'console.log(2);',
    ),
    'function f() { return arguments.length; } console.log(f());': _Row(
        '0\n', 'console.log(0);',
    ),
    "function f() { return arguments[0]; } console.log(f('a'));": _Row(
        'a\n', "console.log('a');",
    ),
    "function f() { return arguments[1]; } console.log(f('a', 'b'));": _Row(
        'b\n', "console.log('b');",
    ),
    "function f() { for (var p = 0; p < arguments.length; p++) return arguments[p]; }"
    " console.log(f('q'));": _Row('q\n', "console.log('q');"),
    "function f(a) { return arguments.length; } console.log(f(1));": _Row(
        '1\n', 'console.log(1);',
    ),
    "var r = (function () { 'use strict'; return arguments.length; })(3); console.log(r);": _Row(
        '1\n', 'console.log(1);',
    ),
    "var r = (function (a) { 'use strict'; a = 2; return arguments[0]; })(1);"
    " console.log(r);": _Row('1\n', 'console.log(1);'),
    'var r = (function () { var arguments; return arguments.length; })(1); console.log(r);':
        _Row('1\n', 'console.log(1);'),
    'var r = (function () { var arguments = [7]; return arguments[0]; })(1); console.log(r);':
        _Row('7\n', 'console.log(7);'),
}

_AN_OBJECT_THE_CALL_CANNOT_MODEL: dict[str, _StandingRow] = {
    'function f(a) { a = 2; return arguments[0]; } console.log(f(1));': _StandingRow(
        '2\n',
        inspect.cleandoc(
            """
            function f(a) {
              a = 2;
              return arguments[0];
            }
            console.log(f(1));
            """
        ),
        'console.log(2);',
    ),
    'function f(a) { a++; return arguments[0]; } console.log(f(1));': _StandingRow(
        '2\n',
        inspect.cleandoc(
            """
            function f(a) {
              a++;
              return arguments[0];
            }
            console.log(f(1));
            """
        ),
        'console.log(2);',
    ),
    'function f(a) { for (a of [5]) {} return arguments[0]; } console.log(f(1));': _StandingRow(
        '5\n',
        inspect.cleandoc(
            """
            function f(a) {
              for (a of [5]) {}
              return arguments[0];
            }
            console.log(f(1));
            """
        ),
        'console.log(5);',
    ),
    'function f(a) { var g = function () { a = 9; }; g(); return arguments[0]; }'
    ' console.log(f(1));': _StandingRow(
        '9\n',
        inspect.cleandoc(
            """
            function f(a) {
              var g = function() {
                a = 9;
              };
              g();
              return arguments[0];
            }
            console.log(f(1));
            """
        ),
        'console.log(9);',
    ),
    "function f() { return arguments['callee'].name; } console.log(f());": _StandingRow(
        'f\n',
        inspect.cleandoc(
            """
            function f() {
              return arguments.callee.name;
            }
            console.log(f());
            """
        ),
        "console.log('f');",
    ),
    'function f() { return Array.isArray(arguments); } console.log(f());': _StandingRow(
        'false\n',
        inspect.cleandoc(
            """
            function f() {
              return Array.isArray(arguments);
            }
            console.log(f());
            """
        ),
        'console.log(false);',
    ),
    "function f() { return arguments[5]; } console.log(f('a'));": _StandingRow(
        'undefined\n',
        inspect.cleandoc(
            """
            function f() {
              return arguments[5];
            }
            console.log(f('a'));
            """
        ),
        'console.log(void 0);',
    ),
    "function f() { return arguments['+1']; } console.log(f('a'));": _StandingRow(
        'undefined\n',
        inspect.cleandoc(
            """
            function f() {
              return arguments['+1'];
            }
            console.log(f('a'));
            """
        ),
        'console.log(void 0);',
    ),
}


def _deobfuscated(source: str) -> str:
    return source.encode('utf8') | djs(strict=True) | str


def _printed(rows: Mapping[str, _Row | _StandingRow]) -> dict[str, tuple[str, str | None]]:
    return {source: (row.printed, None) for source, row in rows.items()}


def _deobfuscated_text(rows: dict[str, _Row]) -> dict[str, str]:
    return {source: row.text for source, row in rows.items()}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnAdmittedArgumentsObjectAnswersWhatItReads(unittest.TestCase):

    def test_node_answers_each_program_the_way_the_row_records(self):
        rows = _AN_ADMITTED_OBJECT_ANSWERS
        self.assertEqual({source: behavior(source) for source in rows}, _printed(rows))

    def test_the_deobfuscation_answers_it_the_same_way(self):
        rows = _AN_ADMITTED_OBJECT_ANSWERS
        self.assertEqual(
            {source: behavior(_deobfuscated(source)) for source in rows},
            _printed(rows),
        )

    def test_the_deobfuscation_writes_the_text_the_row_records(self):
        rows = _AN_ADMITTED_OBJECT_ANSWERS
        self.assertEqual({source: _deobfuscated(source) for source in rows}, _deobfuscated_text(rows))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnObjectTheCallCannotModel(unittest.TestCase):

    def test_node_answers_each_program_the_way_the_row_records(self):
        rows = _AN_OBJECT_THE_CALL_CANNOT_MODEL
        self.assertEqual({source: behavior(source) for source in rows}, _printed(rows))

    def test_the_deobfuscation_answers_it_the_same_way(self):
        rows = _AN_OBJECT_THE_CALL_CANNOT_MODEL
        self.assertEqual(
            {source: behavior(_deobfuscated(source)) for source in rows},
            _printed(rows),
        )

    def test_the_deobfuscation_leaves_the_call_standing_or_folds_it(self):
        for source, row in _AN_OBJECT_THE_CALL_CANNOT_MODEL.items():
            with self.subTest(source=source):
                self.assertIn(_deobfuscated(source), (row.standing, row.folded))

    @opportunity
    def test_the_deobfuscation_folds_the_call_to_the_value_node_prints(self):
        rows = _AN_OBJECT_THE_CALL_CANNOT_MODEL
        self.assertEqual(
            {source: _deobfuscated(source) for source in rows},
            {source: row.folded for source, row in rows.items()},
        )
