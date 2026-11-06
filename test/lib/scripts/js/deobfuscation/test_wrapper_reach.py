"""
A wrapper is a function that disables itself when called:

    function W() { W = function () {}; }

A call `W(a, b)` runs `a` and `b` and answers `undefined`, so the deobfuscation writes it as the
statements `a; b;`, which is right only where the call reaches this declaration of `W`.

SECURITY: every program here is hand-authored in this file and benign. No sample and no stored
obfuscator fixture may be fed to this.
"""
from __future__ import annotations

import inspect
import unittest

from typing import NamedTuple

from test import TestBase, opportunity
from test.lib.scripts.js.analysis.differential import node_executable
from test.lib.scripts.js.ledger import before_and_after, folded, printed

NL = chr(10)


def _the_answer(text: str) -> str:
    return inspect.cleandoc(text)


def _a_program(text: str) -> str:
    return _the_answer(text) + NL


def _prints(*lines: str) -> tuple[str, None]:
    return (''.join(line + NL for line in lines), None)


def _throws(error: str) -> tuple[str, str]:
    return ('', error)


class Row(NamedTuple):
    """
    `text` is the text the deobfuscation has to answer with, `None` for the program printed back
    unchanged, and `cleaner` is a better answer that is accepted as well.
    """
    prints: tuple[str, str | None]
    text: str | None = None
    module: bool = False
    cleaner: str | None = None


A_WRAPPER_THE_EXPANSION_IS_WRONG_FOR = {
    _a_program("""
        function W() { W = function () {}; }
        function outer() {
          function W(a) { console.log('real', a); }
          W(1);
        }
        outer();
        W(2);
        """): Row(
        _prints('real 1'),
        _the_answer("""
            function W(a) {
              console.log('real', a);
            }
            W(1);
            2;
            """),
        cleaner=_the_answer("""
            function W(a) {
              console.log('real', a);
            }
            W(1);
            """),
    ),
    _a_program("""
        function W(a) { console.log('outer', a); }
        function outer() {
          function W() { W = function () {}; }
          W(console.log(1));
        }
        outer();
        W(2);
        """): Row(
        _prints('1', 'outer 2'),
        _the_answer("""
            function W(a) {
              console.log('outer', a);
            }
            console.log(1);
            W(2);
            """),
    ),
    _a_program("""
        function W() { W = function () {}; }
        function W(a) { console.log('real', a); }
        W(1);
        """): Row(
        _prints('real 1'),
        cleaner=_the_answer("""
            function W(a) {
              console.log('real', a);
            }
            W(1);
            """),
    ),
    _a_program("""
        function W() { W = function () {}; }
        W = function (a) { console.log('real', a); };
        W(1);
        """): Row(_prints('real 1')),
    _a_program("""
        function W() { W = function () {}; }
        function g(a) { console.log('real', a); }
        W = g;
        W(1);
        """): Row(_prints('real 1')),
    _a_program("""
        function W() { W = function () {}; }
        var W = function (a) { console.log('real', a); };
        W(1);
        """): Row(
        _prints('real 1'),
        cleaner=_the_answer("""
            var W = function(a) {
              console.log('real', a);
            };
            W(1);
            """),
    ),
    _a_program("""
        function W() { W = function () {}; }
        for (var W of [function (a) { console.log('real', a); }]) { W(1); }
        """): Row(_prints('real 1')),
    _a_program("""
        function W() { W = function () {}; }
        for (var W in { a: 1 }) { }
        try { W(console.log(1)); } catch (e) { console.log('threw'); }
        console.log('end');
        """): Row(_prints('1', 'threw', 'end')),
    _a_program("""
        function W() { W = function () {}; }
        var g = W;
        W(0);
        console.log(g === W);
        """): Row(_prints('false')),
    _a_program("""
        var o = {};
        function W() { W = function () {}; }
        with (o) { W = function (a) { console.log('real', a); }; }
        W(1);
        """): Row(_prints('real 1')),
    _a_program("""
        var o = {};
        function W() { W = function () {}; }
        var g;
        with (o) { g = W; }
        W(0);
        console.log(g === W);
        """): Row(_prints('false')),
    _a_program("""
        W(1);
        { function W() { W = function () {}; } }
        console.log('after');
        """): Row(_throws('TypeError')),
    _a_program("""
        function W() { W = function () {}; }
        eval("W = function (a) { console.log(2, a); }");
        W(1);
        """): Row(
        _prints('2 1'),
        _the_answer("""
            function W() {
              W = function() {};
            }
            W = function(a) {
              console.log(2, a);
            };
            W(1);
            """),
    ),
    _a_program("""
        function W(a) { console.log('real', a); }
        function outer() {
          { function W() { W = function () {}; } }
          W(console.log(1));
        }
        outer();
        W(2);
        """): Row(_prints('1', 'real 2')),
    _a_program("""
        function W(a) { console.log('real', a); }
        function outer() {
          L: function W() { W = function () {}; }
          W(console.log(1));
        }
        outer();
        W(2);
        """): Row(_prints('1', 'real 2')),
    _a_program("""
        function W() { W = function () {}; }
        W(console.log(1));
        export { W };
        console.log(2);
        """): Row(_prints('1', '2'), module=True),
}


A_WRAPPER_THE_EXPANSION_IS_RIGHT_FOR = {
    _a_program("""
        function W() { W = function () {}; }
        W(a = 1, b = 2, c = 3);
        console.log(a, b, c);
        """): Row(
        _prints('1 2 3'),
        _the_answer("""
            a = 1;
            b = 2;
            c = 3;
            console.log(a, b, c);
            """),
    ),
    _a_program("""
        W(console.log(1));
        function W() { W = function () {}; }
        console.log(2);
        """): Row(
        _prints('1', '2'),
        _the_answer("""
            console.log(1);
            console.log(2);
            """),
    ),
    _a_program("""
        function W() { W = function () {}; }
        var arr = [1];
        W(...arr);
        W(console.log(3));
        console.log(4);
        """): Row(
        _prints('3', '4'),
        _the_answer("""
            function W() {
              W = function() {};
            }
            var arr = [1];
            W(...arr);
            console.log(3);
            console.log(4);
            """),
        cleaner=_the_answer("""
            var arr = [1];
            console.log(3);
            console.log(4);
            """),
    ),
    _a_program("""
        function W() { W = function () {}; }
        var W;
        W(console.log(5));
        console.log(6);
        """): Row(
        _prints('5', '6'),
        _the_answer("""
            console.log(5);
            console.log(6);
            """),
    ),
    _a_program("""
        var o = {};
        function W() { W = function () {}; }
        with (o) { W(console.log(7)); }
        console.log(8);
        """): Row(
        _prints('7', '8'),
        _the_answer("""
            var o = {};
            with (o) {
              console.log(7);
            }
            console.log(8);
            """),
    ),
    _a_program("""
        function W() { W = function () {}; }
        W(console.log(9));
        export { readFile } from 'node:fs';
        console.log(10);
        """): Row(
        _prints('9', '10'),
        _the_answer("""
            console.log(9);
            export { readFile } from 'node:fs';
            console.log(10);
            """),
        module=True,
    ),
    _a_program("""
        function W() { W = function () {}; }
        W(console.log(11));
        export {};
        console.log(12);
        """): Row(
        _prints('11', '12'),
        _the_answer("""
            console.log(11);
            export {};
            console.log(12);
            """),
        module=True,
    ),
}


AN_APPLICATION_THE_EXPANSION_IS_NOT_WRITTEN_FOR = {
    _a_program("""
        function W() { W = function () {}; }
        console.log(typeof W`x`);
        """): Row(_prints('undefined'), cleaner="console.log('undefined');"),
    _a_program("""
        function W() { W = function () {}; }
        var y = new W();
        console.log(typeof y);
        """): Row(_prints('object')),
}


A_REDUCTION_THE_ADMISSION_GIVES_UP = {
    _a_program("""
        function W() { W = function () {}; }
        W(console.log(0));
        console.log(typeof W);
        """): Row(
        _prints('0', 'function'),
        cleaner=_the_answer("""
            console.log(0);
            console.log('function');
            """),
    ),
    _a_program("""
        function W() { W = function () {}; }
        W(console.log(0));
        console.log(W.name);
        """): Row(
        _prints('0', 'W'),
        cleaner=_the_answer("""
            console.log(0);
            console.log('W');
            """),
    ),
    _a_program("""
        export function W() { W = function () {}; }
        W(console.log(1));
        console.log(2);
        """): Row(_prints('1', '2'), module=True),
}


def _the_text_each_program_has_to_come_back_as(rows: dict[str, Row]) -> dict[str, str]:
    return {
        source: printed(source) if row.text is None else row.text
        for source, row in rows.items()
    }


def _the_texts_each_program_may_come_back_as(rows: dict[str, Row]) -> dict[str, tuple[str, ...]]:
    required = _the_text_each_program_has_to_come_back_as(rows)
    return {
        source: (required[source],) if row.cleaner is None else (required[source], row.cleaner)
        for source, row in rows.items()
    }


def _what_each_program_prints(rows: dict[str, Row]):
    return {source: before_and_after(source, module=row.module) for source, row in rows.items()}


def _what_each_program_printed(rows: dict[str, Row]):
    return {source: (row.prints, row.prints) for source, row in rows.items()}


class TestOnlyACallThatReachesTheWrapperIsExpanded(TestBase):

    def _assert_each_program_comes_back_as_one_of_its_texts(self, rows: dict[str, Row]):
        for source, texts in _the_texts_each_program_may_come_back_as(rows).items():
            with self.subTest(source=source):
                self.assertIn(folded(source), texts)

    def test_a_call_the_expansion_is_wrong_for_is_left_standing(self):
        self._assert_each_program_comes_back_as_one_of_its_texts(
            A_WRAPPER_THE_EXPANSION_IS_WRONG_FOR
        )

    def test_a_wrapper_the_expansion_is_right_for_is_still_expanded(self):
        self._assert_each_program_comes_back_as_one_of_its_texts(
            A_WRAPPER_THE_EXPANSION_IS_RIGHT_FOR
        )

    def test_an_application_the_expansion_is_not_written_for_is_left_standing_or_answered(self):
        self._assert_each_program_comes_back_as_one_of_its_texts(
            AN_APPLICATION_THE_EXPANSION_IS_NOT_WRITTEN_FOR
        )

    def test_a_reduction_the_admission_gives_up_is_given_up_or_made_in_full(self):
        self._assert_each_program_comes_back_as_one_of_its_texts(
            A_REDUCTION_THE_ADMISSION_GIVES_UP
        )

    @opportunity
    def test_a_program_a_row_names_a_cleaner_text_for_comes_back_as_that_text(self):
        rows = {
            source: row
            for group in (
                A_WRAPPER_THE_EXPANSION_IS_WRONG_FOR,
                A_WRAPPER_THE_EXPANSION_IS_RIGHT_FOR,
                AN_APPLICATION_THE_EXPANSION_IS_NOT_WRITTEN_FOR,
                A_REDUCTION_THE_ADMISSION_GIVES_UP,
            )
            for source, row in group.items()
            if row.cleaner is not None
        }
        for source, row in rows.items():
            with self.subTest(source=source):
                self.assertEqual(folded(source), row.cleaner)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestTheProgramPrintsWhatItPrinted(TestBase):

    def test_a_wrapper_the_expansion_is_wrong_for_prints_what_it_printed(self):
        rows = A_WRAPPER_THE_EXPANSION_IS_WRONG_FOR
        self.assertEqual(_what_each_program_prints(rows), _what_each_program_printed(rows))

    def test_a_wrapper_the_expansion_is_right_for_prints_what_it_printed(self):
        rows = A_WRAPPER_THE_EXPANSION_IS_RIGHT_FOR
        self.assertEqual(_what_each_program_prints(rows), _what_each_program_printed(rows))

    def test_an_application_the_expansion_is_not_written_for_prints_what_it_printed(self):
        rows = AN_APPLICATION_THE_EXPANSION_IS_NOT_WRITTEN_FOR
        self.assertEqual(_what_each_program_prints(rows), _what_each_program_printed(rows))

    def test_a_reduction_the_admission_gives_up_was_never_a_wrong_answer(self):
        rows = A_REDUCTION_THE_ADMISSION_GIVES_UP
        self.assertEqual(_what_each_program_prints(rows), _what_each_program_printed(rows))
