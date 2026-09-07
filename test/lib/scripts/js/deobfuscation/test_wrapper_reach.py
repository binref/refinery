"""
A call is expanded only where it reaches the wrapper.

`refinery.lib.scripts.js.deobfuscation.argwrap` expands the self-disabling wrapper an obfuscator
writes statement sequences as calls to:

    function W() { W = function () {}; }

called as `W(a, b)`, which runs `a` and `b`, disables itself, and answers `undefined`, so such a
call is the statements it carries and nothing else. Which call that is, is a question about the
binding the callee reads. A program may hold a second declaration answering to the same name, may
rebind the name before the call, may observe which of the two functions the name holds after it,
and may hand the name to a scope object or to an `eval` that no reading of the text answers.

Each program here is asked twice. The un-gated question is the exact text the deobfuscation answers
with, which is what says a wrapper the pass refuses is left standing whole rather than quietly
half-expanded, and which is the reading a machine with no Node.js still gets. The gated question is
what the program prints, before and after, with Node deciding
`test.lib.scripts.js.ledger.before_and_after`, so the execution model is the module one, in which a
top-level declaration never reaches the global object.

The other reason a call to a wrapper-shaped function is not the statements it carries — an `async`
or generator body, whose call answers a promise or a generator object rather than `undefined` — is
asked in `test.lib.scripts.js.deobfuscation.test_call_answers_a_wrapper`, whose two `argwrap` groups
hold it.

SECURITY: every program here is hand-authored in this file and benign. No sample and no stored
obfuscator fixture may be fed to this.
"""
from __future__ import annotations

import inspect
import unittest

from typing import NamedTuple

from test import TestBase
from test.lib.scripts.js.analysis.differential import node_executable
from test.lib.scripts.js.ledger import before_and_after, folded, printed

NL = chr(10)


def _the_answer(text: str) -> str:
    """
    A text the deobfuscation answers with, which carries no break after its last line.
    """
    return inspect.cleandoc(text)


def _a_program(text: str) -> str:
    """
    A program as a file holds it, its last line ending in a break too.
    """
    return _the_answer(text) + NL


def _prints(*lines: str) -> tuple[str, None]:
    """
    What a program prints: the lines it writes, each ending in the break `console.log` adds, and the
    empty text for a program that writes none.
    """
    return (''.join(line + NL for line in lines), None)


def _throws(error: str) -> tuple[str, str]:
    return ('', error)


class Row(NamedTuple):
    """
    What Node makes of one program, the text the deobfuscation has to answer it with, and the
    execution model both are read under.

    `text` is `None` where that text is the program itself, spelled back out and otherwise
    untouched, which is what a wrapper the pass may not expand costs it.
    """
    prints: tuple[str, str | None]
    text: str | None = None
    module: bool = False


#: A program the expansion is not equivalent for, mapped to what Node makes of it and to the text
#: the deobfuscation has to answer with. Each of them holds a name that answers to a wrapper and
#: says something other than the wrapper about what a call to it runs: a second declaration the call
#: reads instead, a value put into the name before the call, or a read that tells the wrapper from
#: what the call left behind. Every one of them was a wrong answer while the pass picked its call
#: sites, and the declaration it removed, by that name.
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
            function outer() {
              function W(a) {
                console.log('real', a);
              }
              W(1);
            }
            outer();
            2;
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
            function outer() {
              console.log(1);
            }
            outer();
            W(2);
            """),
    ),
    _a_program("""
        function W() { W = function () {}; }
        function W(a) { console.log('real', a); }
        W(1);
        """): Row(_prints('real 1')),
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
        """): Row(_prints('real 1')),
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


#: The shape the pass exists for, and the shapes beside it a call does reach, mapped to what Node
#: makes of each and to the text the deobfuscation answers with. A rule that refuses more than it
#: says is caught here rather than by a suite that stayed green because nothing was left to expand
#: at all: what a program prints cannot see a refusal, and only the text can.
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


#: A program whose only reference to a wrapper applies it in a way no expansion is written for,
#: mapped to what Node makes of it. A tagged template and a construction each hand the wrapper
#: something a statement list cannot say, so the whole declaration is refused and the file comes
#: back as it went in. These are refusals and belong beside the expansions rather than among them:
#: a group asserting that a rule refuses no more than it says cannot be witnessed by a row the rule
#: refuses outright.
AN_APPLICATION_THE_EXPANSION_IS_NOT_WRITTEN_FOR = {
    _a_program("""
        function W() { W = function () {}; }
        console.log(typeof W`x`);
        """): Row(_prints('undefined')),
    _a_program("""
        function W() { W = function () {}; }
        var y = new W();
        console.log(typeof y);
        """): Row(_prints('object')),
}


#: A program the pass answered correctly while it read names, and no longer reduces now that a call
#: has to reach the wrapper before it is expanded. Nothing here was ever a wrong answer, and each
#: row states what the rule costs: a name read for anything other than the call it makes, and a
#: declaration another file may name.
A_REDUCTION_THE_ADMISSION_GIVES_UP = {
    _a_program("""
        function W() { W = function () {}; }
        W(console.log(0));
        console.log(typeof W);
        """): Row(_prints('0', 'function')),
    _a_program("""
        function W() { W = function () {}; }
        W(console.log(0));
        console.log(W.name);
        """): Row(_prints('0', 'W')),
    _a_program("""
        export function W() { W = function () {}; }
        W(console.log(1));
        console.log(2);
        """): Row(_prints('1', '2'), module=True),
}


def _the_text_each_program_comes_back_as(rows: dict[str, Row]) -> dict[str, str]:
    return {source: folded(source) for source in rows}


def _the_text_each_program_has_to_come_back_as(rows: dict[str, Row]) -> dict[str, str]:
    return {
        source: printed(source) if row.text is None else row.text
        for source, row in rows.items()
    }


def _what_each_program_prints(rows: dict[str, Row]):
    return {source: before_and_after(source, module=row.module) for source, row in rows.items()}


def _what_each_program_printed(rows: dict[str, Row]):
    return {source: (row.prints, row.prints) for source, row in rows.items()}


class TestOnlyACallThatReachesTheWrapperIsExpanded(TestBase):
    """
    What each program comes back as, read from the text and from nothing else, so that the rule is
    reported on a machine with no Node.js as well.
    """

    def test_a_wrapper_the_expansion_is_wrong_for_is_left_standing(self):
        rows = A_WRAPPER_THE_EXPANSION_IS_WRONG_FOR
        self.assertEqual(
            _the_text_each_program_comes_back_as(rows),
            _the_text_each_program_has_to_come_back_as(rows),
        )

    def test_a_wrapper_the_expansion_is_right_for_is_still_expanded(self):
        rows = A_WRAPPER_THE_EXPANSION_IS_RIGHT_FOR
        self.assertEqual(
            _the_text_each_program_comes_back_as(rows),
            _the_text_each_program_has_to_come_back_as(rows),
        )

    def test_an_application_the_expansion_is_not_written_for_is_left_standing(self):
        rows = AN_APPLICATION_THE_EXPANSION_IS_NOT_WRITTEN_FOR
        self.assertEqual(
            _the_text_each_program_comes_back_as(rows),
            _the_text_each_program_has_to_come_back_as(rows),
        )

    def test_a_reduction_the_admission_gives_up_is_given_up(self):
        rows = A_REDUCTION_THE_ADMISSION_GIVES_UP
        self.assertEqual(
            _the_text_each_program_comes_back_as(rows),
            _the_text_each_program_has_to_come_back_as(rows),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestTheProgramPrintsWhatItPrinted(TestBase):
    """
    Node is the oracle for every value here: what it makes of the program, and what it makes of the
    text the deobfuscation answers with, have to be the same thing.
    """

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
