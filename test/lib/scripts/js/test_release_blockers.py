"""
The JavaScript defects a release is held for.

Same form as `test.lib.scripts.js.test_unfixed_defects`, which these entries were separated out of,
and the same rules: every test states what a correct implementation would do, never what the code
does today, and is marked `unittest.expectedFailure`, so an entry that starts passing is reported as
an unexpected success and leaves this file only by being fixed. Where the question is one about
JavaScript rather than about this project, the answer was established with Node.js and is written
into the row the entry holds, so that the only statement of it is the one that is executed.

What sets these apart is what they cost rather than what they are. Each one takes a program an
engine runs and hands back one that behaves differently: nothing throws, nothing is left
half-rewritten, and the analyst reading it gets no signal that the answer is not the one the
language gives. And each is reached by a shape real input plausibly holds: a wrong answer only
a shape constructed for the defect can reach costs no analyst anything, so it lives in the
other file however wrong it is, with the judgment of its unlikelihood written on the entry. An
entry that merely refuses to reduce something, or reduces it to something uglier, belongs in
the other file as well — unless the refusal forfeits the reduction of a whole class of
input, which costs what a wrong answer costs — and so does everything about a file no
engine runs, however clean the answer for one looks: mishandling invalid input is never what a
release is held for. This file emptying is the release gate.

An entry whose programs are spellings of one root is pinned by one test over all of them. An entry
whose programs have roots a fix may reach separately is pinned by one test per program instead,
installed by `test.lib.scripts.js.ledger.one_expected_failure_per_program` and named for the
shape that program holds: a fix that reaches some of the shapes and not the others is then
reported as a fix rather than as nothing at all, which one test over the whole family cannot do.
"""
from __future__ import annotations

import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import node_executable
from test.lib.scripts.js.ledger import (
    Program,
    a_program,
    one_expected_failure_per_program,
    prints,
)


#: Programs writing a value into a variable declared without one in a statement that completes
#: without the write on the run shown, and reading the variable in a function called after that
#: statement, mapped to the behavior an engine gives them.
A_VALUE_STORED_ON_SOME_RUNS_READ_BY_A_FUNCTION = {
    'a store below and, read by a function with a parameter': Program(
        a_program("""
            var c;
            Math.random() > 2 && (c = 5);
            function f(x) { return x + c; }
            console.log(f(Math.random() > 2 ? 1 : 2));
            """),
        prints('NaN'),
    ),
    'a feature test below and, read by a function with a parameter': Program(
        a_program("""
            let o;
            "undefined" != typeof window && (o = !0);
            function n(e) { return e + (o ? " (browser)" : " (node)"); }
            console.log(n(Math.random() > 2 ? 1 : 2));
            """),
        prints('2 (node)'),
    ),
    'a store below and, read by a recursive function': Program(
        a_program("""
            var c;
            Math.random() > 2 && (c = 5);
            function f(n) { return n <= 0 ? c : f(n - 1); }
            console.log(f(2));
            """),
        prints('undefined'),
    ),
    'a store in an arm of a conditional, read by a recursive function': Program(
        a_program("""
            var c;
            Math.random() > 2 ? (c = 5) : 0;
            function f(n) { return n <= 0 ? c : f(n - 1); }
            console.log(f(2));
            """),
        prints('undefined'),
    ),
    'a store behind a logical assignment, read by a recursive function': Program(
        a_program("""
            var c, y = 1;
            y ||= (c = 5);
            function f(n) { return n <= 0 ? c : f(n - 1); }
            console.log(f(2));
            """),
        prints('undefined'),
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(A_VALUE_STORED_ON_SOME_RUNS_READ_BY_A_FUNCTION)
class TestAValueStoredOnSomeRunsIsNotWrittenIntoTheFunctionReadingIt(TestBase):
    """
    Constant inlining writes the one value a variable is given into a function reading it when the
    store runs before every call of that function. The ordering queries of
    `refinery.lib.scripts.js.analysis.dominance.DominanceModel` that it asks answer whether the
    statement holding the store has completed, not whether the store has run, and a store below
    `&&`, in an arm of `?:` or behind `||=` is skipped on runs that complete its statement. The
    function then reads the variable unset while the deobfuscation writes `5` into it. A reader the
    evaluator folds asks
    `refinery.lib.scripts.js.analysis.dominance.DominanceModel.binding_established_before`, which
    also asks whether the store runs with its statement; a reader it leaves is reached by this
    defect. Minifiers spell `if (x) c = 5;` as `x && (c = 5)`, and a test of the host written that
    way, as in the second program, is a shape real input plausibly holds: the deobfuscation keeps
    one branch of the program and gives no sign that it chose. The readers outside constant
    inlining that the same ordering reaches are pinned by
    `TestAValueStoredOnSomeRunsDoesNotDecideATestAfterItsStatement`.
    """


#: Programs storing into a variable or a property in a statement that completes without the store on
#: the run shown, and testing after that statement whether the store ran, mapped to the behavior an
#: engine gives them.
A_VALUE_STORED_ON_SOME_RUNS_DECIDES_A_TEST = {
    'a store below and, deciding an if': Program(
        a_program("""
            var c;
            Math.random() > 2 && (c = {});
            if (c) { console.log("yes"); } else { console.log("no"); }
            """),
        prints('no'),
    ),
    'a store below and, deciding a conditional in a function': Program(
        a_program("""
            var c;
            Math.random() > 2 && (c = {});
            function f() { return c ? "set" : "unset"; }
            console.log(f());
            """),
        prints('unset'),
    ),
    'a key stored below and, asked for with in': Program(
        a_program("""
            var o = {};
            Math.random() > 2 && (o.k = 1);
            console.log("k" in o);
            """),
        prints('false'),
    ),
    'a key stored behind a logical assignment, asked for with in': Program(
        a_program("""
            var o = {}, y = 1;
            y ||= (o.k = 1);
            console.log("k" in o);
            """),
        prints('false'),
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(A_VALUE_STORED_ON_SOME_RUNS_DECIDES_A_TEST)
class TestAValueStoredOnSomeRunsDoesNotDecideATestAfterItsStatement(TestBase):
    """
    The ordering defect of `TestAValueStoredOnSomeRunsIsNotWrittenIntoTheFunctionReadingIt` reaches
    two readers outside constant inlining. The truth of a variable holding an allocation
    (`refinery.lib.scripts.js.deobfuscation.helpers.is_truthy`) and the fold of `in` over the keys a
    program stores on an object (`refinery.lib.scripts.js.deobfuscation.simplify`) each order the
    store before the test with
    `refinery.lib.scripts.js.analysis.dominance.DominanceModel.runs_before` alone, which answers for
    the statement holding the store, so the test is decided as if the store had run. Unlike the
    other entry, an object declared with a value is reached as well. Minifiers spell
    `if (x) o.k = 1;` as `x && (o.k = 1)`, which puts the shape in real input.
    """
