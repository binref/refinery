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


#: Programs reading a variable in the initializer of an instance field and changing the variable
#: between the class statement and the construction, mapped to the behavior an engine gives them.
A_VARIABLE_READ_BY_A_FIELD_WHEN_AN_INSTANCE_IS_CONSTRUCTED = {
    'a var reassigned after the class': Program(
        a_program("""
            function f() { var x = 1; class A { v = x; } x = 2; return new A().v; }
            console.log(f());
            """),
        prints('2'),
    ),
    'a let assigned after the class': Program(
        a_program("""
            function f() { let x; class A { v = x; } x = 2; return new A().v; }
            console.log(f());
            """),
        prints('2'),
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(A_VARIABLE_READ_BY_A_FIELD_WHEN_AN_INSTANCE_IS_CONSTRUCTED)
class TestAFieldReadsAVariableWhenAnInstanceIsConstructed(TestBase):
    """
    The initializer of an instance field runs each time an instance is constructed, as the body of a
    function the class calls then would. The control-flow graph of the function holding the class
    places it at the class statement instead, so the read in the field is taken to happen before
    `x = 2`: the dead-store removal drops that store as one nothing reads, and constant inlining
    writes the earlier value into the field. A class whose fields read state the program sets after
    declaring the class is a shape real input plausibly holds.
    """
