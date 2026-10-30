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
    Reading,
    a_program,
    one_expected_failure_per_program,
    prints,
)

from refinery.lib.scripts.js.analysis.environment import HostEnvironment


#: Programs reading or writing a variable in the initializer of an instance field, and changing or
#: reading the variable between the class statement and the construction, mapped to the behavior an
#: engine gives them.
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
    'a file-level var a field of a class its function returns reads': Program(
        a_program("""
            var x;
            function f(n) {
              x = n;
              console.log(x);
              return class { y = x; };
            }
            var C = f(1);
            f(2);
            console.log(new C().y);
            """),
        prints('1', '2', '2'),
        Reading.COMMONJS,
    ),
    'a var a field writes and a function reads across a construction': Program(
        a_program("""
            var x = 1;
            class C { y = (x = 2); }
            function h() { var t = x; new C(); return t; }
            console.log(h());
            """),
        prints('1'),
        Reading.COMMONJS,
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

    The same placement hides the field from the questions asked about the function around it. A
    file-level `var` the function writes and a field reads is moved into the function, so each
    class it returns keeps the value of the run that made it rather than the last one stored. And a
    write in a field is not seen at `new C()`, so a value read before the construction is taken to
    hold after it.
    """


#: Classic scripts storing into a name a browser window defines as an attribute of the global
#: object, mapped to the behavior a window gives them: a load handler the window calls once the
#: script has run, and a `DOMString` attribute, which keeps what is stored into it as a string.
A_STORE_TO_A_NAME_A_WINDOW_INTERCEPTS = {
    'a load handler stored at the top': Program(
        a_program("""
            onload = function () { console.log('loaded'); };
            """),
        prints('loaded', 'onload=undefined'),
        Reading.WINDOW,
    ),
    'a load handler stored at the top, read for a browser': Program(
        a_program("""
            onload = function () { console.log('loaded'); };
            """),
        prints('loaded', 'onload=undefined'),
        Reading.WINDOW,
        HostEnvironment.browser,
    ),
    'a load handler stored by a function the script calls': Program(
        a_program("""
            function install() { onload = function () { console.log('loaded'); }; }
            install();
            """),
        prints('loaded', 'onload=undefined'),
        Reading.WINDOW,
    ),
    'a load handler stored into a var by a function the script calls': Program(
        a_program("""
            var onload;
            function install() { onload = function () { console.log('loaded'); }; }
            install();
            """),
        prints('loaded', 'onload=undefined'),
        Reading.WINDOW,
    ),
    'a number stored into the var name and read back': Program(
        a_program("""
            var name;
            function f(n) {
              name = n;
              return name + 1;
            }
            console.log(f(5));
            """),
        prints('51', 'onload=undefined'),
        Reading.WINDOW,
    ),
    'a number stored into the var status and compared': Program(
        a_program("""
            var status;
            function f(n) {
              status = n;
              return status === n;
            }
            console.log(f(404));
            """),
        prints('false', 'onload=undefined'),
        Reading.WINDOW,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
@one_expected_failure_per_program(A_STORE_TO_A_NAME_A_WINDOW_INTERCEPTS)
class TestAStoreToANameAWindowInterceptsIsKept(TestBase):
    """
    A browser window defines some names on the global object before a script runs: `onload` holds
    the handler the window calls once the script has run, and `name` and `status` keep what is
    stored into them as a string. A store into such a name, or into a file-level `var` of it, which
    is that same property, is read by the window or converted on the way in. The deobfuscation
    reads it as a store into a variable of the script: a handler nothing in the script calls is
    deleted, also where the host is a browser, and a `var` of such a name is moved into the
    function using it, where it is a plain local that keeps a number. Scripts installing a load
    handler are common among the ones run in a browser.
    """
