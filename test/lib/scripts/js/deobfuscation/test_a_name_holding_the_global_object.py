"""
A name the file gives the global object to is the global object.

`var w = globalThis` and `var w = window || {}` are how a script names the global object once and
reads its properties through the name afterwards, and in a classic script those properties are the
file's own top-level declarations. `refinery.lib.scripts.js.analysis.model.SemanticModel
._name_holds_the_global_object` is what says so, and the references made through such a name are
recorded against the globals they reach — a read so the declaration survives, a write so no value is
folded across it.

The name is asked for its value and never for its spelling, so the cost rows below are the two ways
a name can look like the object and not be one: a name bound to something else, and a name spelled
like the object but bound at all. Each must still fold, or every file holding a `window` parameter
would keep every global it declares.

SECURITY: every program here is hand-authored in this file and benign. No sample and no stored
obfuscator fixture may be fed to this.
"""
from __future__ import annotations

import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import node_executable
from test.lib.scripts.js.ledger import a_program, before_and_after_in_a_host, folded


#: A classic script reading its own globals through a name it put the global object in, mapped to
#: what a host prints for it.
A_NAME_HOLDS_THE_GLOBAL_OBJECT = {
    'a read through the name': a_program("""
        var q = 1;
        var w = globalThis;
        console.log(w.q);
        """),
    'a write through the name': a_program("""
        var q = 1;
        var w = globalThis;
        w.q = 2;
        console.log(q);
        """),
    'a guard names it once': a_program("""
        var q = 1;
        var w = globalThis || {};
        w.q = 2;
        console.log(q);
        """),
    'a call through the name': a_program("""
        var q = function (a) { console.log('q', a); };
        var w = globalThis;
        w.q(1);
        """),
    'a chain of two names': a_program("""
        var q = 1;
        var w = globalThis;
        var v = w;
        console.log(v.q);
        v.q = 2;
        console.log(q);
        """),
    'the name is handed to a call': a_program("""
        var q = 1;
        var w = globalThis;
        function a(g, k) { g[k] = 2; }
        a(w, 'q');
        console.log(q);
        """),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestANameHoldingTheGlobalObjectReachesTheGlobals(TestBase):
    """
    Read under the script execution model, which is the one the unit runs by default and the only one
    in which a top-level declaration is a property of the global object at all.
    """

    def test_every_program_behaves_the_way_the_host_does(self):
        for label, source in A_NAME_HOLDS_THE_GLOBAL_OBJECT.items():
            with self.subTest(label):
                before, after = before_and_after_in_a_host(source)
                self.assertEqual(after, before)


#: Cost-side programs whose fold must not keep a declaration alive through a name that is not the
#: global object, mapped to the text the fold must produce. Each declares a top-level `q` and reads a
#: `q` off a name spelled or shaped like the object but not it, so each must still fold across it.
_A_NAME_THAT_IS_NOT_THE_GLOBAL_OBJECT = {
    'a parameter spelled like the object is not it': (
        a_program("""
            var q = 1;
            function f(window) { console.log(window.q); }
            f({ q: 9 });
            console.log(q);
            """),
        a_program("""
            function f(window) {
              console.log(window.q);
            }
            f({ q: 9 });
            console.log(1);
            """).rstrip(chr(10)),
    ),
    'a name bound to an object literal is not it': (
        a_program("""
            var q = 1;
            var w = { q: 9 };
            console.log(w.q);
            console.log(q);
            """),
        a_program("""
            console.log(9);
            console.log(1);
            """).rstrip(chr(10)),
    ),
    'a name written twice holds no value to read': (
        a_program("""
            var q = 1;
            var w = globalThis;
            w = { q: 9 };
            console.log(w.q);
            console.log(q);
            """),
        a_program("""
            var q = 1;
            var w = globalThis;
            w = { q: 9 };
            console.log(w.q);
            console.log(1);
            """).rstrip(chr(10)),
    ),
    'the right of an and is what the name holds': (
        a_program("""
            var q = 1;
            var w = globalThis && { q: 9 };
            console.log(w.q);
            console.log(q);
            """),
        a_program("""
            var w = globalThis && { q: 9 };
            console.log(w.q);
            console.log(1);
            """).rstrip(chr(10)),
    ),
}


class TestANameThatIsNotTheGlobalObjectStillFolds(TestBase):
    """
    The cost side. Each program declares a `q` at the top level and reads a `q` off a name that is
    not the global object, so a reader answering from the spelling or from a value it cannot pin
    would keep the declaration alive.
    """

    def test_each_cost_row_folds_to_the_pinned_text(self):
        for label, (source, expected) in _A_NAME_THAT_IS_NOT_THE_GLOBAL_OBJECT.items():
            with self.subTest(label):
                self.assertEqual(folded(source), expected)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestANameThatIsNotTheGlobalObjectFoldsWithoutChangingBehaviour(TestBase):
    """
    The pinned text a cost row folds to is not on its own evidence the fold kept the program's
    behavior; a reduction to the wrong value is text too. Read each under the script model the fold
    is written for, so a fold that dropped a live read or moved a value fails here.
    """

    def test_each_cost_row_behaves_the_way_the_host_does(self):
        for label, (source, _) in _A_NAME_THAT_IS_NOT_THE_GLOBAL_OBJECT.items():
            with self.subTest(label):
                before, after = before_and_after_in_a_host(source)
                self.assertEqual(after, before)
