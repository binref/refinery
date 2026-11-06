"""
SECURITY: the programs here run in Node, and every one is hand-authored in this file and benign. No
sample and no stored obfuscator fixture may ever be added here.
"""
from __future__ import annotations

import unittest

from test import TestBase, opportunity
from test.lib.scripts.js.analysis.differential import node_executable
from test.lib.scripts.js.ledger import a_program, before_and_after_in_a_host, folded


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
    'the name is given the object after its declaration': a_program("""
        var q = 1;
        var w;
        w = globalThis;
        w.q = 2;
        console.log(q);
        """),
    'the name is rebound to the object': a_program("""
        var secret = 'S';
        var g = {};
        g = globalThis;
        console.log(g.secret);
        """),
    'a chain of five names': a_program("""
        var q = 1;
        var a = globalThis;
        var b = a;
        var c = b;
        var d = c;
        var e = d;
        e.q = 2;
        console.log(q);
        """),
    'two names copying each other': a_program("""
        var q = 1;
        var a, b;
        a = globalThis;
        if (q > 5) { a = b; }
        b = a;
        b.q = 2;
        console.log(q);
        """),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestANameHoldingTheGlobalObjectReachesTheGlobals(TestBase):

    def test_every_program_behaves_the_way_the_host_does(self):
        for label, source in A_NAME_HOLDS_THE_GLOBAL_OBJECT.items():
            with self.subTest(label):
                before, after = before_and_after_in_a_host(source)
                self.assertEqual(after, before)


A_NAME_THAT_MAY_HOLD_THE_GLOBAL_OBJECT = {
    'a call through the name': a_program("""
        function f() { console.log('global'); }
        var w = { f: function () { console.log('own'); } };
        if (Math.random() > 2) { w = globalThis; }
        w.f();
        """),
    'a store through the name': a_program("""
        var o = {};
        var w = { o: {} };
        if (Math.random() > 2) { w = globalThis; }
        w.o.k = 1;
        console.log('k' in o);
        """),
    'a line-break check called through the name': a_program(r"""
        function subject() { return 1; }
        var check = function () { return new RegExp('\n').test(subject); };
        var w = { check: function () { return 'own'; } };
        if (Math.random() > 2) { w = globalThis; }
        console.log(w.check());
        console.log(check());
        """),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestANameThatMayHoldTheGlobalObjectIsNotTakenForIt(TestBase):

    def test_every_program_behaves_the_way_the_host_does(self):
        for label, source in A_NAME_THAT_MAY_HOLD_THE_GLOBAL_OBJECT.items():
            with self.subTest(label):
                before, after = before_and_after_in_a_host(source)
                self.assertEqual(after, before)


_BOTH_READS_FOLDED = a_program("""
    console.log(9);
    console.log(1);
    """).rstrip(chr(10))

_A_NAME_THAT_IS_NOT_THE_GLOBAL_OBJECT = {
    'a parameter spelled like the object is not it': (
        a_program("""
            var q = 1;
            function f(window) { console.log(window.q); }
            f({ q: 9 });
            console.log(q);
            """),
        (
            a_program("""
                function f(window) {
                  console.log(window.q);
                }
                f({ q: 9 });
                console.log(1);
                """).rstrip(chr(10)),
        ),
    ),
    'a name bound to an object literal is not it': (
        a_program("""
            var q = 1;
            var w = { q: 9 };
            console.log(w.q);
            console.log(q);
            """),
        (_BOTH_READS_FOLDED,),
    ),
    'the right of an and is what the name holds': (
        a_program("""
            var q = 1;
            var w = globalThis && { q: 9 };
            console.log(w.q);
            console.log(q);
            """),
        (
            a_program("""
                var w = globalThis && { q: 9 };
                console.log(w.q);
                console.log(1);
                """).rstrip(chr(10)),
            _BOTH_READS_FOLDED,
        ),
    ),
}

_A_NAME_WRITTEN_OVER_AFTER_IT_HELD_THE_OBJECT = (
    a_program("""
        var q = 1;
        var w = globalThis;
        w = { q: 9 };
        console.log(w.q);
        console.log(q);
        """),
    (
        a_program("""
            var w = globalThis;
            w = { q: 9 };
            console.log(w.q);
            console.log(1);
            """).rstrip(chr(10)),
        _BOTH_READS_FOLDED,
    ),
)


class TestANameThatIsNotTheGlobalObjectStillFolds(TestBase):

    def test_each_cost_row_folds_to_one_of_the_pinned_texts(self):
        for label, (source, expected) in _A_NAME_THAT_IS_NOT_THE_GLOBAL_OBJECT.items():
            with self.subTest(label):
                self.assertIn(folded(source), expected)

    def test_a_name_written_over_after_it_held_the_object_lets_the_read_of_q_fold(self):
        source, cleaner = _A_NAME_WRITTEN_OVER_AFTER_IT_HELD_THE_OBJECT
        only_the_plain_read_folded = a_program("""
            var q = 1;
            var w = globalThis;
            w = { q: 9 };
            console.log(w.q);
            console.log(1);
            """).rstrip(chr(10))
        self.assertIn(folded(source), (only_the_plain_read_folded, *cleaner))

    @opportunity
    def test_a_name_written_over_after_it_held_the_object_folds_to_one_of_the_pinned_texts(self):
        source, expected = _A_NAME_WRITTEN_OVER_AFTER_IT_HELD_THE_OBJECT
        self.assertIn(folded(source), expected)

    @opportunity
    def test_a_read_through_a_name_holding_an_object_literal_folds_to_its_value(self):
        right_of_an_and = 'the right of an and is what the name holds'
        sources = {
            'a name written over after it held the object': _A_NAME_WRITTEN_OVER_AFTER_IT_HELD_THE_OBJECT[0],
            right_of_an_and: _A_NAME_THAT_IS_NOT_THE_GLOBAL_OBJECT[right_of_an_and][0],
        }
        for label, source in sources.items():
            with self.subTest(label):
                self.assertEqual(folded(source), _BOTH_READS_FOLDED)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestANameThatIsNotTheGlobalObjectFoldsWithoutChangingBehaviour(TestBase):

    def test_each_cost_row_behaves_the_way_the_host_does(self):
        for label, (source, _) in {
            **_A_NAME_THAT_IS_NOT_THE_GLOBAL_OBJECT,
            'a name written over after it held the object': _A_NAME_WRITTEN_OVER_AFTER_IT_HELD_THE_OBJECT,
        }.items():
            with self.subTest(label):
                before, after = before_and_after_in_a_host(source)
                self.assertEqual(after, before)
