"""
A call with no receiver gives its body the global object: sloppy code replaces the `undefined` that
`f()` passes as `this` with the global object, so such a function reads and writes a classic
script's top-level declarations through `this`.

SECURITY: every program here is hand-authored in this file and benign. No sample and no stored
obfuscator fixture may be fed to this.
"""
from __future__ import annotations

import inspect
import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import node_executable
from test.lib.scripts.js.ledger import before_and_after_in_a_host


def a_program(text: str) -> str:
    return inspect.cleandoc(text) + chr(10)


A_BARE_CALL_READS_THE_GLOBAL_OBJECT = {
    'a bare call reaches a declaration': a_program("""
        var q = function (a) { console.log('q', a); };
        function f() { this.q(1); }
        f();
        """),
    'a bare call reaches a value': a_program("""
        var q = 7;
        function f() { console.log(this.q); }
        f();
        """),
    'a bare call writes what the top level reads': a_program("""
        var q = 1;
        function f() { this.q = 2; }
        f();
        console.log(q);
        """),
}

A_RECEIVER_THAT_IS_NOT_THE_GLOBAL_OBJECT = {
    'a method reads its own property': a_program("""
        var q = 1;
        var o = { q: 7, m: function () { return this.q; } };
        console.log(o.m());
        """),
    'a method writes its own property': a_program("""
        var q = 1;
        var o = { q: 7, m: function () { this.q = 9; return this.q; } };
        console.log(o.m(), q);
        """),
    'a constructed object reads its own property': a_program("""
        var q = 1;
        function C() { this.q = 7; }
        C.prototype.get = function () { return this.q; };
        console.log(new C().get());
        """),
    'a method reaches a reflective name of its own': a_program("""
        var o = {
          eval: function (s) { return 'method:' + s; },
          m: function () { return this.eval('x'); }
        };
        console.log(o.m());
        """),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestABareCallGivesItsBodyTheGlobalObject(TestBase):

    def test_every_program_behaves_the_way_the_host_does(self):
        for label, source in A_BARE_CALL_READS_THE_GLOBAL_OBJECT.items():
            with self.subTest(label):
                before, after = before_and_after_in_a_host(source)
                self.assertEqual(after, before)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAReceiverThatIsNotTheGlobalObjectKeepsItsOwnProperty(TestBase):

    def test_every_program_behaves_the_way_the_host_does(self):
        for label, source in A_RECEIVER_THAT_IS_NOT_THE_GLOBAL_OBJECT.items():
            with self.subTest(label):
                before, after = before_and_after_in_a_host(source)
                self.assertEqual(after, before)
