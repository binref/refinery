"""
Programs calling a decoder in the initializer of a field. The initializer of an instance field runs
each time an instance is constructed, so a built-in the decoder calls may be replaced between the
class statement and the construction, and a fold made as if the call ran at the class statement
reads the built-in that is no longer there.
"""
from __future__ import annotations

import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import node_executable
from test.lib.scripts.js.ledger import (
    a_program,
    before_and_after,
    each_program_still_prints,
)

#: Programs calling a decoder in a field initializer and replacing the built-in it calls after the
#: class statement, mapped to what Node prints for them.
A_DECODER_CALLED_IN_A_FIELD = {
    a_program("""
        var k = process.argv.length > 99 ? "x" : "String";
        var v = { fromCharCode: function () { return "T"; } };
        function d(n) { return String.fromCharCode(n); }
        function f() {
          class A { x = d(65); }
          globalThis[k] = v;
          return new A().x;
        }
        console.log(f());
        """): 'T\n',
    a_program("""
        var s = ["String.fromCharCode = function () { return '!'; }"][0];
        var q = (function () {
          class A { v = function (e, r) {
            var y = [];
            for (var l = 0; l < e.length; l++) { y[l] = e.charAt(l); }
            var u = String.fromCharCode(65);
            return y.join('') + u;
          }('0', 1); }
          (async function () { await eval(s); })();
          return new A().v;
        })();
        console.log(q);
        """): '0!\n',
    a_program("""
        var k = process.argv.length > 99 ? "x" : "String";
        var v = { fromCharCode: function () { return "T"; } };
        function d(n) { return String.fromCharCode(n); }
        function f() {
          class A { static x = d(65); }
          globalThis[k] = v;
          return A.x;
        }
        console.log(f());
        """): 'A\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNodePrintsTheSameAboutADecoderCalledInAField(TestBase):

    def test_each_program_still_prints_the_same(self):
        rows = A_DECODER_CALLED_IN_A_FIELD
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )
