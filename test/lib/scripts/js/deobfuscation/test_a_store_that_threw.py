"""
SECURITY: every program here is hand-authored in this file and benign. No sample and no stored
obfuscator fixture may be fed to this.
"""
from __future__ import annotations

import inspect
import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import node_executable
from test.lib.scripts.js.ledger import before_and_after, each_program_still_prints


def a_program(text: str) -> str:
    return inspect.cleandoc(text) + chr(10)


A_STORE_WHOSE_STATEMENT_THREW = {
    a_program("""
        function f() {
          var r;
          try { r = window; } catch (e) {}
          return r || this;
        }
        console.log(f() === globalThis);
        """): 'true\n',
    a_program("""
        try { var a = window, w = 5; } catch (e) {}
        function g() { return w; }
        console.log(g());
        """): 'undefined\n',
    a_program("""
        function f() {
          var g;
          try { g = window; } catch (e) {}
          try { return g.String; } catch (e) { return e.name; }
        }
        console.log(f());
        """): 'TypeError\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNodePrintsTheSameAboutAStoreWhoseStatementThrew(TestBase):

    def test_a_read_after_the_handler_sees_the_value_from_before_the_store(self):
        rows = A_STORE_WHOSE_STATEMENT_THREW
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )
