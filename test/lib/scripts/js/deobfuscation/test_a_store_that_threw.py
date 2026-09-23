"""
A store inside `try` whose statement threw is not done on the path through the handler.

A handler runs because a statement of its `try` block threw, and a statement that threw before its
store never wrote the value. So a read reached through the handler, or after a handler that
swallowed the throw, sees the value the name held before. Every fold that orders a store before a
read has to ask whether the store's statement completed, not only whether it was entered.

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


#: Programs whose store inside `try` reads a name Node does not define, so the store's statement
#: throws and the handler swallows it, mapped to what Node prints for them.
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
        """
        Node prints what each name held before its store: the finder reads nothing and falls back,
        the later declarator was never reached, and the alias holds `undefined`, so reading a member
        through it throws a `TypeError` rather than the `ReferenceError` reading `window` would. The
        deobfuscation has to print the same.
        """
        rows = A_STORE_WHOSE_STATEMENT_THREW
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )
