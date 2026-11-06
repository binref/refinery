"""
A call that finds the global object may be rewritten to `globalThis`, and that name has to reach the
global object where it is written: a catch parameter, a block binding or a `var` a direct `eval`
declares can take the name over there.

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


A_GLOBAL_THIS_LANDING_UNDER_A_BINDING_OF_ITS_NAME = {
    a_program("""
        function f() { var r = globalThis.q; return r || this; }
        function g() { eval('var globalThis = 7'); return f() === 7; }
        console.log(g());
        """): 'false\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNodePrintsTheSameAboutAGlobalThisLandingUnderABindingOfItsName(TestBase):

    def test_the_call_keeps_what_it_read(self):
        rows = A_GLOBAL_THIS_LANDING_UNDER_A_BINDING_OF_ITS_NAME
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )
