"""
A `globalThis` the deobfuscation writes has to reach the global object where it lands.

The finder fold writes the name where the program did not: it replaces a call of a recognized
global-object finder with `globalThis`. A catch parameter, a block binding or a `var` a direct `eval`
declares takes the name over at the spot it lands, where the call read something else.

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


#: Programs where a binding of the name `globalThis` stands where a rewrite would write it, mapped
#: to what Node prints for them.
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
        """
        Node prints `false`: the call returns the global object and not the `7` the `eval` declared
        in the caller. The deobfuscation has to print the same.
        """
        rows = A_GLOBAL_THIS_LANDING_UNDER_A_BINDING_OF_ITS_NAME
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )
