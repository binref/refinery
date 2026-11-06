"""
A call the deobfuscation replaces with `globalThis` has to answer the global object.

SECURITY: every program here is hand-authored in this file and benign. No sample and no stored
obfuscator fixture may be fed to this.
"""
from __future__ import annotations

import inspect
import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import node_executable
from test.lib.scripts.js.ledger import (
    before_and_after,
    before_and_after_in_a_host,
    each_program_still_prints,
)

A_FINDER_ANSWERING_SOMETHING_ELSE = {
    inspect.cleandoc("""
        "use strict";
        function getG() { try { return window; } catch (e) { return this; } }
        console.log(typeof getG());
    """): 'undefined\n',
    inspect.cleandoc("""
        function getG() {
          "use strict";
          try { return window; } catch (e) { return this; }
        }
        console.log(typeof getG());
    """): 'undefined\n',
    inspect.cleandoc("""
        function getG() {
          var candidates = [function () { return globalThis; }, function () { return this; }];
          return candidates[1]();
        }
        console.log(Array.isArray(getG()));
    """): 'true\n',
    inspect.cleandoc("""
        var o = { globalThis: 5 };
        with (o) {
          function getG() { try { return window; } catch (e) { return globalThis; } }
        }
        console.log(getG());
    """): '5\n',
}

A_CONSTRUCTED_BODY_UNDER_A_REBOUND_GLOBAL_THIS = {
    inspect.cleandoc("""
        var globalThis = 5;
        console.log(Function("return this")() === 5);
    """): 'false\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNodePrintsTheSameAboutACallAnsweringTheGlobalObject(TestBase):

    def test_a_finder_answering_something_else_still_answers_it(self):
        rows = A_FINDER_ANSWERING_SOMETHING_ELSE
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_constructed_body_keeps_its_receiver_under_a_rebound_global_this(self):
        rows = A_CONSTRUCTED_BODY_UNDER_A_REBOUND_GLOBAL_THIS
        self.assertEqual(
            {source: before_and_after_in_a_host(source) for source in rows},
            each_program_still_prints(rows),
        )
