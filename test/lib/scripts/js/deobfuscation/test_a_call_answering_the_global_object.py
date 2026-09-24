"""
A call the deobfuscation replaces with `globalThis` has to answer the global object.

The finder fold replaces a call of a function it recognizes as a global-object finder with
`globalThis`, and the reflection pass replaces the `this` of a `Function`-constructed body with it.
The code such a call runs answers the global object only where its `this` is the global object,
which strict code and a call through an array element deny, and only where the name `globalThis`
it reads reaches the global object, which a `with` object can take over. The replacement then has
to reach the global object where it lands, which a script declaring `var globalThis` takes over.

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

#: Functions that look for the global object and answer something else, each called with no
#: receiver, mapped to what Node prints for them.
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

#: A classic script that stores something else under the name `globalThis` and then asks a
#: `Function`-constructed body for its `this`, mapped to what a host prints for it.
A_CONSTRUCTED_BODY_UNDER_A_REBOUND_GLOBAL_THIS = {
    inspect.cleandoc("""
        var globalThis = 5;
        console.log(Function("return this")() === 5);
    """): 'false\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNodePrintsTheSameAboutACallAnsweringTheGlobalObject(TestBase):

    def test_a_finder_answering_something_else_is_kept(self):
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
