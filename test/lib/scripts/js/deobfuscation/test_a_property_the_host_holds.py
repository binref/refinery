"""
A property the global object holds before a script runs: `Math` in every host, `top`, `history`
and `status` in a browser window. A `var` of such a name at the top of a classic script declares no
property of its own but names the host's, so no pass may turn a variable of the program into one
(`refinery.lib.scripts.js.analysis.model.SemanticModel.lands_on_the_host`), and where the property
keeps a value of its own when a store is made into it, the program's own `var` of the name is not
read as a variable either, nor is a store into it dropped as one nothing reads
(`refinery.lib.scripts.js.analysis.model.SemanticModel.held_by_the_host`).
Each program is written by hand, and each row says what Node prints for it, run as a classic
script, in the window `test.lib.scripts.js.ledger` sets up where the row says so.
"""
from __future__ import annotations

import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import node_executable
from test.lib.scripts.js.ledger import Program, Reading, a_program, before_and_after, folded, prints

from refinery.lib.scripts.js.analysis.environment import HostEnvironment

#: Classic scripts keeping a value in a variable or key of their own named like a property the global
#: object holds, mapped to what a host prints for each: the host's property never holds the value.
A_VALUE_OF_ITS_OWN_NAMED_LIKE_A_PROPERTY_THE_HOST_HOLDS: dict[str, Program] = {
    'a key top of an object of its own': Program(
        a_program("""
            var pos = {};
            pos.top = String(Math.random() < 2);
            pos.left = String(Math.random() < 2);
            console.log(pos.top + pos.left);
            """),
        prints('truetrue', 'onload=undefined'),
        Reading.WINDOW,
    ),
    'a key Math of an object of its own that nothing stores': Program(
        a_program("""
            var o = {};
            console.log(o.Math);
            """),
        prints('undefined'),
        Reading.SCRIPT,
    ),
    'a var history of a function called once': Program(
        a_program("""
            function f() { var history = [Date.now()]; history.push(1); console.log(history.length); }
            f();
            """),
        prints('2', 'onload=undefined'),
        Reading.WINDOW,
    ),
    'a var status of a Function body': Program(
        a_program("""
            Function("var status = [Date.now()]; status.push(1); console.log(status.length);")();
            """),
        prints('2', 'onload=undefined'),
        Reading.WINDOW,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAValueOfItsOwnNamedLikeAPropertyTheHostHoldsStaysItsOwn(TestBase):

    def test_a_host_prints_what_each_row_pins(self):
        for label, row in A_VALUE_OF_ITS_OWN_NAMED_LIKE_A_PROPERTY_THE_HOST_HOLDS.items():
            with self.subTest(label=label):
                self.assertEqual(row.behaves(), row.prints)

    def test_each_program_still_prints_it_after_the_deobfuscation(self):
        for label, row in A_VALUE_OF_ITS_OWN_NAMED_LIKE_A_PROPERTY_THE_HOST_HOLDS.items():
            with self.subTest(label=label):
                self.assertEqual(row.read(), row.required())


#: Classic scripts storing into a property the global object holds and keeps a value of its own in,
#: under a `var` at their top or a name they never declare, mapped to what a host prints for each:
#: a store into it is ignored, or kept as a string.
A_NAME_OF_A_PROPERTY_THE_HOST_KEEPS_ITS_OWN_VALUE_IN: dict[str, Program] = {
    'a number stored into the var status and compared': Program(
        a_program("""
            var status;
            function f(n) {
              status = n;
              return status === n;
            }
            console.log(f(404));
            """),
        prints('false', 'onload=undefined'),
        Reading.WINDOW,
    ),
    'a number stored into the var top and compared': Program(
        a_program("""
            var top = 5;
            console.log(top === 5);
            """),
        prints('false', 'onload=undefined'),
        Reading.WINDOW,
    ),
    'a number stored into the var NaN and read back': Program(
        a_program("""
            var NaN = 5;
            console.log(NaN);
            """),
        prints('NaN'),
        Reading.SCRIPT,
    ),
    'a number stored into the var undefined by a function': Program(
        a_program("""
            var undefined;
            function f() { undefined = 5; return undefined; }
            console.log(f());
            """),
        prints('undefined'),
        Reading.SCRIPT,
    ),
    'an object with a toString of its own stored into status': Program(
        a_program("""
            var c = 0;
            status = { toString: function () { c = 1; return 'x'; } };
            console.log(c);
            """),
        prints('1', 'onload=undefined'),
        Reading.WINDOW,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestANameOfAPropertyTheHostKeepsItsOwnValueInIsNoVariable(TestBase):

    def test_a_host_prints_what_each_row_pins(self):
        for label, row in A_NAME_OF_A_PROPERTY_THE_HOST_KEEPS_ITS_OWN_VALUE_IN.items():
            with self.subTest(label=label):
                self.assertEqual(row.behaves(), row.prints)

    def test_each_program_still_prints_it_after_the_deobfuscation(self):
        for label, row in A_NAME_OF_A_PROPERTY_THE_HOST_KEEPS_ITS_OWN_VALUE_IN.items():
            with self.subTest(label=label):
                self.assertEqual(row.read(), row.required())


#: A strict region assigning to one of the global names that is not writable, mapped to the behavior
#: Node gives it: the pair of what it prints and what it throws. The write is refused in every row,
#: so the statement does exactly one thing and that thing is throw. What varies is where the mode
#: comes from, how the assignment is spelled, and whether anything catches what it throws.
A_STRICT_REGION_ASSIGNING_TO_A_NON_WRITABLE_GLOBAL = {
    "'use strict';\nNaN = 1;\nconsole.log(1);\n": ('', 'TypeError'),
    "'use strict';\nundefined = 1;\nconsole.log(1);\n": ('', 'TypeError'),
    "'use strict';\nInfinity = 1;\nconsole.log(1);\n": ('', 'TypeError'),
    "'use strict';\n(NaN) = 1;\nconsole.log(1);\n": ('', 'TypeError'),
    "'use strict';\n[NaN] = [1];\nconsole.log(1);\n": ('', 'TypeError'),
    "'use strict';\n({p: undefined} = {p: 1});\nconsole.log(1);\n": ('', 'TypeError'),
    "(function () { 'use strict'; NaN = 1; console.log(1); })();\n": ('', 'TypeError'),
    "var out = 'L';\nclass C { static { NaN = 1; } }\nconsole.log(out);\n": ('', 'TypeError'),
    "'use strict';\ntry { NaN = 1; console.log('L'); }"
    " catch (e) { console.log(e.constructor.name); }\n": ('TypeError\n', None),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAWriteTheModeRefusesThrows(TestBase):

    def test_an_assignment_to_a_non_writable_global_throws_in_a_strict_region(self):
        rows = A_STRICT_REGION_ASSIGNING_TO_A_NON_WRITABLE_GLOBAL
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            {source: (answer, answer) for source, answer in rows.items()},
        )


class TestAPropertyABrowserKeepsItsOwnValueInIsNotReadAsAVariable(TestBase):

    def test_the_type_of_a_number_stored_into_status_is_not_folded_to_number(self):
        source = 'var status = 1; console.log(typeof status);'
        self.assertNotIn("'number'", folded(source, environment=HostEnvironment.browser))

    def test_a_strict_store_into_top_which_throws_is_kept(self):
        source = "'use strict'; top = 1; console.log('after');"
        self.assertIn('top = 1', folded(source, environment=HostEnvironment.browser))


class TestAPropertyTheHostHoldsLeavesTheFoldsOfAVariable(TestBase):

    def test_a_var_of_a_property_that_gives_back_what_is_stored_is_folded(self):
        source = a_program("""
            var Math = 5;
            console.log(Math);
            """)
        self.assertEqual(folded(source), 'console.log(5);')

    def test_a_key_top_of_an_object_of_its_own_is_folded(self):
        source = a_program("""
            var C = {};
            C.top = 'svc';
            C.url = 'http://x.test/a';
            console.log(C.top, C.url);
            """)
        self.assertEqual(folded(source), "console.log('svc', 'http://x.test/a');")

    def test_a_function_called_once_declaring_history_is_inlined(self):
        source = a_program("""
            function main() { var history = [prompt()]; console.log(history.length); }
            main();
            """)
        self.assertNotIn('main', folded(source))
