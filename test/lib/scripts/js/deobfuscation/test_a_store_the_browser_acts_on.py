"""
A store into a property of the global object whose value a browser reads: a store into `location`
navigates the window, and what is stored into `name` is kept for the next page. No read of the
property shows in the file, so the store is never dead, and no pass may turn a variable of the
program into such a property
(`refinery.lib.scripts.js.analysis.model.SemanticModel.host_reaches_global`). Each program is
written by hand, and each row says what Node prints for it run as a classic script in the window
`test.lib.scripts.js.ledger` sets up.
"""
from __future__ import annotations

import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import node_executable
from test.lib.scripts.js.deobfuscation.test_dispatcher import a_dispatcher
from test.lib.scripts.js.ledger import Program, Reading, a_program, folded, prints

from refinery.lib.scripts.js.analysis.environment import HostEnvironment

#: Classic scripts storing an address into `location`, mapped to what a browser window prints for
#: each.
A_NAVIGATION_A_WINDOW_MAKES: dict[str, Program] = {
    'an address stored at the top': Program(
        a_program("""
            location = 'http://x.test/';
            """),
        prints('navigate http://x.test/', 'onload=undefined'),
        Reading.WINDOW,
    ),
    'an address stored into a var': Program(
        a_program("""
            var location = 'http://x.test/';
            """),
        prints('navigate http://x.test/', 'onload=undefined'),
        Reading.WINDOW,
    ),
    'an address stored through globalThis': Program(
        a_program("""
            globalThis.location = 'http://x.test/';
            """),
        prints('navigate http://x.test/', 'onload=undefined'),
        Reading.WINDOW,
    ),
    'an address stored through the window, read for a browser': Program(
        a_program("""
            window.location = 'http://x.test/';
            """),
        prints('navigate http://x.test/', 'onload=undefined'),
        Reading.WINDOW,
        HostEnvironment.browser,
    ),
    'an address stored by a function the script calls': Program(
        a_program("""
            function go(u) { location = u; }
            go('http://x.test/');
            """),
        prints('navigate http://x.test/', 'onload=undefined'),
        Reading.WINDOW,
    ),
    'an address stored by a function called where it is written': Program(
        a_program("""
            (function () { location = 'http://x.test/'; })();
            """),
        prints('navigate http://x.test/', 'onload=undefined'),
        Reading.WINDOW,
    ),
    'an address a decoder builds': Program(
        a_program("""
            function d(s) {
              var r = '';
              for (var i = 0; i < s.length; i++) r += String.fromCharCode(s.charCodeAt(i) - 1);
              return r;
            }
            location = d('iuuq;00y/uftu0');
            """),
        prints('navigate http://x.test/', 'onload=undefined'),
        Reading.WINDOW,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestANavigationIsKept(TestBase):

    def test_a_window_prints_what_each_row_pins(self):
        for label, row in A_NAVIGATION_A_WINDOW_MAKES.items():
            with self.subTest(label=label):
                self.assertEqual(row.behaves(), row.prints)

    def test_each_program_still_prints_it_after_the_deobfuscation(self):
        for label, row in A_NAVIGATION_A_WINDOW_MAKES.items():
            with self.subTest(label=label):
                self.assertEqual(row.read(), row.required())


#: Classic scripts keeping a value in a variable or key of their own named like a property whose
#: value the window reads, mapped to what a browser window prints for each: the window never sees
#: the value.
A_VALUE_OF_ITS_OWN_NAMED_LIKE_A_PROPERTY_THE_WINDOW_READS: dict[str, Program] = {
    'an address stored under the key location': Program(
        a_program("""
            var cfg = {};
            cfg.location = String(Math.random() < 2 ? 'http://x.test/' : '');
            console.log(cfg.location);
            """),
        prints('http://x.test/', 'onload=undefined'),
        Reading.WINDOW,
    ),
    'a function stored under the key onload': Program(
        a_program("""
            var cfg = {};
            cfg.onload = Math.random() < 2 ? function () { console.log('loaded'); } : null;
            console.log(typeof cfg.onload);
            """),
        prints('function', 'onload=undefined'),
        Reading.WINDOW,
    ),
    'an address a function called once keeps in a var of its own': Program(
        a_program("""
            function main() {
              var location = String(Math.random() < 2 ? 'http://x.test/' : '');
              console.log(location);
            }
            main();
            """),
        prints('http://x.test/', 'onload=undefined'),
        Reading.WINDOW,
    ),
    'an address a Function body keeps in a var of its own': Program(
        a_program("""
            Function("var location = String(Math.random() < 2 ? 'http://x.test/' : ''); console.log(location);")();
            """),
        prints('http://x.test/', 'onload=undefined'),
        Reading.WINDOW,
    ),
    'a list a Function body keeps in a var name and reads through a shorthand': Program(
        a_program("""
            Function("var name = [1, 2]; console.log(JSON.stringify({ name }));")();
            """),
        prints('{"name":[1,2]}', 'onload=undefined'),
        Reading.WINDOW,
    ),
    'a list a Function body stores into its var name through a pattern': Program(
        a_program("""
            Function("var name; ({ name } = { name: [1, 2] }); console.log(JSON.stringify(name));")();
            """),
        prints('[1,2]', 'onload=undefined'),
        Reading.WINDOW,
    ),
    'a list a Function body stores into its var name as the default of a pattern': Program(
        a_program("""
            Function("var name; ({ name = [3] } = {}); console.log(JSON.stringify(name));")();
            """),
        prints('[3]', 'onload=undefined'),
        Reading.WINDOW,
    ),
    'a class a Function body declares under the name name': Program(
        a_program("""
            Function("class name { static m() { return name; } } console.log(name.m() === name);")();
            """),
        prints('true', 'onload=undefined'),
        Reading.WINDOW,
    ),
    'a function a dispatcher holds under the key onload': Program(
        a_dispatcher(
            ['"onload": function () { console.log("ran"); return 1; }'],
            ['console.log(d("onload"));'],
        ),
        prints('ran', '1', 'onload=undefined'),
        Reading.WINDOW,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAValueOfItsOwnNamedLikeAPropertyTheWindowReadsStaysItsOwn(TestBase):

    def test_a_window_prints_what_each_row_pins(self):
        for label, row in A_VALUE_OF_ITS_OWN_NAMED_LIKE_A_PROPERTY_THE_WINDOW_READS.items():
            with self.subTest(label=label):
                self.assertEqual(row.behaves(), row.prints)

    def test_each_program_still_prints_it_after_the_deobfuscation(self):
        for label, row in A_VALUE_OF_ITS_OWN_NAMED_LIKE_A_PROPERTY_THE_WINDOW_READS.items():
            with self.subTest(label=label):
                self.assertEqual(row.read(), row.required())


class TestAValueOfItsOwnNamedLikeAPropertyTheWindowReadsIsStillFolded(TestBase):

    def test_a_function_body_declaring_name_is_unpacked_and_folded(self):
        source = a_program("""
            Function('var name = 5; console.log(name + 1);')();
            """)
        self.assertEqual(folded(source), 'console.log(6);')

    def test_a_function_called_once_declaring_name_is_inlined(self):
        source = a_program("""
            function main() { var name = prompt(); console.log(name); }
            main();
            """)
        self.assertNotIn('main', folded(source))

    def test_a_key_name_of_an_object_of_its_own_is_folded(self):
        source = a_program("""
            var C = {};
            C.name = 'svc';
            C.url = 'http://x.test/a';
            console.log(C.name, C.url);
            """)
        self.assertEqual(folded(source), "console.log('svc', 'http://x.test/a');")

    def test_a_function_named_name_nothing_calls_any_more_is_removed(self):
        source = a_program("""
            function name(a) { return a + 1; }
            console.log(name(1));
            """)
        self.assertEqual(folded(source), 'console.log(2);')


#: A classic script storing a number into `var name`, which a browser window keeps as a string,
#: mapped to what a window prints for it.
A_STORE_A_WINDOW_KEEPS_AS_A_STRING: dict[str, Program] = {
    'a number stored into the var name and read back': Program(
        a_program("""
            var name;
            function f(n) {
              name = n;
              return name + 1;
            }
            console.log(f(5));
            """),
        prints('51', 'onload=undefined'),
        Reading.WINDOW,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAStoreIntoNameIsReadAsTheWindowKeepsIt(TestBase):

    def test_a_window_prints_what_each_row_pins(self):
        for label, row in A_STORE_A_WINDOW_KEEPS_AS_A_STRING.items():
            with self.subTest(label=label):
                self.assertEqual(row.behaves(), row.prints)

    def test_each_program_still_prints_it_after_the_deobfuscation(self):
        for label, row in A_STORE_A_WINDOW_KEEPS_AS_A_STRING.items():
            with self.subTest(label=label):
                self.assertEqual(row.read(), row.required())

    def test_the_type_of_a_number_stored_into_name_is_not_folded_to_number(self):
        source = 'var name = 1; console.log(typeof name);'
        self.assertNotIn("'number'", folded(source, environment=HostEnvironment.browser))


class TestAStoreTheBrowserReadsIsKept(TestBase):

    def test_a_name_stored_on_the_window_is_kept_for_a_browser(self):
        source = a_program("""
            window.name = 'payload';
            """)
        self.assertEqual(folded(source, environment=HostEnvironment.browser), "window.name = 'payload';")

    def test_an_opener_cleared_at_the_top_is_kept(self):
        source = a_program("""
            opener = null;
            """)
        self.assertEqual(folded(source), 'opener = null;')

    def test_an_unread_address_is_removed_for_node(self):
        source = a_program("""
            location = 'http://x.test/';
            """)
        self.assertEqual(folded(source, environment=HostEnvironment.node), '')
