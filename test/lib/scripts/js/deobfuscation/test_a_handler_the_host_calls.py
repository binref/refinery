"""
A function a script stores where the host calls it from outside the file: an event handler of the
global object, such as the `onload` a browser window calls once the script has run, or a name the
analyst declared a host reaches. No call of it shows in the file, so the store is never dead
(`refinery.lib.scripts.js.options.is_host_entrypoint`). Each program is written by hand, and each
row says what Node prints for it run as a classic script in the window `test.lib.scripts.js.ledger`
sets up.
"""
from __future__ import annotations

import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import deobfuscate_source, host_behavior, node_executable
from test.lib.scripts.js.ledger import Program, Reading, a_program, folded, prints

from refinery.lib.scripts.js.analysis.environment import HostEnvironment

#: Classic scripts storing a load handler, mapped to what a browser window prints for each.
A_LOAD_HANDLER_A_WINDOW_CALLS: dict[str, Program] = {
    'a load handler stored at the top': Program(
        a_program("""
            onload = function () { console.log('loaded'); };
            """),
        prints('loaded', 'onload=undefined'),
        Reading.WINDOW,
    ),
    'a load handler stored at the top, read for a browser': Program(
        a_program("""
            onload = function () { console.log('loaded'); };
            """),
        prints('loaded', 'onload=undefined'),
        Reading.WINDOW,
        HostEnvironment.browser,
    ),
    'a load handler stored on the window, read for a browser': Program(
        a_program("""
            window.onload = function () { console.log('loaded'); };
            """),
        prints('loaded', 'onload=undefined'),
        Reading.WINDOW,
        HostEnvironment.browser,
    ),
    'a load handler stored by a function the script calls': Program(
        a_program("""
            function install() { onload = function () { console.log('loaded'); }; }
            install();
            """),
        prints('loaded', 'onload=undefined'),
        Reading.WINDOW,
    ),
    'a load handler stored into a var by a function the script calls': Program(
        a_program("""
            var onload;
            function install() { onload = function () { console.log('loaded'); }; }
            install();
            """),
        prints('loaded', 'onload=undefined'),
        Reading.WINDOW,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestALoadHandlerTheWindowCallsIsKept(TestBase):

    def test_a_window_prints_what_each_row_pins(self):
        for label, row in A_LOAD_HANDLER_A_WINDOW_CALLS.items():
            with self.subTest(label=label):
                self.assertEqual(row.behaves(), row.prints)

    def test_each_program_still_prints_it_after_the_deobfuscation(self):
        for label, row in A_LOAD_HANDLER_A_WINDOW_CALLS.items():
            with self.subTest(label=label):
                self.assertEqual(row.read(), row.required())


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAFunctionTheAnalystDeclaredIsKeptWhereStoredOnTheGlobalObject(TestBase):

    def test_the_host_still_calls_it_after_the_deobfuscation(self):
        source = a_program("""
            globalThis.run = function () { console.log('ran'); };
            """)
        rewritten = deobfuscate_source(source, entrypoints=('run',))
        self.assertEqual(
            (host_behavior(source, calls=('run',)), host_behavior(rewritten, calls=('run',))),
            (prints('ran', 'run=undefined'), prints('ran', 'run=undefined')),
        )


class TestAHandlerIsCalledOnlyByAHostThatHasIt(TestBase):

    def test_a_message_handler_is_kept_for_a_worker(self):
        source = a_program("""
            onmessage = function (event) { postMessage(event.data); };
            """)
        self.assertIn('postMessage', folded(source, environment=HostEnvironment.worker))

    def test_an_unread_load_handler_is_removed_for_node(self):
        source = a_program("""
            onload = function () { console.log('loaded'); };
            """)
        self.assertNotIn('loaded', folded(source, environment=HostEnvironment.node))
