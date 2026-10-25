from __future__ import annotations

import os
import unittest
import unittest.mock

from test import TestBase

from test.lib.scripts.js.analysis.differential import (
    behavior,
    node_executable,
)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNodePrintsTheSameWhateverTheShellSaysAboutColors(TestBase):

    def test_a_number_is_printed_without_colors_when_the_shell_forces_them(self):
        with unittest.mock.patch.dict(os.environ, {'FORCE_COLOR': '3'}):
            self.assertEqual(behavior('console.log(1);', fresh=True), ('1\n', None))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestTheLineBreaksNodePrintsAreTheLineBreaksTheTestReads(TestBase):

    def test_a_carriage_return_alone_or_before_a_line_feed_is_read_as_node_printed_it(self):
        program = 'console.log("a" + String.fromCharCode(13) + "b" + String.fromCharCode(13, 10) + "c");'
        self.assertEqual(behavior(program, fresh=True), ('a\rb\r\nc\n', None))
