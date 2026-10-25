from __future__ import annotations

import os
import unittest
import unittest.mock

from test import TestBase

from test.lib.scripts.js.analysis.differential import (
    behavior,
    node_executable,
    node_reads_as_a_program,
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


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestTheErrorAProgramEndsInIsTheOneNodeNames(TestBase):

    def test_each_uncaught_error_is_named_by_its_type_and_a_thrown_string_by_none(self):
        for program, error in [
            ('throw new Error("x");', 'Error'),
            ('throw new TypeError();', 'TypeError'),
            ('console.error("RangeError: printed first"); throw new TypeError("x");', 'TypeError'),
            ('throw "x";', 'ERROR'),
        ]:
            with self.subTest(program=program):
                self.assertEqual(behavior(program, fresh=True), ('', error))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestTheLineBreaksOfASnippetAreTheLineBreaksNodeChecks(TestBase):

    def test_a_backslash_before_a_carriage_return_and_line_feed_continues_a_string(self):
        self.assertTrue(node_reads_as_a_program('var s = "a\\\r\nb";'))
