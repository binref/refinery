from __future__ import annotations

import importlib.util
import pathlib
import unittest

from samples import ScriptHostRefused
from test import TestBase
from test.lib.scripts.js.analysis import nodejs
from test.lib.scripts.js.analysis.differential import behavior, node_executable, node_reads_as_a_program
from test.lib.scripts.ps1.oracle import run


def _the_fuzzer():
    path = pathlib.Path(__file__).resolve().parents[1] / 'scripts' / 'js-node-fuzzer.py'
    spec = importlib.util.spec_from_file_location('js_node_fuzzer', path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnAnswerNodeGaveBeforeASampleWasDecodedIsNotGivenAfterIt(TestBase):

    def test_a_program_answered_before_a_sample_was_decoded_is_refused_after_it(self):
        self.assertEqual(behavior('console.log(1);'), ('1\n', None))
        self.download_sample('0fd7c8302457d9d9099282439d8413d9122a5d3cff3467d5042e51fc1156fa5b')
        with self.assertRaises(ScriptHostRefused):
            behavior('console.log(1);')

    def test_a_snippet_checked_before_a_sample_was_decoded_is_refused_after_it(self):
        self.assertTrue(node_reads_as_a_program('0;'))
        self.download_sample('0fd7c8302457d9d9099282439d8413d9122a5d3cff3467d5042e51fc1156fa5b')
        with self.assertRaises(ScriptHostRefused):
            node_reads_as_a_program('0;')


class TestATestThatDecodedASampleCannotStartAScriptHost(TestBase):

    def setUp(self):
        super().setUp()
        self.download_sample('0fd7c8302457d9d9099282439d8413d9122a5d3cff3467d5042e51fc1156fa5b')

    def test_node_does_not_run_a_snippet(self):
        with self.assertRaises(ScriptHostRefused):
            behavior('0;')

    def test_node_is_not_asked_what_it_is(self):
        with self.assertRaises(ScriptHostRefused):
            nodejs.identity('node')

    def test_node_does_not_check_a_snippet(self):
        with self.assertRaises(ScriptHostRefused):
            node_reads_as_a_program('/* a test that decoded a sample */ 0;')

    def test_the_fuzzer_does_not_run_a_batch(self):
        fuzzer = _the_fuzzer()
        with self.assertRaises(ScriptHostRefused):
            fuzzer._behavior_batch(['0;'], 5.0)

    def test_windows_powershell_does_not_run_a_snippet(self):
        with self.assertRaises(ScriptHostRefused):
            run('0')
