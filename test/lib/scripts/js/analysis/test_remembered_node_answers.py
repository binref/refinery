from __future__ import annotations

import contextlib
import os
import tempfile
import unittest
import unittest.mock

from pathlib import Path

from test import TestBase

from test.lib.scripts.js.analysis import differential
from test.lib.scripts.js.analysis.differential import (
    NODE_TIMEOUT,
    NodeAnswers,
    behavior,
    node_executable,
)

A_PROGRAM_THAT_PRINTS_SOMETHING_ELSE_ON_EVERY_RUN = 'console.log(Math.random());'


@contextlib.contextmanager
def a_run_keeping_answers_in(folder: str):
    """
    A run of the test suite as far as Node's answers go: it starts with no answer remembered in the
    process, and it keeps its answers in *folder*.
    """
    with unittest.mock.patch.dict(os.environ, {'REFINERY_TEST_NODE_ANSWERS': folder}):
        differential._remembered_node_behavior.cache_clear()
        try:
            yield
        finally:
            differential._remembered_node_behavior.cache_clear()


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNodeIsAskedAboutAProgramOnlyOnceUnlessARunIsAskedFor(TestBase):

    def test_a_program_asked_about_twice_is_given_the_same_answer(self):
        program = A_PROGRAM_THAT_PRINTS_SOMETHING_ELSE_ON_EVERY_RUN
        self.assertEqual(behavior(program), behavior(program))

    def test_a_fresh_run_runs_the_program_again(self):
        program = A_PROGRAM_THAT_PRINTS_SOMETHING_ELSE_ON_EVERY_RUN
        self.assertNotEqual(behavior(program), behavior(program, fresh=True))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnAnswerWithoutAnErrorIsKeptForTheNextRun(TestBase):

    def test_a_later_run_is_given_the_answer_an_earlier_run_kept(self):
        program = A_PROGRAM_THAT_PRINTS_SOMETHING_ELSE_ON_EVERY_RUN
        with tempfile.TemporaryDirectory() as folder:
            with a_run_keeping_answers_in(folder):
                first = behavior(program)
            with a_run_keeping_answers_in(folder):
                again = behavior(program)
        self.assertEqual(first, again)

    def test_an_answer_that_ends_in_an_error_is_not_kept(self):
        program = 'console.log(Math.random()); throw new TypeError("after printing");'
        with tempfile.TemporaryDirectory() as folder:
            with a_run_keeping_answers_in(folder):
                first = behavior(program)
            with a_run_keeping_answers_in(folder):
                again = behavior(program)
        self.assertEqual((first[1], again[1]), ('TypeError', 'TypeError'))
        self.assertNotEqual(first[0], again[0])


class TestTheAnswersOfOneVersionOfNodeAreNotGivenForAnother(TestBase):

    def test_opening_the_answers_for_another_version_drops_those_of_the_first(self):
        question = ((('snippet.js', 'console.log(1);'),), 'snippet.js', NODE_TIMEOUT)
        with tempfile.TemporaryDirectory() as folder:
            NodeAnswers(Path(folder), 'v1.0.0').keep(question, '1\n')
            self.assertEqual(NodeAnswers(Path(folder), 'v1.0.0').answer(question), '1\n')
            self.assertIsNone(NodeAnswers(Path(folder), 'v2.0.0').answer(question))
            self.assertIsNone(NodeAnswers(Path(folder), 'v1.0.0').answer(question))
