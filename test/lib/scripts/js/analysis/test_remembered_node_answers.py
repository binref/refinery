from __future__ import annotations

import contextlib
import os
import shutil
import sys
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

    def test_answers_kept_in_one_time_zone_are_not_given_in_another(self):
        program = A_PROGRAM_THAT_PRINTS_SOMETHING_ELSE_ON_EVERY_RUN
        with tempfile.TemporaryDirectory() as folder:
            with a_run_keeping_answers_in(folder), unittest.mock.patch.dict(os.environ, {'TZ': 'UTC'}):
                first = behavior(program)
            with a_run_keeping_answers_in(folder), unittest.mock.patch.dict(os.environ, {'TZ': 'Asia/Tokyo'}):
                again = behavior(program)
        self.assertNotEqual(first, again)


class TestNoAnswerIsKeptForANodeThatCannotSayWhatItIs(TestBase):

    def test_a_missing_node_or_another_program_in_its_place_keeps_nothing(self):
        with tempfile.TemporaryDirectory() as programs:
            impostor = os.path.join(programs, 'impostor.cmd' if os.name == 'nt' else 'impostor')
            with open(impostor, 'w') as script:
                if os.name == 'nt':
                    script.write('@echo ["not a version","en-US","UTC"]\n')
                else:
                    script.write('#!/bin/sh\necho \'["not a version","en-US","UTC"]\'\n')
            os.chmod(impostor, 0o755)
            for name, executable in [
                ('missing', os.path.join(programs, 'missing')),
                ('python', sys.executable),
                ('impostor', impostor),
            ]:
                with self.subTest(node=name), tempfile.TemporaryDirectory() as folder:
                    environment = tuple(os.environ.items())
                    self.assertIsNone(differential._kept_answers(executable, folder, environment))
                    self.assertEqual(os.listdir(folder), [])


class TestTheAnswersOfOneVersionOfNodeAreNotGivenForAnother(TestBase):

    FIRST = 'v1.0.0-0123456789abcdef'
    OTHER = 'v2.0.0-0123456789abcdef'
    QUESTION = ((('snippet.js', 'console.log(1);'),), 'snippet.js', NODE_TIMEOUT)

    def test_opening_the_answers_for_another_version_drops_those_of_the_first(self):
        with tempfile.TemporaryDirectory() as folder:
            NodeAnswers(Path(folder), self.FIRST).keep(self.QUESTION, '1\n')
            self.assertEqual(NodeAnswers(Path(folder), self.FIRST).answer(self.QUESTION), '1\n')
            self.assertIsNone(NodeAnswers(Path(folder), self.OTHER).answer(self.QUESTION))
            self.assertIsNone(NodeAnswers(Path(folder), self.FIRST).answer(self.QUESTION))

    def test_an_answer_that_cannot_be_kept_is_only_not_kept(self):
        with tempfile.TemporaryDirectory() as folder:
            answers = NodeAnswers(Path(folder), self.FIRST)
            shutil.rmtree(answers.folder)
            answers.keep(self.QUESTION, '1\n')
            self.assertIsNone(answers.answer(self.QUESTION))

    def test_a_kept_answer_whose_file_was_emptied_or_garbled_is_no_answer(self):
        for name, damage in [
            ('emptied', lambda _: b''),
            ('zeroed', lambda kept: bytes(len(kept))),
            ('garbled', lambda kept: kept[:-1] + b'2'),
        ]:
            with self.subTest(damage=name), tempfile.TemporaryDirectory() as folder:
                answers = NodeAnswers(Path(folder), self.FIRST)
                answers.keep(self.QUESTION, '1\n')
                kept, = answers.folder.iterdir()
                kept.write_bytes(damage(kept.read_bytes()))
                self.assertIsNone(answers.answer(self.QUESTION))

    def test_opening_the_answers_leaves_whatever_else_the_folder_holds(self):
        with tempfile.TemporaryDirectory() as folder:
            Path(folder, 'notes').mkdir()
            Path(folder, 'notes', 'todo.txt').write_text('keep me')
            NodeAnswers(Path(folder), self.FIRST)
            NodeAnswers(Path(folder), self.OTHER)
            self.assertEqual(Path(folder, 'notes', 'todo.txt').read_text(), 'keep me')
