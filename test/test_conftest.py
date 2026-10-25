from __future__ import annotations

import contextlib
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import unittest.mock

from pathlib import Path

from test import TestBase, conftest
from test.lib.scripts.js.analysis.differential import behavior, node_executable


def a_configuration(cache: unittest.mock.Mock | None, **options: bool) -> unittest.mock.Mock:
    def getoption(name: str) -> bool:
        return options.get(name.lstrip('-').replace('-', '_'), False)
    config = unittest.mock.Mock(spec=['getoption'] if cache is None else ['getoption', 'cache'])
    config.getoption.side_effect = getoption
    if cache is not None:
        config.cache = cache
    return config


class TestTheFolderOfKeptNodeAnswers(unittest.TestCase):

    def test_the_answers_are_kept_in_the_folder_node_of_the_cache(self):
        cache = unittest.mock.Mock()
        cache.mkdir.return_value = Path('.pytest_cache', 'd', 'node')
        folder = conftest.node_answers_folder(a_configuration(cache))
        self.assertEqual(folder, Path('.pytest_cache', 'd', 'node'))
        cache.mkdir.assert_called_once_with('node')

    def test_a_cache_folder_that_cannot_be_made_keeps_no_answers(self):
        cache = unittest.mock.Mock()
        cache.mkdir.side_effect = PermissionError('read-only checkout')
        self.assertIsNone(conftest.node_answers_folder(a_configuration(cache)))

    def test_asking_node_about_every_program_keeps_no_answers_and_makes_no_folder(self):
        cache = unittest.mock.Mock()
        self.assertIsNone(conftest.node_answers_folder(a_configuration(cache, no_node_answers=True)))
        cache.mkdir.assert_not_called()

    def test_a_run_without_the_cache_provider_keeps_no_answers(self):
        self.assertIsNone(conftest.node_answers_folder(a_configuration(None)))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestASessionThatAsksNodeAboutOneProgram(TestBase):

    def test_node_prints_one(self):
        self.assertEqual(behavior('console.log(1);'), ('1\n', None))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestASessionKeepsWhatNodeAnsweredWhenItEnds(TestBase):

    def test_the_one_answer_of_a_session_is_in_the_store_of_its_cache_after_it(self):
        root = Path(__file__).resolve().parents[1]
        session = F'{Path(__file__).relative_to(root).as_posix()}::TestASessionThatAsksNodeAboutOneProgram'
        with tempfile.TemporaryDirectory() as cache:
            completed = subprocess.run(
                [sys.executable, '-m', 'pytest', '-q', '-o', F'cache_dir={cache}', session],
                cwd=root,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stdout)
            with contextlib.closing(sqlite3.connect(Path(cache, 'd', 'node', 'answers.sqlite'))) as db:
                kept = db.execute('SELECT count(*) FROM answers').fetchone()
        self.assertEqual(kept, (1,))
