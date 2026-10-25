from __future__ import annotations

import unittest
import unittest.mock

from pathlib import Path

from test import conftest


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
