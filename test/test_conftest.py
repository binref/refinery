from __future__ import annotations

import os
import unittest
import unittest.mock

from test import conftest


def a_configuration(cache: unittest.mock.Mock | None, **options: bool) -> unittest.mock.Mock:
    def getoption(name: str) -> bool:
        return options.get(name.lstrip('-').replace('-', '_'), False)
    config = unittest.mock.Mock(spec=['getoption', 'cache'])
    config.getoption.side_effect = getoption
    config.cache = cache
    return config


class TestTheFolderOfKeptNodeAnswers(unittest.TestCase):

    def test_a_cache_folder_that_cannot_be_created_keeps_no_answers_and_runs_the_tests(self):
        cache = unittest.mock.Mock()
        cache.mkdir.side_effect = PermissionError('read-only checkout')
        with unittest.mock.patch.dict(os.environ):
            os.environ.pop('REFINERY_TEST_NODE_ANSWERS', None)
            conftest.pytest_configure(a_configuration(cache))
            self.assertNotIn('REFINERY_TEST_NODE_ANSWERS', os.environ)

    def test_asking_node_about_every_program_keeps_no_answers_even_where_a_folder_is_set(self):
        with unittest.mock.patch.dict(os.environ, {'REFINERY_TEST_NODE_ANSWERS': 'answers'}):
            conftest.pytest_configure(a_configuration(unittest.mock.Mock(), no_node_answers=True))
            self.assertEqual(os.environ['REFINERY_TEST_NODE_ANSWERS'], '')

    def test_a_folder_named_already_is_kept_and_no_cache_folder_is_made(self):
        cache = unittest.mock.Mock()
        with unittest.mock.patch.dict(os.environ, {'REFINERY_TEST_NODE_ANSWERS': 'answers'}):
            conftest.pytest_configure(a_configuration(cache))
            self.assertEqual(os.environ['REFINERY_TEST_NODE_ANSWERS'], 'answers')
        cache.mkdir.assert_not_called()
