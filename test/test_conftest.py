from __future__ import annotations

import os
import unittest
import unittest.mock

from test import conftest


def a_configuration(cache: unittest.mock.Mock | None, **options: bool) -> unittest.mock.Mock:
    config = unittest.mock.Mock(spec=['getoption', 'cache'])
    config.getoption.side_effect = lambda name: options.get(name.lstrip('-').replace('-', '_'), False)
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
