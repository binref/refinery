from __future__ import annotations

import unittest

from typing import Callable

from test import backlog, blocker, opportunity, todo

_MARKERS = (opportunity, todo, backlog, blocker)


def _run_marked(marker: Callable, body: Callable[[unittest.TestCase], None]) -> unittest.TestResult:
    class Marked(unittest.TestCase):
        @marker
        def test(self):
            body(self)
    result = unittest.TestResult()
    Marked('test').run(result)
    return result


def _tally(result: unittest.TestResult) -> dict[str, int]:
    return {
        'expected failures': len(result.expectedFailures),
        'unexpected successes': len(result.unexpectedSuccesses),
        'failures': len(result.failures),
        'errors': len(result.errors),
    }


def _fail(case: unittest.TestCase):
    case.assertEqual(1, 2)


def _crash(case: unittest.TestCase):
    raise ValueError('crash')


def _fail_in_a_subtest(case: unittest.TestCase):
    with case.subTest('only'):
        case.assertEqual(1, 2)


def _crash_in_a_subtest(case: unittest.TestCase):
    with case.subTest('only'):
        raise ValueError('crash')


def _pass(case: unittest.TestCase):
    case.assertEqual(1, 1)


class TestAMarkedTestIsExpectedToFailAnAssertion(unittest.TestCase):

    def _assertTally(self, body: Callable[[unittest.TestCase], None], **expected: int):
        for marker in _MARKERS:
            with self.subTest(marker=marker.__name__):
                tally = dict.fromkeys(_tally(unittest.TestResult()), 0)
                tally.update({key.replace('_', ' '): count for key, count in expected.items()})
                self.assertEqual(_tally(_run_marked(marker, body)), tally)

    def test_a_failed_assertion_is_the_expected_failure(self):
        self._assertTally(_fail, expected_failures=1)

    def test_a_failed_assertion_in_a_subtest_is_the_expected_failure(self):
        self._assertTally(_fail_in_a_subtest, expected_failures=1)

    def test_a_crash_is_an_error(self):
        self._assertTally(_crash, errors=1)

    def test_a_crash_in_a_subtest_is_an_error(self):
        self._assertTally(_crash_in_a_subtest, errors=1)

    def test_a_pass_is_an_unexpected_success(self):
        self._assertTally(_pass, unexpected_successes=1)

    def test_the_error_a_crash_reports_is_the_crash(self):
        for body in (_crash, _crash_in_a_subtest):
            with self.subTest(body.__name__):
                (_, traceback), = _run_marked(todo, body).errors
                self.assertIn('ValueError: crash', traceback)
