from __future__ import annotations

from refinery.lib.scripts.xlm import XlmSeverity, XlmStatus, XlmStep, visible_steps
from test import TestBase


def _step(
    status: XlmStatus = XlmStatus.FullEvaluation,
    text: str = 'text',
    severity: XlmSeverity = XlmSeverity.NORMAL,
) -> XlmStep:
    return XlmStep('Sheet1', 1, 1, status, text, 0, severity)


class TestVisibleSteps(TestBase):

    def test_every_step_shows_at_level_zero(self):
        steps = [
            _step(severity=XlmSeverity.JUMP),
            _step(severity=XlmSeverity.NORMAL),
            _step(severity=XlmSeverity.IMPORTANT),
        ]
        self.assertEqual(list(visible_steps(steps, 0)), steps)

    def test_level_one_hides_the_steps_that_move_execution(self):
        jump = _step(severity=XlmSeverity.JUMP)
        normal = _step(severity=XlmSeverity.NORMAL)
        important = _step(severity=XlmSeverity.IMPORTANT)
        self.assertEqual(list(visible_steps([jump, normal, important], 1)), [normal, important])

    def test_level_two_keeps_only_the_triage_commands(self):
        jump = _step(severity=XlmSeverity.JUMP)
        normal = _step(severity=XlmSeverity.NORMAL)
        important = _step(severity=XlmSeverity.IMPORTANT)
        self.assertEqual(list(visible_steps([jump, normal, important], 2)), [important])

    def test_an_ignored_step_never_shows(self):
        for level in range(4):
            ignored = _step(status=XlmStatus.Ignored)
            self.assertEqual(list(visible_steps([ignored], level)), [])

    def test_a_level_above_the_highest_shows_the_steps_of_the_highest(self):
        steps = [
            _step(severity=XlmSeverity.JUMP),
            _step(severity=XlmSeverity.NORMAL),
            _step(severity=XlmSeverity.IMPORTANT),
        ]
        self.assertEqual(list(visible_steps(steps, 3)), list(visible_steps(steps, 2)))
