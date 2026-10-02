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
            ignored = _step(status=XlmStatus.IGNORED)
            self.assertEqual(list(visible_steps([ignored], level)), [])

    def test_level_three_shows_the_strings_of_a_triage_command(self):
        step = _step(
            text='=EXEC("regsvr32  C:\\ProgramData\\Ropedjo1.ocx")',
            severity=XlmSeverity.IMPORTANT,
        )
        visible = list(visible_steps([step], 3))
        self.assertEqual(len(visible), 1)
        self.assertEqual(visible[0].text, '"regsvr32  C:\\ProgramData\\Ropedjo1.ocx"')

    def test_level_three_joins_the_strings_of_one_step(self):
        step = _step(
            text='=CALL("a","b")',
            severity=XlmSeverity.IMPORTANT,
        )
        visible = list(visible_steps([step], 3))
        self.assertEqual(visible[0].text, '"a"\n"b"')

    def test_level_three_drops_a_triage_command_without_strings(self):
        step = _step(text='=HALT()', severity=XlmSeverity.IMPORTANT)
        self.assertEqual(list(visible_steps([step], 3)), [])

    def test_level_three_drops_the_commands_below_the_triage_class(self):
        for severity in (XlmSeverity.JUMP, XlmSeverity.NORMAL):
            step = _step(text='=EXEC("x")', severity=severity)
            self.assertEqual(list(visible_steps([step], 3)), [])

    def test_a_step_keeps_its_place_indent_and_status_through_extraction(self):
        step = XlmStep(
            'Doc1', 12, 3, XlmStatus.PartialEvaluation,
            '=FWRITE(1,"cache.dat")', 2, XlmSeverity.IMPORTANT,
        )
        visible = list(visible_steps([step], 3))
        self.assertEqual(len(visible), 1)
        self.assertEqual(
            visible[0],
            XlmStep(
                'Doc1', 12, 3, XlmStatus.PartialEvaluation,
                '"cache.dat"', 2, XlmSeverity.IMPORTANT,
            ),
        )
