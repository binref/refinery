from __future__ import annotations

import unittest

from refinery.lib.excel import parse_formula, synthesize_formula
from refinery.lib.excel.formula.model import XlFunctionCall
from refinery.lib.scripts.xlm import XlmCursor, XlmEngine, XlmReference, XlmView
from refinery.lib.scripts.xlm.evaluate import evaluate_expression
from refinery.lib.scripts.xlm.trace import XlmStatus
from test import TestBase
from test.lib.excel.samples import XLM_MACRO_TEXT_XLSM
from test.lib.scripts.xlm.modify import date_cell, replace_cell_formula
from test.lib.scripts.xlm.test_engine import _steps

_CURSOR = XlmCursor('Doc1', 109, 52)


def _parsed_call(formula: str) -> XlFunctionCall:
    call = parse_formula(formula)
    assert isinstance(call, XlFunctionCall)
    return call


def _answer(formula: str):
    engine = XlmEngine(XlmView(XLM_MACRO_TEXT_XLSM))
    return engine.call(_parsed_call(formula), _CURSOR)


class TestNumericCommands(TestBase):

    def test_arithmetic_commands_answer_their_numbers(self):
        for formula, expected in [
            ('ABS(-3)', '3'),
            ('INT(4.7)', '4'),
            ('SQRT(16)', '4'),
            ('TRUNC(-4.7)', '-4'),
            ('ROUND(3.14159,2)', '3.14'),
            ('ROUNDUP(3.1)', '4'),
            ('MOD(7,2)', '1'),
            ('SUM(1,2,3)', '6'),
            ('PRODUCT(2,3)', '6'),
            ('MAX(0,5)', '5'),
            ('VALUE("42")', '42'),
            ('_xlfn.ARABIC("XIV")', '14'),
        ]:
            with self.subTest(formula=formula):
                outcome = _answer(formula)
                self.assertEqual(outcome.value.text, expected)
                self.assertEqual(outcome.status, None)

    def test_quotient_divides_both_of_its_operands(self):
        outcome = _answer('QUOTIENT(7,2)')
        self.assertEqual(outcome.value.text, '3')
        self.assertEqual(outcome.status, None)

    def test_the_rounding_commands_answer_the_examples_excel_documents(self):
        for formula, expected in [
            ('ROUND(2.15,1)', '2.2'),
            ('ROUND(2.149,1)', '2.1'),
            ('ROUND(-1.475,2)', '-1.48'),
            ('ROUND(21.5,-1)', '20'),
            ('ROUND(626.3,-3)', '1000'),
            ('ROUND(1.98,-1)', '0'),
            ('ROUND(-50.55,-2)', '-100'),
            ('ROUNDUP(3.2,0)', '4'),
            ('ROUNDUP(76.9,0)', '77'),
            ('ROUNDUP(3.14159,3)', '3.142'),
            ('ROUNDUP(-3.14159,1)', '-3.2'),
            ('ROUNDUP(31415.92654,-2)', '31500'),
            ('TRUNC(8.9)', '8'),
            ('TRUNC(-8.9)', '-8'),
            ('TRUNC(0.45)', '0'),
            ('INT(8.9)', '8'),
            ('INT(-8.9)', '-9'),
            ('QUOTIENT(5,2)', '2'),
            ('QUOTIENT(4.5,3.1)', '1'),
            ('QUOTIENT(-10,3)', '-3'),
            ('SQRT(16)', '4'),
            ('SQRT(2.25)', '1.5'),
        ]:
            with self.subTest(formula=formula):
                outcome = _answer(formula)
                self.assertEqual(outcome.value.text, expected)
                self.assertEqual(outcome.status, None)

    def test_count_counts_only_the_arguments_that_are_numbers(self):
        data = replace_cell_formula(XLM_MACRO_TEXT_XLSM, 'AZ113', '123')
        data = replace_cell_formula(data, 'AZ114', '"text"')
        engine = XlmEngine(XlmView(data))
        for formula, expected in [
            ('COUNT(1,"a",TRUE)', 2),
            ('COUNT("7",8)', 2),
            ('COUNT(AZ113:AZ114)', 1),
            ('COUNT(AZ113:AZ114,AZ200)', 1),
        ]:
            with self.subTest(formula=formula):
                self.assertEqual(
                    engine.call(_parsed_call(formula), _CURSOR).value.value,
                    expected,
                )

    def test_iserror_holds_for_the_error_values_a_formula_computes(self):
        for formula, expected in [
            ('ISERROR(1/0)', True),
            ('ISERROR(#VALUE!)', True),
            ('ISERROR(SEARCH("x","abc"))', True),
            ('ISERROR(AZ200)', False),
        ]:
            with self.subTest(formula=formula):
                self.assertEqual(_answer(formula).value.value, expected)

    def test_max_keeps_a_zero_result(self):
        outcome = _answer('MAX(-1,0)')
        self.assertEqual(outcome.value.text, '0')
        self.assertEqual(outcome.status, None)

    def test_a_partial_operand_leaves_mod_unevaluated(self):
        steps = _steps(('AZ110', 'MOD(FOO(1),2)'))
        self.assertEqual(steps[1].status, XlmStatus.PartialEvaluation)
        self.assertEqual(steps[1].text, 'MOD(FOO(1),2)')

    def test_now_advances_two_seconds_per_call(self):
        engine = XlmEngine(XlmView(XLM_MACRO_TEXT_XLSM))
        first = engine.call(_parsed_call('NOW()'), _CURSOR).value.value
        second = engine.call(_parsed_call('NOW()'), _CURSOR).value.value
        self.assertAlmostEqual((second - first) * 86400, 2, delta=1)

    def test_iserror_flips_after_ten_repeats_at_one_cell(self):
        engine = XlmEngine(XlmView(XLM_MACRO_TEXT_XLSM))
        call = _parsed_call('ISERROR(1)')
        answers = [engine.call(call, _CURSOR).value.value for _ in range(12)]
        self.assertEqual(answers, [False] * 10 + [True, False])

    def test_value_rejects_a_text_that_spells_no_number(self):
        outcome = _answer('VALUE("x")')
        self.assertEqual(outcome.status, XlmStatus.Error)
        self.assertEqual(outcome.value.value, 0)

    def test_arabic_degrades_a_text_that_is_no_roman_numeral(self):
        outcome = _answer('_xlfn.ARABIC("junk")')
        self.assertEqual(outcome.value.partial, True)
        self.assertEqual(outcome.value.text, '_xlfn.ARABIC("junk")')

    def test_logic_commands_answer_the_truth_of_their_arguments(self):
        for formula, expected in [
            ('AND(TRUE,TRUE)', 'TRUE'),
            ('AND(TRUE,FALSE)', 'FALSE'),
            ('OR(FALSE,TRUE)', 'TRUE'),
            ('OR(FALSE,FALSE)', 'FALSE'),
            ('NOT(TRUE)', 'FALSE'),
            ('COUNT(1,2,3)', '3'),
            ('ISNUMBER(1)', 'TRUE'),
            ('ISNUMBER("a")', 'FALSE'),
        ]:
            with self.subTest(formula=formula):
                outcome = _answer(formula)
                self.assertEqual(outcome.value.text, expected)
                self.assertEqual(outcome.status, None)

    def test_logic_commands_read_what_their_arguments_hold_rather_than_their_spelling(self):
        for formula, expected in [
            ('AND(1,2)', True),
            ('AND(1,0)', False),
            ('OR(0,3)', True),
            ('NOT(0)', True),
            ('NOT(5)', False),
            ('AND(GET.WORKSPACE(19),GET.WORKSPACE(42))', True),
            ('NOT(GET.WORKSPACE(19))', False),
        ]:
            with self.subTest(formula=formula):
                self.assertEqual(_answer(formula).value.value, expected)

    def test_isnumber_does_not_convert_a_text_that_spells_a_number(self):
        self.assertEqual(_answer('ISNUMBER("19")').value.value, False)

    def test_isnumber_answers_the_type_of_the_value_it_reads(self):
        data = date_cell(XLM_MACRO_TEXT_XLSM, 'BH120', '2017-12-27T00:00:00')
        engine = XlmEngine(XlmView(data))
        for formula, expected in [
            ('ISNUMBER(BH120)', True),
            ('ISNUMBER(TRUE)', False),
            ('ISNUMBER(AZ200)', False),
            ('ISNUMBER(SEARCH("x","abc"))', False),
        ]:
            with self.subTest(formula=formula):
                self.assertEqual(
                    engine.call(_parsed_call(formula), _CURSOR).value.value,
                    expected,
                )

    def test_a_condition_that_spells_no_truth_value_is_the_value_error(self):
        self.assertEqual(_answer('IF("yes",1,2)').value.text, '#VALUE!')

    def test_the_logic_commands_answer_the_error_of_their_conditions(self):
        for formula in [
            'AND("yes",TRUE)',
            'AND(FALSE,"yes")',
            'OR("yes",FALSE)',
            'NOT("yes")',
            'NOT(SEARCH("x","abc"))',
        ]:
            with self.subTest(formula=formula):
                outcome = _answer(formula)
                self.assertEqual(outcome.value.text, '#VALUE!')
                self.assertEqual(outcome.value.error, True)

    def test_an_empty_condition_answers_false(self):
        self.assertEqual(_answer('NOT("")').value.text, 'TRUE')


class TestStringCommands(TestBase):

    def test_string_commands_answer_their_texts(self):
        for formula, expected in [
            ('CHAR(65)', 'A'),
            ('CODE("A")', '65'),
            ('CONCATENATE("a","b")', '"ab"'),
            ('LEN("abcd")', '4'),
            ('MID("abcdef",2,3)', 'bcd'),
            ('SEARCH("c","abcd")', '3'),
            ('T(5)', '5'),
            ('TEXT(5,0)', '5'),
        ]:
            with self.subTest(formula=formula):
                outcome = _answer(formula)
                self.assertEqual(outcome.value.text, expected)
                self.assertEqual(outcome.status, None)

    def test_char_answers_the_value_error_for_a_code_outside_the_bytes(self):
        outcome = _answer('CHAR(300)')
        self.assertEqual(outcome.value.text, '#VALUE!')
        self.assertEqual(outcome.value.error, True)
        self.assertEqual(outcome.status, None)

    def test_search_answers_the_examples_excel_documents(self):
        for formula, expected in [
            ('SEARCH("e","Statements",6)', '7'),
            ('SEARCH("margin","Profit Margin")', '8'),
            ('SEARCH("p?o","Profit Margin")', '1'),
            ('SEARCH("m*n","Profit Margin")', '8'),
            ('SEARCH("~?","what?")', '5'),
        ]:
            with self.subTest(formula=formula):
                outcome = _answer(formula)
                self.assertEqual(outcome.value.text, expected)
                self.assertEqual(outcome.value.error, False)

    def test_search_answers_the_value_error_for_a_text_it_does_not_find(self):
        for formula in [
            'SEARCH("x","abc")',
            'SEARCH("a","abc",4)',
            'SEARCH("a","abc",0)',
        ]:
            with self.subTest(formula=formula):
                outcome = _answer(formula)
                self.assertEqual(outcome.value.text, '#VALUE!')
                self.assertEqual(outcome.value.error, True)

    def test_mid_keeps_the_leading_zeros_of_the_text_it_cuts(self):
        self.assertEqual(_answer('MID("abc007",4,3)').value.text, '007')

    def test_mid_answers_the_value_error_for_a_start_below_one(self):
        self.assertEqual(_answer('MID("abc",0,1)').value.text, '#VALUE!')

    def test_char_answers_the_value_error_for_a_code_outside_one_to_255(self):
        formulas = ['CHAR(0)', 'CHAR(256)']
        self.assertEqual(
            {formula: _answer(formula).value.text for formula in formulas},
            {formula: '#VALUE!' for formula in formulas},
        )

    def test_code_answers_the_code_page_byte_of_a_character_beyond_latin1(self):
        for formula, expected in [
            ('CODE("€")', 128),
            ('CODE("Ā")', 63),
            ('CODE(CHAR(200))', 200),
        ]:
            with self.subTest(formula=formula):
                self.assertEqual(_answer(formula).value.value, expected)


class TestLookupCommands(TestBase):

    def test_address_spells_the_cell_it_names(self):
        self.assertEqual(_answer('ADDRESS(2,3)').value.text, 'Doc1!$C$2')
        self.assertEqual(_answer('ADDRESS(2,3,4,FALSE)').value.text, 'Doc1!R[2]C[3]')

    def test_address_reads_a_zero_style_flag_as_the_r1c1_style(self):
        self.assertEqual(_answer('ADDRESS(2,3,4,0)').value.text, 'Doc1!R[2]C[3]')

    def test_absref_adds_an_offset_to_a_cell(self):
        self.assertEqual(_answer('ABSREF("R[1]C[2]",AZ109)').value.text, 'BB110')

    def test_rows_counts_the_rows_of_a_range(self):
        outcome = _answer('ROWS(AZ112:AZ116)')
        self.assertEqual(outcome.value.value, 5)
        self.assertEqual(outcome.status, None)

    def test_index_reads_the_cell_of_a_range_at_a_position(self):
        data = replace_cell_formula(XLM_MACRO_TEXT_XLSM, 'AZ113', '123')
        engine = XlmEngine(XlmView(data))
        outcome = engine.call(_parsed_call('INDEX(AZ112:AZ116,2)'), _CURSOR)
        self.assertEqual(outcome.value.value, 123)

    def test_indirect_reads_the_cell_its_text_names(self):
        data = replace_cell_formula(XLM_MACRO_TEXT_XLSM, 'AZ113', '123')
        engine = XlmEngine(XlmView(data))
        outcome = engine.call(_parsed_call('INDIRECT("AZ113")'), _CURSOR)
        self.assertEqual(outcome.value.value, 123)

    def test_hlookup_finds_the_column_of_its_needle_in_the_top_row(self):
        data = replace_cell_formula(XLM_MACRO_TEXT_XLSM, 'AZ112', '"needle"')
        data = replace_cell_formula(data, 'AZ114', '123')
        engine = XlmEngine(XlmView(data))
        call = _parsed_call('HLOOKUP("needle",AZ112:AZ116,3,FALSE)')
        outcome = engine.call(call, _CURSOR)
        self.assertEqual(outcome.value.value, 123)
        self.assertEqual(outcome.status, None)

    def test_hlookup_answers_nothing_when_the_top_row_holds_no_match(self):
        data = replace_cell_formula(XLM_MACRO_TEXT_XLSM, 'AZ114', '"needle"')
        engine = XlmEngine(XlmView(data))
        call = _parsed_call('HLOOKUP("needle",AZ112:AZ116,3,FALSE)')
        outcome = engine.call(call, _CURSOR)
        self.assertEqual(outcome.value.partial, True)
        self.assertEqual(outcome.value.text, 'HLOOKUP("needle",AZ112:AZ116,3,FALSE)')

    def test_counta_counts_the_cells_of_a_range_that_hold_a_value(self):
        self.assertEqual(_answer('COUNTA(AZ109:AZ109)').value.value, 1)
        self.assertEqual(_answer('COUNTA(AZ200:AZ210)').value.value, 0)

    def test_counta_counts_a_cell_that_holds_empty_text(self):
        data = replace_cell_formula(XLM_MACRO_TEXT_XLSM, 'AZ113', '""')
        engine = XlmEngine(XlmView(data))
        outcome = engine.call(_parsed_call('COUNTA(AZ113:AZ113)'), _CURSOR)
        self.assertEqual(outcome.value.value, 1)


class TestMutationCommands(TestBase):

    def test_a_formula_write_installs_a_tree_that_a_later_read_executes(self):
        engine = XlmEngine(XlmView(XLM_MACRO_TEXT_XLSM))
        engine.call(_parsed_call('FORMULA("=1+2",BA110)'), _CURSOR)
        self.assertEqual(
            engine.read_reference(XlmReference('Doc1', 110, 53), _CURSOR).value,
            3,
        )

    def test_a_set_value_write_keeps_a_formula_text_a_literal_value(self):
        engine = XlmEngine(XlmView(XLM_MACRO_TEXT_XLSM))
        engine.call(_parsed_call('SET.VALUE(BA110,"=1+2")'), _CURSOR)
        self.assertEqual(
            engine.read_reference(XlmReference('Doc1', 110, 53), _CURSOR).value,
            '=1+2',
        )

    def test_a_partial_source_fails_the_write_and_marks_the_destination(self):
        engine = XlmEngine(XlmView(XLM_MACRO_TEXT_XLSM))
        outcome = engine.call(_parsed_call('FORMULA(FOO(1),BA110)'), _CURSOR)
        self.assertEqual(outcome.value.partial, True)
        read = engine.read_reference(XlmReference('Doc1', 110, 53), _CURSOR)
        self.assertEqual(read.value, 'BA110')
        self.assertEqual(read.partial, True)

    def test_set_name_stores_the_value_a_later_resolution_reads(self):
        engine = XlmEngine(XlmView(XLM_MACRO_TEXT_XLSM))
        engine.call(_parsed_call('SET.NAME("carry",42)'), _CURSOR)
        entry = engine.view.names.resolve('carry')
        assert entry is not None
        self.assertEqual(synthesize_formula(entry.formula), '42')
        engine.call(_parsed_call('SET.NAME("carrier",AZ109)'), _CURSOR)
        entry = engine.view.names.resolve('carrier')
        assert entry is not None
        self.assertEqual(synthesize_formula(entry.formula), 'AZ109')

    def test_define_name_stores_the_value_its_argument_evaluated_to(self):
        engine = XlmEngine(XlmView(XLM_MACRO_TEXT_XLSM))
        outcome = engine.call(_parsed_call('DEFINE.NAME("result",""&7)'), _CURSOR)
        self.assertEqual(outcome.value.text, 'DEFINE.NAME("result",7)')
        entry = engine.view.names.resolve('result')
        assert entry is not None
        self.assertEqual(synthesize_formula(entry.formula), '7')

    def test_a_name_stores_the_number_a_command_answered_rather_than_its_spelling(self):
        call = 'CALL("Kernel32","VirtualAlloc","JJJJJ",0,16,4096,64)'
        for command in ('SET.NAME', 'DEFINE.NAME'):
            with self.subTest(command=command):
                engine = XlmEngine(XlmView(XLM_MACRO_TEXT_XLSM))
                outcome = engine.call(_parsed_call(F'{command}("addr",{call})'), _CURSOR)
                self.assertEqual(outcome.status, None)
                entry = engine.view.names.resolve('addr')
                assert entry is not None
                self.assertEqual(synthesize_formula(entry.formula), '0')

    def test_a_name_set_to_a_command_result_lets_the_run_go_on(self):
        call = 'CALL("Kernel32","VirtualAlloc","JJJJJ",0,16,4096,64)'
        steps = _steps(('AZ109', F'SET.NAME("addr",{call})'))
        self.assertEqual(
            [(step.row, step.status) for step in steps[:2]],
            [(109, XlmStatus.FullEvaluation), (110, XlmStatus.FullEvaluation)],
        )

    def test_select_moves_the_cell_that_active_cell_reads(self):
        data = replace_cell_formula(XLM_MACRO_TEXT_XLSM, 'AZ112', '42')
        engine = XlmEngine(XlmView(data))
        engine.call(_parsed_call('SELECT(AZ112)'), _CURSOR)
        self.assertEqual(engine.call(_parsed_call('ACTIVE.CELL()'), _CURSOR).value.value, 42)

    def test_active_cell_without_a_selection_degrades(self):
        engine = XlmEngine(XlmView(XLM_MACRO_TEXT_XLSM))
        outcome = engine.call(_parsed_call('ACTIVE.CELL()'), _CURSOR)
        self.assertEqual(outcome.value.partial, True)
        self.assertEqual(outcome.value.text, 'ACTIVE.CELL()')


class TestSystemCommands(TestBase):

    @unittest.expectedFailure
    def test_get_cell_answers_the_contents_of_the_cell_it_reads(self):
        engine = XlmEngine(XlmView(XLM_MACRO_TEXT_XLSM))
        contents = engine.call(_parsed_call('GET.CELL(5,Doc2!AT74)'), _CURSOR)
        read = evaluate_expression(engine, parse_formula('Doc2!AT74'), _CURSOR)
        self.assertEqual(contents.value.value, read.value)

    @unittest.expectedFailure
    def test_get_cell_answers_the_default_height_of_a_row_that_stores_none(self):
        # the row of the cell stores no height, and its sheet stores 15 points as the default
        self.assertEqual(_answer('GET.CELL(17,Doc2!AT74)').value.value, 15)

    def test_the_get_commands_answer_the_environment_tables(self):
        for formula, expected in [
            ('GET.WORKSPACE(1)', 'Windows (64-bit) NT :.00'),
            ('GET.WORKSPACE(13)', '1016.25'),
            ('GET.WORKSPACE(14)', '480'),
            ('GET.DOCUMENT(76)', '[workbook.xlsm]Doc1'),
            ('GET.DOCUMENT(88)', 'workbook.xlsm'),
        ]:
            with self.subTest(formula=formula):
                outcome = _answer(formula)
                self.assertEqual(outcome.value.value, expected)
                self.assertEqual(outcome.value.partial, False)

    def test_the_workspace_and_window_tables_spell_their_calls(self):
        for formula, expected in [
            ('GET.WORKSPACE(13)', 'GET.WORKSPACE(13)'),
            ('GET.DOCUMENT(76)', '[workbook.xlsm]Doc1'),
            ('GET.WINDOW(30)', '[Book1]Sheet1'),
        ]:
            with self.subTest(formula=formula):
                outcome = _answer(formula)
                self.assertEqual(outcome.value.text, expected)

    def test_the_file_commands_write_and_measure_the_emulated_files(self):
        engine = XlmEngine(XlmView(XLM_MACRO_TEXT_XLSM))
        engine.call(_parsed_call('FOPEN("stager.js")'), _CURSOR)
        engine.call(_parsed_call('FWRITE("stager.js","var x = 1;")'), _CURSOR)
        outcome = engine.call(_parsed_call('FSIZE("stager.js")'), _CURSOR)
        self.assertEqual(outcome.value.value, 10)
        engine.call(_parsed_call('FWRITELN("stager.js","var y = 2;")'), _CURSOR)
        outcome = engine.call(_parsed_call('FSIZE("stager.js")'), _CURSOR)
        self.assertEqual(outcome.value.value, 22)

    def test_a_write_that_names_no_file_answers_the_first_opened_one(self):
        engine = XlmEngine(XlmView(XLM_MACRO_TEXT_XLSM))
        engine.call(_parsed_call('FOPEN("one.tmp")'), _CURSOR)
        engine.call(_parsed_call('FOPEN("two.tmp")'), _CURSOR)
        outcome = engine.call(_parsed_call('FWRITE("","payload")'), _CURSOR)
        self.assertEqual(outcome.value.text, 'FWRITE("one.tmp","payload")')
        self.assertEqual(engine.files.size('one.tmp'), 7)
        self.assertEqual(engine.files.size('two.tmp'), 0)

    def test_the_stubs_of_the_workspace_answer_their_fixed_values(self):
        for formula, value, text in [
            ('DIRECTORY()', 'C:\\Users\\user\\Documents', 'C:\\Users\\user\\Documents'),
            ('FILES("C:")', 'C:', 'FILES("C:")'),
            ('ERROR(FALSE)', 0, 'ERROR(FALSE)'),
            ('APP.MAXIMIZE()', True, 'TRUE'),
        ]:
            with self.subTest(formula=formula):
                outcome = _answer(formula)
                self.assertEqual(outcome.value.value, value)
                self.assertEqual(outcome.value.text, text)
                self.assertEqual(outcome.status, None)

    def test_register_makes_its_alias_answer_under_the_registered_name(self):
        engine = XlmEngine(XlmView(XLM_MACRO_TEXT_XLSM))
        outcome = engine.call(_parsed_call(
            'REGISTER("urlmon","URLDownloadToFileA","JJCCJJ","load",0,0)'), _CURSOR)
        self.assertEqual(outcome.status, None)
        self.assertEqual(engine.aliases['load'], 'urlmon.URLDownloadToFileA')

    def test_a_register_with_a_missing_argument_keeps_the_alias_at_its_position(self):
        engine = XlmEngine(XlmView(XLM_MACRO_TEXT_XLSM))
        outcome = engine.call(_parsed_call(
            'REGISTER("urlmon","URLDownloadToFileA",,"load")'), _CURSOR)
        self.assertEqual(outcome.status, None)
        self.assertEqual(engine.aliases['load'], 'urlmon.URLDownloadToFileA')
        self.assertEqual(
            outcome.value.text,
            'REGISTER("urlmon","URLDownloadToFileA",,"load")',
        )

    def test_register_id_names_the_function_but_registers_nothing(self):
        engine = XlmEngine(XlmView(XLM_MACRO_TEXT_XLSM))
        outcome = engine.call(_parsed_call(
            'REGISTER.ID("urlmon","URLDownloadToFileA","x")'), _CURSOR)
        self.assertEqual(outcome.value.value, 'urlmon.URLDownloadToFileA')
        self.assertEqual(engine.aliases, {})

    def test_the_kernel32_commands_write_through_the_emulated_memory(self):
        engine = XlmEngine(XlmView(XLM_MACRO_TEXT_XLSM))
        outcome = engine.call(_parsed_call('Kernel32.VirtualAlloc(0,16)'), _CURSOR)
        base = outcome.value.value
        outcome = engine.call(_parsed_call(
            F'Kernel32.WriteProcessMemory(-1,{base},"AB",2,0)'), _CURSOR)
        self.assertEqual(outcome.status, None)
        outcome = engine.call(_parsed_call(
            F'Kernel32.RtlCopyMemory({base + 8},"CD",2)'), _CURSOR)
        self.assertEqual(outcome.status, None)
        self.assertEqual(
            bytes(engine.memory._regions[0].data[:10]),
            b'AB\x00\x00\x00\x00\x00\x00CD',
        )
        self.assertEqual(outcome.value.text, F'Kernel32.RtlCopyMemory({base + 8},"4344",2)')

    def test_a_short_memory_write_keeps_the_length_of_its_region(self):
        engine = XlmEngine(XlmView(XLM_MACRO_TEXT_XLSM))
        base = engine.call(_parsed_call('Kernel32.VirtualAlloc(0,16)'), _CURSOR).value.value
        outcome = engine.call(_parsed_call(
            F'Kernel32.WriteProcessMemory(-1,{base},"AB",4,0)'), _CURSOR)
        self.assertEqual(outcome.status, None)
        self.assertEqual(engine.memory.peek(base, 16), b'AB' + bytes(14))

    def test_a_memory_write_of_a_negative_size_writes_nothing(self):
        engine = XlmEngine(XlmView(XLM_MACRO_TEXT_XLSM))
        base = engine.call(_parsed_call('Kernel32.VirtualAlloc(0,16)'), _CURSOR).value.value
        outcome = engine.call(_parsed_call(
            F'Kernel32.WriteProcessMemory(-1,{base + 4},"AB",-2,0)'), _CURSOR)
        self.assertEqual(outcome.status, XlmStatus.Error)
        self.assertEqual(engine.memory.peek(base, 16), bytes(16))

    def test_a_memory_write_spells_a_character_beyond_latin1_by_its_code_page_byte(self):
        engine = XlmEngine(XlmView(XLM_MACRO_TEXT_XLSM))
        base = engine.call(_parsed_call('Kernel32.VirtualAlloc(0,16)'), _CURSOR).value.value
        outcome = engine.call(_parsed_call(
            F'Kernel32.RtlCopyMemory({base},"€Ā",2)'), _CURSOR)
        self.assertEqual(outcome.status, None)
        self.assertEqual(engine.memory.peek(base, 2), b'\x80?')


class TestControlCommands(TestBase):

    def test_a_goto_to_a_missing_sheet_is_an_error_step(self):
        outcome = _answer('GOTO(NoSuch!A1)')
        self.assertEqual(outcome.status, XlmStatus.Error)
        self.assertEqual(outcome.jump, None)

    def test_a_goto_jumps_to_the_cell_it_names(self):
        outcome = _answer('GOTO(AZ109)')
        self.assertEqual(outcome.jump, XlmCursor('Doc1', 109, 52))

    def test_a_run_jumps_and_spells_the_address_it_resolves(self):
        self.assertEqual(_answer('RUN(AZ109)').jump, XlmCursor('Doc1', 109, 52))
        self.assertEqual(_answer('RUN(AZ109)').value.text, 'RUN(Doc1!AZ109)')
        self.assertEqual(
            _answer('RUN(AZ109,AZ109)').value.text,
            'RUN(Doc1!AZ109, AZ109)',
        )

    def test_an_offset_jumps_by_the_rows_and_columns_it_is_given(self):
        self.assertEqual(_answer('OFFSET(AZ109,1,0)').jump, XlmCursor('Doc1', 110, 52))

    def test_an_offset_above_the_first_formula_of_a_column_falls_through_to_it(self):
        self.assertEqual(_answer('OFFSET(AZ109,-1,0)').jump, XlmCursor('Doc1', 109, 52))

    def test_an_offset_without_its_columns_stays_partial(self):
        outcome = _answer('OFFSET(AZ109,1)')
        self.assertEqual(outcome.jump, None)
        self.assertEqual(outcome.value.partial, True)

    def test_an_on_time_jumps_to_the_cell_it_names(self):
        outcome = _answer('ON.TIME(0,AZ109)')
        self.assertEqual(outcome.jump, XlmCursor('Doc1', 109, 52))

    def test_an_on_time_with_the_wrong_number_of_arguments_is_an_error_step(self):
        outcome = _answer('ON.TIME(0,AZ109,1)')
        self.assertEqual(outcome.status, XlmStatus.Error)
        self.assertEqual(outcome.jump, None)

    def test_a_while_on_a_condition_that_spells_no_truth_value_is_an_error_step(self):
        outcome = _answer('WHILE("junk")')
        self.assertEqual(outcome.status, XlmStatus.Error)
        self.assertEqual(outcome.value.text, 'WHILE("junk")')
