from __future__ import annotations

from refinery.lib.excel import parse_formula, synthesize_formula
from refinery.lib.scripts.xlm import XlmCursor, XlmEngine, XlmReference, XlmView
from refinery.lib.scripts.xlm.trace import XlmStatus
from test import TestBase
from test.lib.excel.samples import XLM_MACRO_TEXT_XLSM
from test.lib.scripts.xlm.test_engine import _steps, _with_cell_formula

_CURSOR = XlmCursor('Doc1', 109, 52)


def _answer(formula: str):
    engine = XlmEngine(XlmView(XLM_MACRO_TEXT_XLSM))
    return engine.call(parse_formula(formula), _CURSOR)


class TestNumericCommands(TestBase):

    def test_arithmetic_commands_answer_their_numbers(self):
        for formula, expected in [
            ('ABS(-3)', '3'),
            ('INT(4.7)', '4'),
            ('SQRT(10)', '3'),
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
        first = engine.call(parse_formula('NOW()'), _CURSOR).value.value
        second = engine.call(parse_formula('NOW()'), _CURSOR).value.value
        self.assertAlmostEqual((second - first) * 86400, 2, delta=1)

    def test_iserror_flips_after_ten_repeats_at_one_cell(self):
        engine = XlmEngine(XlmView(XLM_MACRO_TEXT_XLSM))
        call = parse_formula('ISERROR(1)')
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
            ('AND(TRUE,TRUE)', 'True'),
            ('AND(TRUE,FALSE)', 'False'),
            ('OR(FALSE,TRUE)', 'True'),
            ('OR(FALSE,FALSE)', 'False'),
            ('NOT(TRUE)', 'False'),
            ('COUNT(1,2,3)', '3'),
            ('ISNUMBER(1)', '1'),
            ('ISNUMBER("a")', '0'),
        ]:
            with self.subTest(formula=formula):
                outcome = _answer(formula)
                self.assertEqual(outcome.value.text, expected)
                self.assertEqual(outcome.status, None)


class TestStringCommands(TestBase):

    def test_string_commands_answer_their_texts(self):
        for formula, expected in [
            ('CHAR(65)', 'A'),
            ('CODE("A")', '65'),
            ('CONCATENATE("a","b")', '"ab"'),
            ('LEN("abcd")', '4'),
            ('MID("abcdef",2,3)', 'bcd'),
            ('SEARCH("c","abcd")', '2'),
            ('T(5)', '5'),
            ('TEXT(5,0)', '5'),
        ]:
            with self.subTest(formula=formula):
                outcome = _answer(formula)
                self.assertEqual(outcome.value.text, expected)
                self.assertEqual(outcome.status, None)

    def test_char_answers_an_error_for_a_code_outside_the_bytes(self):
        outcome = _answer('CHAR(300)')
        self.assertEqual(outcome.status, XlmStatus.Error)


class TestLookupCommands(TestBase):

    def test_address_spells_the_cell_it_names(self):
        self.assertEqual(_answer('ADDRESS(2,3)').value.text, 'Doc1!$C$2')
        self.assertEqual(_answer('ADDRESS(2,3,4,FALSE)').value.text, 'Doc1!R[2]C[3]')

    def test_absref_adds_an_offset_to_a_cell(self):
        self.assertEqual(_answer('ABSREF("R[1]C[2]",AZ109)').value.text, 'BB110')

    def test_rows_counts_the_rows_of_a_range(self):
        outcome = _answer('ROWS(AZ112:AZ116)')
        self.assertEqual(outcome.value.value, 5)
        self.assertEqual(outcome.status, None)

    def test_index_reads_the_cell_of_a_range_at_a_position(self):
        data = _with_cell_formula(XLM_MACRO_TEXT_XLSM, 'AZ113', '123')
        engine = XlmEngine(XlmView(data))
        outcome = engine.call(parse_formula('INDEX(AZ112:AZ116,2)'), _CURSOR)
        self.assertEqual(outcome.value.value, 123)

    def test_indirect_reads_the_cell_its_text_names(self):
        data = _with_cell_formula(XLM_MACRO_TEXT_XLSM, 'AZ113', '123')
        engine = XlmEngine(XlmView(data))
        outcome = engine.call(parse_formula('INDIRECT("AZ113")'), _CURSOR)
        self.assertEqual(outcome.value.value, 123)

    def test_hlookup_finds_the_first_match_below_its_index_row(self):
        data = _with_cell_formula(XLM_MACRO_TEXT_XLSM, 'AZ114', '"needle"')
        engine = XlmEngine(XlmView(data))
        call = parse_formula('HLOOKUP("needle",AZ112:AZ116,1,FALSE)')
        outcome = engine.call(call, _CURSOR)
        self.assertEqual(outcome.value.value, 'needle')
        self.assertEqual(outcome.status, None)

    def test_counta_counts_the_cells_of_a_range_that_hold_a_value(self):
        self.assertEqual(_answer('COUNTA(AZ109:AZ109)').value.value, 1)
        self.assertEqual(_answer('COUNTA(AZ200:AZ210)').value.value, 0)


class TestMutationCommands(TestBase):

    def test_a_formula_write_installs_a_tree_that_a_later_read_executes(self):
        engine = XlmEngine(XlmView(XLM_MACRO_TEXT_XLSM))
        engine.call(parse_formula('FORMULA("=1+2",BA110)'), _CURSOR)
        self.assertEqual(
            engine.read_reference(XlmReference('Doc1', 110, 53), _CURSOR).value,
            3,
        )

    def test_a_set_value_write_keeps_a_formula_text_a_literal_value(self):
        engine = XlmEngine(XlmView(XLM_MACRO_TEXT_XLSM))
        engine.call(parse_formula('SET.VALUE(BA110,"=1+2")'), _CURSOR)
        self.assertEqual(
            engine.read_reference(XlmReference('Doc1', 110, 53), _CURSOR).value,
            '=1+2',
        )

    def test_a_partial_source_fails_the_write_and_marks_the_destination(self):
        engine = XlmEngine(XlmView(XLM_MACRO_TEXT_XLSM))
        outcome = engine.call(parse_formula('FORMULA(FOO(1),BA110)'), _CURSOR)
        self.assertEqual(outcome.value.partial, True)
        read = engine.read_reference(XlmReference('Doc1', 110, 53), _CURSOR)
        self.assertEqual(read.value, 'BA110')
        self.assertEqual(read.partial, True)

    def test_set_name_stores_the_value_a_later_resolution_reads(self):
        engine = XlmEngine(XlmView(XLM_MACRO_TEXT_XLSM))
        engine.call(parse_formula('SET.NAME("carry",42)'), _CURSOR)
        entry = engine.view.names.resolve('carry')
        assert entry is not None
        self.assertEqual(synthesize_formula(entry.formula), '42')
        engine.call(parse_formula('SET.NAME("carrier",AZ109)'), _CURSOR)
        entry = engine.view.names.resolve('carrier')
        assert entry is not None
        self.assertEqual(synthesize_formula(entry.formula), 'AZ109')

    def test_define_name_stores_the_value_its_argument_evaluated_to(self):
        engine = XlmEngine(XlmView(XLM_MACRO_TEXT_XLSM))
        outcome = engine.call(parse_formula('DEFINE.NAME("result",""&7)'), _CURSOR)
        self.assertEqual(outcome.value.text, 'DEFINE.NAME("result",7)')
        entry = engine.view.names.resolve('result')
        assert entry is not None
        self.assertEqual(synthesize_formula(entry.formula), '7')

    def test_select_moves_the_cell_that_active_cell_reads(self):
        data = _with_cell_formula(XLM_MACRO_TEXT_XLSM, 'AZ112', '42')
        engine = XlmEngine(XlmView(data))
        engine.call(parse_formula('SELECT(AZ112)'), _CURSOR)
        self.assertEqual(engine.call(parse_formula('ACTIVE.CELL()'), _CURSOR).value.value, 42)

    def test_active_cell_without_a_selection_degrades(self):
        engine = XlmEngine(XlmView(XLM_MACRO_TEXT_XLSM))
        outcome = engine.call(parse_formula('ACTIVE.CELL()'), _CURSOR)
        self.assertEqual(outcome.value.partial, True)
        self.assertEqual(outcome.value.text, 'ACTIVE.CELL()')


class TestSystemCommands(TestBase):

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
        engine.call(parse_formula('FOPEN("stager.js")'), _CURSOR)
        engine.call(parse_formula('FWRITE("stager.js","var x = 1;")'), _CURSOR)
        outcome = engine.call(parse_formula('FSIZE("stager.js")'), _CURSOR)
        self.assertEqual(outcome.value.value, 10)
        engine.call(parse_formula('FWRITELN("stager.js","var y = 2;")'), _CURSOR)
        outcome = engine.call(parse_formula('FSIZE("stager.js")'), _CURSOR)
        self.assertEqual(outcome.value.value, 22)

    def test_a_write_that_names_no_file_answers_the_first_opened_one(self):
        engine = XlmEngine(XlmView(XLM_MACRO_TEXT_XLSM))
        engine.call(parse_formula('FOPEN("one.tmp")'), _CURSOR)
        engine.call(parse_formula('FOPEN("two.tmp")'), _CURSOR)
        outcome = engine.call(parse_formula('FWRITE("","payload")'), _CURSOR)
        self.assertEqual(outcome.value.text, 'FWRITE("one.tmp","payload")')
        self.assertEqual(engine.files.size('one.tmp'), 7)
        self.assertEqual(engine.files.size('two.tmp'), 0)

    def test_the_stubs_of_the_workspace_answer_their_fixed_values(self):
        for formula, value, text in [
            ('DIRECTORY()', 'C:\\Users\\user\\Documents', 'C:\\Users\\user\\Documents'),
            ('FILES("C:")', 'C:', 'FILES("C:")'),
            ('ERROR(FALSE)', 0, 'ERROR(FALSE)'),
            ('APP.MAXIMIZE()', True, 'True'),
        ]:
            with self.subTest(formula=formula):
                outcome = _answer(formula)
                self.assertEqual(outcome.value.value, value)
                self.assertEqual(outcome.value.text, text)
                self.assertEqual(outcome.status, None)

    def test_register_makes_its_alias_answer_under_the_registered_name(self):
        engine = XlmEngine(XlmView(XLM_MACRO_TEXT_XLSM))
        outcome = engine.call(parse_formula(
            'REGISTER("urlmon","URLDownloadToFileA","JJCCJJ","load",0,0)'), _CURSOR)
        self.assertEqual(outcome.status, None)
        self.assertEqual(engine.aliases['load'], 'urlmon.URLDownloadToFileA')

    def test_register_id_names_the_function_but_registers_nothing(self):
        engine = XlmEngine(XlmView(XLM_MACRO_TEXT_XLSM))
        outcome = engine.call(parse_formula(
            'REGISTER.ID("urlmon","URLDownloadToFileA","x")'), _CURSOR)
        self.assertEqual(outcome.value.value, 'urlmon.URLDownloadToFileA')
        self.assertEqual(engine.aliases, {})

    def test_the_kernel32_commands_write_through_the_emulated_memory(self):
        engine = XlmEngine(XlmView(XLM_MACRO_TEXT_XLSM))
        outcome = engine.call(parse_formula('Kernel32.VirtualAlloc(0,16)'), _CURSOR)
        base = outcome.value.value
        outcome = engine.call(parse_formula(
            F'Kernel32.WriteProcessMemory(-1,{base},"AB",2,0)'), _CURSOR)
        self.assertEqual(outcome.status, None)
        outcome = engine.call(parse_formula(
            F'Kernel32.RtlCopyMemory({base + 8},"CD",2)'), _CURSOR)
        self.assertEqual(outcome.status, None)
        self.assertEqual(
            bytes(engine.memory._regions[0].data[:10]),
            b'AB\x00\x00\x00\x00\x00\x00CD',
        )
        self.assertEqual(outcome.value.text, F'Kernel32.RtlCopyMemory({base + 8},"4344",2)')
