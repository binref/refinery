from __future__ import annotations

from refinery.lib.excel import open_workbook, synthesize_formula
from refinery.lib.excel.formula.model import Expression, XlUnparsedFormula
from refinery.lib.scripts import TREE_RECURSION_DEPTH, RecursionDepth
from refinery.lib.scripts.xlm import XlmNameEntry, XlmNameTable
from test import TestBase
from test.lib.excel.samples import (
    XLM_MACRO_ASSIGN_BIFF8,
    XLM_MACRO_FORMULA_XLSM,
    XLM_MACRO_NAMES_BIFF8,
    XLM_MACRO_RPN_BIFF8,
    XLM_MACRO_TEXT_XLSM,
)

_MALDOC = 'dc44bbfc845fc078cf38b9a3543a32ae1742be8c6320b81cf6cd5a8cee3c696a'


def _table(data: bytes) -> XlmNameTable:
    return XlmNameTable(open_workbook(data))


def _resolve(table: XlmNameTable, name: str) -> XlmNameEntry:
    entry = table.resolve(name)
    assert entry is not None
    return entry


def _text(formula: Expression) -> str:
    with RecursionDepth(TREE_RECURSION_DEPTH):
        return synthesize_formula(formula)


class TestXlmNameResolution(TestBase):

    def test_auto_open_resolves_to_a_cell_reference_on_every_sample(self):
        for data, expected in [
            (XLM_MACRO_RPN_BIFF8, 'mP9mScF1m5!$S$41'),
            (XLM_MACRO_NAMES_BIFF8, 'Acf444!$A$9591'),
            (XLM_MACRO_ASSIGN_BIFF8, 'sod!$ER$25268'),
            (XLM_MACRO_TEXT_XLSM, 'Doc1!$AZ$102'),
            (XLM_MACRO_FORMULA_XLSM, 'PCWV!$G$1'),
        ]:
            with self.subTest(expected=expected):
                table = _table(data)
                entry = _resolve(table, 'AUTO_OPEN')
                self.assertEqual(entry.sheet, None)
                self.assertEqual(_text(entry.formula), expected)

    def test_entries_of_the_xlsb_maldoc(self):
        table = _table(self.download_sample(_MALDOC))
        entry_point = 'Auto_Open' + '7' * 114
        self.assertEqual(_text(_resolve(table, entry_point).formula), 'Tiposa!$G$1')
        self.assertEqual(_text(_resolve(table, 'Fola').formula), 'Tiposa!$E$16')
        self.assertEqual(_text(_resolve(table, 'Ropaasf').formula), '-679215104')

    def test_name_sets_of_the_samples(self):
        for sample, data, expected in [
            ('rpn_biff8', XLM_MACRO_RPN_BIFF8, ['_xlfn.CONCAT', 'auto_open']),
            (
                'names_biff8',
                XLM_MACRO_NAMES_BIFF8,
                [
                    'Application.Quit', 'auto_open', 'Bhf3WDT', 'bXTBeZNN',
                    'fhQ3BngPgn8GXh2', 'gefg', 'hf3iCgNUuxNu1WDT', 'uBdhH',
                    'VhQn8GXh2', 'VPYBVp', 'YwPkVFIXiyQV',
                ],
            ),
            (
                'assign_biff8',
                XLM_MACRO_ASSIGN_BIFF8,
                [
                    'auto_open', 'GyGkxwNQ', 'jRiUYymkewtQ', 'pjZFOONS',
                    'uTZVgjyU', 'xofsDmlZLmJV', 'ZirmQgyT',
                ],
            ),
            ('text_xlsm', XLM_MACRO_TEXT_XLSM, ['auto_open']),
            (
                'formula_xlsm',
                XLM_MACRO_FORMULA_XLSM,
                ['NEVR1', 'NEVR2', 'NEVR3', 'NEVR4', 'NEVR5', 'NEVR6', 'NEVR7', 'auto_open'],
            ),
        ]:
            with self.subTest(sample=sample):
                self.assertEqual(
                    [name for name, _ in _table(data).entries()],
                    expected,
                )

    def test_a_name_the_reader_cannot_decode_stays_the_carrier(self):
        table = _table(XLM_MACRO_NAMES_BIFF8)
        formula = _resolve(table, 'gefg').formula
        assert isinstance(formula, XlUnparsedFormula)
        self.assertEqual(formula.text, '3a000000000000')
        self.assertIsInstance(_resolve(table, 'Application.Quit').formula, XlUnparsedFormula)

    def test_a_scoped_name_keeps_its_sheet_index(self):
        entry = _resolve(_table(XLM_MACRO_NAMES_BIFF8), 'ubdhh')
        self.assertEqual((entry.sheet, _text(entry.formula)), (0, '#NAME?'))


class TestXlmNameDiscovery(TestBase):

    def test_prefix_matches_list_every_entry_that_starts_with_the_pattern(self):
        self.assertEqual(
            [name for name, _ in _table(XLM_MACRO_FORMULA_XLSM).fuzzy('NEVR')],
            ['NEVR1', 'NEVR2', 'NEVR3', 'NEVR4', 'NEVR5', 'NEVR6', 'NEVR7'],
        )

    def test_a_prefix_match_suppresses_the_subsequence_fallback(self):
        self.assertEqual(
            [name for name, _ in _table(XLM_MACRO_NAMES_BIFF8).fuzzy('app')],
            ['Application.Quit'],
        )

    def test_without_a_prefix_match_the_characters_in_order_match(self):
        self.assertEqual(
            [name for name, _ in _table(XLM_MACRO_NAMES_BIFF8).fuzzy('ao')],
            ['Application.Quit', 'auto_open'],
        )

    def test_a_pattern_no_name_matches_yields_no_entries(self):
        self.assertEqual(_table(XLM_MACRO_NAMES_BIFF8).fuzzy('xyzzy'), [])

    def test_the_maldoc_entry_point_is_found_by_prefix_alone(self):
        table = _table(self.download_sample(_MALDOC))
        self.assertEqual(
            [name for name, _ in table.fuzzy('auto')],
            ['Auto_Open' + '7' * 114],
        )


class TestXlmNameTableMutation(TestBase):

    def test_undefine_removes_and_define_installs_an_entry(self):
        table = _table(XLM_MACRO_TEXT_XLSM)
        entry = _resolve(table, 'auto_open')
        table.undefine('AUTO_OPEN')
        self.assertEqual(table.resolve('auto_open'), None)
        table.define('EntryPoint', entry)
        self.assertEqual(_resolve(table, 'entrypoint'), entry)
