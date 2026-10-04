from __future__ import annotations

from refinery.lib.excel import parse_formula
from refinery.lib.scripts.xlm.blocks import XlmBlock, marker_of, pair_blocks
from test import TestBase


class TestMarkerOf(TestBase):

    def test_the_block_markers_their_formulas_spell(self):
        for formula, expected in [
            ('IF(A1)', 'IF'),
            ('ELSE()', 'ELSE'),
            ('ELSE.IF(A1)', 'ELSE.IF'),
            ('END.IF()', 'END.IF'),
        ]:
            with self.subTest(formula=formula):
                self.assertEqual(marker_of(parse_formula(formula)), expected)

    def test_no_other_formula_spells_a_block_marker(self):
        for formula in [
            'IF(A1,1)',
            'IF(A1,1,2)',
            'IF()',
            'WHILE(A1)',
            'FOR.CELL("x",A1:B2)',
            'NEXT()',
            'GOTO(A1)',
            'A1',
            '1',
            '"ELSE"',
        ]:
            with self.subTest(formula=formula):
                self.assertEqual(marker_of(parse_formula(formula)), None)


class TestPairBlocks(TestBase):

    def test_the_markers_of_a_column_pair_by_nesting(self):
        blocks = pair_blocks([
            (1, 'IF'),
            (3, 'ELSE.IF'),
            (5, 'ELSE'),
            (7, 'END.IF'),
            (9, 'IF'),
            (11, 'END.IF'),
        ])
        self.assertEqual(blocks[1], XlmBlock(1, (3, 5), 7))
        self.assertEqual(blocks[3], blocks[1])
        self.assertEqual(blocks[5], blocks[1])
        self.assertEqual(blocks[7], blocks[1])
        self.assertEqual(blocks[9], XlmBlock(9, (), 11))
        self.assertEqual(blocks[11], blocks[9])

    def test_a_marker_no_open_block_owns_pairs_with_nothing(self):
        self.assertEqual(pair_blocks([(2, 'ELSE'), (3, 'ELSE.IF'), (4, 'END.IF')]), {})

    def test_a_block_no_end_if_closes_pairs_with_nothing(self):
        self.assertEqual(pair_blocks([(1, 'IF'), (3, 'ELSE'), (5, 'ELSE.IF')]), {})
