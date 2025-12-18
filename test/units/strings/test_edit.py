from .. import TestUnitBase


class TestEditUnit(TestUnitBase):

    def test_simple_edit_insert(self):
        unit = self.load('3:3', B'ARY.')
        self.assertEqual(unit(B'BINREF'), B'BINARY.REF')

    def test_simple_edit_overwrite_01(self):
        unit = self.load(3, B'ARY.', insert=False)
        self.assertEqual(unit(B'BINREF'), B'BINARY.')

    def test_simple_edit_overwrite_02(self):
        unit = self.load(4, B'O')
        self.assertEqual(unit(B'BINREF'), B'BINROF')
