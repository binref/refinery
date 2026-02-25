from .. import TestUnitBase


class TestCCA(TestUnitBase):

    def test_append_basic(self):
        unit = self.load(b'XYZ')
        self.assertEqual(unit(b'ABC'), b'ABCXYZ')

    def test_append_empty_input(self):
        unit = self.load(b'XYZ')
        self.assertEqual(unit(b''), b'XYZ')

    def test_append_empty_argument(self):
        unit = self.load(b'')
        self.assertEqual(unit(b'ABC'), b'ABC')

    def test_append_binary(self):
        unit = self.load(B'\xFF\x00')
        self.assertEqual(unit(B'\x01\x02'), B'\x01\x02\xFF\x00')
