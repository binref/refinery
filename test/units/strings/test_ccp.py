from .. import TestUnitBase


class TestCCP(TestUnitBase):

    def test_prepend_basic(self):
        unit = self.load(b'XYZ')
        self.assertEqual(unit(b'ABC'), b'XYZABC')

    def test_prepend_empty_input(self):
        unit = self.load(b'XYZ')
        self.assertEqual(unit(b''), b'XYZ')

    def test_prepend_empty_argument(self):
        unit = self.load(b'')
        self.assertEqual(unit(b'ABC'), b'ABC')

    def test_prepend_binary(self):
        unit = self.load(B'\xFF\x00')
        self.assertEqual(unit(B'\x01\x02'), B'\xFF\x00\x01\x02')
