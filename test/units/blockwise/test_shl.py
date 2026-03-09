from .. import TestUnitBase


class TestSHL(TestUnitBase):

    def test_shift_left_by_one(self):
        unit = self.ldu('shl', 1)
        self.assertEqual(unit(B'\x01\x02\x03'), B'\x02\x04\x06')

    def test_shift_left_by_four(self):
        unit = self.ldu('shl', 4)
        self.assertEqual(unit(B'\x01\x0A'), B'\x10\xA0')

    def test_shift_left_by_zero(self):
        unit = self.ldu('shl', 0)
        data = B'\xAB\xCD\xEF'
        self.assertEqual(unit(data), data)
