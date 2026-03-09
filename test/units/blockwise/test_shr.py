from .. import TestUnitBase


class TestSHR(TestUnitBase):

    def test_shift_right_by_one(self):
        unit = self.ldu('shr', 1)
        self.assertEqual(unit(B'\x02\x04\x06'), B'\x01\x02\x03')

    def test_shift_right_by_four(self):
        unit = self.ldu('shr', 4)
        self.assertEqual(unit(B'\x10\xA0'), B'\x01\x0A')

    def test_shift_right_by_zero(self):
        unit = self.ldu('shr', 0)
        data = B'\xAB\xCD\xEF'
        self.assertEqual(unit(data), data)
