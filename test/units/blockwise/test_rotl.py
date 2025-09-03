from .. import TestUnitBase


class TestROTL(TestUnitBase):

    def test_byte_swapping(self):
        unit = self.ldu('rotl', '-B', 2, 8)
        self.assertEqual(unit(B'ABCDEFGHI'), B'BADCFEHG\0')

    def test_no_auto_block(self):
        unit = self.ldu('rotl', 0x101)
        self.assertEqual(unit(B'\x01\x01\x01'), B'\x02\x02\x02')

    def test_byte_circular(self):
        unit = self.ldu('rotl', '-B', 3, 8)
        self.assertEqual(unit(B'AABAACAAD'), B'BAACAADAA')

    def test_iterable_argument(self):
        unit = self.ldu('rotl', 'range:3')
        self.assertEqual(unit(B'\x02\x01\x01\x01'), B'\x02\x02\x04\x01')
