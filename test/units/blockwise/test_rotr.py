from .. import TestUnitBase


class TestROTR(TestUnitBase):

    def test_byte_swapping(self):
        unit = self.ldu('rotr', '-B', 2, 8)
        self.assertEqual(unit(B'ABCDEFGHI'), B'BADCFEHG\0')

    def test_no_auto_block(self):
        unit = self.ldu('rotr', 0x101)
        self.assertEqual(unit(B'\x02\x02\x02'), B'\x01\x01\x01')

    def test_byte_circular(self):
        unit = self.ldu('rotr', '-B', 3, 8)
        self.assertEqual(unit(B'BAACAADAA'), B'AABAACAAD')

    def test_invertible_with_rotl(self):
        data = B'\x01\x02\x03\x04\x05\x06\x07\x08'
        rotl = self.ldu('rotl', 3)
        rotr = self.ldu('rotr', 3)
        self.assertEqual(rotr(rotl(data)), data)
