from ... import TestUnitBase


class TestDES(TestUnitBase):

    def test_ecb_roundtrip(self):
        K = b'REFINERY'
        M = b'TestData'
        unit = self.load(K, mode='ecb', raw=True)
        C = M | -unit | bytes
        self.assertEqual(unit(C), M)

    def test_cbc_roundtrip(self):
        K = b'REFINERY'
        V = b'\x00' * 8
        M = b'TestData'
        unit = self.load(K, iv=V, mode='cbc', raw=True)
        C = M | -unit | bytes
        self.assertEqual(unit(C), M)

    def test_ecb_known_vector(self):
        K = bytes.fromhex('0123456789ABCDEF')
        M = bytes.fromhex('4E6F772069732074')
        C = bytes.fromhex('3FA40E8A984D4815')
        unit = self.load(K, mode='ecb', raw=True)
        self.assertEqual(unit(C), M)
