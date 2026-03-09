from ... import TestUnitBase


class TestBlowfish(TestUnitBase):

    def test_ecb_roundtrip(self):
        K = b'REFINERY' * 2
        M = b'Blowfish'
        unit = self.load(K, mode='ecb', raw=True)
        C = M | -unit | bytes
        self.assertEqual(unit(C), M)

    def test_cbc_roundtrip(self):
        K = b'REFINERY' * 2
        V = b'\x00' * 8
        M = b'TestData'
        unit = self.load(K, iv=V, mode='cbc', raw=True)
        C = M | -unit | bytes
        self.assertEqual(unit(C), M)

    def test_ecb_known_vector(self):
        K = bytes.fromhex('0000000000000000')
        M = bytes.fromhex('0000000000000000')
        C = bytes.fromhex('4EF997456198DD78')
        unit = self.load(K, mode='ecb', raw=True)
        self.assertEqual(unit(C), M)
