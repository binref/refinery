from ... import TestUnitBase


class TestDES3(TestUnitBase):

    def test_ecb_roundtrip(self):
        K = b'REFINERYBINREFIN3RDBLOCK'
        M = b'TestData'
        unit = self.load(K, mode='ecb', raw=True)
        C = M | -unit | bytes
        self.assertEqual(unit(C), M)

    def test_cbc_roundtrip(self):
        K = b'REFINERYBINREFIN3RDBLOCK'
        V = b'\x00' * 8
        M = b'TestData'
        unit = self.load(K, iv=V, mode='cbc', raw=True)
        C = M | -unit | bytes
        self.assertEqual(unit(C), M)

    def test_ecb_known_vector(self):
        K = bytes.fromhex('0123456789ABCDEF23456789ABCDEF01456789ABCDEF0123')
        M = bytes.fromhex('4E6F772069732074')
        unit = self.load(K, mode='ecb', raw=True)
        C = M | -unit | bytes
        self.assertEqual(unit(C), M)
