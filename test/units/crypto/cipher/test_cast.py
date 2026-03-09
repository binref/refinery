from ... import TestUnitBase


class TestCAST(TestUnitBase):

    def test_ecb_roundtrip(self):
        K = b'REFINERY' * 2
        M = b'TestData'
        unit = self.load(K, mode='ecb', raw=True)
        C = M | -unit | bytes
        self.assertEqual(unit(C), M)

    def test_cbc_roundtrip(self):
        K = b'REFINERY' * 2
        V = b'\x00' * 8
        M = b'CastTest'
        unit = self.load(K, iv=V, mode='cbc', raw=True)
        C = M | -unit | bytes
        self.assertEqual(unit(C), M)

    def test_rfc2144_128bit(self):
        K = bytes.fromhex('0123456712345678234567893456789A')
        M = bytes.fromhex('0123456789ABCDEF')
        C = bytes.fromhex('238B4FE5847E44B2')
        unit = self.load(K, mode='ecb', raw=True)
        self.assertEqual(unit(C), M)
