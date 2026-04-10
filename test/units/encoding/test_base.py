from refinery import b64, b85, map
from .. import TestUnitBase


class TestBaseUnit(TestUnitBase):

    def test_base64_01(self):
        unit = self.load('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/')
        data = self.generate_random_buffer(200)
        self.assertEqual(bytes(data | -self.ldu('b64') | unit), data)

    def test_base64_02(self):
        alphabet = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
        shuffled = b'tu1grak3IXc2p/yfY4mqMQbZEOD7Nhl9G06eB+RFCALi8jW5ToKJVwSdPvsUHznx'
        unit = self.load(shuffled)
        data = self.generate_random_buffer(200)
        self.assertEqual(bytes(data | -b64 | map(alphabet, shuffled) | unit), data)

    def test_base85_01(self):
        unit = self.load('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~')
        data = self.generate_random_buffer(200)
        self.assertEqual(bytes(data | -b85 | unit), data)

    def test_base85_02(self):
        alphabet = b'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~'
        shuffled = b'HD+>Wg&c;Rp}_N!a|1i#5IC<mG=(wOlZ2~?8`s*PXyToSveQ@$96Lru%t7zUkq{3BYA40M)E-jdKJhbxVfF^n'
        unit = self.load(shuffled)
        data = self.generate_random_buffer(200)
        self.assertEqual(bytes(data | -b85 | map(alphabet, shuffled) | unit), data)

    def test_against_b32(self):
        from refinery import b32
        base = self.load('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567')
        for k in (4, 8, 12, 50, 117):
            b = self.generate_random_buffer(k)
            self.assertEqual(b | -base | b32 | bytes, b)
            self.assertEqual(b | -b32 | base | bytes, b)

    def test_against_b64(self):
        from refinery import b64
        alphabet = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
        base = self.load(alphabet)
        for k in (4, 8, 12, 50, 117):
            b = self.generate_random_buffer(k)
            self.assertEqual(b | -base | b64 | bytes, b)
            self.assertEqual(b | -b64 | base | bytes, b)
