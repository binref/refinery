from ... import TestUnitBase


class TestCryptDeriveKey(TestUnitBase):

    def test_SHA2(self):
        from hashlib import sha256
        data = B'PASSWORD'
        unit = self.load(32, 'SHA256')
        test = data | unit | bytes
        goal = sha256(data).digest()[:32]
        self.assertEqual(test, goal)

    def test_md5(self):
        unit = self.load(32, 'MD5')
        self.assertEqual(unit(B'PASSWORD'), bytes.fromhex(
            'E05607004B7B480E50F30B43B0AB617B446FC8CFB7CFCA6F6BDC157523FAE4B4'))

    def test_sha1(self):
        unit = self.load(32, 'SHA1')
        self.assertEqual(unit(B'PASSWORD'), bytes.fromhex(
            '0419E7805CA7B3B87A9BBE78792E047325C2DA4C2F53BCDCE64DCD4E6E2B1A84'))

    def test_md2(self):
        unit = self.load(32, 'MD2')
        self.assertEqual(unit(B'PASSWORD'), bytes.fromhex(
            '659B4DE15B771070AB9CA0FA4A3A76AB28F6F34DE11F52BD9E76F92BF16C6C2E'))

    def test_md4(self):
        unit = self.load(32, 'MD4')
        self.assertEqual(unit(B'PASSWORD'), bytes.fromhex(
            '8705FDEB84BBA6CAC8AD364996741F81723287B33601C1E60D5F31F90FA0AF34'))

    def test_sha224(self):
        unit = self.load(28, 'SHA224')
        self.assertEqual(unit(B'PASSWORD'), bytes.fromhex(
            '91F0572F12A77295E530583937E9D463C37C11760562E189CBB8188C'))

    def test_sha384(self):
        unit = self.load(32, 'SHA384')
        self.assertEqual(unit(B'PASSWORD'), bytes.fromhex(
            'D141B7E90779B15793CCE4046F86FAA9D32950D7E542761874460231EB94BCFE'))

    def test_sha512(self):
        unit = self.load(32, 'SHA512')
        self.assertEqual(unit(B'PASSWORD'), bytes.fromhex(
            '911B0A07A8CACFEBC5F1F45596D67017136C950499FA5B4FF6FAFFA031F3CEC7'))

    def test_too_large(self):
        from refinery.units import RefineryPartialResult
        unit = self.load(33, 'MD5')
        with self.assertRaises(RefineryPartialResult) as context:
            unit(B'PASSWORD')
        self.assertEqual(context.exception.partial, bytes.fromhex(
            'E05607004B7B480E50F30B43B0AB617B446FC8CFB7CFCA6F6BDC157523FAE4B4'))
