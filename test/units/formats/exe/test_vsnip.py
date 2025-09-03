from ... import TestUnitBase
from . import MACHO_TEST


class TestVirtualAddressSnip(TestUnitBase):

    def test_pe_01(self):
        data = self.download_sample('c41d0c40d1a19820768ea76111c9d5210c2cb500e93a85bf706dfea9244ce916')
        unit = self.load('0x0140002030', ascii=True)
        self.assertEqual(unit(data), B'You will never see me.')

    def test_pe_02(self):
        data = self.download_sample('c41d0c40d1a19820768ea76111c9d5210c2cb500e93a85bf706dfea9244ce916')
        unit = self.load(slice(0x0140002030, 22))
        self.assertEqual(unit(data), B'You will never see me.')

    def test_pe_rebase(self):
        data = self.download_sample('c41d0c40d1a19820768ea76111c9d5210c2cb500e93a85bf706dfea9244ce916')
        unit = self.load('0x2030', ascii=True, base=0)
        self.assertEqual(unit(data), B'You will never see me.')

    def test_elf_01(self):
        data = self.download_sample('c5ba314fbf02989af9e2b5edb48626aede10f2d4569095a542ed0f2033068117')
        unit = self.load('0x08054203', ascii=True)
        self.assertEqual(unit(data), B' rootkiter : The creator')

    def test_elf_02(self):
        data = self.download_sample('c5ba314fbf02989af9e2b5edb48626aede10f2d4569095a542ed0f2033068117')
        addr = bytes(reversed(self.load(slice(0x0804F188, 4))(data))).hex()
        unit = self.load(F'0x{addr}', ascii=True)
        self.assertEqual(unit(data), B'MY ID IS %d, Upper ID is %d')

    def test_macho(self):
        unit = self.load(0x0FB8, ascii=True)
        self.assertEqual(unit(MACHO_TEST), b'audio filter for float32->s16 conversion')

    def test_malformed_fo10c6(self):
        file = 'ce970ff0f1d20ad7471f224dafd7a7beef82713ea67a0278d94e8a38a92132fe'
        data = self.download_sample(file, key='OKFR20ALOEN23UPS')
        data = data | self.ldu('xt7z', pwd='flare') | self.load('0x408ea0:0x54') | bytes
        self.assertEqual(data, bytes.fromhex(
            '39 29 cf 6d a8 e0 1c eb aa 6e b3 a4 e1 bc 72 98 14 9c 59 49 7f f3 ba dc 8f d8 79 c1'
            '2e 0e df 2a f8 c5 ce 25 d0 ef 10 01 0b ca a6 f2 79 01 9a 98 7e 71 fe 1f a8 a6 9d c9'
            '7b a3 1d bd 17 b3 0a 88 e5 df 21 78 29 6b 83 52 8e bd e9 b2 7c ee 05 52 8e 09 63 d9'))
