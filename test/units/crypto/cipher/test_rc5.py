from ... import TestUnitBase

from refinery.units.crypto.cipher.rc5 import RC5, rc5constants


class TestRC5(TestUnitBase):

    def test_magic_constants(self):
        self.assertEqual(rc5constants(16), (0xB7E1, 0x9E37))
        self.assertEqual(rc5constants(32), (0xB7E15163, 0x9E3779B9))
        self.assertEqual(rc5constants(64), (0xB7E151628AED2A6B, 0x9E3779B97F4A7C15))

    def test_examples_kryptografie_de(self):
        # https://kryptografie.de/kryptografie/chiffre/rc5.htm
        sample = B'BeispielklartextBeispielklartext'
        for (w, r), result in {
            (0x08, 12): 'FDE9091D AF439BD1 2DE6EF5C AC8DA3CC FDE9091D AF439BD1 2DE6EF5C AC8DA3CC',
            (0x10, 16): '89EE3CE5 19048197 22821B38 052FDFAC 89EE3CE5 19048197 22821B38 052FDFAC',
            (0x20, 20): 'D5CB6FAB E83BF333 56263D02 E25A0BB7 D5CB6FAB E83BF333 56263D02 E25A0BB7',
            (0x40, 24): '45757C47 EC1575D0 A6CE92AD E5078A2A 45757C47 EC1575D0 A6CE92AD E5078A2A',
        }.items():
            cipher = RC5(B'Schokoladentorte', None, w, r)
            ciphertext = cipher.encrypt(sample)
            self.assertEqual(ciphertext, bytes.fromhex(result))
            self.assertEqual(cipher.decrypt(ciphertext), sample)

    def test_with_iv(self):
        msg = B'\xFF' * 32
        key = iv = B'\xFF' * 8
        unit = self.load(key=key, iv=iv, raw=True, reverse=True)
        out = msg | unit | bytearray
        self.assertEqual(out, bytes.fromhex(
            'C5 0A FD 28 73 E3 7F 10 55 63 96 41 4D 4A 03 3C'
            '07 05 32 53 54 89 07 E9 B9 0F FF A3 86 34 1E CC'
        ))
        unit = self.load(key=key, iv=iv, raw=True)
        test = out | unit | bytearray
        self.assertEqual(test, msg)

    def test_official_test_vectors_01(self):
        K = bytes.fromhex('000102030405060708090A0B0C0D0E0F')
        M = bytes.fromhex('0001020304050607')
        C = bytes.fromhex('2A0EDC0E9431FF73')
        U = self.load(key=K, raw=True, rounds=20, word_size=32)
        self.assertEqual(M | -U | bytearray, C)

    def test_segment_size(self):
        msg = bytes.fromhex('7ad51c93c2e36a3e26a318806b9ab8562837137fb1b4327e8d')
        unit = self.load(b'0123456789abcdef', mode='cfb', iv=b'01234567', segment_size=64)
        self.assertEqual(msg | unit | bytes, b'This is a secret message.')

    def test_regression_ctr_mode(self):
        data = B'This is a secret message.'
        unit = self.load(mode='ctr', key=b'0123456789abcdef', iv=b'0123456')
        self.assertEqual(data, data | -unit | unit | bytes)
