#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase

from refinery.lib.loader import resolve


class TestCipherUnits(TestUnitBase):

    def test_basic_for_block_ciphers(self):
        for buffersize in (3, 7, 56, 128, 1231):
            data = self.generate_random_buffer(buffersize)
            for name in ('aes', 'blowfish', 'cast', 'des', 'des3', 'rc2'):
                unit = resolve(name)
                for size in unit.key_sizes:
                    K = self.generate_random_buffer(size)
                    V = self.generate_random_buffer(unit.blocksize)
                    D = unit(key=K, iv=V, mode='CBC')
                    for P in ['PKCS7', 'ISO7816', 'X923']:
                        E = unit(key=K, iv=V, padding=P, mode='CBC')
                    self.assertEqual(D.process(E.reverse(data)), data)

    def test_basic_for_stream_ciphers(self):
        for buffersize in (3, 7, 56, 128, 1231):
            data = self.generate_random_buffer(buffersize)
            for name in ('rc4', 'seal', 'chacha', 'salsa', 'hc128'):
                unit = resolve(name)
                for size in unit.key_sizes:
                    S = unit(key=self.generate_random_buffer(size))
                    self.assertEqual(S(S(data)), data)

    def test_chacha(self):
        for buffersize in (3, 7, 56, 128, 1231):
            data = self.generate_random_buffer(buffersize)
            key = self.generate_random_buffer(32)
            for n in (8, 12, 24):
                S = self.ldu('chacha', key=key, nonce=self.generate_random_buffer(n))
                self.assertEqual(S(S(data)), data)
            with self.assertRaises(ValueError):
                S = self.ldu('chacha', key=key, nonce=B'FLABBERGAST')
                S(data)

    def test_xtea(self):
        for buffersize in (3, 7, 56, 128, 1231):
            data = self.generate_random_buffer(buffersize)
            key = self.generate_random_buffer(16)
            E = self.ldu('xtea', key=key, reverse=True)
            D = self.ldu('xtea', key=key)
            self.assertEqual(D(E(data)), data)

    def test_vigenere(self):
        data = (
            B" Take this kiss upon the brow!"
            B" And, in parting from you now,"
            B" Thus much let me avow -"
            B" You are not wrong, who deem"
            B" That my days have been a dream;"
            B" Yet if hope has flown away"
            B" In a night, or in a day,"
            B" In a vision, or in none,"
            B" Is it therefore the less gone? "
            B" All that we see or seem"
            B" Is but a dream within a dream."
        )
        key = 'dream'
        E = self.ldu('vigenere', key=key, reverse=True)
        D = self.ldu('vigenere', key=key)
        self.assertEqual(D(E(data)), data)

    def test_rncrypt(self):
        for k in (3, 12, 41):
            for n in (5, 12, 102, 3455):
                P = self.generate_random_buffer(k)
                M = self.generate_random_buffer(n)
                E = self.ldu('rncrypt', P, reverse=True)
                D = self.ldu('rncrypt', P)
                self.assertEqual(D(E(M)), M)

    def test_hc128_sample(self):
        hc = self.ldu('hc128', 'H:676672656668726575676867676873006A646469686577666577696668666800')
        self.assertEqual(hc(bytes(514)), bytes.fromhex(
            '71DCE88CFC7522B351CBFED515DBE1380FA6ED5C6695585C396389C333AD20EF1F913B7C608B2D1A'
            '6B85AB437949181846A5243D44968C9682234D45C1168D077F1E7D5EC804047DE43B7FF9D231B6DD'
            '6B250DBE909269E380D91765ED086D382F878914B6AEA6974ED18FD06AEF552935F12A1095D7D433'
            '4AFDD10B6A72FD0E9E18BE24AFF73FE9DFED2758F7DD6453035733E97A3CAAB2457880087D0D520E'
            'E672A09804568669DCB7FC2ACD09CBD92A39C9E7A51BCFCDE7F6722824F5057545F25D4D0C8DA47F'
            '58E149C76344D530856DCF322286B88EE3C163A57A1FA7CFF146C1A6794C7766A08603618F2AF142'
            '4D3AD4A75DDB360E6E35585C9F3D96E22FD4D7918FBC168A779900195256D0EA277EE1EFFA7F91F6'
            '3BD2781115C430CF79AF7B642471016E381E9CEFA1DE0035F0FBF3D5920C98846A5A516747C545EC'
            'E577A52CACF74525CABD78852A44EDE35059DE116CB5F3E70EA5D2F008C6FA10AC9E2B57DB051561'
            '65A7DC3477C678DE40F2BA0240082C1620CAC3437E50B8E97ADADF05675E60E988A21E7628BBFD2A'
            '42E232B78E7F5F86BD04D3E0945023F9177AF1D79B1C814B09550D80607D652043440E5E04FB17EE'
            '0B61DB67587CD25BE17C5DB8B298CFCCA60AC6116ABB048A072D32235A7A960103DD38F6E5807EE7'
            '1ACCD48247C58E0CD17D2467BE0B284C3F066977EA95B42D8A37DFD4646A21EDF5ED'
        ))
