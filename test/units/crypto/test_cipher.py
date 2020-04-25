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
            for name in ('rc4', 'seal', 'chacha', 'salsa'):
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
