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
                    for P in ['pkcs7', 'iso7816', 'x923']:
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
                S = self.ldu('chacha20', key=key, nonce=self.generate_random_buffer(n))
                self.assertEqual(S(S(data)), data)
            with self.assertRaises(ValueError):
                S = self.ldu('chacha20', key=key, nonce=B'FLABBERGAST')
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
        self.assertEqual(hc(bytes(31337))[-256:], bytes.fromhex(
            'DA7165199B12ED0AA003495B7600F63D5C5CB371127A30142C829EEC305B1D2A3EB7C0A65CFE44D4'
            '5B434DA4CF1C6343BEF5B12DFC666148687DBFDD71B3856E9E8A649DA89E95CCE6F3348C5771ABDF'
            'B7C9BA8A88DEACBF8FE09F391A57FF6F6B844DE3CF77019267193998D4C51CC037752A456230CD8E'
            'C66B402EB17F0AAAB73C1BD96567A2D35275D762A02127822F52935BC10B37C1D6BB1ED534C3395A'
            'A4A9DDE02EA898C9B351D48B7536B411E2D6C27AD533923FB5D0C92E1C9CADB5BAEA1DD9284E549F'
            '831D2210E0AD5DA7F8523D304CA9BEB469DBAEA5D19D4C0329C5B438699C1B6BF7F3536B66BDD786'
            '8C098316D544C767A679CC47747D4A47'
        ))
