#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase
from refinery import pad, snip, scope, chop, pick, rep
from refinery import aes, blowfish, cast, chacha, salsa, seal, des, des3, rc2, rc4


class TestCipherUnits(TestUnitBase):

    def test_basic_for_block_ciphers(self):
        for buffersize in (3, 7, 56, 128, 1231):
            data = self.generate_random_buffer(buffersize)
            for unit in (aes, blowfish, cast, des, des3, rc2):
                for size in unit.__key_sizes__:
                    K = self.generate_random_buffer(size)
                    V = self.generate_random_buffer(unit.__blocksize__)
                    D = unit('CBC', key=K, iv=V, reverse=False)
                    for P in ['PKCS7', 'ISO7816', 'X923']:
                        E = unit(F'-P{P}', 'CBC', key=K, iv=V, reverse=True)
                    self.assertEqual(D(E(data)), data)

    def test_basic_for_stream_ciphers(self):
        for buffersize in (3, 7, 56, 128, 1231):
            data = self.generate_random_buffer(buffersize)
            for unit in (rc4, seal, chacha, salsa):
                for size in unit.__key_sizes__:
                    S = unit(key=self.generate_random_buffer(size))
                    self.assertEqual(S(S(data)), data)

    def test_chacha(self):
        for buffersize in (3, 7, 56, 128, 1231):
            data = self.generate_random_buffer(buffersize)
            key = self.generate_random_buffer(32)
            for n in (8, 12, 24):
                S = chacha(key=key, nonce=self.generate_random_buffer(n))
                self.assertEqual(S(S(data)), data)
            with self.assertRaises(ValueError):
                S = chacha(key=key, nonce=B'FLABBERGAST')
                S(data)


class TestAES(TestUnitBase):

    def test_invertible_01(self):
        cipher = aes('CBC', 'PBKDF2[32,s4ltY]:p4$$w0rd')
        test = self.generate_random_buffer(200)
        self.assertEqual(cipher.process(cipher.reverse(test)), test)

    def test_invertible_02(self):
        cipher = aes('CBC', 'PBKDF2[32,s4ltY]:p4$$w0rd', iv=(b'MYIV' * 4))
        test = self.generate_random_buffer(200)
        self.assertEqual(cipher.process(cipher.reverse(test)), test)

    def test_cbc(self):
        K = self.generate_random_buffer(16)
        V = self.generate_random_buffer(16)
        M = self.generate_random_buffer(5 * 16)
        D = aes('CBC', key=K, iv=V)
        E = aes('CBC', key=K, iv=V, reverse=True)
        self.assertEqual(M, D(E(M)))

    def test_cbc_ciphertext_stealing(self):
        L = 5 * 16 + 11
        K = self.generate_random_buffer(16)
        M = self.generate_random_buffer(L)

        D = chop(0x10)[
            pick(':~1', ':~2:~0') | scope('~0') | rep | scope('~1') | aes('-PRAW', 'ECB', key=K) | snip('11:')
        ] | aes('CBC', key=K)

        E = pad('-b16') | aes('-RPRAW', 'CBC', key=K) | chop(16)[pick(':(-2)', '(-1)', '(-2)')]

        C = E(M)[:L]
        P = D(C)[:L]

        self.assertEqual(M, P)
