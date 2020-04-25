#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase

from refinery.lib.loader import load_commandline as L, resolve


class TestAES(TestUnitBase):

    def test_panic(self):
        data = B'BINARY REFINERY REFINES BINARIES FINER THAN BINARY TOOLS'
        pp = L('aes -R CBC range:16 --iv rep[16]:H:AC') | L('ccp rep[16]:H:AC') | L('aes CBC range:16 --iv x::16')
        self.assertEqual(pp(data), data)

    def test_invertible_01(self):
        cipher = L('aes CBC PBKDF2[32,s4ltY]:p4$$w0rd')
        test = self.generate_random_buffer(200)
        self.assertEqual(cipher.process(cipher.reverse(test)), test)

    def test_invertible_02(self):
        cipher = self.load('cbc', 'PBKDF2[32,s4ltY]:p4$$w0rd', iv=(b'MYIV' * 4))
        test = self.generate_random_buffer(200)
        self.assertEqual(cipher.process(cipher.reverse(test)), test)

    def test_cbc(self):
        K = self.generate_random_buffer(16)
        V = self.generate_random_buffer(16)
        M = self.generate_random_buffer(5 * 16)
        D = self.load('cbc', key=K, iv=V)
        E = self.load('CBC', key=K, iv=V, reverse=True)
        self.assertEqual(M, D(E(M)))

    def test_cbc_ciphertext_stealing(self):
        N = 5 * 16 + 11
        M = self.generate_random_buffer(N)

        # flake8: noqa
        D = L('chop 0x10') [
            L('pick :~1 :~2:~0') | L('scope ~0') | L('rep') | L('scope ~1') 
                | L('aes -PRAW ECB H:C0CAC01AFACEBEA75DEFACEDBEEFCACE') | L('snip 11:')
        ] | L('aes CBC -PRAW H:C0CAC01AFACEBEA75DEFACEDBEEFCACE')

        # flake8: noqa
        E = L('pad -b 16') | L('aes -RPRAW CBC H:C0CAC01AFACEBEA75DEFACEDBEEFCACE') | L('chop 16') [
                L('pick :(-2) (-1) (-2)') ]

        C = E(M)[:N]
        P = D(C)[:N]

        self.assertEqual(M, P)
