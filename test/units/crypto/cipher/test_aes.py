#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase


class TestAES(TestUnitBase):

    def test_invertible_01(self):
        cipher = self.load('CBC', 'PBKDF2[32,s4ltY]:p4$$w0rd')
        test = self.generate_random_buffer(200)
        self.assertEqual(cipher.process(cipher.reverse(test)), test)

    def test_invertible_02(self):
        cipher = self.load('CBC', 'PBKDF2[32,s4ltY]:p4$$w0rd', iv=(b'MYIV' * 4))
        test = self.generate_random_buffer(200)
        self.assertEqual(cipher.process(cipher.reverse(test)), test)
