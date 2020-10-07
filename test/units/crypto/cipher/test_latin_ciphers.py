#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase


class TestLatinCiphers(TestUnitBase):

    def assertEqualOutputs(self, u1, u2, size):
        data = self.generate_random_buffer(size)
        args = dict(
            key=self.generate_random_buffer(32),
            nonce=self.generate_random_buffer(8)
        )
        unit1 = self.ldu(u1, **args)
        unit2 = self.ldu(u2, **args)
        self.assertEqual(unit1(data), unit2(data))

    def test_salsa(self):
        for size in (3, 5, 12, 56, 2013):
            self.assertEqualOutputs('salsa', 'salsa20', size)

    def test_chacha(self):
        for size in (3, 5, 12, 56, 2013):
            self.assertEqualOutputs('chacha', 'chacha20', size)
