#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestBase32(TestUnitBase):

    def test_too_much_padding(self):
        unit = self.load()
        self.assertEqual(B'KRSXG5A====' | unit | bytes, B'Test')

    def test_too_little_padding(self):
        unit = self.load()
        self.assertEqual(B'KRSXG5A' | unit | bytes, B'Test')

    def test_correct_existing_padding(self):
        unit = self.load()
        self.assertEqual(B'KRSXG5A=' | unit | bytes, B'Test')

    def test_b32_handles(self):
        import base64
        data = self.generate_random_buffer(500)
        unit = self.unit()
        for name, encoding, test in [
            ('base16', base64.b16encode, self.assertFalse),
            ('base32', base64.b32encode, self.assertTrue),
            ('base64', base64.b64encode, self.assertFalse),
            ('base85', base64.b85encode, self.assertFalse),
        ]:
            test(unit.handles(encoding(data)), msg=F'handler test for {name} failed')
