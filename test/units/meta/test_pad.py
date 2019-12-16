#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from . import TestMetaBase


class TestPad(TestMetaBase):

    def test_block_size_padding(self):
        unit = self.load('-b', 17)
        data = unit(
            self.generate_random_buffer(0 * 17 + 12),
            self.generate_random_buffer(9 * 17 + 3),
            self.generate_random_buffer(2 * 17 + 7),
            self.generate_random_buffer(3 * 17 + 7),
            self.generate_random_buffer(8 * 17 + 16),
            self.generate_random_buffer(4 * 17 + 1)
        )
        for entry in data:
            self.assertEqual(len(entry) % 17, 0)
            self.assertEqual(entry[-1], 0)

    def test_fixed_size_padding(self):
        unit = self.load('-a', 1337)
        data = unit(
            self.generate_random_buffer(212),
            self.generate_random_buffer(2),
            self.generate_random_buffer(31337),
            self.generate_random_buffer(111)
        )
        for entry in data:
            self.assertGreaterEqual(len(entry), 1337)
        self.assertEqual(len(data[2]), 31337)

    def test_custom_padding(self):
        unit = self.load('-a', 40, 'badger')
        self.assertEqual(
            unit(B'mushroom, ').pop(),
            B'mushroom, badgerbadgerbadgerbadgerbadger'
        )
