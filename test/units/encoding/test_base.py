#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestBaseUnit(TestUnitBase):

    def test_inversion_base_02e(self):
        unit = self.load('-e', '2')
        data = self.generate_random_buffer(24)
        self.assertEqual(data, unit.process(unit.reverse(data)))

    def test_inversion_base_02E(self):
        unit = self.load('2')
        data = self.generate_random_buffer(24)
        self.assertEqual(data, unit.process(unit.reverse(data)))

    def test_inversion_base_10(self):
        unit = self.load('10')
        data = self.generate_random_buffer(24)
        self.assertEqual(data, unit.process(unit.reverse(data)))

    def test_inversion_base_16re(self):
        unit = self.load()
        data = B'0xBAADF00DC0FFEEBABE'
        self.assertEqual(data, unit.reverse(unit.process(data)))

    def test_inversion_base_16(self):
        unit = self.load('0x10')
        data = B'BAADF00DC0FFEEBABE'
        self.assertEqual(data, unit.reverse(unit.process(data)))

    def test_invalid_base_values(self):
        self.assertRaises(Exception, self.load, 1)
        self.assertRaises(Exception, self.load, 37)
        self.assertRaises(Exception, self.load, -2)

    def test_hardcoded_example_base_36(self):
        unit = self.load(36)
        data = B'BINARYREFINERY'
        self.assertEqual(data, unit.reverse(unit.process(data)))
