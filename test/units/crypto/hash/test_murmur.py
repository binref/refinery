#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase


class TestMurmurHash(TestUnitBase):

    def test_murmur32_seedless(self):
        mmh3 = self.ldu('mmh32')
        self.assertEqual(bytes(B'Binary Refinery' | mmh3), bytes.fromhex('CED26A19'))

    def test_murmur32_seeded(self):
        mmh3 = self.ldu('mmh32', 4578)
        self.assertEqual(bytes(B'Binary Refinery' | mmh3), bytes.fromhex('A5DB2491'))

    def test_murmur128x64_seedless(self):
        mmh3 = self.ldu('mmh128x64')
        data = B'refining binaries with the binary refinery is rather fine!'
        self.assertEqual(bytes(data | mmh3), bytes.fromhex('14a119b95256e70c5a1164c42eb08b1c'))

    def test_murmur128x64_seeded(self):
        mmh3 = self.ldu('mmh128x64', 42)
        data = B'refining binaries with the binary refinery is rather fine!'
        self.assertEqual(bytes(data | mmh3), bytes.fromhex('3f591f0dc9cdf8d0f434911ec4a6c856'))

    def test_murmur128x32_seedless(self):
        mmh3 = self.ldu('mmh128x32')
        data = B'even the finest binaries get finer by refining them with the binary refinery.'
        self.assertEqual(bytes(data | mmh3), bytes.fromhex('776c26e7d58a12501ee3172d765913a7'))

    def test_murmur128x32_seeded(self):
        mmh3 = self.ldu('mmh128x32', 31337)
        data = B'even the finest binaries get finer by refining them with the binary refinery.'
        self.assertEqual(bytes(data | mmh3), bytes.fromhex('967fb441ac023250fa29840ee484d2f0'))
