#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase


class TestMurmurHash(TestUnitBase):

    def test_murmur3_seedless(self):
        mmh3 = self.ldu('m3h')
        self.assertEqual(bytes(B'Binary Refinery' | mmh3), bytes.fromhex('CED26A19'))

    def test_murmur3_seeded(self):
        mmh3 = self.ldu('m3h', 4578)
        self.assertEqual(bytes(B'Binary Refinery' | mmh3), bytes.fromhex('A5DB2491'))

    def test_murmur3_128_64_seedless(self):
        mmh3 = self.ldu('m3h64')
        data = B'refining binaries with the binary refinery is rather fine!'
        self.assertEqual(bytes(data | mmh3), bytes.fromhex('14a119b95256e70c5a1164c42eb08b1c'))

    def test_murmur3_128_64_seeded(self):
        mmh3 = self.ldu('m3h64', 42)
        data = B'refining binaries with the binary refinery is rather fine!'
        self.assertEqual(bytes(data | mmh3), bytes.fromhex('3f591f0dc9cdf8d0f434911ec4a6c856'))

    def test_murmur3_128_32_seedless(self):
        mmh3 = self.ldu('m3h32')
        data = B'even the finest binaries get finer by refining them with the binary refinery.'
        self.assertEqual(bytes(data | mmh3), bytes.fromhex('776c26e7d58a12501ee3172d765913a7'))

    def test_murmur3_128_32_seeded(self):
        mmh3 = self.ldu('m3h32', 31337)
        data = B'even the finest binaries get finer by refining them with the binary refinery.'
        self.assertEqual(bytes(data | mmh3), bytes.fromhex('967fb441ac023250fa29840ee484d2f0'))

    def test_murmur2a_seeded(self):
        mmh2 = self.ldu('m2ha', 0xB801FCDA)
        data = B'LoadLibraryA\0'
        self.assertEqual(bytes(data | mmh2), bytes.fromhex('E155747A'))

    def test_murmur2(self):
        s = 0xB801FCDA
        H = bytes.fromhex
        self.assertEqual(B'LoadLibraryA\0' | self.ldu('m2h', s) | bytes, H('13B9A204'))
        self.assertEqual(B'LoadLibraryA\0' | self.ldu('m2h'   ) | bytes, H('E81CF845'))

    def test_murmur2a(self):
        s = 0xB801FCDA
        H = bytes.fromhex
        self.assertEqual(B'LoadLibraryA\0' | self.ldu('m2ha', s) | bytes, H('E155747A'))
        self.assertEqual(B'LoadLibraryA\0' | self.ldu('m2ha'   ) | bytes, H('198B2E99'))

    def test_murmur2_64(self):
        s = 0xB801FCDA_B801FCDA
        H = bytes.fromhex
        self.assertEqual(B'LoadLibraryA\0' | self.ldu('m2h64a', s) | bytes, H('57DCF3A6FAA116D7'))
        self.assertEqual(B'LoadLibraryA\0' | self.ldu('m2h64a'   ) | bytes, H('154D7D839E0A4ABD'))
        self.assertEqual(B'LoadLibraryA\0' | self.ldu('m2h64b', s) | bytes, H('E4CD938EAFBE94C3'))
        self.assertEqual(B'LoadLibraryA\0' | self.ldu('m2h64b'   ) | bytes, H('7317DC58B6DA4D67'))
