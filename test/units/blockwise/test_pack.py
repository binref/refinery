#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import struct

from .. import TestUnitBase


class TestPack(TestUnitBase):

    def test_pack_wrapping_byte(self):
        pack = self.load()
        self.assertEqual(
            pack(B'123, 34, 256, 12, 1, 234'),
            bytes(bytearray((123, 34, 0, 12, 1, 234)))
        )

    def test_pack_wrapping_dword(self):
        pack = self.load(blocksize=4, bigendian=True)
        self.assertEqual(
            pack(B'0xB0000000D 0x31337BAADC0DE'),
            bytes.fromhex('0000000DBAADC0DE')
        )

    def test_pack_words_default(self):
        pack = self.load(16, blocksize=2)
        self.assertEqual(
            pack(B'BAAD F00D FACE C0CA C01A'),
            struct.pack('<HHHHH', 0xBAAD, 0xF00D, 0xFACE, 0xC0CA, 0xC01A)
        )

    def test_pack_words_big(self):
        pack = self.load(16, blocksize=2, bigendian=True)
        self.assertEqual(
            pack(B'BAAD F00D FACE C0CA C01A'),
            struct.pack('>HHHHH', 0xBAAD, 0xF00D, 0xFACE, 0xC0CA, 0xC01A)
        )

    def test_pack_bigblock(self):
        bigint = 0xAB0F4E70B00A20391B0BB03C92D8110CE33017BE
        buffer = bigint.to_bytes(20, 'big')
        pack = self.load(blocksize=len(buffer), bigendian=True)
        self.assertEqual(
            pack('0x{:X}'.format(bigint).encode('utf-8')),
            buffer
        )

    def test_pack_reverse_01(self):
        unpack = self.load(16, blocksize=2, reverse=True, prefix=True, bigendian=True)
        self.assertEqual(
            unpack(bytes.fromhex('C0CAC01A')),
            B'\n'.join([B'0xC0CA', B'0xC01A'])
        )

    def test_pack_reverse_02(self):
        unpack = self.load('-B2', '-R', '16')
        self.assertEqual(
            unpack(bytes.fromhex('C0CAC01A')),
            B'\n'.join([B'CAC0', B'1AC0'])
        )

    def test_pack_reverse_03(self):
        packer = self.load('-B4')
        unpack = self.load('-B4', '-R', '16')
        self.assertEqual(unpack(packer(B'0x4512')), B'4512')

    def test_pack_hexint_array(self):
        pack = self.load()
        self.assertEqual(
            pack(B'0x90,0x90,0x34,0x65,0xAF,0xFD,0x01,0x02'),
            bytes.fromhex('90 90 34 65 AF FD 01 02')
        )
