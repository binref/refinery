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

    def test_pack_hexdump(self):
        dump = (
            'dump: 000: 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00\n'
            'dump: 010: B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00\n'
            'dump: 020: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00\n'
            'dump: 030: 00 00 00 00 00 00 00 00 00 00 00 00 D0 00 00 00\n'
            'dump: 040: 0E 1F BA 0E 00 B4 09 CD 21 B8 01 4C CD 21 54 68\n'
            'dump: 050: 69 73 20 70 72 6F 67 72 61 6D 20 63 61 6E 6E 6F\n'
            'dump: 060: 74 20 62 65 20 72 75 6E 20 69 6E 20 44 4F 53 20\n'
            'dump: 070: 6D 6F 64 65 2E 0D 0D 0A 24 00 00 00 00 00 00 00\n'
            'dump: 080: 35 75 76 5D 71 14 18 0E 71 14 18 0E 71 14 18 0E\n'
            'dump: 090: 14 72 19 0F 76 14 18 0E 71 14 19 0E 79 14 18 0E\n'
            'dump: 0A0: 05 7F 10 0F 70 14 18 0E 05 7F 1A 0F 70 14 18 0E\n'
            'dump: 0B0: 52 69 63 68 71 14 18 0E 00 00 00 00 00 00 00 00\n'
            'dump: 0C0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00\n'
            'dump: 0D0: 50 45 00 00 4C 01 03 00 29 CC C8 5C 00 00 00 00\n'
            'dump: 0E0: 00 00 00 00 E0 00 02 01 0B 01 0E 14 00 02 00 00\n'
            'dump: 0F0: 00 04 00 00 00 00 00 00 DC 10 00 00 00 10 00 00\n'
            'dump: 100: 00 20 00 00 00 00 40 00 00 10 00 00 00 02 00 00\n'
            'dump: 110: 06 00 00 00 00 00 00 00 06 00 00 00 00 00 00 00\n'
            'dump: 120: 00 40 00 00 00 04 00 00 00 00 00 00 02 00 40 85\n'
            'dump: 130: 00 00 10 00 00 10 00 00 00 00 10 00 00 10 00 00\n'
            'dump: 140: 00 00 00 00 10 00 00 00 00 00 00 00 00 00 00 00\n'
            'dump: 150: 2C 20 00 00 50 00 00 00 00 00 00 00 00 00 00 00\n'
            'dump: 160: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00\n'
            'dump: 170: 00 30 00 00 18 00 00 00 00 10 00 00 38 00 00 00\n'
            'dump: 180: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00\n'
            'dump: 190: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00\n'
            'dump: 1A0: 00 00 00 00 00 00 00 00 00 20 00 00 2C 00 00 00\n'
            'dump: 1B0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00\n'
            'dump: 1C0: 00 00 00 00 00 00 00 00 2E 74 65 78 74 00 00 00\n'
            'dump: 1D0: 76 01 00 00 00 10 00 00 00 02 00 00 00 04 00 00\n'
            'dump: 1E0: 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 60\n'
            'dump: 1F0: 2E 69 64 61 74 61 00 00 4C 01 00 00 00 20 00 00\n'
            'dump: 200: 00 02 00 00 00 06 00 00 00 00 00 00 00 00 00 00\n'
            'dump: 210: 00 00 00 00 40 00 00 40 2E 72 65 6C 6F 63 00 00\n'
            'dump: 220: 18 00 00 00 00 30 00 00 00 02 00 00 00 08 00 00\n'
            'dump: 230: 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 42\n'
        ).encode('utf-8')

        data = bytes.fromhex(
            '4D5A90000300000004000000FFFF0000B800000000000000400000000000'
            '000000000000000000000000000000000000000000000000000000000000'
            'D00000000E1FBA0E00B409CD21B8014CCD21546869732070726F6772616D'
            '2063616E6E6F742062652072756E20696E20444F53206D6F64652E0D0D0A'
            '24000000000000003575765D7114180E7114180E7114180E1472190F7614'
            '180E7114190E7914180E057F100F7014180E057F1A0F7014180E52696368'
            '7114180E0000000000000000000000000000000000000000000000005045'
            '00004C01030029CCC85C0000000000000000E00002010B010E1400020000'
            '0004000000000000DC100000001000000020000000004000001000000002'
            '000006000000000000000600000000000000004000000004000000000000'
            '020040850000100000100000000010000010000000000000100000000000'
            '0000000000002C2000005000000000000000000000000000000000000000'
            '000000000000000000300000180000000010000038000000000000000000'
            '000000000000000000000000000000000000000000000000000000000000'
            '00000000002000002C000000000000000000000000000000000000000000'
            '0000000000002E7465787400000076010000001000000002000000040000'
            '000000000000000000000000200000602E696461746100004C0100000020'
            '00000002000000060000000000000000000000000000400000402E72656C'
            '6F6300001800000000300000000200000008000000000000000000000000'
            '000040000042'
        )

        pack = self.load('-x')
        self.assertEqual(pack(dump), data)

    def test_pack_hexdump_auto(self):
        dump = self.ldu('hexview', expand=True)
        pack = self.load(hexdump=True)
        for size in (20, 200, 400):
            data = self.generate_random_buffer(size)
            self.assertEqual(pack(dump(data)), data)

    def test_pack_hexint_array(self):
        pack = self.load()
        self.assertEqual(
            pack(B'0x90,0x90,0x34,0x65,0xAF,0xFD,0x01,0x02'),
            bytes.fromhex('90 90 34 65 AF FD 01 02')
        )
