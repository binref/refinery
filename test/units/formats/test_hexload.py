#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestHexLoad(TestUnitBase):

    def test_hexdump_01(self):
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

        unit = self.load()
        self.assertEqual(unit(dump), data)

    def test_pack_hexdump_auto(self):
        dump = self.load(reverse=True)
        pack = self.load()
        for size in (20, 200, 400):
            data = self.generate_random_buffer(size)
            dumped = dump(data)
            packed = pack(dumped)
            self.assertEqual(packed, data, dumped.decode('utf8'))

    def test_pack_hexdump_overhang(self):
        dump = self.load(reverse=True, width=20)
        pack = self.load()
        for k in range(1, 5):
            data = self.generate_random_buffer(40 + k)
            dumped = dump(data)
            packed = pack(dumped)
            self.assertEqual(packed, data)

    def test_wide_hexdumps(self):
        data = (
            '0x018DE80 dc2a 0100 8b45 2048 8d4d 1048 c1e0 2048  Ü*...E H.M.HÁà H\n'
            '0x018DE90 3345 2048 3345 1048 33c1 48b9 ffff ffff  3E H3E.H3ÁH¹ÿÿÿÿ\n'
            '0x018DEA0 ffff 0000 4823 c148 b933 a2df 2d99 2b00  ÿÿ..H#ÁH¹3¢ß-.+.\n'
        ).encode('utf8')
        unit = self.load()
        self.assertEqual(unit(data), bytes.fromhex(
            'DC 2A 01 00 8B 45 20 48 8D 4D 10 48 C1 E0 20 48'
            '33 45 20 48 33 45 10 48 33 C1 48 B9 FF FF FF FF'
            'FF FF 00 00 48 23 C1 48 B9 33 A2 DF 2D 99 2B 00'
        ))

    def test_hex_byte_in_text_preview_01(self):
        data = (
            '00: 4B 2F 3A 54 DE C4 D2 C1 08 95 D1 3C C5 55 B3 D6 B6 F2 9D 5A  K/:T.......<.U.....Z\n'
            '14: 61 37 6D 76 84 A8 0F 32 47 80 AA 13 C5 FF A7 5E 0C 31 16 0E  a7mv...2G......^.1..\n'
            '28: 0D 3A B3 E2                                                  .:..'
        ).encode('utf8')
        unit = self.load()
        self.assertEqual(unit(data), bytes.fromhex(
            '4B 2F 3A 54 DE C4 D2 C1 08 95 D1 3C C5 55 B3 D6 B6 F2 9D 5A'
            '61 37 6D 76 84 A8 0F 32 47 80 AA 13 C5 FF A7 5E 0C 31 16 0E'
            '0D 3A B3 E2'
        ))

    def test_hex_byte_in_text_preview_02(self):
        data = (
            '000000000018DE80  DC 2A 01 00 8B 45 20 48 8D 4D 10 48 C1 E0 20 48  Ü*...E H.M.HÁà H  \n'
            '000000000018DE90  33 45 20 48 33 45 10 48 33 C1 48 B9 FF FF FF FF  3E H3E.H3ÁH¹ÿÿÿÿ  \n'
            '000000000018DEA0  FF FF 00 00 48 23 C1 48 B9 33 A2 DF 2D 99 2B 00  ÿÿ..H#ÁH¹3¢ß-.+.  \n'
        ).encode('utf8')
        unit = self.load()
        self.assertEqual(unit(data), bytes.fromhex(
            'DC 2A 01 00 8B 45 20 48 8D 4D 10 48 C1 E0 20 48'
            '33 45 20 48 33 45 10 48 33 C1 48 B9 FF FF FF FF'
            'FF FF 00 00 48 23 C1 48 B9 33 A2 DF 2D 99 2B 00'
        ))

    def test_unknown(self):
        data = (
            '000000000018F4D0  3B 63 73 6D E0 75 1E 83 7B 18 04 75 18 8B 43 20  ;csmàu..{..u..C   \n'
            '000000000018F4E0  2D 20 05 93 19 83 F8 02 77 0B 48 83 7B 30 00 0F  - ....ø.w.H.{0..  \n'
            '000000000018F4F0  84 88 03 00 00 E8 BA F8 FF FF 48 83 78 38 00 74  .....èºøÿÿH.x8.t  \n'
        ).encode('utf8')
        unit = self.load()
        self.assertEqual(unit(data), bytes.fromhex(
            '3B 63 73 6D E0 75 1E 83 7B 18 04 75 18 8B 43 20'
            '2D 20 05 93 19 83 F8 02 77 0B 48 83 7B 30 00 0F'
            '84 88 03 00 00 E8 BA F8 FF FF 48 83 78 38 00 74'
        ))

    def test_shellcode_dump(self):
        data = (
            R'31 F6 56 64 8B 76 30 8B 76 0C 8B 76 1C 8B 6E 08  1.Vd.v0.v..v..n.\n'
            R'8B 36 8B 5D 3C 8B 5C 1D 78 01 EB 8B 4B 18 67 E3  .6.]<.\.x...K.g.\n'
            R'EC 8B 7B 20 01 EF 8B 7C 8F FC 01 EF 31 C0 99 32  ..{....|....1..2\n'
            R'17 66 C1 CA 01 AE 75 F7 66 81 FA 10 F5 E0 E2 75  .f....u.f......u\n'
            R'CC 8B 53 24 01 EA 0F B7 14 4A 8B 7B 1C 01 EF 03  ..S$.....J.{....\n'
            R'2C 97 68 2E 65 78 65 68 63 61 6C 63 54 87 04 24  ,.h.exehcalcT..$\n'
            R'50 FF D5 CC                                      P...\n'
        ).encode('utf8')
        unit = self.load()
        self.assertEqual(unit(data), bytes.fromhex(
            '31 F6 56 64 8B 76 30 8B 76 0C 8B 76 1C 8B 6E 08'
            '8B 36 8B 5D 3C 8B 5C 1D 78 01 EB 8B 4B 18 67 E3'
            'EC 8B 7B 20 01 EF 8B 7C 8F FC 01 EF 31 C0 99 32'
            '17 66 C1 CA 01 AE 75 F7 66 81 FA 10 F5 E0 E2 75'
            'CC 8B 53 24 01 EA 0F B7 14 4A 8B 7B 1C 01 EF 03'
            '2C 97 68 2E 65 78 65 68 63 61 6C 63 54 87 04 24'
            '50 FF D5 CC'
        ))

    def test_mr_pancakes(self):
        data = (
            '00000020: 6F A9 BC 24 09 48 C9 04  D4 00 00 00 8C 14 11 54  o..$.H.........T\n'
            '00000030: 74 16 0A 57 B8 8B EC 48  83 EC 4A 48 8B D1 48 CB  t..W...H..JH..H.'
        )
        unit = self.load()
        self.assertEqual(data | unit | bytes, bytes.fromhex(
            '6F A9 BC 24 09 48 C9 04  D4 00 00 00 8C 14 11 54'
            '74 16 0A 57 B8 8B EC 48  83 EC 4A 48 8B D1 48 CB'
        ))

    def test_oledump_output(self):
        data = (
            '00000000: 01 00 FE FF 03 0A 00 00  FF FF FF FF 00 00 00 00  ................' '\n'
            '00000010: 00 00 00 00 00 00 00 00  00 00 00 00 19 00 00 00  ................' '\n'
            '00000020: 4D 69 63 72 6F 73 6F 66  74 20 46 6F 72 6D 73 20  Microsoft Forms ' '\n'
            '00000030: 32 2E 30 20 46 6F 72 6D  00 10 00 00 00 45 6D 62  2.0 Form.....Emb' '\n'
            '00000040: 65 64 64 65 64 20 4F 62  6A 65 63 74 00 00 00 00  edded Object....' '\n'
            '00000050: 00 F4 39 B2 71 00 00 00  00 00 00 00 00 00 00 00  ..9.q...........' '\n'
            '00000060: 00                                                .'
        )
        unit = self.load()
        self.assertEqual(data | unit | bytes, bytes.fromhex(
            '01 00 FE FF 03 0A 00 00  FF FF FF FF 00 00 00 00'
            '00 00 00 00 00 00 00 00  00 00 00 00 19 00 00 00'
            '4D 69 63 72 6F 73 6F 66  74 20 46 6F 72 6D 73 20'
            '32 2E 30 20 46 6F 72 6D  00 10 00 00 00 45 6D 62'
            '65 64 64 65 64 20 4F 62  6A 65 63 74 00 00 00 00'
            '00 F4 39 B2 71 00 00 00  00 00 00 00 00 00 00 00'
            '00'
        ))

    def test_copy_from_website(self):
        data = (
            R'0x00000000 07 02 00 00 00 a4 00 00 ........' '\n'
            R'0x00000008 52 53 41 32 00 02 00 00 RSA2....' '\n'
            R'0x00000010 01 00 01 00 6b df 51 ef ....k.Q.' '\n'
            R'0x00000018 db 6f 10 5c 32 bf 87 1c .o.\2...' '\n'
            R'0x00000020 d1 4c 24 7e e7 2a 14 10 .L$~.*..' '\n'
            R'0x00000028 6d eb 2c d5 8c 0b 95 7b m.,....{' '\n'
            R'0x00000030 c7 5d c6 87 12 ea a9 cd .]......' '\n'
            R'0x00000038 57 7d 3e cb e9 6a 46 d0 W}>..jF.' '\n'
            R'0x00000040 e1 ae 2f 86 d9 50 f9 98 ../..P..' '\n'
            R'0x00000048 71 dd 39 fc 0e 60 a9 d3 q.9..`..' '\n'
            R'0x00000050 f2 38 bb 8d 5d 2c bc 1e .8..],..' '\n'
            R'0x00000058 c3 38 fe 00 5e ca cf cd .8..^...' '\n'
            R'0x00000060 b4 13 89 16 d2 07 bc 9b ........' '\n'
            R'0x00000068 e1 20 31 0b 81 28 17 0c . 1..(..' '\n'
            R'0x00000070 c7 73 94 ee 67 be 7b 78 .s..g.{x' '\n'
            R'0x00000078 4e c7 91 73 a8 34 5a 24 N..s.4Z$' '\n'
            R'0x00000080 9d 92 0d e8 91 61 24 dc .....a$.' '\n'
            R'0x00000088 b5 eb df 71 66 dc e1 77 ...qf..w' '\n'
            R'0x00000090 d4 78 14 98 79 44 b0 19 .x..yD..' '\n'
            R'0x00000098 f6 f0 7d 63 cf 62 67 78 ..}c.bgx' '\n'
            R'0x000000a0 d0 7b 10 ae 6b db 40 b3 .{..k.@.' '\n'
            R'0x000000a8 b2 eb 2e 9f 31 34 2d cb ....14-.' '\n'
            R'0x000000b0 bf a2 6a a6 1f e9 03 42 ..j....B' '\n'
            R'0x000000b8 f2 63 9b b7 33 d0 fe 20 .c..3..' '\n'
            R'0x000000c0 83 26 1f 56 a8 24 f5 6d .&.V.$.m' '\n'
            R'0x000000c8 19 51 a5 92 31 e4 2b bc .Q..1.+.' '\n'
            R'0x000000d0 11 c8 26 75 a0 51 e9 83 ..&u.Q..' '\n'
            R'0x000000d8 ca ee 4b f0 59 eb a4 81 ..K.Y...' '\n'
            R'0x000000e0 d6 1f 49 42 2b 75 89 a7 ..IB+u..' '\n'
            R'0x000000e8 9f 84 7f 1f c3 8f 70 b6 ......p.' '\n'
            R'0x000000f0 7e 06 5e 8b c9 53 65 80 ~.^..Se.' '\n'
            R'0x000000f8 b7 16 f2 5e 5e de 0b 57 ...^^..W' '\n'
            R'0x00000100 47 43 86 85 8a fb 37 ac GC....7.' '\n'
            R'0x00000108 66 34 ba 09 1a b1 21 0b f4....!.' '\n'
            R'0x00000110 aa fa 6c b7 75 a7 3e 23 ..l.u.>#' '\n'
            R'0x00000118 18 58 95 90 b5 29 a4 1e .X...)..' '\n'
            R'0x00000120 15 76 52 56 bb 3d 6b 1d .vRV.=k.' '\n'
            R'0x00000128 2a d1 9f 5c 8a c0 55 ea *..\..U.' '\n'
            R'0x00000130 c3 29 a2 1e .)..' '\n'
        )
        goal = bytes.fromhex(
            '07 02 00 00 00 a4 00 00 52 53 41 32 00 02 00 00 01 00 01 00 6b df 51 ef db 6f 10 5c 32 bf 87 1c'
            'd1 4c 24 7e e7 2a 14 10 6d eb 2c d5 8c 0b 95 7b c7 5d c6 87 12 ea a9 cd 57 7d 3e cb e9 6a 46 d0'
            'e1 ae 2f 86 d9 50 f9 98 71 dd 39 fc 0e 60 a9 d3 f2 38 bb 8d 5d 2c bc 1e c3 38 fe 00 5e ca cf cd'
            'b4 13 89 16 d2 07 bc 9b e1 20 31 0b 81 28 17 0c c7 73 94 ee 67 be 7b 78 4e c7 91 73 a8 34 5a 24'
            '9d 92 0d e8 91 61 24 dc b5 eb df 71 66 dc e1 77 d4 78 14 98 79 44 b0 19 f6 f0 7d 63 cf 62 67 78'
            'd0 7b 10 ae 6b db 40 b3 b2 eb 2e 9f 31 34 2d cb bf a2 6a a6 1f e9 03 42 f2 63 9b b7 33 d0 fe 20'
            '83 26 1f 56 a8 24 f5 6d 19 51 a5 92 31 e4 2b bc 11 c8 26 75 a0 51 e9 83 ca ee 4b f0 59 eb a4 81'
            'd6 1f 49 42 2b 75 89 a7 9f 84 7f 1f c3 8f 70 b6 7e 06 5e 8b c9 53 65 80 b7 16 f2 5e 5e de 0b 57'
            '47 43 86 85 8a fb 37 ac 66 34 ba 09 1a b1 21 0b aa fa 6c b7 75 a7 3e 23 18 58 95 90 b5 29 a4 1e'
            '15 76 52 56 bb 3d 6b 1d 2a d1 9f 5c 8a c0 55 ea c3 29 a2 1e'
        )
        self.assertEqual(goal, data | self.load() | bytes)
