#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase

from refinery.lib.loader import load_detached as L, resolve


class TestAES(TestUnitBase):

    def test_panic(self):
        data = B'BINARY REFINERY REFINES BINARIES FINER THAN BINARY TOOLS'
        pp = L('aes -R range:16 --iv rep[16]:H:AC') | L('ccp rep[16]:H:AC') | L('aes range:16 --iv x::16')
        self.assertEqual(pp(data), data)

    def test_invertible_01(self):
        cipher = L('aes pbkdf2[32,s4ltY]:p4$$w0rd')
        test = self.generate_random_buffer(200)
        self.assertEqual(cipher.process(cipher.reverse(test)), test)

    def test_invertible_02(self):
        cipher = self.load('pbkdf2[32,s4ltY]:p4$$w0rd', iv=(b'MYIV' * 4))
        test = self.generate_random_buffer(200)
        self.assertEqual(cipher.process(cipher.reverse(test)), test)

    def test_cyberchef_cfb(self):
        data = B'hello world! this is my plaintext.'
        goal = bytes.fromhex('3357121ebb5a29468bd861467596ce3d6f99e251cc2d9f0a598032ae386d0ab995b3')
        unit = self.load(key=(b'\x42' * 16), iv=(b'\x24' * 16), mode='cfb')
        self.assertEqual(data | -unit | bytes, goal)

    def test_cyberchef_ctr(self):
        data = B'hello world! this is my plaintext.'
        goal = bytes.fromhex('3357121ebb5a29468bd861467596ce3d046163d218d0bae9a9d5532a8d4e19f5bf9a')
        unit = self.load(key=(b'\x42' * 16), iv=(b'\x24' * 16), mode='ctr')
        self.assertEqual(data | -unit | bytes, goal)

    def test_le_ctr(self):
        data = B'hello world! this is my plaintext.'
        goal = bytes.fromhex('3357121ebb5a29468bd861467596ce3da59bdee42dcc0614dea955368d8a5dc0cad4')
        unit = self.load(key=(b'\x42' * 16), iv=(b'\x24' * 16), mode='ctr', little_endian=True)
        self.assertEqual(data | -unit | bytes, goal)

    def test_gcm(self):
        K = self.generate_random_buffer(16)
        V = self.generate_random_buffer(12)
        M = self.generate_random_buffer(5 * 16)
        D = self.load(mode='gcm', key=K, iv=V)
        E = self.load(mode='GCM', key=K, iv=V, reverse=True)
        self.assertEqual(M, D(E(M)))

    def test_cbc_ciphertext_stealing(self):
        N = 5 * 16 + 11
        M = self.generate_random_buffer(N)

        # flake8: noqa
        D = L('chop 0x10') [
            L('pick :~1 :~2:~0') | L('scope ~0') | L('rep') | L('scope ~1') 
                | L('aes -r H:C0CAC01AFACEBEA75DEFACEDBEEFCACE') | L('snip 11:')
        ] | L('aes -r -mCBC H:C0CAC01AFACEBEA75DEFACEDBEEFCACE')

        # flake8: noqa
        E = L('pad 16') | L('aes -rR -mCBC H:C0CAC01AFACEBEA75DEFACEDBEEFCACE') | L('chop 16') [
                L('pick :(-2) (-1) (-2)') ]

        C = E(M)[:N]
        P = D(C)[:N]

        self.assertEqual(M, P)

    def test_ctr_mode(self):
        data = bytes.fromhex(
            'BF 4F DA 5F BF D4 AF D1 78 FE 1A BC B1 E0 61 26 60 5F B8 FA 3B B7 01 11'  #  .O._....x.....a&`_..;...
            '35 8E 65 A8 4E B9 94 BF 04 68 8C 9E 5A AC 5B AA 1A 4C 35 4B F3 81 E4 9B'  #  5.e.N....h..Z.[..L5K....
            '08 A6 B5 60 15 DB 83 FC EA 6F 5E 4E FB 60 92 44 01 77 42 6D 9C 18 30 26'  #  ...`.....o^N.`.D.wBm..0&
            '11 99 47 66 0F FD 9A E6 9A FD 86 66 38 FE 2D 12 14 F2 AB FC 64 BC BD F4'  #  ..Gf.......f8.-.....d...
            '17 06 96 76 12 0D DB 7C 52 96 C2 3C 9D 82 6C E3 E3 87 7C B5 2D A9 74 AD'  #  ...v...|R..<..l...|.-.t.
            'BC A4 BF 17 3C 40 F3 4B EA 24 52 00 BD D2 03 34 73 1E 8D 59 77 70 9F 06'  #  ....<@.K.$R....4s..Ywp..
            'BB D8 A5 01 66 64 FC 7F FC 75 69 E0 AB 91 BE 08 A1 C7 5B 31 5D E1 97 E6'  #  ....fd...ui.......[1]...
            '6A E8 74 DA F2 C3 ED C8 25 C1 8B 3A 52 26 E6 20 92 FB 20 7B CB E6 AE C9'  #  j.t.....%..:R&.....{....
            'BC 22 F1 83 E5 D2 5E F4 15 82 73 33 AB 48 B3 48 D1 CC DB 42 D3 4C 19 5A'  #  ."....^...s3.H.H...B.L.Z
            '32 64 64 DE 76 3E 4F 11 43 56 02 91 24 6C B9 E8 22 8E ED 0E 6F 06 59 B1'  #  2dd.v>O.CV..$l.."...o.Y.
        )
        unit = self.load(mode='ctr', padding='raw', key=b'sdaagsdagdsgddsg', iv=b'sdagdasghaswqwet')
        self.assertIn(b'your files have been encrypted with military grade algorithms', unit(data))

    def test_custom_segment_size(self):
        data = (L('emit b64:*O*ZQovuDl4bWaG/VhH4lW6y3luVi9/tBvTM0tRoe7cdQ=') |
            L('aes -m CFB -i h:2D4E1D3B2B3B5A1C0E141B0739C8AD31 h:A8B5C1A7E4A2D8A9D93F53DBB0B2A1F7F928DAF3D2F6FACBE61FFF3BFEDCDDBA -S 128') | ...)
        self.assertIn(B'xxxxxx22www2', data)
        self.assertIn(B'vpknpomashni', data)

    def test_authentication(self):
        data = B'The binary refinery refines the finest binaries!'

        with self.assertRaises(ValueError):
            data | L('aes -m=gcm -i=schokolade12 schokoladentorte --tag=16') | bytes

        test = self.load_pipeline('|'.join((
            'aes -m=gcm -i=schokolade12 schokoladentorte --tag=16 -R [',
            'aes -m=gcm -i=schokolade12 schokoladentorte --tag=v:tag ]',
        )))
        self.assertEqual(data, data | test | bytes)

        test = self.load_pipeline('|'.join((
            'aes -m=gcm -i=schokolade12 schokoladentorte --tag=16 -R [',
            'aes -m=gcm -i=schokolade12 schokoladentorte ]',
        )))
        self.assertEqual(data, data | test | bytes)

        test = self.load_pipeline('|'.join((
            'aes -m=gcm -i=schokolade12 schokoladentorte --aad=refined --tag=16 -R [',
            'aes -m=gcm -i=schokolade12 schokoladentorte --aad=refined --tag=v:tag ]',
        )))
        self.assertEqual(data, data | test | bytes)

        test = self.load_pipeline('|'.join((
            'aes -m=gcm -i=schokolade12 schokoladentorte --aad=refined -R [',
            'aes -m=gcm -i=schokolade12 schokoladentorte --aad=refined --tag=v:tag ]',
        )))
        self.assertEqual(data, data | test | bytes)

        with self.assertRaises(ValueError):
            data | self.load_pipeline('|'.join((
                'aes -m=gcm -i=schokolade12 schokoladentorte -R [',
                'put tag bogusbogustagtag'
                'aes -m=gcm -i=schokolade12 schokoladentorte --tag=v:tag ]',
            ))) | None

        with self.assertRaises(ValueError):
            data | self.load_pipeline('|'.join((
                'aes -m=gcm -i=schokolade12 schokoladentorte --aad=refined --tag=16 -R [',
                'aes -m=gcm -i=schokolade12 schokoladentorte --aad=REFYNED --tag=v:tag ]',
            ))) | None
        with self.assertRaises(ValueError):
            data | self.load_pipeline('|'.join((
                'aes -m=gcm -i=schokolade12 schokoladentorte               --tag=16 -R [',
                'aes -m=gcm -i=schokolade12 schokoladentorte --aad=refyned --tag=v:tag ]',
            ))) | None
        with self.assertRaises(ValueError):
            data | self.load_pipeline('|'.join((
                'aes -m=gcm -i=schokolade12 schokoladentorte --aad=refined --tag=16 -R [',
                'aes -m=gcm -i=schokolade12 schokoladentorte               --tag=v:tag ]',
            ))) | None
