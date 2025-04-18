#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# flake8: noqa
from ... import TestUnitBase


class TestInnoExtractor(TestUnitBase):

    def test_real_world_01_script(self):
        test = (
            self.download_sample('c6bb166294257e53d0d4b9ef6fe362c8cbacef5ec2bd26f98c6d7043284dec73')
            | self.load('script.bin')
            | self.ldu('ifpsstr')
                [ self.ldu('rev')
                | self.ldu('vigenere', 'm')
                | self.ldu('iffp', 'url') ]
            | str
        )
        self.assertEqual(test, 'http''s:/''/t.''me/+r1hwDlb8VAI5ZTQy')

    def test_real_world_02_script(self):
        test = (
            self.download_sample('c6bb166294257e53d0d4b9ef6fe362c8cbacef5ec2bd26f98c6d7043284dec73')
            | self.load('script.ps') | str
        )
        self.assertNotIn('LocalVar3 := Argument2', test)
        self.assertIn   ('LocalVar3 := Argument1', test) # noqa

    def test_real_world_01_file(self):
        test = (
            self.download_sample('c6bb166294257e53d0d4b9ef6fe362c8cbacef5ec2bd26f98c6d7043284dec73')
            | self.load('idp.dll')
            | self.ldu('pemeta')
            | self.ldu('xtjson', 'ProductName')
            | str
        )
        self.assertEqual(test, 'Inno Download Plugin')

    def test_v_6_3_00(self):
        test = (
            self.download_sample('eeafd3fe2280e065aac87ca8b210be5873be5fe1f51ca4156d12bcf4f0d1eb1e')
            | self.load('script.bin')
            | self.ldu('ifpsstr')
                [ self.ldu('iffp', 'url')
                | self.ldu('urlfix')
                | self.ldu('dedup')
            ]| str
        )
        self.assertEqual(test, 'ht''tps:''//mealkittens''.''cfd/exte.php')

    def test_v_5_2_01(self):
        test = (
            self.download_sample('0c9ffd51196d71bba19a708bb64224be87c8fceb0b22b71262080c1055b5a642')
            | self.load('arrow.x')
            | str
        )
        self.assertIn('6f0d123b-bad2-4167-a0d0-80224f25fabb', test)

    def test_v_5_5_07(self):
        test = (
            self.download_sample('9271acdc528deb7d971f742c94d772b1f408b5db00ae949f79221a3545f41314')
            | self.load('History.txt')
            | str
        )
        self.assertIn('5, UltraISO 4.1 (July 28, 2002)', test)

    def test_proc_ptr_parsing(self):
        data = self.download_sample('cdbc92e0d280e54a66c347b0178d0b34a9ee8fc6c241ebfeb48bdcb31ddd774c')
        ifps = data | self.load('script.ps') | str
        self.assertIn('LocalVar3 := &RADIOBUTTONQUICKONCLICK', ifps)
