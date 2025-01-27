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

    def test_real_world_01_file(self):
        test = (
            self.download_sample('c6bb166294257e53d0d4b9ef6fe362c8cbacef5ec2bd26f98c6d7043284dec73')
            | self.load('idp.dll')
            | self.ldu('pemeta')
            | self.ldu('xtjson', 'ProductName')
            | str
        )
        self.assertEqual(test, 'Inno Download Plugin')
