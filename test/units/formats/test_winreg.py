#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from inspect import cleandoc
from .. import TestUnitBase


class TestWindowsRegistryExtractor(TestUnitBase):

    def test_registry_export(self):
        unit = self.load()
        data = cleandoc(
            R"""
            Windows Registry Editor Version 5.00

            [HKEY_CURRENT_USER\Test]
            "Bin"=hex:41,42,43,43,44,44,01,02
            "Str"="This is a \"string value\"."
            "u32"=dword:00000032
            "u64"=hex(b):64,00,00,00,00,00,00,00
            "Multi"=hex(7):4d,00,75,00,6c,00,74,00,69,00,00,00,22,00,53,00,74,00,72,00,69,\
              00,6e,00,67,00,22,00,00,00,56,00,61,00,6c,00,75,00,65,00,21,00,00,00,00,00
            "Exp"=hex(2):25,00,41,00,70,00,70,00,44,00,61,00,74,00,61,00,25,00,00,00
            @="Wookie"
            """
        ).encode(unit.codec)
        items = {chunk['path']: chunk for chunk in data | unit}
        self.assertEqual(items[B'HKEY_CURRENT_USER/Test/Bin'], B'ABCCDD\x01\x02')
        self.assertEqual(items[B'HKEY_CURRENT_USER/Test/Str'], B'This is a "string value".')
        self.assertEqual(items[B'HKEY_CURRENT_USER/Test/u32'], B'0x32')
        self.assertEqual(items[B'HKEY_CURRENT_USER/Test/u64'], B'0x64')
        self.assertEqual(items[B'HKEY_CURRENT_USER/Test/Multi.0'], B'Multi')
        self.assertEqual(items[B'HKEY_CURRENT_USER/Test/Multi.1'], B'"String"')
        self.assertEqual(items[B'HKEY_CURRENT_USER/Test/Multi.2'], B'Value!')
        self.assertEqual(items[B'HKEY_CURRENT_USER/Test/Exp'], B'%AppData%')
        self.assertEqual(items[B'HKEY_CURRENT_USER/Test/@'], B'Wookie')
