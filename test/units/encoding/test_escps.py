#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestEscPS(TestUnitBase):

    def test_unicode_with_quotes(self):
        unit = self.load()
        data = U"refinery:\n all about the 'パイプライン'.".encode('UTF8')
        self.assertEqual(unit.reverse(data).decode('UTF8'),
            U'''"refinery:`n all about the `'パイプライン`'."''')

    def test_string_with_variables(self):
        unit = self.load()
        data = B'"This $variable contains a `$ symbol!`r`n"'
        self.assertEqual(unit(data), B'This $variable contains a $ symbol!\r\n')

    def test_single_quoted_string(self):
        unit = self.load()
        data = B"'$var = ''`refined`'';'"
        self.assertEqual(unit(data), B"$var = '`refined`';")
