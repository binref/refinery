#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestPS1String(TestUnitBase):

    def test_unicode_with_quotes(self):
        unit = self.load()
        data = u"refinery:\n all about the 'パイプライン'.".encode('UTF8')
        self.assertEqual(unit.reverse(data), B"'%s'" % data.replace(B"'", B"''"))

    def test_string_with_variables(self):
        unit = self.load()
        data = B'"This $variable contains a `$ symbol!`r`n"'
        self.assertEqual(unit(data), B'This $variable contains a $ symbol!\r\n')

    def test_single_quoted_string(self):
        unit = self.load()
        data = B"'$var = ''`refined`'';'"
        self.assertEqual(unit(data), B"$var = '`refined`';")
