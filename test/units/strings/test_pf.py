#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase

from refinery.lib.loader import load_commandline


class TestFormatter(TestUnitBase):

    def test_with_escape_sequence(self):
        data = B'refinery!'
        unit = self.load(R'{}\n', unescape=True)
        self.assertEqual(unit(data), B'refinery!\n')

    def test_utf8_metadata_value(self):
        message = U'рафинировочный завод'
        unit = load_commandline(F'put msg "s:{message}"')[self.load(R'{msg}')]
        result = unit(B'')
        self.assertEqual(result.decode(unit.codec), message)

    def test_linebreak_01(self):
        self.assertEqual(B'XX' | self.load('{\\n:_}{}') | str, '{\\n:_}XX')

    def test_linebreak_02(self):
        self.assertEqual(B'XX' | self.load('A\\nB\\n{}') | str, 'A\\nB\\nXX')

    def test_linebreak_03(self):
        self.assertEqual(B'XX' | self.load('A{\\n!n}B\\n{}') | str, 'A\nB\\nXX')
        self.assertEqual(B'XX' | self.load('A{0A!h}B\\n{}') | str, 'A\nB\\nXX')
        self.assertEqual(B'XX' | self.load('A{%0a!q}B\\n{}') | str, 'A\nB\\nXX')
        self.assertEqual(B'XX' | self.load('{A\\nB\\n!n}{}') | str, 'A\nB\nXX')

    def test_crc32(self):
        self.assertEqual(B'X' | self.load(r'{size} {crc32:hex:be}') | str, '1 3081909835')

    def test_escaped_formats(self):
        for u, g in [(False, 'Y\\nX'), (True, 'Y\nX')]:
            self.assertEqual(B'X' | self.load(r'Y\n{}', unescape=u) | str, g)

    def test_formatting_something_that_is_also_a_handler(self):
        self.assertEqual(B'access.h' | self.load('{:px}') | str, 'h')
