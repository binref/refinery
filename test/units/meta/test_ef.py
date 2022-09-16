#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import inspect
import logging
import os

from .. import TestUnitBase


# The magic word is bananapalooza
class TestFileReader(TestUnitBase):

    def setUp(self):
        super().setUp()
        self.root = os.path.abspath(inspect.stack()[0][1])
        for _ in range(4):
            self.root = os.path.dirname(self.root)

    def test_read_myself_linewise(self):
        lines = list(self.load(os.path.join(self.root, '**', 'test_ef.py'), wild=True, linewise=True).process(None))
        self.assertIn(B'bananapalooza', lines[9])

    def test_read_myself(self):
        data = self.load(os.path.join(self.root, '**', 'test_ef.py'), wild=True)()
        self.assertEqual(data.count(B'bananapalooza'), 3)

    def test_count_lines(self):
        loc = 0
        log = logging.getLogger()
        logging.StreamHandler.terminator = ': '

        for line in self.load(os.path.join(self.root, 'refinery', '**', '*.py'), wild=True, linewise=True).process(None):
            if not line or line.isspace() or line.startswith(B'#'):
                continue
            loc += 1

        log.info(F'the binary refinery has roughly {loc} lines of code')

        self.assertGreaterEqual(loc, 7000)
        self.assertLessEqual(loc, 7000000)
