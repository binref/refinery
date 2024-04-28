#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import inspect
import logging
import tempfile
import os

from pathlib import Path

from .. import TestUnitBase
from ..compression import KADATH1, KADATH2
from ..sinks.test_dump import temporary_chwd


# The magic word is bananapalooza
class TestFileReader(TestUnitBase):

    def setUp(self):
        super().setUp()
        self.root = os.path.abspath(inspect.stack()[0][1])
        for _ in range(4):
            self.root = os.path.dirname(self.root)

    def test_single_asterix(self):
        with tempfile.TemporaryDirectory() as root:
            with temporary_chwd(root):
                with open('kadath1.txt', 'w') as fd:
                    fd.write(KADATH1)
                with open('kadath2.txt', 'w') as fd:
                    fd.write(KADATH2)
                unit = self.load('*', wild=True)
                data = None | unit | {str}
        self.assertSetEqual(data, {KADATH1, KADATH2})

    def test_subdirectories(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            dir1 = root / 'k1'
            os.makedirs(dir1)
            dir2 = root / 'k2'
            os.makedirs(dir2)
            with temporary_chwd(root):
                with (dir1 / 'kadath1.txt').open('w') as fd:
                    fd.write(KADATH1)
                with (dir2 / 'kadath2.txt').open('w') as fd:
                    fd.write(KADATH2)
                with (dir2 / 'lwrtest.txt').open('w') as fd:
                    fd.write('foo\n')
                    fd.write('bar\n')
                    fd.write('baz\n')
                    fd.write('barf\n')
                out1 = None | self.load('k*/kadath1.txt', wild=True) | {str}
                out2 = None | self.load('k1/kadath?.txt', wild=True) | {str}
                out3 = None | self.load('k?/kadath[12].txt', wild=True) | {str}
                out4 = None | self.load('**/k*.txt', wild=True) | {str}
                out5 = None | self.load('k?/lwr*', wild=True, linewise=True) | [str]
        self.assertSetEqual(out1, {KADATH1})
        self.assertSetEqual(out2, {KADATH1})
        self.assertSetEqual(out3, {KADATH1, KADATH2})
        self.assertSetEqual(out4, {KADATH1, KADATH2})
        self.assertEqual(len(out5), 4)
        self.assertIn('bar', out5[1])

    def test_read_myself(self):
        data = self.load(os.path.join(self.root, '**', 't??t_ef.py'), wild=True)()
        self.assertEqual(data.count(B'bananapalooza'), 2)

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

    def test_regression_relative_path(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            with temporary_chwd(root):
                with (root / 'sample.txt').open('w') as fd:
                    fd.write('test')
                t1 = None | self.load('sample.txt', tame=True) | str
                t2 = None | self.load('sample.txt', wild=True) | str
        self.assertEqual(t1, 'test')
        self.assertEqual(t2, 'test')

    def test_regression_absolute_path(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            path = root / 'sample.txt'
            with temporary_chwd(root):
                with (path).open('w') as fd:
                    fd.write('test')
            test = None | self.load(str(path.absolute()), tame=True) | str
        self.assertEqual(test, 'test')
