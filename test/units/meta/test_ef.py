import inspect
import logging
import tempfile
import os

from pathlib import Path

from test.units import TestUnitBase
from test.units.compression import KADATH1, KADATH2
from test import temporary_chwd


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

    def test_filter_by_file_size(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            with temporary_chwd(root):
                with (root / 'small.txt').open('wb') as fd:
                    fd.write(b'tiny')
                with (root / 'large.txt').open('wb') as fd:
                    fd.write(b'A' * 100)
                results = None | self.load('*.txt', wild=True, size=slice(10, None)) | [bytes]
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0], b'A' * 100)

    def test_filter_by_size_excludes_large_files(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            with temporary_chwd(root):
                with (root / 'small.txt').open('wb') as fd:
                    fd.write(b'hello')
                with (root / 'big.txt').open('wb') as fd:
                    fd.write(b'X' * 200)
                results = None | self.load('*.txt', wild=True, size=slice(None, 10)) | [bytes]
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0], b'hello')

    def test_read_file_in_chunks(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            with temporary_chwd(root):
                with (root / 'chunked.bin').open('wb') as fd:
                    fd.write(b'AAABBBCCC')
                results = None | self.load('chunked.bin', tame=True, read=3) | [bytes]
        self.assertEqual(len(results), 3)
        self.assertEqual(results[0], b'AAA')
        self.assertEqual(results[1], b'BBB')
        self.assertEqual(results[2], b'CCC')

    def test_linewise_reading(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            with temporary_chwd(root):
                with (root / 'lines.txt').open('w') as fd:
                    fd.write('alpha\nbeta\ngamma\n')
                results = None | self.load('lines.txt', tame=True, linewise=True) | [str]
        self.assertEqual(len(results), 3)
        self.assertIn('alpha', results[0])
        self.assertIn('beta', results[1])
        self.assertIn('gamma', results[2])

    def test_list_mode_returns_filename(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            with temporary_chwd(root):
                with (root / 'listed.dat').open('wb') as fd:
                    fd.write(b'content')
                results = None | self.load('listed.dat', tame=True, list=True) | [str]
        self.assertEqual(len(results), 1)
        self.assertIn('listed.dat', results[0])
