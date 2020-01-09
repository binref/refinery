#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import tempfile
import pyperclip

from refinery import emit
from .. import TestUnitBase


class TestDump(TestUnitBase):

    def test_clipboard_copy(self):
        copy = self.load()
        data = 'Too much technology, in too little time.'
        prev = pyperclip.paste()
        pyperclip.copy('I love Apples')
        copy(data.encode(copy.codec))
        try:
            self.assertEqual(pyperclip.paste(), data)
        finally:
            pyperclip.copy(prev)

    def test_dump_to_single_file(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, 'foo', 'bar')
            self.load(path)(b'Waffles')
            self.assertTrue(os.path.exists(path))
            with open(path, 'rb') as result:
                self.assertEqual(result.read(), b'Waffles')

    def test_dump_formatted(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, 'file-{index:02d}-{length:02d}.dat')
            cola = os.path.join(root, 'file-02-04.dat')
            dump = self.load(path, format=True)
            emit('Coca', 'Cola', 'Code')[dump]()
            self.assertTrue(os.path.exists(cola))
            with open(cola, 'rb') as result:
                self.assertEqual(result.read(), b'Cola')

    def test_dump_multiple(self):
        with tempfile.TemporaryDirectory() as root:
            words = ['coca', 'cola', 'code']
            paths = [os.path.join(root, word) for word in words]
            dump = self.load(*paths)
            emit(*words)[dump]()
            for word, path in zip(words, paths):
                self.assertTrue(os.path.exists(path))
                with open(path, 'r') as result:
                    self.assertEqual(result.read(), word)
