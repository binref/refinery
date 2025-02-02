#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import marshal
import json

from .. import TestUnitBase


class TestPyMarshal(TestUnitBase):

    def test_integer(self):
        unit = self.load()
        data = 935532112
        test = marshal.dumps(data) | unit | bytes
        self.assertEqual(int.from_bytes(test, 'big'), data)

    def test_string(self):
        unit = self.load()
        data = 'The binary refinery refines the finest binaries.'
        test = marshal.dumps(data) | unit | str
        self.assertEqual(test, data)

    def test_strings(self):
        unit = self.load()
        data = 'The binary refinery refines the finest binaries.'.split()
        test = marshal.dumps(data) | unit | [str]
        self.assertEqual(test, data)

    def test_json(self):
        unit = self.load()
        data = {
            'foo': None,
            'bar': [1, 12, 7],
            'baz': {
                'x': 'refined',
                'y': 'binaries',
            }
        }
        test = marshal.dumps(data) | unit | json.loads
        self.assertEqual(test, data)

    def test_bytes(self):
        unit = self.load()
        for k in (1, 2, 12, 200, 353444):
            t = self.generate_random_buffer(k)
            self.assertEqual(marshal.dumps(t) | unit | bytes, t)

    def test_code(self):
        import importlib.util
        M = importlib.util.MAGIC_NUMBER

        def test_function():
            print('refine your binaries!')

        data = marshal.dumps(test_function.__code__)
        test = data | self.load() | bytes
        self.assertIn(b'refine your binaries!', test)
        self.assertEqual(test[:len(M)], M)
