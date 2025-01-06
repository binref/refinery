#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.lib.frame import Chunk
from .. import TestUnitBase


class TestJSONExtractor(TestUnitBase):

    def test_basic(self):
        document = B'''
        {
            "foo": {
                "bar": [
                    0, 1, 2, 3
                ],
                "baz": true,
                "b0": "Binary",
                "b1": "Refinery"
            },
            "bar": {
                "bar": {
                    "ef": 0,
                    "eg": 1,
                    "ep": 2
                }
            }
        }
        '''
        unit = self.ldu('xtjson', list=True)
        listing = {bytes(t) for t in document | unit}
        self.assertEqual(listing, {
            B'foo.bar.0',
            B'foo.bar.1',
            B'foo.bar.2',
            B'foo.bar.3',
            B'foo.bar',
            B'foo.baz',
            B'foo.b0',
            B'foo.b1',
            B'foo',
            B'bar.bar.ef',
            B'bar.bar.eg',
            B'bar.bar.ep',
            B'bar.bar',
            B'bar',
        })

        unit = self.ldu('xtjson', 'foo.b0')
        self.assertEqual(bytes(document | unit), b'Binary')


class TestJSONLevel0Extractor(TestUnitBase):

    def test_basic(self):
        data = br'''
        {
            "data": "Binary Refinery!",
            "date": "2021-09-04 12:00",
            "test": true,
            "keys": [7, 1, 12, 9, 1, 4],
            "n1": "I have\nline breaks and should not be in meta",
            "n2": {
                "nope": "I am a dictionary and should not be in meta"
            },
            "n3": ["No", ["nested", "lists"], "even when they contain numbers:", 7, 8],
            "n4": "something way too long %s"
        }''' % (B'OOM' * 200)
        unit = self.ldu('xj0', '{data}')
        result: Chunk = next(data | unit)

        for k in range(4):
            self.assertNotIn(F'n{k + 1}', result.meta)

        self.assertEqual(result['date'], b'2021-09-04 12:00')
        self.assertEqual(result['test'], True)
        self.assertEqual(result['keys'], [7, 1, 12, 9, 1, 4])
        self.assertEqual(result, B'Binary Refinery!')

        unit = self.ldu('xj0', '{data}', one=True)
        result: Chunk = next(data | unit)
        self.assertEqual(0, len(result.meta))

        unit = self.ldu('xj0', '{data}', all=True)
        result: Chunk = next(data | unit)
        self.assertEqual(result['date'], b'2021-09-04 12:00')
        self.assertEqual(result['test'], True)
        self.assertEqual(result['keys'], [7, 1, 12, 9, 1, 4])
        self.assertEqual(result, B'Binary Refinery!')
        self.assertNotIn('n3', result.meta)
        self.assertEqual(result['n1'], b'I have\nline breaks and should not be in meta')
        self.assertIn('n2', result.meta)
        self.assertIn('n4', result.meta)
