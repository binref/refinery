#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json

from .. import TestUnitBase


class TestJSON(TestUnitBase):

    def test_trailing_commas(self):
        unit = self.load()
        test = json.loads(unit(B'{"foo": 9, "bar": [1,2,3,], "baz": 11,}'))
        self.assertEqual(test, {'foo': 9, 'bar': [1, 2, 3], 'baz': 11})

    def test_leave_string_literals_unchanged(self):
        unit = self.load()
        test = json.loads(unit(
            BR'''{
                "[key,]": 9,
                "{\"foo\": 7, \"bar\":6,}": 10
            }
            '''
        ))
        self.assertIn('[key,]', test)
        self.assertIn('{"foo": 7, "bar":6,}', test)

    def test_minify_json(self):
        unit = self.load(indent=0)
        data = {"A": [1, 2, 3], "B": {"C": "Yes", "D": "No"}}
        test = unit(json.dumps(data, indent=4).encode(unit.codec))
        self.assertEqual(len(test), 38)
        self.assertEqual(json.loads(test), data)

    def test_tabular_output(self):
        unit = self.load(tabular=True)
        data = {"binary": "foo", "bar": ["rattle", "tattle", {"baz": 1, "baf": 2}]}
        data = json.dumps(data).encode(unit.codec)
        test = {
            tuple(p.strip() for p in line.split(':'))
            for line in str(data | unit).splitlines(False)
        }
        for line in [
            ('binary', 'foo'),
            ('bar[0x0]', 'rattle'),
            ('bar[0x1]', 'tattle'),
            ('bar[0x2].baz', '1'),
            ('bar[0x2].baf', '2')
        ]:
            self.assertIn(line, test)
