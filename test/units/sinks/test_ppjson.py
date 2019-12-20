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
