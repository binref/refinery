#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json

from .. import TestUnitBase


class TestPHPDeserializer(TestUnitBase):

    def test_reversible_property(self):
        data = {"42": True, "A to Z": {"0": 1, "1": 2, "2": 3}}
        ds = self.load()
        self.assertEqual(json.dumps(data) | -ds | ds | json.loads, data)

    def test_wikipedia(self):
        out = B'O:8:"stdClass":2:{s:4:"John";d:3.14;s:4:"Jane";d:2.718;}' | self.load() | json.loads
        self.assertEqual(out, {
            "John": 3.14,
            "Jane": 2.718
        })
