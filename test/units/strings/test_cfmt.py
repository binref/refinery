#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase

from refinery.lib.loader import load_commandline


class TestFormatter(TestUnitBase):

    def test_with_escape_sequence(self):
        data = B'refinery!'
        unit = self.load(R'{}\n')
        self.assertEqual(unit(data), B'refinery!\n')

    def test_utf8_metadata_value(self):
        message = U'рафинировочный завод'
        unit = load_commandline(F'put msg "s:{message}"')[self.load(R'{msg}')]
        result = unit(B'')
        self.assertEqual(result.decode(unit.codec), message)
