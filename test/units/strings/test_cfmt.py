#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestFormatter(TestUnitBase):

    def test_with_escape_sequence(self):
        data = B'refinery!'
        unit = self.load(R'{}\n')
        self.assertEqual(unit(data), B'refinery!\n')
