#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase


class TestNameCases(TestUnitBase):

    def test_set_variable(self):
        self.assertEqual(
            self.load().process(b'SET-vaRIabLE'),
            b'Set-Variable'
        )
