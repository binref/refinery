#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase


class TestConcat(TestUnitBase):

    def test_trivial(self):
        self.assertEqual(self.load()(b"'T'+'b'"), b'"Tb"')
