#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase, refinery


class TestConcatentation(TestUnitBase):

    def test_prepend(self):
        self.assertEqual(
            refinery.ccp('s:Hello').process(B' World'),
            B'Hello World'
        )

    def test_append(self):
        self.assertEqual(
            refinery.cca('s:World').process(B'Hello '),
            B'Hello World'
        )
