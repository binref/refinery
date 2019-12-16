#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from . import TestMetaBase


class TestDeduplication(TestMetaBase):

    def test_duplicated_strings(self):
        unit = self.load()
        self.assertEqual(
            unit(
                B'aldebaran',
                B'geminorum',
                B'aldebaran',
                B'arcturus',
                B'cassiopeiae',
                B'arcturus',
                B'sagittarii',
                B'cephei',
                B'sagittarii',
                B'polaris',
                B'sol',
                B'geminorum',
                B'vulpeculae'
            ), [
                B'aldebaran',
                B'geminorum',
                B'arcturus',
                B'cassiopeiae',
                B'sagittarii',
                B'cephei',
                B'polaris',
                B'sol',
                B'vulpeculae'
            ]
        )

    def test_sorting_strings(self):
        unit = self.load('-s')
        self.assertEqual(
            unit(
                B'alpha',
                B'alpha',
                B'beta',
                B'gamma',
                B'delta',
                B'epsilon',
                B'epsilon',
            ), [
                B'alpha',
                B'beta',
                B'delta',
                B'epsilon',
                B'gamma'
            ]
        )