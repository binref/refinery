#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from . import TestMetaBase
from refinery.lib.loader import load_pipeline as L


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

    def test_count(self):
        pipeline = L('emit HELLO-WORLD [| push [| rex . | dedup -c | sorted count | pick :2 | pop t s ]| cfmt {t}{s} ]')
        self.assertEqual(pipeline(), B'LO')

    def test_key(self):
        pipeline = L('emit FOO BAR BAZ BAMPF [| dedup size ]')
        self.assertEqual(pipeline(), B'FOOBAMPF')
