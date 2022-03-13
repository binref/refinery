#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery import Unit
from refinery.units.meta.pick import pick
from refinery.lib.loader import load_pipeline
from itertools import count

from . import TestMetaBase


class TestPick(TestMetaBase):

    def test_selection_mixed(self):
        unit = self.load('1', '3:6', '9:')
        self.assertEqual(
            unit(
                B'ENTRY #0',
                B'ENTRY #1',
                B'ENTRY #2',
                B'ENTRY #3',
                B'ENTRY #4',
                B'ENTRY #5',
                B'ENTRY #6',
                B'ENTRY #7',
                B'ENTRY #8',
                B'ENTRY #9',
            ), [
                B'ENTRY #1',
                B'ENTRY #3',
                B'ENTRY #4',
                B'ENTRY #5',
                B'ENTRY #9',
            ]
        )

    def test_pick_backref(self):
        unit = self.load('8', '2:5', '2', '1')
        self.assertEqual(
            unit(
                B'ENTRY #0',
                B'ENTRY #1',
                B'ENTRY #2',
                B'ENTRY #3',
                B'ENTRY #4',
                B'ENTRY #5',
                B'ENTRY #6',
                B'ENTRY #7',
                B'ENTRY #8',
                B'ENTRY #9',
            ), [
                B'ENTRY #8',
                B'ENTRY #2',
                B'ENTRY #3',
                B'ENTRY #4',
                B'ENTRY #2',
                B'ENTRY #1',
            ]
        )

    def test_pick_unbounded(self):
        unit = self.load('--', '-2:', '5', '3:')
        self.assertEqual(
            unit(
                B'ENTRY #0',
                B'ENTRY #1',
                B'ENTRY #2',
                B'ENTRY #3',
                B'ENTRY #4',
                B'ENTRY #5',
                B'ENTRY #6',
                B'ENTRY #7',
                B'ENTRY #8',
                B'ENTRY #9',
            ), [
                B'ENTRY #8',
                B'ENTRY #9',
                B'ENTRY #5',
                B'ENTRY #3',
                B'ENTRY #4',
                B'ENTRY #5',
                B'ENTRY #6',
                B'ENTRY #7',
                B'ENTRY #8',
                B'ENTRY #9',
            ]
        )

    def test_pick_reverse(self):
        unit = self.load('::-1')
        self.assertEqual(
            unit(
                B'ENTRY #0',
                B'ENTRY #1',
                B'ENTRY #2',
                B'ENTRY #3',
                B'ENTRY #4',
                B'ENTRY #5',
                B'ENTRY #6',
                B'ENTRY #7',
                B'ENTRY #8',
                B'ENTRY #9',
            ), [
                B'ENTRY #9',
                B'ENTRY #8',
                B'ENTRY #7',
                B'ENTRY #6',
                B'ENTRY #5',
                B'ENTRY #4',
                B'ENTRY #3',
                B'ENTRY #2',
                B'ENTRY #1',
                B'ENTRY #0',
            ]
        )

    def test_abort_early(self):

        class inf(Unit):
            def process(self, _):
                for k in count():
                    yield B'$'
                    if k > 5:
                        raise OverflowError

        unit = pick(slice(None, 2))
        data = str(B'' | inf[unit])
        self.assertEqual(data, '$$')

    def test_scroll_past_invisible_chunks(self):
        pl = load_pipeline('emit FOO [| push [| rex . | pick :1 | pop o ]| ccp var:o ]')
        self.assertEqual(pl(), B'FFOO')
