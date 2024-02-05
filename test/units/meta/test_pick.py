#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery import Unit
from refinery.units.meta.pick import pick
from refinery.lib.loader import load_pipeline

from itertools import count
from hashlib import sha256

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
        pl = load_pipeline('emit FOO [| push | rex . | pick :1 | iff size -eq 1 | pop o | ccp var:o ]')
        self.assertEqual(pl(), B'FFOO')

    def test_squeezing_as_expected(self):
        pl = load_pipeline('emit range:0x30:0x3A | chop 1 [| pick 3:5 1 7: []| sep , ]')
        self.assertEqual(pl(), B'34,1,789')

    def test_regression_arg_not_populated(self):
        src = self.download_sample('302c0d553c9e7f2561864d79022b780a53ec0a5927e8962d883b88dde249d044')

        pl1 = load_pipeline('xt *.html | carve -sd intarray | xt')
        hta = src | pl1 | bytearray
        self.assertTrue(hta.startswith(B'<html>\r\n<head>\r\n<script language="javascript">'))

        pl2 = load_pipeline('|'.join([
            'put p [',
            '   carve -n20 intarray',
            '   pack -B2',
            '   swap p',
            '   put i index',
            '   carve -d string [',
            '      pick 9+i*13 6+i*13',
            '      qb var:p',
            '      pop x n',
            '      ccp var:x ]]',
        ]))
        out = hta | pl2 | {'n': ...}

        self.assertContains(out, b'\\mso.dll')
        self.assertContains(out, b'\\msoev.exe')
        self.assertContains(out, b'\\AppVIsvSubsystems64.dll')
        self.assertContains(out, b'\\Invitation.pdf')

        self.assertTrue(out[b'\\mso.dll'].startswith(b'MZ'))
        self.assertTrue(out[b'\\msoev.exe'].startswith(b'MZ'))
        self.assertTrue(out[b'\\AppVIsvSubsystems64.dll'].startswith(b'MZ'))
        self.assertTrue(out[b'\\Invitation.pdf'].startswith(b'%P'))

        self.assertEqual(sha256(out[b'\\msoev.exe']).hexdigest(),
            '06cea3a5ef9641bea4704e9f6d2ed13286f9e5ec7ab43f8067f15b5a41053d33')
