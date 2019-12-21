#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import io

from . import TestMetaBase
from .. import refinery as r


class TestSorting(TestMetaBase):

    def test_with_scoping(self):
        with io.BytesIO() as result:
            r.emit('F2', 'F3', 'S4', 'S6', 'S5', 'F1', 'S2', 'S3', 'S1')[
                r.scope('2:5', '6:') | r.sorted | r.sep('-')] | result
            self.assertEqual(result.getvalue(), B'F2-F3-S1-S2-S3-S4-F1-S5-S6')

    def test_trailing_chunks(self):
        pipeline = r.rep[r.scope(0) | r.chop(1)[r.sorted]]
        self.assertEqual(pipeline(B'8492756031'), B'01234567898492756031')
