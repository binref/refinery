#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.lib.loader import load_pipeline as L
from .. import TestUnitBase


class TestQueue(TestUnitBase):

    def test_variables_are_available(self):
        data = B'{"foo":"X","bar":"Y"}'
        pipeline = L('xtjson [| rex . [| qb var:path ]]')
        out = pipeline(data)
        self.assertEqual(out, B'XfooYbar')

    def test_inserted_chunks_are_visible(self):
        pipeline = L('emit AA | push [| qb BB | pop a b | cfmt {a}{b} ]')
        self.assertEqual(pipeline(), b'AABB')
