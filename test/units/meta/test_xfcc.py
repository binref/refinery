#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase

from refinery.lib.loader import load_pipeline as L


class TestCrossFrameChunkCount(TestUnitBase):

    def test_01(self):
        pipeline = L('emit ABDF AEC ABE [| rex . [| xfcc ]]')
        results = {bytes(chunk): chunk['count'] for chunk in pipeline}
        self.assertEqual(results, {
            B'A': 3,
            B'B': 2,
            B'C': 1,
            B'D': 1,
            B'E': 2,
            B'F': 1,
        })
