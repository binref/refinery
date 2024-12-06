#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase


class TestVMemRef(TestUnitBase):

    def test_real_world_01(self):
        data = self.download_sample('e7a198902409517fc723d40b79c27b1776509d63c461b8f5daf5bb664f9e0589')
        pipe = self.load_pipeline('vmemref --take=50 0x1400541E2 [| terminate | iff size -ge 8 ]')
        test = data | pipe | {str}
        self.assertSetEqual(test, {
            'ToXic Loader',
            'I UwU Yu!',
            'W!@ld2odcOIeYh2nHym$VUjTKd#o5hmD65q6d4f42A82ATCwmJ0',
        })
