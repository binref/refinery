#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestBitReversal(TestUnitBase):

    def test_idempotence(self):
        for b in (1, 2, 3, 4, 5, 7, 8, 12, 17):
            unit = self.load(blocksize=b)
            data = self.generate_random_buffer(841)
            self.assertEqual(data, unit(unit(data)))
