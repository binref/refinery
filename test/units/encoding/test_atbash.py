#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestAtBash(TestUnitBase):
    def test_fo8(self):
        unit = self.load()
        self.assertEqual(
            'If you can solve this, try FLARE-ON 8',
            str(B'Ru blf xzm hloev gsrh, gib UOZIV-LM 8' | unit)
        )
