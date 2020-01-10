#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase


class TestPESlicing(TestUnitBase):

    def test_real_world_01(self):
        data = self.download_from_malshare('c41d0c40d1a19820768ea76111c9d5210c2cb500e93a85bf706dfea9244ce916')
        unit = self.load('0140002030', ascii=True)
        self.assertEqual(unit(data), B'You will never see me.')

    def test_real_world_02(self):
        data = self.download_from_malshare('c41d0c40d1a19820768ea76111c9d5210c2cb500e93a85bf706dfea9244ce916')
        unit = self.load('0140002030', take=22)
        self.assertEqual(unit(data), B'You will never see me.')
