#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase


class TestELFSlicing(TestUnitBase):

    def test_real_world_01(self):
        data = self.download_from_malshare('c5ba314fbf02989af9e2b5edb48626aede10f2d4569095a542ed0f2033068117')
        unit = self.load('08054203', ascii=True)
        self.assertEqual(unit(data), B' rootkiter : The creator')

    def test_real_world_02(self):
        data = self.download_from_malshare('c5ba314fbf02989af9e2b5edb48626aede10f2d4569095a542ed0f2033068117')
        addr = bytes(reversed(self.load('0804F188', take=4)(data))).hex()
        unit = self.load(addr, ascii=True)
        self.assertEqual(unit(data), B'MY ID IS %d, Upper ID is %d')
