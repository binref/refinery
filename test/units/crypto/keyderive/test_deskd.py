#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase


class TestDESDerive(TestUnitBase):

    def test_real_world_01(self):
        self.assertEqual(self.load()(B''), B'\x01' * 8)

    def test_real_world_02(self):
        self.assertEqual(self.load()(B'pw0rdEXAMPLE.Cpianist'), bytes.fromhex('158961F132EC04BC'))

    def test_real_world_03(self):
        self.assertEqual(self.load()(B'ANND3133'), bytes.fromhex('BF79FDA76267E089'))

    def test_real_world_04(self):
        self.assertEqual(self.load()(B'NNNN6666FFFFAAAA'), bytes.fromhex('F71FC802192A0DD5'))
