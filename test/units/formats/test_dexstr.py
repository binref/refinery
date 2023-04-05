#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestDexStrings(TestUnitBase):

    def test_real_world_01(self):
        data = self.download_sample('0266de70dec416d1046d1b52e794a9138cf2520a57d5c9badf6411b19a9a03f0')
        unit = self.load()
        strings = data | unit | {str}
        self.assertContains(strings, 'http:''//37.''57.96''.145:8099/')
        self.assertContains(strings, 'http:''//37.''57.96''.145:8099/permanentlyRemove')
        self.assertContains(strings, 'http:''//37.''57.96''.145:8099/registerUser')
        self.assertContains(strings, 'http:''//37.''57.96''.145:8099/sync')
