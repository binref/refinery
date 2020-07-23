#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json

from .... import TestUnitBase


class TestDotNetFieldExtractor(TestUnitBase):

    def test_real_world(self):
        data = self.download_from_malshare('82831deadbb41d00df1f45c1b1e7cb89901531ab784a55171f11c891f92fffaf')
        unit = self.load('*70ED*', '*6DDE*')
        key, payload = unit.process(data)
        test = json.loads(payload | self.ldu('xor', key) | self.ldu('pemeta'))
        self.assertIn('DotNet', test)
        self.assertEqual(test['DotNet']['ModuleName'], 'atwork.exe')
