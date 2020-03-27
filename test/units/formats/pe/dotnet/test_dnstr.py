#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .... import TestUnitBase


class TestDotNetHeaderParser(TestUnitBase):

    def test_require_one_mode(self):
        with self.assertRaises(ValueError):
            self.load(user=False, meta=False)

    def test_hawkeye(self):
        unit_both = self.load()
        unit_meta = self.load(user=False)
        unit_user = self.load(meta=False)
        data = self.download_from_malshare('ee790d6f09c2292d457cbe92729937e06b3e21eb6b212bf2e32386ba7c2ff22c')

        data_both = unit_both(data)
        data_meta = unit_meta(data)
        data_user = unit_user(data)

        sample_meta = B'System.Runtime.Serialization.Formatters.Binary'
        sample_user = B'HawkEye Keylogger - Reborn v9'

        self.assertIn(sample_meta, data_meta)
        self.assertIn(sample_user, data_user)
        self.assertIn(sample_meta, data_both)
        self.assertIn(sample_user, data_both)

        self.assertNotIn(sample_meta, data_user)
        self.assertNotIn(sample_user, data_meta)
