#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json

from .... import TestUnitBase


class TestDotNetHeaderParser(TestUnitBase):

    def test_hawkeye_header(self):
        unit = self.load()
        data = self.download_from_malshare('ee790d6f09c2292d457cbe92729937e06b3e21eb6b212bf2e32386ba7c2ff22c')
        header = json.loads(unit(data))
        streams = header['Meta']['Streams']

        self.assertIn(
            'HawkEye Keylogger - Reborn v9 - {0} Logs - {1} \\ {2}',
            streams['US'].values()
        )

        self.assertEqual('Reborn Stub', streams['Tables']['Assembly'][0]['Name'])
        self.assertEqual(0x2050, streams['Tables']['FieldRVA'][0]['RVA'])
