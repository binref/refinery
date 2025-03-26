#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json

from .. import TestUnitBase


class TestLNK(TestUnitBase):

    def test_real_world_with_datetime_entries(self):
        data = self.download_sample('03160be7cb698e1684f47071cb441ff181ff299cb38429636d11542ba8d306ae')
        result = data | self.load() | json.loads
        self.assertEqual(result['header']['creation_time'], '2021-12-26 21:31:16+00:00')
        self.assertEqual(result['header']['accessed_time'], '2022-06-03 12:49:55+00:00')
        self.assertEqual(result['header']['modified_time'], '2021-12-26 21:31:16+00:00')
        self.assertEqual(result['data']['command_line_arguments'], '019338921.dll,DllInstall')
        result = data | self.load(tabular=True) | [str]
        result = [entry.partition(':') for entry in result]
        result = {k.strip(): v.strip() for k, _, v in result}
        self.assertEqual(result['header.creation_time'], '2021-12-26 21:31:16+00:00')
        self.assertEqual(result['header.accessed_time'], '2022-06-03 12:49:55+00:00')
        self.assertEqual(result['header.modified_time'], '2021-12-26 21:31:16+00:00')
        self.assertEqual(result['data.command_line_arguments'], '019338921.dll,DllInstall')
