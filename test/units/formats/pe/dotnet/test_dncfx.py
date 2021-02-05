#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import io

from .... import TestUnitBase


class TestConfuserXDecryptor(TestUnitBase):

    def test_hawkeye(self):
        unit = self.load()
        data = self.download_sample('094e7d3e6aebf99663993e342401423dff3f444c332eae0b8f0d9eeda1b809a7')
        with io.BytesIO(data) as sample:
            strings = list(sample | unit)

        for sentinel in {
            BR'0cd08c62-955c-4bdb-aa2b-a33280e3ddce',
            BR'{0}{0}============={1} {2}============={0}{0}',
            BR'Microsoft.NET\Framework\v2.0.50727\vbc.exe',
            BR'HawkEye RebornX{0}{1} Logs{0}{2} \ {3}{0}{0}{4}'
        }:
            self.assertIn(sentinel, strings)
