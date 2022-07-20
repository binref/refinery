#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json

from ... import TestUnitBase


class TestNSISExtractor(TestUnitBase):

    def test_modified_archive(self):
        data = self.download_sample('e58d7a6fe9d80d757458a5ebc7c8bddd345b355c2bce06fd86d083b5d0ee8384')
        unit = self.load()
        result = data | unit | self.ldu('xt7z') | self.ldu('pemeta') | json.loads
        self.assertEqual(result['Signature']['Fingerprint'], '6509312e581ef5ba12be11ed427a66f8fd80e819')
