
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestRTFExtractor(TestUnitBase):

    def test_maldoc(self):
        data = self.download_sample('40f97cf37c136209a65d5582963a72352509eb802da7f1f5b4478a0d9e0817e8')
        unit = self.load()
        bins = list(unit.process(data))
        self.assertLessEqual(
            {'aaaaaaaaaa.txt', 'SutLzbCFI.txt', 'fbZjJrTooKyVebB.sct'},
            {bin.meta['path'] for bin in bins}
        )
        for bin in bins:
            if bin.meta['path'] == 'fbZjJrTooKyVebB.sct':
                self.assertIn(B'{76456238-5834-4f65-4437-4c3555674232}', bin)
                break
