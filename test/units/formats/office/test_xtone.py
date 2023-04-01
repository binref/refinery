
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# flake8: noqa
from ... import TestUnitBase


class TestOneNoteExtractor(TestUnitBase):

    def test_maldoc(self):
        data = self.download_sample('15212428deeeabcd5b11a1b8383c654476a3ea1b19b804e4aca606fac285387f')
        out = data | self.load() | {'path': ...}
        self.assertSetEqual(set(out), {
            '268ad1c2-aafb-4d3b-91f8-74977fee1cc7.png',
            'b5e524e3-a396-4746-93a3-c5616f0932cc.hta',
            '851ac4a2-6395-4508-9aee-289a87e1c342.png',
        })
        for key, value in out.items():
            self.assertEqual(len(value), 1)
            value, = value
            out[key] = value
            self.assertContains(data, value)
        doc = out['b5e524e3-a396-4746-93a3-c5616f0932cc.hta']
        self.assertContains(doc, b'https:'b'//transfer'b'.sh/get/5dLEvB/sky.bat')
