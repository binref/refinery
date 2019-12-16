#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestCarve(TestUnitBase):

    def test_extract_base64(self):
        unit = self.load('b64', longest=True, take=1)
        data = B'%s-(VG9vIG11Y2ggdGVjaG5vbG9neSwgaW4gdG9vIGxpdHRsZSB0aW1lLg==),%s' % (
            self.generate_random_buffer(11),
            self.generate_random_buffer(12)
        )
        self.assertEqual(unit(data), b'VG9vIG11Y2ggdGVjaG5vbG9neSwgaW4gdG9vIGxpdHRsZSB0aW1lLg==')
