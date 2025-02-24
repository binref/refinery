#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase


class TestSmartInstallMakerExtractor(TestUnitBase):

    def test_simple_archive(self):
        data = self.download_sample('fe261013faaf34429df7459f6d1ba9e1f2fc9def540976cfa11a6b653f1f20d3')
        test = data | self.load() | {'path': ...}
        test = {str(key): value for key, value in test.items()}
        path = [
            'content/$SystemDrive/Intel/Платежное поручение № 131.pdf',
            'content/$SystemDrive/Intel/curl.exe',
            'content/$SystemDrive/Intel/AnyDesk/bat.lnk',
        ]
        for p in path:
            self.assertIn(p, test)
        self.assertEqual(test[path[0]][:8], b'%PDF-1.7')
        self.assertEqual(test[path[1]][:2], b'MZ')
        self.assertEqual(test[path[2]][:2], b'L\0')
