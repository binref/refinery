#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase


class TestZipFileExtractor(TestUnitBase):

    def test_winzip_self_extracting_archive(self):
        data = self.download_sample('43db90bee13041cf0a53ca97f89054bc26465fe575ed40b1cb6476f3119cd8c1')
        self.assertEqual(
            str(data | self.load('1386431813jtun_streamset.zip') | self.load('stream.dis')),
            'MOVE([TempDir],%StreamDefDir%)')
