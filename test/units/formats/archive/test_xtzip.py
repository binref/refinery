#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase


class TestZipFileExtractor(TestUnitBase):

    def test_winzip_self_extracting_archive(self):
        data = self.download_sample('43db90bee13041cf0a53ca97f89054bc26465fe575ed40b1cb6476f3119cd8c1')
        self.assertEqual(
            str(data | self.load('1386431813jtun_streamset.zip') | self.load('stream.dis')),
            'MOVE([TempDir],%StreamDefDir%)')

    def test_password_protected_zip(self):
        data = bytes.fromhex(
            '504B03041400010000001505FA5496732F8E130000000700000008000000746573742E7478749C4E'
            '1F7FD879AA31F390F53CCD310BA615503F504B01023F001400010000001505FA5496732F8E130000'
            '0007000000080024000000000000002000000000000000746573742E7478740A0020000000000001'
            '0018000C83349177A0D8010C83349177A0D801EA64048F77A0D801504B050600000000010001005A'
            '000000390000000000'
        )
        put = self.ldu('put', 'p', 'refined')
        xtzip = self.load(pwd='var:p')
        self.assertEqual(str(data | put[xtzip]), 'foobar.')
