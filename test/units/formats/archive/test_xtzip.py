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

    def test_empty_filename(self):
        data = bytes.fromhex(
            '504b0304140000080e00359eff54a5004e70a90000009400000000000000091405005d0000000100'
            '03008cc274baf7b3de2d96ead6a430098a4c88fdaddf5f4c29a3233472aedccfebda2bafb00162f0'
            '84cf660a7824199d6a3e1f68766e78dc5539561a8a1cfaba3192d7daee41449e4304188998b59f2a'
            'e06dc233c9e7164eef4055a129a79bc044c7eaab667314030b8dcc20535c0c003b681ae3a08c6f10'
            'cdc06d140dbe7a5c56d19085ce86d93feb2031a5a36e92cd085ceca38044f84eb0ec8d04f1800050'
            '4b01021400140000080e00359eff54a5004e70a90000009400000000000000000000000000000000'
            '0000000000504b050600000000010001002e000000c700000000000505050505'
        )
        unit = self.load()
        result, = data | unit
        self.assertEqual(result[:12], b'\x06\x02\0\0\0\xA4\0\0RSA1')
