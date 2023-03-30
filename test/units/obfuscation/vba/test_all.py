#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase


class TestVBADeobfuscator(TestUnitBase):

    def test_real_world_01(self):
        data = BR'''Execute chr(311-(&HF1))&chr(1112-(&H3E3))&chr(422-(&H138))&chr(1064-(&H3C5))'''
        result = self.load().process(data)
        self.assertEqual(result, b'Execute "Func"')

    def test_real_world_02(self):
        data = self.download_sample('07e25cb7d427ac047f53b3badceacf6fc5fb395612ded5d3566a09800499cd7d')
        unit = self.load()
        self.assertIn(
            r'POwerShell.exe -noProfilE -ExEcutionPolicy Bypass -Command C:\ProgramData\UPFCRQOFGHVNBVUABXGFIW\UPFCRQOFGHVNBVUABXGFIW.bat',
            data | unit | str
        )
