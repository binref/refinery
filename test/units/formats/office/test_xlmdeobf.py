#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase


class TestXLMMacroDeobfuscator(TestUnitBase):
    def test_maldoc(self):
        data = self.download_sample(
            'dc44bbfc845fc078cf38b9a3543a32ae1742be8c6320b81cf6cd5a8cee3c696a'
        )
        unit = self.load()
        code = str(data | unit)
        self.assertIn(r'C:\ProgramData\Ropedjo1.ocx', code)

    def test_maldo_extrac_only(self):
        data = self.download_sample(
            'dc44bbfc845fc078cf38b9a3543a32ae1742be8c6320b81cf6cd5a8cee3c696a'
        )
        unit = self.load(extract_only=True)
        code = str(data | unit)
        self.assertNotIn(r'C:\ProgramData\Ropedjo1.ocx', code)
        self.assertIn(r'"h"&"t"&"tp"&":"&"/"&"/"&Tiposa!E21&Tiposa1!G11&Sheet2!K12', code)
