#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestIPFS(TestUnitBase):

    def test_pup_installer_script(self):
        data = self.download_sample('ccc40b5355ab03d75fb66742558031a452986cfb0110804fd8614f52226ca1bf')
        disassembly = str(data | self.load())
        for line in (
            R"""typedef TWINDOWSVERSION = struct {U32, U32, U32, U32, U32, BOOLEAN, U08, U16}""",
            R"""typedef TFILETIME = struct {U32, U32}""",
            R"""  0x0374  Assign      LocalVar5, 'WinHttp.WinHttpRequest.5.1'""",
            R"""begin sub PAGEDOWNLOADCANCELBUTTONCLICK(Argument0: TWIZARDPAGE, *Argument1: BOOLEAN, *Argument2: BOOLEAN)"""
        ):
            self.assertIn(line, disassembly)


class TestIFPSStrings(TestUnitBase):

    def test_pup_installer_script(self):
        data = self.download_sample('ccc40b5355ab03d75fb66742558031a452986cfb0110804fd8614f52226ca1bf')
        strings = data | self.ldu('ifpsstr') | {str}
        for string in (
            R'https''://''d1pqn6m5ywnw3a.cloudfront''.''net/o',
            R'https''://''d1pqn6m5ywnw3a.cloudfront''.''net/f',
            R'https''://''d1pqn6m5ywnw3a.cloudfront''.''net/zbd',
            R'https''://''control.kochava''.''com/v1/cpi/click?campaign_id=kohotspot-shield-2oo5a3058127822662&network_id=5716&site_id=',
            R'https''://''d1pqn6m5ywnw3a.cloudfront''.''net/f/',
        ):
            self.assertIn(string, strings)
