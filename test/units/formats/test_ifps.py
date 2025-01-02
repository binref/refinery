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
            R"""  0x0373  Assign      LocalVar5, 'WinHttp.WinHttpRequest.5.1'""",
            R"""begin sub PAGEDOWNLOADCANCELBUTTONCLICK(Argument0: TWIZARDPAGE, *Argument1: BOOLEAN, *Argument2: BOOLEAN)"""
        ):
            self.assertIn(line, disassembly)

    def test_regression_01(self):
        data = self.download_sample('2d3f393969037a0d0f19e1e01637bed00e0d766fafbb8916a2f6d0b1f8d4cdcd')
        test = data | self.load() | str
        self.assertIn('external symbol GETARRAYLENGTH', test)

    def test_regression_02(self):
        data = self.download_sample('24e78242889d836eb31e2e7d39c7c87f97dcd35f15282813aad5f02978b5bf3b')
        test = data | self.load() | str
        self.assertEqual(test.count('https://aka.ms/vs/16/release/vc_redist.x64.exe'), 1)
        self.assertEqual(test.count('https://aka.ms/vs/16/release/vc_redist.x86.exe'), 1)


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

    def test_function_signature_parsing_version_22(self):
        data = self.download_sample('fb0fc2e3c2059e6159540920a4ff7f75f92212639b318da7eb7fadece4a46ecc')
        goal = {'path', 'b512c1_Flash7231FixClass_b512c1', 'mp3-cd-ripper-beta-', 'A1ADB8BE8E677894E', 'M'}
        test = data | self.ldu('ifpsstr') | {str}
        self.assertSetEqual(test, goal)

    def test_issue_70(self):
        data = self.download_sample('dd4b75e1045c32756de639404b1d9644394891dfb53adc8b701c7a5c2a4b650c')
        test = data | self.load() | self.ldu('resplit') | [str]
        self.assertIn('WIZARDFORM: Class;', test)
