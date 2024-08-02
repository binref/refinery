#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json
from .. import TestUnitBase


class TestCarveJSON(TestUnitBase):

    def test_wikipedia_unicode_example(self):
        data = (
            BR'''---------FXFFGA-------##:{"data":{"cobaltstrike":{"status":"success","protocol":"cobaltstrike","result":'''
            BR'''{"config32":{"License":"licensed","Beacon_Type":"0 (HTTP)","Checkin_Interval":7000,"Jitter":37,"Max_DNS"'''
            BR''':0,"HTTP_Method2_Path":"/jquery-3.3.2.min.js","Year":0,"Month":0,"Day":0,"DNS_idle":0,"DNS_sleep":0,"Met'''
            BR'''hod1":"GET","Method2":"POST","Spawnto_x86":"%windir%\\syswow64\\edpnotify.exe","Spawnto_x64":"%windir%\\'''
            BR'''sysnative\\edpnotify.exe","PublicKey":"30819f300d06092a864886f70d010101050003818d0030818902818100d0e198b'''
            BR'''6d7b3e2511a877e25395013605643f18835496d711ec25a0c818f4cc33819d7d81fa2a5f5ea96516fd6d06013b6b853ac4c7bee9'''
            BR'''3043547bd20de7bfb04e6598a98e503c64438fc2ddf41b9a2a599fc7b0ca34b9ea40b557d3d5f5df08720b8362056f830b72c44c'''
            BR'''7ad5f8bdfeb907a10a6d6a65fa1c6f6f6f55a4cb7","PayloadOffset":348,"PayloadKey":3882455566,"PayloadSize":208'''
            BR'''388,"XorKey":46},"config64":{"License":"licensed","Beacon_Type":"0 (HTTP)","Checkin_Interval":7000,"Jitt'''
            BR'''er":37,"Max_DNS":0,"HTTP_Method2_Path":"/jquery-3.3.2.min.js","Year":0,"Month":0,"Day":0,"DNS_idle":0,"D'''
            BR'''NS_sleep":0,"Method1":"GET","Method2":"POST","Spawnto_x86":"%windir%\\syswow64\\edpnotify.exe","Spawnto_'''
            BR'''x64":"%windir%\\sysnative\\edpnotify.exe","PublicKey":"30819f300d06092a864886f70d010101050003818d0030818'''
            BR'''902818100d0e198b6d7b3e2511a877e25395013605643f18835496d711ec25a0c818f4cc33819d7d81fa2a5f5ea96516fd6d0601'''
            BR'''3b6b853ac4c7bee93043547bd20de7bfb04e6598a98e503c64438fc2ddf41b9a2a599fc7b0ca34b9ea40b557d3d5f5df08720b83'''
            BR'''62056f830b72c44c7ad5f8bdfeb907a10a6d6a65fa1c6f6f6f55a4cb7","PayloadOffset":333,"PayloadKey":1633212012,"'''
            BR'''PayloadSize":261636,"XorKey":46}},"timestamp":"2020-12-11T14:34:03Z"}}}::#FGAX12'''
        )
        unit = self.load()
        output = unit(data).decode('ascii')
        output = json.loads(output)
        self.assertEqual(output['data']['cobaltstrike']['status'], 'success')

    def test_incorrect_string_parsing(self):
        data = """{
            "bugcheck": "]",
            "escape": "\\"",
            "problem": false
        }""".encode('latin1')
        self.assertEqual(data, data | self.load() | bytes)
