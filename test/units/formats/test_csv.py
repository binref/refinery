#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import inspect
import json

from .. import TestUnitBase


class TestCSVConverter(TestUnitBase):

    def test_basic(self):
        @inspect.getdoc
        class data:
            R"""
            systemname,timeGenerated,scriptblock,foo,owner,"uk_foo",sourceName
            KAREN,"2021-09-30T12:19:39.989Z","$MultiLine = @()
            Get-ChildItem C:\ | select ""Name"" | ForEach-Object {
                Write-Output $_.Name
            }",12,"NT AUTHORITY\SYSTEM | S-1-5-18","1/2/3/4","Microsoft-Windows-PowerShell"
            OLIVER,"2021-09-30T12:29:19.079Z","$MultiLine = @()
            Get-ChildItem C:\ | select ""Name"" | ForEach-Object {
                Write-Output $_.Name
            }",17,"NT AUTHORITY\SYSTEM | S-1-5-18","1/2/3/4","Microsoft-Windows-PowerShell"
            RAE,"2021-09-30T11:07:23.662Z","$MultiLine = @()
            Get-ChildItem C:\ | select ""Name"" | ForEach-Object {
                Write-Output $_.Name
            }",1,"NT AUTHORITY\SYSTEM | S-1-5-18","1/2/3/4","Microsoft-Windows-PowerShell"
            """
        unit = self.load()
        result = [json.loads(t) for t in data | unit]
        self.assertEqual(result[1]['systemname'], 'OLIVER')
        self.assertEqual(result[1]['timeGenerated'], '2021-09-30 12:29:19')
        self.assertEqual(result[2]['owner'], R'NT AUTHORITY\SYSTEM | S-1-5-18')
        self.assertEqual(result[0]['foo'], 12)
