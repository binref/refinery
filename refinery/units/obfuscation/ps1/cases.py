#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

from .. import Deobfuscator


class deob_ps1_cases(Deobfuscator):
    NAMES = [
        '-BXor',
        '-Exec Bypass',
        '-NoLogo',
        '-NonInter',
        '-Replace',
        '-Windows Hidden',
        '.Invoke',
        'Assembly',
        'Byte',
        'Char',
        'ChildItem',
        'CreateThread',
        'Get-Variable',
        'GetType',
        'IntPtr',
        'Invoke-Expression',
        'Invoke',
        'Length',
        'Net.WebClient',
        'PowerShell',
        'PSVersionTable',
        'Set-Item',
        'Set-Variable',
        'Start-Sleep',
        'ToString',
        'Type',
        'Value',
        'Void',
    ]

    def deobfuscate(self, data):
        for name in self.NAMES:
            data = re.sub(re.escape(name), name, data, flags=re.IGNORECASE)
        return data
