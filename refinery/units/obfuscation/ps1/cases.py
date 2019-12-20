#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

from .. import Deobfuscator, outside
from ....lib.patterns import formats


class deob_ps1_cases(Deobfuscator):
    _NAMES = [
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

    @outside(formats.ps1str)
    def deobfuscate(self, data):
        for name in self._NAMES:
            data = re.sub(RF'\b{re.escape(name)}\b', name, data, flags=re.IGNORECASE)
        return data
