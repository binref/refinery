from __future__ import annotations

import re

from refinery.lib.patterns import formats
from refinery.units.obfuscation import Deobfuscator, outside


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
