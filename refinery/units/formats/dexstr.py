from __future__ import annotations

from refinery.lib.dex import DexFile
from refinery.units import Unit


class dexstr(Unit):
    """
    Extract strings from DEX (Dalvik Executable) files.
    """
    def process(self, data):
        dex = DexFile.Parse(data)
        for string in dex.read_strings():
            yield string.encode(self.codec)
