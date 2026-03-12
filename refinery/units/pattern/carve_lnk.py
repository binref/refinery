from __future__ import annotations

from refinery.lib.lnk import LnkFile
from refinery.units import Unit


class carve_lnk(Unit):
    """
    Extracts anything from the input data that looks like a Windows shortcut (i.e. an LNK file)
    """

    def process(self, data: bytearray):
        pos = 0
        mem = memoryview(data)
        sig = B'\x4C\x00\x00\x00\x01\x14\x02\x00'

        while True:
            pos = data.find(sig, pos)
            if pos < 0:
                break
            try:
                parsed = LnkFile(mem[pos:])
            except Exception:
                pos += 1
                continue
            end = pos + parsed.size
            yield self.labelled(mem[pos:end], offset=pos)
            pos = end
