from __future__ import annotations

from refinery.lib import lief
from refinery.units.crypto.hash import HashUnit


class imphash(HashUnit):
    """
    Implements the import hash for PE files.
    """

    def _algorithm(self, data):
        pe = lief.load_pe(data)
        th = lief.PE.get_imphash(pe, lief.PE.IMPHASH_MODE.PEFILE)
        return bytes.fromhex(th)
