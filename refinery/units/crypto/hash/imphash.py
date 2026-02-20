from __future__ import annotations

from refinery.units.crypto.hash import HashUnit


class imphash(HashUnit):
    """
    Implements the import hash for PE files.
    """

    def _algorithm(self, data):
        from refinery.lib import lief
        pe = lief.load_pe(data)
        th = lief.PE.get_imphash(pe, lief.PE.IMPHASH_MODE.PEFILE)
        return bytes.fromhex(th)
