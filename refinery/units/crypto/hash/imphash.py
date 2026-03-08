from __future__ import annotations

from refinery.units.crypto.hash import HashUnit


class imphash(HashUnit):
    """
    Implements the import hash for PE files.
    """
    @classmethod
    def handles(cls, data) -> bool | None:
        from refinery.lib.id import is_likely_pe
        if is_likely_pe(data):
            return True

    def _algorithm(self, data):
        from refinery.lib import lief
        pe = lief.load_pe(data)
        th = lief.PE.get_imphash(pe, lief.PE.IMPHASH_MODE.PEFILE)
        return bytes.fromhex(th)
