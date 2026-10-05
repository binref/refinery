from __future__ import annotations

from refinery import perc, xtcab
from refinery.lib.id import is_likely_pe, buffer_contains
from refinery.lib.types import buf
from refinery.units.formats.archive import ArchiveUnit


class xtiex(xtcab, docs='{0}{p}{PathExtractorUnit}'):
    """
    Extract files from IExpress setup self-extracting archive.
    """
    def unpack(self, data: buf):
        try:
            cab = next(data | perc('RCDATA/CABINET/*'))
        except StopIteration as SI:
            raise ValueError('no RCDATA resource named CABINET was found') from SI
        yield from super().unpack(cab)

    def filter(self, chunks):
        yield from super(ArchiveUnit, self).filter(chunks)

    @classmethod
    def handles(cls, data: buf) -> bool:
        if not is_likely_pe(data):
            return False
        return buffer_contains(data, B'CABINET')
