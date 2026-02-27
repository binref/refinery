from __future__ import annotations

from refinery.lib.fast.pkware import PKWareError, pkware_decompress
from refinery.units import RefineryPartialResult, Unit


class pkw(Unit):
    """
    This unit implements PKWare decompression.
    """
    def process(self, data):
        try:
            return pkware_decompress(data)
        except PKWareError as E:
            raise RefineryPartialResult(str(E), E.partial) from E

    @classmethod
    def handles(cls, data) -> bool:
        return (len(data) > 2) and (0 <= data[0] <= 1) and (4 <= data[1] <= 6)
