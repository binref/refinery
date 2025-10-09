from __future__ import annotations

import bz2 as bz2_

from refinery.lib.types import Param
from refinery.units import Arg, Unit


class bz2(Unit):
    """
    BZip2 compression and decompression.
    """
    def __init__(self, level: Param[int, Arg.Number('-l', bound=(1, 9), help='compression level preset between 1 and 9')] = 9):
        super().__init__(level=level)

    def process(self, data):
        return bz2_.decompress(data)

    def reverse(self, data):
        return bz2_.compress(data, self.args.level)

    @classmethod
    def handles(cls, data):
        return data[:3] == B'BZh'
