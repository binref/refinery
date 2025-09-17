from __future__ import annotations

from refinery.lib.types import Param, buf
from refinery.units import Arg, Unit


class cca(Unit):
    """
    Short for ConCatAppend: This unit concatenates the input data with its argument by
    appending the latter to the former. See also `refinery.ccp` for the unit that prepends
    instead.
    """

    def __init__(self, data: Param[buf, Arg(help='Binary string to be appended to the input.')]):
        super().__init__(data=data)

    def process(self, data: bytearray):
        data.extend(self.args.data)
        return data
