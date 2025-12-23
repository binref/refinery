from __future__ import annotations

from refinery.lib.types import Param, buf
from refinery.units import Arg, Unit


class edit(Unit):
    """
    Overwrites the input chunk at a given slice with a given piece of data.
    """
    def __init__(
        self,
        offset: Param[int, Arg.Bounds(intok=True, help=(
            'Specify the slice to edit. An integer value is allowed; in this case the input data '
            'ad the given offset is overwritten with the provided string.'))],
        string: Param[buf, Arg.Binary(help='The binary string to be written at the given offset.')],
    ):
        super().__init__(offset=offset, string=string)

    def process(self, data: bytearray):
        offset = self.args.offset
        string = self.args.string
        if isinstance(offset, int):
            offset = slice(offset, offset + len(string))
        data[offset] = string
        return data
