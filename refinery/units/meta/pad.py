from __future__ import annotations

from refinery.lib.types import Param, buf
from refinery.units import Arg, Unit


class pad(Unit):
    """
    Allows padding of the input data.
    """

    def __init__(
        self,
        width: Param[int, Arg.Number(help='Input is padded to the nearest multiple of this size.')],
        padding: Param[buf, Arg(help=(
            'This custom binary sequence is used (repeatedly, if necessary) to pad the '
            'input. The default is a zero byte.'))] = B'\0',
        left: Param[bool, Arg.Switch('-l', help='Pad on the left instead of the right.')] = False,
        absolute: Param[bool, Arg.Switch('-a', help=(
            'The width argument specifies an absolute size, not a block size.'))] = False
    ):
        super().__init__(width=width, padding=padding, left=left, absolute=absolute)

    def process(self, data):
        width = self.args.width
        if self.args.absolute and len(data) >= width:
            return data
        q, r = divmod(len(data), width)
        size = (q + bool(r)) * width
        missing = (size - len(data))
        if missing <= 0:
            return data
        pad = self.args.padding
        if missing > len(pad):
            pad *= missing // len(pad)
        if self.args.left:
            return pad[:missing] + data
        else:
            data += pad[:missing]
            return data
