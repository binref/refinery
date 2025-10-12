from __future__ import annotations

from refinery.lib.py import Marshal
from refinery.lib.types import Param
from refinery.units import Arg, Unit


class pymstr(Unit):
    """
    Extract string constants from Python-Marshaled objects.
    """
    def __init__(
        self,
        buffers: Param[bool, Arg.Switch('-b', help='Dump byte strings.')] = False,
        strings: Param[bool, Arg.Switch('-s', help='Dump strings.')] = False,
    ):
        if not buffers and not strings:
            buffers = strings = True
        super().__init__(buffers=buffers, strings=strings)

    def process(self, data):
        marshaled = Marshal(memoryview(data))
        marshaled.object()
        if self.args.buffers:
            for bs in marshaled.buffers:
                yield bs
        if self.args.strings:
            for us in marshaled.strings:
                yield us.encode(self.codec)
