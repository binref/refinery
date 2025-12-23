from __future__ import annotations

from refinery.lib.seven.lzx import LzxDecoder
from refinery.lib.types import Param
from refinery.units import Arg, RefineryPartialResult, Unit


class lzx(Unit):

    def __init__(
        self,
        window: Param[int, Arg(help='Optionally specify the window size; the default is {default}.')] = 15,
        wim: Param[bool, Arg('-w', help='Use the WIM flavor of LZX.')] = False,
    ):
        super().__init__(window=window, wim=wim)

    def process(self, data):
        lzx = LzxDecoder(self.args.wim)
        lzx.set_params_and_alloc(self.args.window)

        try:
            return lzx.decompress(memoryview(data))
        except Exception as E:
            if out := lzx.get_output_data():
                raise RefineryPartialResult(str(E), out) from E
            raise
