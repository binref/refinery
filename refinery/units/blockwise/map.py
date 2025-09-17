from __future__ import annotations

from itertools import cycle
from typing import Sequence

from refinery.lib.tools import isbuffer
from refinery.lib.types import Param, isq
from refinery.units.blockwise import Arg, BlockTransformation


class map(BlockTransformation):
    """
    Each block of the input data which occurs as a block of the index argument is replaced by the
    corresponding block of the image argument. If a block size is specified, and if the index or
    image argument are byte sequences, they are unpacked into chunks of that size, and excess bytes
    that are not an integer multiple of the block size are discarded. To prevent any automatic
    chunking, the `refinery.lib.argformats.DelayedArgument.btoi` handler can be used.
    An optional default value can be provided to serve as inserts for any blocks in the input that
    do not occur in the index sequence. If this argument is not specified, such blocks are left
    unchanged.
    """
    _map: dict[int, int]

    def __init__(
        self,
        index   : Param[isq, Arg.NumSeq(help='index characters')],
        image   : Param[isq, Arg.NumSeq(help='image characters')],
        default : Param[isq, Arg.NumSeq(help='default value')] = (),
        blocksize=1
    ):
        super().__init__(blocksize=blocksize, index=index, image=image, default=default, _truncate=2)
        self._map = {}

    def reverse(self, data):
        return self._process(data, self.args.image, self.args.index, self.args.default)

    def process(self, data):
        return self._process(data, self.args.index, self.args.image, self.args.default)

    def _process(self, data: bytearray, index: Sequence[int], image: Sequence[int], default: Sequence[int]):
        if not self.bytestream:
            if isbuffer(index):
                self.log_info(F'chunking index sequence into blocks of size {self.blocksize}')
                index = list(self.chunk(index))
                self.log_debug(F'index sequence: {index}')
            if isbuffer(image):
                self.log_info(F'chunking image sequence into blocks of size {self.blocksize}')
                image = list(self.chunk(image))
                self.log_debug(F'image sequence: {image}')
            if isbuffer(default):
                self.log_info(F'chunking default sequence into blocks of size {self.blocksize}')
                default = list(self.chunk(default))
                self.log_debug(F'default sequence: {default}')
        if len(set(index)) != len(index):
            raise ValueError('The index sequence contains duplicates.')
        if len(index) > len(image):
            raise ValueError('The index sequence is longer than the image sequence.')

        if self.bytestream:
            mapping = dict(zip(index, image))
            if default:
                d = iter(cycle(default))
                mapping = bytes(mapping.get(c, d) for c in range(0x100))
            else:
                mapping = bytes(mapping.get(c, c) for c in range(0x100))
            if not isinstance(data, bytearray):
                data = bytearray(data)
            data[:] = (mapping[b] for b in data)
            return data
        try:
            self.log_info(default)
            self._def = cycle(default) if default else None
            self._map = dict(zip(index, image))
            return super().process(data)
        finally:
            self._map = {}

    def process_block(self, block):
        default = next(it) if (it := self._def) else block
        return self._map.get(block, default)
