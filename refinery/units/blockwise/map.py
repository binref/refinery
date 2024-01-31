#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import Dict, Optional, Sequence

from refinery.units.blockwise import Arg, BlockTransformation
from refinery.lib.tools import isbuffer


class map(BlockTransformation):
    """
    Each block of the input data which occurs as a block of the index argument is replaced by the
    corresponding block of the image argument. If a block size is specified, and if the index or
    image argument are byte sequences, they are unpacked into chunks of that size, and excess bytes
    that are not an integer multiple of the block size are discarded. To prevent any automatic
    chunking, the `refinery.lib.argformats.DelayedArgument.btoi` handler can be used.
    """
    _map: Optional[Dict[int, int]]

    def __init__(
        self,
        index: Arg.NumSeq(help='index characters'),
        image: Arg.NumSeq(help='image characters'),
        blocksize=None
    ):
        super().__init__(blocksize=blocksize, index=index, image=image, _truncate=2)
        self._map = None

    def reverse(self, data):
        return self._process(data, self.args.image, self.args.index)

    def process(self, data):
        return self._process(data, self.args.index, self.args.image)

    def _process(self, data: bytearray, index: Sequence[int], image: Sequence[int]):
        if not self.bytestream:
            if isbuffer(index):
                self.log_info(F'chunking index sequence into blocks of size {self.blocksize}')
                index = list(self.chunk(index))
                self.log_debug(F'index sequence: {index}')
            if isbuffer(image):
                self.log_info(F'chunking image sequence into blocks of size {self.blocksize}')
                image = list(self.chunk(image))
                self.log_debug(F'image sequence: {image}')
        if len(set(index)) != len(index):
            raise ValueError('The index sequence contains duplicates.')
        if len(index) > len(image):
            raise ValueError('The index sequence is longer than the image sequence.')
        if self.bytestream:
            mapping = dict(zip(index, image))
            mapping = bytes(mapping.get(c, c) for c in range(0x100))
            if not isinstance(data, bytearray):
                data = bytearray(data)
            data[:] = (mapping[b] for b in data)
            return data
        try:
            self._map = dict(zip(index, image))
            return super().process(data)
        finally:
            self._map = None

    def process_block(self, token):
        return self._map.get(token, token)
