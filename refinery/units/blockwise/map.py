#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import Dict, Optional, Sequence
from refinery.units.blockwise import arg, BlockTransformation


class map(BlockTransformation):
    """
    Each block of the input data which occurs as a block of the index argument
    is replaced by the corresponding block of the image argument.
    """
    _map: Optional[Dict[int, int]]

    def __init__(
        self,
        index: arg(help='index characters'),
        image: arg(help='image characters'),
        blocksize=1
    ):
        super().__init__(blocksize=blocksize, index=index, image=image)
        self._map = None

    def process(self, data):
        index: Sequence[int] = self.args.index
        image: Sequence[int] = self.args.image
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
            self._map = dict(zip(self.chunk(index), self.chunk(image)))
            return super().process(data)
        finally:
            self._map = None

    def process_block(self, token):
        return self._map.get(token, token)
