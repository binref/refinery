#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from . import arg, BlockTransformation


class map(BlockTransformation):
    """
    Each block of the input data which occurs as a block of the index argument
    is replaced by the corresponding block of the image argument.
    """
    def __init__(
        self,
        index: arg(help='index characters'),
        image: arg(help='image characters'),
        blocksize=1
    ):
        super().__init__(blocksize=blocksize, index=index, image=image)

    def process(self, data):
        self._map = dict(zip(
            self.chunk(self.args.index),
            self.chunk(self.args.image)))
        return super().process(data)

    def process_block(self, token):
        return self._map.get(token, token)
