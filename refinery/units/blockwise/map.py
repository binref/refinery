#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from . import BlockTransformation
from ...lib.argformats import multibin


class map(BlockTransformation):
    """
    Each block of the input data which occurs as a block of the index argument
    is replaced by the corresponding block of the image argument.
    """
    def interface(self, argp):
        argp.add_argument('index', type=multibin, help='index characters')
        argp.add_argument('image', type=multibin, help='image characters')
        return super().interface(argp)

    def process(self, data):
        self._map = dict(zip(
            self.chunk(self.args.index),
            self.chunk(self.args.image)))
        return super().process(data)

    def process_block(self, token):
        return self._map.get(token, token)
