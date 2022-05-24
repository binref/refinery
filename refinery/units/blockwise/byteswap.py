#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units.blockwise import Arg, BlockTransformationBase
from refinery.lib.structures import MemoryFile


class byteswap(BlockTransformationBase):
    """
    Reverses the order of bytes in each block.
    """
    def __init__(self, size: Arg.Number(help='the block size in bytes; the default is {default}.') = 4):
        super().__init__(blocksize=size)

    def process(self, data):
        if self.bytestream:
            self.log_warn('running this unit with a block size of 1 does not have any effect')
            return data
        with MemoryFile() as stream:
            for block in self.chunk(data, True):
                stream.write(block[::-1])
            rest = self.rest(data)
            if rest:
                padding = -len(rest) % self.args.blocksize
                stream.write(B'\0' * padding + rest[::-1])
            return stream.getvalue()
