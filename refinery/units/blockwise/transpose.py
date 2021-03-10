#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from . import arg, BlockTransformationBase


class transpose(BlockTransformationBase):
    """
    Interprets the sequence of blocks as rows of a matrix and returns the
    blocks that correspond to the columns of this matrix.
    """
    def __init__(
        self, padding: arg(help='Optional byte sequence to use as padding for tail end.') = B'',
        bigendian=False, blocksize=1
    ):
        super().__init__(bigendian=bigendian, blocksize=blocksize, padding=padding)

    def process(self, data):
        rest = self.rest(data)
        data = list(self.chunk(data, raw=True))

        if self.args.padding:
            while len(rest) < self.args.blocksize:
                rest += self.args.padding
            rest = rest[:self.args.blocksize]
            data.append(rest)
            rest = B''

        return self.unchunk((
            bytes(data[j][i] for j in range(len(data)))
            for i in range(self.args.blocksize)), raw=True)
