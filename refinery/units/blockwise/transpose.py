#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ...lib.argformats import multibin
from . import BlockTransformation


class transpose(BlockTransformation):
    """
    Interprets the sequence of blocks as rows of a matrix and returns the
    blocks that correspond to the columns of this matrix.
    """
    def interface(self, argp):
        argp.add_argument('padding', type=multibin, default=None, nargs='?',
            help='Optional byte sequence to use as padding for tail end.')
        return super().interface(argp)

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
