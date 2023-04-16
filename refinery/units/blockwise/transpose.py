#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units.blockwise import Arg, BlockTransformationBase


class transpose(BlockTransformationBase):
    """
    Interprets the sequence of blocks as rows of a matrix and returns the
    blocks that correspond to the columns of this matrix.
    """
    @BlockTransformationBase.Requires("numpy")
    def _numpy():
        import numpy
        return numpy

    def __init__(
        self, padding: Arg(help='Optional byte sequence to use as padding for tail end.') = B'',
        blocksize=1
    ):
        super().__init__(bigendian=False, blocksize=blocksize, padding=padding)

    def process(self, data):
        rest = self.rest(data)
        data = list(self.chunk(data, raw=True))
        padding = self.args.padding
        bs = self.args.blocksize
        rs = len(rest)

        if rest and padding:
            while len(rest) < bs:
                rest += padding
            rest = rest[:bs]

        try:
            np = self._numpy
        except ImportError:
            if rest:
                data.append(rest)
            it = (bytes(row[i] for row in data if len(row) > i) for i in range(bs))
            return self.unchunk(it, raw=True)
        else:
            if rest:
                if not padding:
                    rest += bytes(bs - rs)
                data.append(rest)
            a = np.array(data, dtype=np.uint8).transpose()
            if rest and not padding:
                b = a[:rs]
                a = a[rs:]
                a = np.delete(a, a.shape[1] - 1, 1)
                return b.tobytes('C') + a.tobytes('C')
            else:
                return a.tobytes('C')
