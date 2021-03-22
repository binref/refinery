#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from . import arg, numseq, chunks, BlockTransformationBase


class terminate(BlockTransformationBase):
    """
    The unit reads data from the incoming chunk in blocks of any given size until the
    sentinel value is encountered. The output of the unit is all data that was read,
    excluding the sentinel. The default block size is one and the default sentinel value
    is zero, which corresponds to reading a null-terminated string from the input.
    If the sentinel value is not found anywhere in the incoming data, the complete input
    is returned as output.
    """
    def __init__(
        self,
        sentinel: arg(type=numseq, help='sentinel value to look for; default is {default}') = 0,
        blocksize=1,
        bigendian=False
    ):
        if not isinstance(sentinel, int):
            sentinel = next(chunks.unpack(sentinel, blocksize, bigendian))
        super().__init__(blocksize=blocksize, bigendian=bigendian, sentinel=sentinel)

    def process(self, data: bytearray):
        sentinel: int = self.args.sentinel

        self.log_debug(F'using sentinel value: 0x{sentinel:0{self.args.blocksize*2}X}')

        if self.bytestream:
            pos = data.find(sentinel)
            if pos < 0:
                self.log_info(F'the sentinel value {sentinel} was not found')
            else:
                data[pos:] = []
            return data

        def seek(it):
            for chunk in it:
                if chunk == sentinel:
                    break
                yield chunk

        return self.unchunk(seek(self.chunk(data)))
