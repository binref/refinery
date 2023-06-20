#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import Iterable, List, Tuple
from refinery.units.blockwise import Arg, BlockTransformationBase


class bitsnip(BlockTransformationBase):
    """
    Pick a certain range of bits from each block of the input. The extracted ranges of bits are
    concatenated. Leftover bits that do not form at least one full byte are discarded. Bits are
    indexed from least significant at index 0 to most significant in each block. When the unit
    operates in big endian mode, the internal bit buffer is shifted left in each step and new bits
    are inserted as the least significant portion. Conversely, in default (little endian) mode,
    newly extracted bits are added as the now most significant ones. After concatenating all bit
    slices into a large integer, this integer is converted into a byte string according to the
    given byte ordering.
    """
    def __init__(
        self,
        slices: Arg(help='Specify start:stop:step in Python slice syntax. Default ist 0:1.') = [slice(0, 1)],
        bigendian=False, blocksize=1
    ):
        super().__init__(slices=slices, bigendian=bigendian, blocksize=blocksize)

    def process(self, data: bytearray):
        bitsnip_data = 0
        bitsnip_size = 0
        slices: List[Tuple[int, int, int]] = []
        maxbits = 8 * self.args.blocksize
        args: Iterable[slice] = iter(self.args.slices)
        indices = list(range(0, maxbits))
        bigendian: bool = self.args.bigendian

        for s in args:
            if s.step is not None:
                slices.extend((i, 1, 1) for i in indices[s])
                continue
            start = s.start
            stop = s.stop
            if start is None:
                start = 0
            if stop is None:
                stop = maxbits
            elif stop > maxbits:
                raise ValueError(F'the selection {start}:{stop} is out of bounds for the block size {self.args.blocksize}')
            if start >= stop:
                continue
            size = stop - start
            mask = (1 << (stop - start)) - 1
            slices.append((start, mask, stop - start))

        for item in self.chunk(data):
            for shift, mask, size in slices:
                bits = (item >> shift) & mask
                if bigendian:
                    bitsnip_data <<= size
                    bitsnip_data |= bits
                else:
                    bitsnip_data |= bits << bitsnip_size
                bitsnip_size += size

        length, remainder = divmod(bitsnip_size, 8)

        if remainder != 0:
            self.log_info(F'discarding {bitsnip_size%8} bits')
            if bigendian:
                bitsnip_data >>= remainder
            else:
                bitsnip_data &= (1 << (8 * length)) - 1

        if bigendian:
            return bitsnip_data.to_bytes(length, 'big')
        else:
            return bitsnip_data.to_bytes(length, 'little')
