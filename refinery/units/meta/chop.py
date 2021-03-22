#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import arg, Unit
from ...lib.tools import splitchunks


class chop(Unit):
    """
    Reinterprets the input as a sequence of equally sized chunks and outputs this sequence.
    """

    def __init__(
        self, size: arg.number('size', help='Chop data into chunks of this size.'),
        truncate: arg.switch('-t', help=(
            'Truncate possible excess bytes at the end of the input, by default they are appended as a single chunk.')) = False,
        into: arg.switch('-i', help=(
            'If this flag is specified, the size parameter determines the number of blocks to be produced rather than the size '
            'of each block. In this case, truncation is performed before the data is split.')) = False
    ):
        return super().__init__(size=size, into=into, truncate=truncate)

    def process(self, data):
        size = self.args.size
        if size < 1:
            raise ValueError('The chunk size has to be a positive integer value.')
        if self.args.into:
            size, remainder = divmod(len(data), size)
            if remainder and not self.args.truncate:
                partition = remainder * (size + 1)
                part1, part2 = data[:partition], data[partition:]
                yield from splitchunks(part1, size + 1)
                yield from splitchunks(part2, size)
                return

        yield from splitchunks(data, size, self.args.truncate)
