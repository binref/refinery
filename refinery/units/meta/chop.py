#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import Unit
from ...lib.argformats import number


class chop(Unit):
    """
    Reinterprets the input as a sequence of equally sized chunks and outputs
    this sequence.
    """

    def interface(self, argp):
        argp.add_argument('-t', '--truncate', action='store_true',
            help=(
                'Truncate possible excess bytes at the end of the input, '
                'by default they are appended as a single chunk.'
            )
        )
        argp.add_argument('-l', '--len', action='store_true',
            help=(
                'If this flag is specified, the size parameter determines '
                'the number of blocks to be produced rather than the size '
                'of each block.'
            )
        )
        argp.add_argument('size', type=number[1:],
            help='Chop data into chunks of this size.')

        return super().interface(argp)

    def process(self, data):
        size = self.args.size
        if self.args.len:
            size = len(data) // size
        for chunk in zip(*[iter(data)] * size):
            yield bytes(chunk)
        excess = len(data) % size
        if excess and not self.args.truncate:
            yield data[-excess:]
