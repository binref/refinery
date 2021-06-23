#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import arg, Unit


class pad(Unit):
    """
    Allows padding of the input data. By default, multiple inputs are padded
    to all have length equal to the size of the longest input. Other optional
    size specifications override this behaviour.
    """

    def __init__(
        self, padding: arg('padding', help=(
            'This custom binary sequence is used (repeatedly, if necessary) '
            'to pad the input. The default is a zero byte.')) = B'\0',
        absolute : arg.number('-a', group='HOW', help='Pad inputs to be at least N bytes in size.') = 0,
        blocksize: arg.number('-b', group='HOW', help='Pad inputs to any even multiple of N.') = 0,
        left: arg.switch('-l', help='Pad on the left instead of the right.') = False
    ):
        if absolute and blocksize:
            raise ValueError('Cannot pad simultaneously to a given block size and absolutely.')
        self.superinit(super(), **vars())
        self._maxlen = None

    @property
    def relative(self):
        if self.args.blocksize:
            return False
        if self.args.absolute:
            return False
        return True

    def _pad(self, data, size):
        missing = (size - len(data))
        if missing <= 0:
            return data
        pad = self.args.padding
        if missing > len(pad):
            pad *= (missing // len(pad))
        if self.args.left:
            return pad[:missing] + data
        else:
            data += pad[:missing]
            return data

    def filter(self, chunks):
        if self.relative:
            self.log_info('padding up to longest input')
            if not isinstance(chunks, list):
                chunks = list(chunks)
            self._maxlen = max(len(d) for d in chunks)
        else:
            self._maxlen = None
        yield from chunks

    def process(self, data):
        if self._maxlen is not None:
            return self._pad(data, self._maxlen)
        if self.args.blocksize:
            q, r = divmod(len(data), self.args.blocksize)
            size = (q + bool(r)) * self.args.blocksize
        else:
            size = self.args.absolute
        return self._pad(data, size)
