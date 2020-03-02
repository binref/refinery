#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import Unit
from ...lib.argformats import multibin, number


class pad(Unit):
    """
    Allows padding of the input data. By default, multiple inputs are padded
    to all have length equal to the size of the longest input. Other optional
    size specifications override this behaviour.
    """

    @classmethod
    def interface(cls, argp):
        size = argp.add_mutually_exclusive_group()
        size.add_argument(
            '-b', '--blocksize',
            type=number,
            default=0,
            metavar='N',
            help='Pad inputs to any even multiple of N.'
        )
        size.add_argument(
            '-a', '--absolute',
            type=number,
            default=0,
            metavar='N',
            help='Pad inputs to be at least N bytes in size.'
        )
        argp.add_argument(
            '-l', '--left',
            action='store_true',
            help='Pad on the left instead of the right.'
        )
        argp.add_argument(
            'padding',
            type=multibin,
            default=B'\0',
            nargs='?',
            help='This custom binary sequence is used (repeatedly, if necessary) '
                 'to pad the input. The default is a zero byte.'
        )
        return super().interface(argp)

    @property
    def relative(self):
        if self.args.blocksize:
            return False
        if self.args.absolute:
            return False
        return True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._maxlen = None

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

    def filter(self, inputs):
        if self.relative:
            self.log_info('padding up to longest input')
            if not isinstance(inputs, list):
                inputs = list(inputs)
            self._maxlen = max(len(d) for d in inputs)
        else:
            self._maxlen = None
        yield from inputs

    def process(self, data):
        if self._maxlen is not None:
            return self._pad(data, self._maxlen)
        if self.args.blocksize:
            q, r = divmod(len(data), self.args.blocksize)
            size = (q + bool(r)) * self.args.blocksize
        else:
            size = self.args.absolute
        return self._pad(data, size)
