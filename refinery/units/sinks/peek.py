#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import textwrap

from math import log

from . import HexViewerMixin, get_terminal_size
from .. import Unit

try:
    import numpy

    def _np_entropy(data: bytearray) -> float:
        value, counts = numpy.unique(data, return_counts=True)
        probs = counts / len(data)
        # 8 bits are the maximum number of bits of information in a byte
        return 0.0 + -sum(p * log(p, 2) for p in probs) / 8.0

except ImportError:
    _np_entropy = None


def entropy(data: bytearray) -> float:
    """
    Computes the entropy of `data` over the alphabet of all bytes.
    """
    if not data:
        return 0.0
    if _np_entropy:
        return _np_entropy(data)
    else:
        from collections import defaultdict
        histogram = defaultdict(int)
        for b in data:
            histogram[b] += 1
        p = 1. / len(data)
        S = [histogram[b] * p for b in histogram]
        return 0.0 + -sum(q * log(q, 2) for q in S) / 8.0


class peek(Unit, HexViewerMixin):
    """
    The unit extracts preview information of the input data and displays it on
    the standard error stream. If the standard output of this unit is connected
    by a pipe, the incoming data is forwarded. However, if the unit outputs to
    a terminal, the data is discarded instead.
    """

    def interface(self, argp):
        from ...lib.argformats import number
        lines = argp.add_mutually_exclusive_group()
        lines.add_argument('-l', '--lines', metavar='N', type=number, default=10,
            help='Specify number N of lines in the preview, default is 10.')
        lines.add_argument('-a', '--lines-all', action='store_const', dest='lines', const=None,
            help='Output all possible preview lines without restriction')
        peek = argp.add_mutually_exclusive_group()
        peek.add_argument('-d', '--decode', action='store_true',
            help='Attempt to decode and display printable data.')
        peek.add_argument('-e', '--esc', action='store_true',
            help='Always peek data as string, escape characters if necessary.')
        peek.add_argument('-b', '--brief', action='store_true',
            help='One line peek, implies --lines=0.')
        return super().interface(self.hexviewer_interface(argp))

    def process(self, data):
        for line in self._peeklines(data):
            print(line, file=sys.stderr)
        if not sys.stdout.isatty():
            self.log_info('forwarding input to next unit')
            yield data

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.separate = True

    def _peeklines(self, data):
        import codecs
        import string
        import itertools
        from ...lib.tools import format_size
        from ...lib.magic import magicparse

        peeks = [
            F'{entropy(bytearray(data)) * 100:05.2f}% entropy',
            format_size(len(data), align=not self.args.lines)
        ]

        magic = magicparse(data)

        if magic is not None:
            peeks.append(magic)

        header = ', '.join(peeks)

        dump = None
        working_codec = None

        if data and not self.args.brief:
            if self.args.decode:
                for codec in ('UTF8', 'UTF-16LE', 'UTF-16', 'UTF-16BE'):
                    try:
                        self.log_info(F'trying to decode as {codec}.')
                        handler = 'backslashreplace' if self.args.esc else 'strict'
                        decoded = codecs.decode(data, codec, errors=handler)
                        count = sum(x in string.printable for x in decoded)
                        ratio = count / len(data)
                    except ValueError as V:
                        self.log_info('decoding failed:', V)
                        continue
                    if ratio < 0.8 or any(x in decoded for x in '\b\v'):
                        self.log_info(F'data contains {ratio * 100:.2f}% printable characters, this is too low.')
                        continue

                    width = self.args.width or get_terminal_size()
                    if self.args.lines is not None:
                        decoded = decoded[:width * self.args.lines]
                    dump = [
                        line.rstrip('\r')
                        for chunk in textwrap.wrap(
                            decoded,
                            width,
                            break_on_hyphens=False,
                            replace_whitespace=False
                        )
                        for line in chunk.split('\n')
                    ]
                    working_codec = codec
                    break

            if not dump:
                total = self.args.lines * get_terminal_size() // 3
                dump = self.hexdump(data, total=total)

            dump = list(itertools.islice(dump, 0, self.args.lines))

        termsize = get_terminal_size()

        def separator(title=None):
            if title is None or termsize <= len(title) + 8:
                return termsize * '-'
            return F'--{title}' + '-' * (termsize - len(title) - 2)

        yield separator()

        if termsize:
            yield from textwrap.wrap(header, termsize)
        else:
            yield header

        if dump:
            yield separator(F'CODEC={working_codec}' if working_codec else 'HEXDUMP')
            yield from dump

        if self.separate:
            yield separator()

    def filter(self, inputs):
        from ...lib.tools import lookahead
        for last, item in lookahead(inputs):
            self.separate = last
            yield item
