#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys

from . import HexViewerMixin, get_terminal_size, magic
from .. import Unit


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
        peek.add_argument('-x', '--hex', action='store_true',
            help='Always peek data as hexdump.')
        peek.add_argument('-e', '--esc', action='store_true',
            help='Always peek data as string, escape characters if necessary.')
        return super().interface(self.hexviewer_interface(argp))

    def process(self, data):
        for line in self._peeklines(data):
            print(line, file=sys.stderr)
        if not sys.stdout.isatty():
            self.log_info('forwarding input to next unit')
            yield data

    def _peeklines(self, data):
        import codecs
        import string
        import itertools
        from ...lib.tools import format_size, entropy

        peeks = [
            format_size(len(data)),
            F'{entropy(bytearray(data)) * 100:.2f}% entropy'
        ]

        if magic:
            peeks.append(magic.Magic().from_buffer(data))

        header = ', '.join(peeks)
        yield header

        if not data:
            return

        for codec in ('UTF8', 'UTF-16LE', 'UTF-16', 'UTF-16BE'):
            if self.args.hex:
                continue
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

            import textwrap
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
            break
        else:
            dump = self.hexdump(data)

        dump = list(itertools.islice(dump, 0, self.args.lines))

        if dump:
            sepwidth = max(len(header), max(len(l) for l in dump))
            sepwidth = min(sepwidth, get_terminal_size())
            separator = sepwidth * '-'

            if len(separator) > 10:
                yield separator[:-8] + '[PEEK]--'
            else:
                yield separator

            yield from dump
            yield separator
