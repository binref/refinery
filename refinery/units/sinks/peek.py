#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import textwrap

from . import arg, HexViewer, get_terminal_size
from ...lib.types import INF
from ...lib.tools import entropy, isbuffer


class peek(HexViewer):
    """
    The unit extracts preview information of the input data and displays it on
    the standard error stream. If the standard output of this unit is connected
    by a pipe, the incoming data is forwarded. However, if the unit outputs to
    a terminal, the data is discarded instead.
    """

    def __init__(
        self,
        lines  : arg('-l', group='SIZE', help='Specify number N of lines in the preview, default is 10.') = 10,
        all    : arg('-a', group='SIZE', help='Output all possible preview lines without restriction') = False,
        brief  : arg('-b', group='SIZE', help='One line peek, implies --lines=1.') = False,
        decode : arg('-d', group='MODE', help='Attempt to decode and display printable data.') = False,
        esc    : arg('-e', group='MODE', help='Always peek data as string, escape characters if necessary.') = False,
        hexaddr=True, dense=False, expand=False, width=0
    ):
        lines = 1 if brief else INF if all else lines
        dense = dense or brief
        super(peek, self).__init__(
            hexaddr=hexaddr and not brief, expand=expand, width=width, dense=dense, lines=lines, decode=decode, esc=esc, brief=brief)
        self._sep = True
        self._idx = None

    def process(self, data):
        for line in self._peeklines(data):
            print(line, file=sys.stderr)
        if not sys.stdout.isatty():
            self.log_info('forwarding input to next unit')
            yield data

    def _peekmeta(self, data, linewidth, sep):
        try:
            meta = data.meta
        except AttributeError:
            return
        if not meta:
            return
        width = max(len(name) for name in data.meta)
        if not self.args.brief:
            yield sep
        for name, value in data.meta.items():
            if isbuffer(value):
                try:
                    decoded: str = value.decode(self.codec)
                    assert decoded.isprintable()
                except UnicodeDecodeError:
                    decoded = None
                except AssertionError:
                    decoded = None
                value = decoded or F'h:{value.hex()}'
            elif isinstance(value, int):
                value = F'0x{value:X}'
            metavar = F'{name:>{width}} = {value!s}'
            if len(metavar) > linewidth:
                metavar = metavar[:linewidth - 3] + '...'
            yield metavar

    def _peeklines(self, data):
        import codecs
        import string
        import itertools
        from ...lib.tools import format_size
        from ...lib.magic import magicparse

        peeks = [
            F'{entropy(memoryview(data)) * 100:05.2f}% entropy',
            format_size(len(data), align=not self.args.lines)
        ]

        magic = magicparse(data)

        if magic is not None:
            peeks.append(magic)
        if self._idx is not None:
            peeks.insert(0, F'item {self._idx:02d}')

        header = ', '.join(peeks)

        dump = None
        termsize = get_terminal_size()
        working_codec = None

        if data:
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

                    width = self.args.width or termsize
                    decoded = decoded[:abs(width * self.args.lines)]
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
                total = abs(self.args.lines * termsize // 3)
                dump = self.hexdump(data, total=total)

            dump = list(itertools.islice(dump, 0, abs(self.args.lines)))

        width = max(len(d) for d in dump) if self.args.width else termsize

        def separator(title=None):
            if title is None or width <= len(title) + 8:
                return width * '-'
            return F'--{title}' + '-' * (width - len(title) - 2)

        yield separator()

        if width:
            yield from textwrap.wrap(header, width)
        else:
            yield header

        yield from self._peekmeta(data, width, separator())

        if dump:
            if not self.args.brief:
                yield separator(F'CODEC={working_codec}' if working_codec else None)
                yield from dump
            else:
                yield next(iter(dump)).strip()

        if self._sep:
            yield separator()

    def filter(self, inputs):
        from ...lib.tools import lookahead
        for last, (index, item) in lookahead(enumerate(inputs)):
            self._sep = last
            if not last or index:
                self._idx = index
            yield item
        self._idx = None
