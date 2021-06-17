#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import textwrap

from . import arg, HexViewer, get_terminal_size
from ...lib.meta import GetMeta
from ...lib.types import INF
from ...lib.tools import isbuffer


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

    def _peekmeta(self, linewidth, sep, **meta):
        if not meta:
            return
        width = max(len(name) for name in meta)
        yield sep
        for name, value in meta.items():
            if value is None:
                continue
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
            elif isinstance(value, float):
                value = F'{value*100:.2f}%' if 0 <= value <= 1 else F'{value:.4f}'
            metavar = F'{name:>{width}} = {value!s}'
            if len(metavar) > linewidth:
                metavar = metavar[:linewidth - 3] + '...'
            yield metavar

    def _peeklines(self, data):
        import codecs
        import string
        import itertools
        from ...lib.tools import format_size

        dump = None
        termsize = get_terminal_size()
        working_codec = None

        if self.args.brief:
            wmod = -format_size.width - 2
            if self._idx is not None:
                wmod -= 6
        else:
            wmod = 0

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
                    dump = []
                    remaining = self.args.lines
                    for paragraph in decoded.splitlines(False):
                        if not remaining:
                            break
                        lines = [
                            line for chunk in textwrap.wrap(
                                paragraph,
                                width + wmod,
                                break_long_words=True,
                                break_on_hyphens=False,
                                drop_whitespace=False,
                                expand_tabs=True,
                                max_lines=abs(remaining + 1),
                                replace_whitespace=False,
                                tabsize=4,
                            )
                            for line in chunk.splitlines(keepends=False)
                        ]
                        remaining -= len(lines)
                        dump.extend(lines)

                    working_codec = codec
                    break

            if not dump:
                total = abs(self.args.lines * termsize // 3)
                dump = self.hexdump(data, total=total, width=wmod)

            dump = list(itertools.islice(dump, 0, abs(self.args.lines)))

        width = max(len(d) for d in dump) if self.args.width else termsize

        def separator(title=None):
            if title is None or width <= len(title) + 8:
                return width * '-'
            return F'--{title}' + '-' * (width - len(title) - 2)

        if not self.args.brief:
            meta = GetMeta(data)
            if meta['magic'] == 'data':
                del meta['magic']
            entropy_percent = meta['entropy'] * 100.0
            meta['entropy'] = F'{entropy_percent:.2f}%'
            meta['size'] = format_size(meta['size'])
            yield from self._peekmeta(width, separator(), **meta)

        if dump:
            if not self.args.brief:
                yield separator(F'CODEC={working_codec}' if working_codec else None)
                yield from dump
            else:
                brief = next(iter(dump))
                brief = F'{format_size(len(data), True)}: {brief}'
                if self._idx is not None:
                    brief = F'#{self._idx:03d}: {brief}'
                yield brief

        if self._sep and not self.args.brief:
            yield separator()

    def filter(self, inputs):
        from ...lib.tools import lookahead
        for last, (index, item) in lookahead(enumerate(inputs)):
            self._sep = last
            if not last or index:
                self._idx = index
            yield item
        self._idx = None
