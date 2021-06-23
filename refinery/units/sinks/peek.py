#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import textwrap
import codecs
import string
import itertools

from . import arg, HexViewer, get_terminal_size
from ...lib.meta import GetMeta, CustomStringRepresentation, SizeInt
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
        meta   : arg('-m', help='Accumulate metadata that requires scanning the data, such as entropy and file magic.') = False,
        hexaddr=True, dense=False, expand=False, width=0
    ):
        lines = 1 if brief else INF if all else lines
        super(peek, self).__init__(
            brief=brief,
            decode=decode,
            dense=dense,
            esc=esc,
            expand=expand,
            hexaddr=hexaddr and not brief,
            lines=lines,
            meta=meta,
            width=width,
        )
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
        for name in sorted(meta):
            value = meta[name]
            if value is None:
                continue
            if isinstance(value, CustomStringRepresentation):
                value = str(value).strip()
            elif isbuffer(value):
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

    def _trydecode(self, data, codec, width):
        remaining = linecount = self.args.lines
        result = []
        if codec is None:
            from ..encoding.esc import esc
            decoded = data[:abs(width * linecount)]
            decoded = str(decoded | -esc)
            for k in range(0, abs(linecount), width):
                result.append(decoded[k:k + width])
            return result
        try:
            self.log_info(F'trying to decode as {codec}.')
            decoded = codecs.decode(data, codec, errors='strict')
            count = sum(x in string.printable for x in decoded)
            ratio = count / len(data)
        except ValueError as V:
            self.log_info('decoding failed:', V)
            return None
        if ratio < 0.8 or any(x in decoded for x in '\b\v'):
            self.log_info(F'data contains {ratio * 100:.2f}% printable characters, this is too low.')
            return None
        for paragraph in decoded.splitlines(False):
            if not remaining:
                break
            wrapped = [
                line for chunk in textwrap.wrap(
                    paragraph,
                    width,
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
            remaining -= len(wrapped)
            result.extend(wrapped)
        return result[:linecount]

    def _peeklines(self, data):

        dump = None
        termsize = get_terminal_size() or 75
        width = self.args.width or termsize
        working_codec = None

        if not self.args.brief:
            padding = 0
        else:
            padding = SizeInt.width + 2
            if self._idx is not None:
                padding += 6

        inner_width = width - padding

        if self.args.lines and data:
            if self.args.esc:
                dump = self._trydecode(data, None, inner_width)
            if self.args.decode:
                for codec in ('UTF8', 'UTF-16LE', 'UTF-16', 'UTF-16BE'):
                    dump = self._trydecode(data, codec, inner_width)
                    if dump:
                        working_codec = codec
                        break
            if dump is None:
                total = abs(self.args.lines * termsize // 3)
                dump = self.hexdump(data, total=total, padding=padding)
                dump = list(itertools.islice(dump, 0, abs(self.args.lines)))
                width = max(len(line) for line in dump)

        def separator(title=None):
            if title is None or width <= len(title) + 8:
                return width * '-'
            return F'--{title}' + '-' * (width - len(title) - 2)

        if not self.args.brief:
            meta = GetMeta(data)
            if self.args.meta:
                if meta['magic'] == 'data':
                    del meta['magic']
                entropy_percent = meta['entropy'] * 100.0
                meta['entropy'] = F'{entropy_percent:.2f}%'
                meta['size'] = meta['size']
            yield from self._peekmeta(width, separator(), **meta)

        if dump:
            if not self.args.brief:
                yield separator(F'CODEC={working_codec}' if working_codec else None)
                yield from dump
            else:
                brief = next(iter(dump))
                brief = F'{SizeInt(len(data))!r}: {brief}'
                if self._idx is not None:
                    brief = F'#{self._idx:03d}: {brief}'
                yield brief

        if self._sep and not self.args.brief:
            yield separator()

    def filter(self, chunks):
        from ...lib.tools import lookahead
        for last, (index, item) in lookahead(enumerate(chunks)):
            self._sep = last
            if not last or index:
                self._idx = index
            yield item
        self._idx = None
