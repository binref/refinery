#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import textwrap
import codecs
import string

from . import arg, HexViewer
from ...lib.meta import metavars, CustomStringRepresentation, SizeInt
from ...lib.types import INF
from ...lib.tools import isbuffer, lookahead
from ...lib.patterns import formats


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
        meta   : arg('-m', group='META', help='Accumulate metadata that requires a full scan.') = False,
        bare   : arg('-r', group='META', help='Do not list any metadata, only peek the data itself.') = False,
        hexaddr=True, dense=False, expand=False, width=0
    ):
        if bare and meta:
            raise ValueError('The bare and meta options are exclusive.')
        if decode and esc:
            raise ValueError('The decode and esc options are exclusive.')
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
            bare=bare,
            width=width,
        )

    def process(self, data):
        for line in self._peeklines(data):
            print(line, file=sys.stderr)
        if not self.isatty:
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
                value = repr(value).strip()
            elif isbuffer(value):
                try:
                    decoded: str = value.decode(self.codec)
                except UnicodeDecodeError:
                    decoded = None
                if not formats.printable.match(decoded):
                    decoded = None
                value = decoded or F'h:{value.hex()}'
            elif isinstance(value, int):
                value = F'0x{value:X}'
            elif isinstance(value, float):
                value = F'{value:.4f}'
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
            printable = string.printable + string.whitespace
            self.log_info(F'trying to decode as {codec}.')
            decoded = codecs.decode(data, codec, errors='strict')
            count = sum(x in printable for x in decoded)
            ratio = count / len(data)
        except UnicodeDecodeError as DE:
            self.log_info('decoding failed:', DE.reason)
            return None
        except ValueError as V:
            self.log_info('decoding failed:', V)
            return None
        if ratio < 0.8:
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
        return result[:abs(linecount)]

    def _peeklines(self, data):

        codec = None
        lines = None
        index = None
        final = True
        empty = True

        if data.temp:
            final, index = data.temp
        if final and not index:
            index = None

        if not self.args.brief:
            padding = 0
        else:
            padding = SizeInt.width + 2
            if index is not None:
                padding += 6

        metrics = self._get_metrics(len(data), self.args.lines, padding)
        sepsize = metrics.hexdump_width
        txtsize = metrics.argument or sepsize

        if self.args.lines and data:
            if self.args.esc:
                lines = self._trydecode(data, None, txtsize)
            if self.args.decode:
                for codec in ('UTF8', 'UTF-16LE', 'UTF-16', 'UTF-16BE'):
                    lines = self._trydecode(data, codec, txtsize)
                    if lines:
                        codec = codec
                        break
                else:
                    codec = None
            if lines is None:
                lines = list(self.hexdump(data, metrics))
            else:
                sepsize = txtsize

        def separator(title=None):
            if title is None or sepsize <= len(title) + 8:
                return sepsize * '-'
            return F'--{title}' + '-' * (sepsize - len(title) - 2)

        if self.args.brief:
            final = False
        elif not self.args.bare:
            meta = metavars(data)
            if self.args.meta:
                meta['size'] = meta['size']
                if meta['magic'] == 'data':
                    del meta['magic']
                entropy_percent = meta['entropy'] * 100.0
                meta['entropy'] = F'{entropy_percent:.2f}%'
                meta['ic']
            if index is not None:
                meta['index'] = index
            for line in self._peekmeta(metrics.hexdump_width, separator(), **meta):
                empty = False
                yield line

        if lines:
            empty = False
            if not self.args.brief:
                yield separator(F'CODEC={codec}' if codec else None)
                yield from lines
            else:
                brief = next(iter(lines))
                brief = F'{SizeInt(len(data))!r}: {brief}'
                if index is not None:
                    brief = F'#{index:03d}: {brief}'
                yield brief

        if final and not empty:
            yield separator()

    def filter(self, chunks):
        for final, (index, item) in lookahead(enumerate(chunks)):
            item.temp = final, index
            yield item
