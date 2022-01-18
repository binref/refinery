#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import Generator, Optional

import sys
import textwrap
import codecs
import string

from refinery.units.sinks import arg, HexViewer
from refinery.lib.meta import metavars, CustomStringRepresentation, SizeInt
from refinery.lib.types import INF
from refinery.lib.tools import isbuffer, lookahead
from refinery.lib.patterns import formats


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
        escape : arg('-e', group='MODE', help='Always peek data as string, escape characters if necessary.') = False,
        index  : arg('-i', help='Display the index of each chunk within the current frame.') = False,
        meta   : arg('-m', group='META', help='Accumulate metadata that requires a full scan.') = False,
        bare   : arg('-r', group='META', help='Do not list any metadata, only peek the data itself.') = False,
        stdout : arg('-2', help='Print the peek to STDOUT rather than STDERR; the input data is lost.') = False,
        narrow=False, blocks=1, dense=False, expand=False, width=0
    ):
        if bare and meta:
            raise ValueError('The bare and meta options are exclusive.')
        if decode and escape:
            raise ValueError('The decode and esc options are exclusive.')
        if brief:
            narrow = True
        lines = 1 if brief else INF if all else lines
        super(peek, self).__init__(
            brief=brief,
            blocks=blocks,
            decode=decode,
            dense=dense,
            index=index,
            escape=escape,
            expand=expand,
            narrow=narrow,
            lines=lines,
            meta=meta,
            bare=bare,
            width=width,
            stdout=stdout,
        )

    def process(self, data):
        lines = self._peeklines(data)
        if self.args.stdout:
            for line in lines:
                yield line.encode(self.codec)
        else:
            for line in lines:
                print(line, file=sys.stderr)
            if not self.isatty:
                self.log_info('forwarding input to next unit')
                yield data

    def _peekmeta(self, linewidth, sep, **meta) -> Generator[str, None, None]:
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
                value: bytes
                for prefix, codec in (
                    ('s', 'utf8'),
                    ('a', 'latin1'),
                    ('u', 'utf-16le'),
                ):
                    try:
                        decoded: str = value.decode(codec)
                    except UnicodeDecodeError:
                        decoded = None
                    if decoded is not None:
                        if not formats.printable.fullmatch(decoded):
                            decoded = None
                    if decoded is not None:
                        if prefix == 's' and ':' not in decoded:
                            value = decoded
                        else:
                            value = F'{prefix}:{decoded}'
                        break
                else:
                    value = F'h:{value.hex()}'
            elif isinstance(value, int):
                value = F'0x{value:X}'
            elif isinstance(value, float):
                value = F'{value:.4f}'
            metavar = F'{name:>{width}} = {value!s}'
            if len(metavar) > linewidth:
                metavar = metavar[:linewidth - 3] + '...'
            yield metavar

    def _trydecode(self, data, codec: Optional[str], width: int, linecount: int) -> str:
        remaining = linecount
        result = []
        if codec is None:
            from refinery.units.encoding.esc import esc
            decoded = data[:abs(width * linecount)]
            decoded = str(decoded | -esc(bare=True))
            limit = min(abs(linecount) * width, len(decoded))
            for k in range(0, limit, width):
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

    def _peeklines(self, data) -> Generator[str, None, None]:

        meta = metavars(data)

        codec = None
        lines = None
        final = data.temp or False
        empty = True

        if not self.args.index:
            meta.discard('index')
            index = None
        else:
            index = meta.get('index', None)

        if not self.args.brief:
            padding = 0
        else:
            padding = SizeInt.width + 2
            if index is not None:
                padding += 6

        metrics = self._get_metrics(len(data), self.args.lines, padding)

        if self.args.brief:
            metrics.address_width = 0
            metrics.fit_to_width(allow_increase=True)

        sepsize = metrics.hexdump_width
        txtsize = self.args.width or sepsize

        if self.args.lines and data:
            if self.args.escape:
                lines = self._trydecode(data, None, txtsize, metrics.line_count)
            if self.args.decode:
                for codec in ('UTF8', 'UTF-16LE', 'UTF-16', 'UTF-16BE'):
                    lines = self._trydecode(data, codec, txtsize, metrics.line_count)
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
            magic = meta._derive_magic()
            size = meta._derive_size()
            if self.args.meta:
                entropy_percent = meta['entropy'] * 100.0
                meta['magic'] = magic
                meta['size'] = size
                meta['entropy'] = F'{entropy_percent:.2f}%'
            else:
                peek = repr(size).strip()
                if len(data) <= 5_000_000:
                    peek = F'{peek}; {meta._derive_entropy()!r} entropy'
                meta['peek'] = F'{peek}; {magic!s}'
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
        discarded = 0
        for final, item in lookahead(chunks):
            item.temp = final
            if not item.visible and self.isatty:
                discarded += 1
            else:
                yield item
        if discarded:
            self.log_warn(F'discarded {discarded} invisible chunks to prevent them from leaking into the terminal.')
