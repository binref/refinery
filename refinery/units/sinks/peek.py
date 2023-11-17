#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import Generator, Optional

import sys
import os
import textwrap
import codecs

from refinery.units.sinks import Arg, HexViewer
from refinery.lib.meta import ByteStringWrapper, metavars, CustomStringRepresentation, SizeInt
from refinery.lib.types import INF
from refinery.lib.tools import get_terminal_size, isbuffer, lookahead
from refinery.lib.environment import environment


class peek(HexViewer):
    """
    The unit extracts preview information of the input data and displays it on
    the standard error stream. If the standard output of this unit is connected
    by a pipe, the incoming data is forwarded. However, if the unit outputs to
    a terminal, the data is discarded instead.
    """

    def __init__(
        self,
        lines  : Arg('-l', group='SIZE', help='Specify number N of lines in the preview, default is 10.') = 10,
        all    : Arg('-a', group='SIZE', help='Output all possible preview lines without restriction') = False,
        brief  : Arg('-b', group='SIZE', help='One line peek, implies --lines=1.') = False,
        decode : Arg('-d', group='MODE', help='Attempt to decode and display printable data.') = False,
        escape : Arg('-e', group='MODE', help='Always peek data as string, escape characters if necessary.') = False,
        bare   : Arg('-r', group='META', help='Only peek the data itself, do not show a metadata preview.') = False,
        meta   : Arg('-m', group='META', action='count', help=(
            'Show more auto-derivable metadata. Specify multiple times to populate more variables.')) = 0,
        gray   : Arg('-g', help='Do not colorize the output.') = False,
        index  : Arg('-i', help='Display the index of each chunk within the current frame.') = False,
        stdout : Arg('-2', help='Print the peek to STDOUT rather than STDERR; the input data is lost.') = False,
        narrow=False, blocks=1, dense=False, expand=False, width=0
    ):
        if decode and escape:
            raise ValueError('The decode and esc options are exclusive.')
        if brief:
            narrow = True
        if environment.colorless.value:
            gray = True
        lines = 1 if brief else INF if all else lines
        super(peek, self).__init__(
            brief=brief,
            gray=gray,
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

    @HexViewer.Requires('colorama', 'display', 'default')
    def _colorama():
        import colorama
        return colorama

    def process(self, data):
        colorize = not self.args.gray and not self.args.stdout
        lines = self._peeklines(data, colorize)

        if self.args.stdout:
            for line in lines:
                yield line.encode(self.codec)
            return

        stderr = sys.stderr

        if colorize:
            colorama = self._colorama
            if os.name == 'nt':
                stderr = colorama.AnsiToWin32(stderr).stream
            _erase = ' ' * get_terminal_size()
            _reset = F'\r{colorama.Style.RESET_ALL}{_erase}\r'
        else:
            _reset = ''

        try:
            for line in lines:
                print(line, file=stderr)
        except BaseException:
            stderr.write(_reset)
            raise
        if not self.isatty:
            self.log_info('forwarding input to next unit')
            yield data

    def _peekmeta(self, linewidth, sep, _x_peek=None, **meta) -> Generator[str, None, None]:
        if not meta and not _x_peek:
            return
        width = max((len(name) for name in meta), default=0)
        separators = iter([sep])
        if _x_peek is not None:
            if len(_x_peek) > linewidth:
                _x_peek = _x_peek[:linewidth - 3] + '...'
            yield from separators
            yield _x_peek
        for name in sorted(meta):
            value = meta[name]
            if value is None:
                continue
            if isinstance(value, CustomStringRepresentation):
                value = repr(value).strip()
            elif isbuffer(value):
                value = repr(ByteStringWrapper(value))
            elif isinstance(value, int):
                if value in range(-999, 1000):
                    value = str(value)
                elif value > 0:
                    value = F'0x{value:X}'
                else:
                    value = F'-0x{-value:X}'
            elif isinstance(value, float):
                value = F'{value:.4f}'
            metavar = F'{name:>{width+2}} = {value!s}'
            if len(metavar) > linewidth:
                metavar = metavar[:linewidth - 3] + '...'
            yield from separators
            yield metavar

    def _trydecode(self, data, codec: Optional[str], width: int, linecount: int) -> str:
        remaining = linecount
        result = []
        if codec is None:
            from refinery.units.encoding.esc import esc
            decoded = data[:abs(width * linecount)]
            decoded = str(decoded | -esc(bare=True))
            limit = abs(min(linecount * width, len(decoded)))
            for k in range(0, limit, width):
                result.append(decoded[k:k + width])
            return result
        try:
            import unicodedata
            unprintable = {'Cc', 'Cf', 'Co', 'Cs'}
            self.log_info(F'trying to decode as {codec}.')
            decoded = codecs.decode(data, codec, errors='strict')
            count = sum(unicodedata.category(c) not in unprintable for c in decoded)
            ratio = count / len(decoded)
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

    def _peeklines(self, data: bytearray, colorize: bool) -> Generator[str, None, None]:

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
                for codec in ('utf8', 'utf-16le', 'utf-16', 'utf-16be'):
                    lines = self._trydecode(data, codec, txtsize, metrics.line_count)
                    if lines:
                        codec = codec
                        break
                else:
                    codec = None
            if lines is None:
                lines = list(self.hexdump(data, metrics, colorize))
            else:
                sepsize = txtsize

        def separator(title=None):
            if title is None or sepsize <= len(title) + 8:
                return sepsize * '-'
            return '-' * (sepsize - len(title) - 5) + F'[{title}]---'

        if self.args.brief:
            final = False
        elif not self.args.bare:
            peek = repr(meta.size)
            line = separator()
            if len(data) <= 5_000_000:
                peek = F'{peek}; {meta.entropy!r} entropy'
            peek = F'{peek}; {meta.magic!s}'
            if self.args.lines == 0:
                peek = None
            elif not data:
                peek = None
                line = separator('empty chunk')
            if self.args.meta > 0:
                meta.derive('size')
                meta.derive('magic')
                meta.derive('entropy')
                peek = None
            if self.args.meta > 1:
                meta.derive('crc32')
                meta.derive('sha256')
            if self.args.meta > 2:
                for name in meta.derivations:
                    meta[name]
            for line in self._peekmeta(metrics.hexdump_width, line, _x_peek=peek, **meta):
                empty = False
                yield line

        if lines:
            empty = False
            if not self.args.brief:
                yield separator(codec or None)
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
        try:
            self._colorama.init(wrap=False)
        except ImportError:
            pass
        discarded = 0
        for final, item in lookahead(chunks):
            item.temp = final
            if not item.visible and self.isatty:
                discarded += 1
            else:
                yield item
        if discarded:
            self.log_warn(F'discarded {discarded} invisible chunks to prevent them from leaking into the terminal.')
