#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
import dataclasses

from typing import ByteString, Iterable, Optional

from refinery.units import arg, Unit
from refinery.lib.tools import get_terminal_size, lookahead
from refinery.lib import chunks


@dataclasses.dataclass
class HexDumpMetrics:
    hex_columns: int = 0
    address_width: int = 0
    line_count: int = 0
    block_size: int = 1
    big_endian: bool = True
    padding: int = 0
    expand: bool = False
    max_width: int = 0
    txt_separator: str = '  '
    hex_char_format: str = '{:02X}'
    hex_char_spacer: str = ' '
    hex_addr_spacer: str = ': '

    @property
    def hex_column_width(self):
        return len(self.hex_char_format.format(0)) + len(self.hex_char_spacer)

    def get_max_width(self):
        width = self.max_width
        if not width:
            width = get_terminal_size()
            width = width and width or 75
            self.max_width = width
        return width

    def fit_to_width(self, width: int = 0, allow_increase: bool = False):
        padding = self.padding + len(self.txt_separator)
        if self.address_width:
            padding += self.address_width + len(self.hex_addr_spacer)
        width_max = width or self.get_max_width()
        width_available_for_hexdump = width_max - padding
        width_required_per_column = self.hex_column_width + self.block_size
        limit, r = divmod(width_available_for_hexdump, width_required_per_column)
        if r + len(self.hex_char_spacer) >= width_required_per_column:
            limit += 1
        if allow_increase or not self.hex_columns or limit < self.hex_columns:
            self.hex_columns = limit
        if self.address_width:
            gap = width_max - self.hexdump_width
            self.address_width += gap

    @property
    def hexdump_width(self):
        width = (self.hex_columns * (self.hex_column_width + self.block_size))
        width -= len(self.hex_char_spacer)
        width += len(self.txt_separator)
        if self.address_width:
            width += self.address_width + len(self.hex_addr_spacer)
        return width


def hexdump(data: ByteString, metrics: HexDumpMetrics) -> Iterable[str]:
    separator = metrics.hex_char_spacer
    hex_width = metrics.hex_column_width
    addr_width = metrics.address_width
    columns = metrics.hex_columns
    hexformat = metrics.hex_char_format

    if columns <= 0:
        raise RuntimeError('Requested width is too small.')

    def pieces(data):
        view = memoryview(data)
        step = columns * metrics.block_size
        for lno, offset in enumerate(range(0, len(data), step)):
            if metrics.line_count and lno >= metrics.line_count:
                break
            yield lno, view[offset:offset + step]

    previous = None
    repetitions = 0

    for last, (lno, chunk) in lookahead(pieces(data)):
        if not metrics.expand:
            if chunk == previous and not last:
                repetitions += 1
                continue
            elif repetitions > 0:
                line = F' repeats {repetitions} times '
                line = F'{line:=^{hex_width*columns-1}}  {"":=<{columns}}'
                if addr_width:
                    line = F'{".":.>{addr_width}}{metrics.hex_addr_spacer}{line}'
                yield line
                repetitions = 0

        blocks = chunks.unpack(chunk, metrics.block_size, metrics.big_endian)
        dump = separator.join(hexformat.format(b) for b in blocks)
        ascii_preview = re.sub(B'[^!-~]', B'.', chunk).decode('ascii')
        line = (
            F'{dump:<{hex_width*columns-len(separator)}}'
            F'{metrics.txt_separator}{ascii_preview:<{columns}}'
        )
        if addr_width:
            line = F'{lno*columns:0{addr_width}X}: {line}'

        yield line

        if not metrics.expand:
            previous = chunk


class HexViewer(Unit, abstract=True):

    def __init__(
        self,
        blocks  : arg.number('-B', help='Group hexadecimal bytes in blocks of the given size; default is {default}.') = 1,
        dense   : arg.switch('-D', help='Do not insert spaces in hexdump.') = False,
        expand  : arg.switch('-E', help='Do not compress sequences of identical lines in hexdump') = False,
        narrow  : arg.switch('-N', help='Do not show addresses in hexdump') = False,
        width   : arg.number('-W', help='Specify the number of hexadecimal characters to use in preview.') = 0,
        **kwargs
    ):
        super().__init__(
            blocks=blocks,
            dense=dense,
            expand=expand,
            narrow=narrow,
            width=width,
            **kwargs
        )

    def _get_metrics(self, data_size: int, line_count: Optional[int] = None, padding: int = 0) -> HexDumpMetrics:
        blocks = self.args.blocks
        metrics = HexDumpMetrics(
            self.args.width,
            line_count=line_count,
            padding=padding,
            expand=self.args.expand,
            block_size=blocks,
            hex_char_format=F'{{:0{2*blocks}X}}'
        )
        if not self.args.narrow:
            metrics.address_width = len(F'{data_size:X}')
        if self.args.dense:
            metrics.hex_char_spacer = ''
        if not metrics.hex_columns:
            metrics.fit_to_width()
        return metrics

    def hexdump(self, data: ByteString, metrics: Optional[HexDumpMetrics] = None):
        metrics = metrics or self._get_metrics(len(data))
        yield from hexdump(data, metrics)
