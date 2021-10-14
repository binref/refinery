#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
import dataclasses

from typing import Optional

from .. import arg, Unit
from ...lib.tools import get_terminal_size, lookahead


@dataclasses.dataclass
class HexDumpMetrics:
    hex_columns: int = 0
    address_width: int = 0
    line_count: int = 0
    padding: int = 0
    dense: bool = False
    max_width: int = 0

    @property
    def hex_column_width(self):
        return 3 - int(self.dense)

    def get_max_width(self):
        width = self.max_width
        if not width:
            width = get_terminal_size()
            width = width and width - 1 or 75
            self.max_width = width
        return width

    def fit_to_width(self, width: int = 0):
        padding = self.padding
        if self.address_width:
            padding += self.address_width + 2
        width_max = width or self.get_max_width()
        width_total = width_max - padding - 1
        width_each = self.hex_column_width + 1
        self.hex_columns = width_total // width_each

    @property
    def hexdump_width(self):
        width = (self.hex_columns * (self.hex_column_width + 1)) + 1
        if self.address_width:
            width += self.address_width + 2
        return width


_EMPTY = ''
_SPACE = ' '


class HexViewer(Unit, abstract=True):

    def __init__(
        self,
        hexaddr : arg.switch('-A', '--no-addr', help='Do not show addresses in hexdump', off=True) = True,
        width   : arg.number('-W', help='Specify the number of hexadecimal characters to use in preview.') = 0,
        dense   : arg.switch('-D', help='Do not insert spaces in hexdump.') = False,
        expand  : arg.switch('-E', help='Do not compress sequences of identical lines in hexdump') = False,
        **kwargs
    ):
        super().__init__(hexaddr=hexaddr, width=width, dense=dense, expand=expand, **kwargs)

    def _get_metrics(self, data_size: int, line_count: Optional[int] = None, padding: int = 0) -> HexDumpMetrics:
        metrics = HexDumpMetrics(
            self.args.width,
            line_count=line_count,
            padding=padding,
            dense=self.args.dense,
            address_width=len(F'{data_size:X}')
        )
        if not metrics.hex_columns:
            metrics.fit_to_width()
        return metrics

    def hexdump(self, data, metrics: Optional[HexDumpMetrics] = None):
        separator = _EMPTY if self.args.dense else _SPACE
        metrics = metrics or self._get_metrics(len(data))
        hex_width = metrics.hex_column_width
        addr_width = metrics.address_width
        columns = metrics.hex_columns

        if columns <= 0:
            raise RuntimeError('Requested width is too small.')

        def pieces(data):
            view = memoryview(data)
            for lno, offset in enumerate(range(0, len(data), columns)):
                if metrics.line_count and lno > metrics.line_count:
                    break
                yield lno, view[offset:offset + columns]

        previous = None
        repetitions = 0

        for last, (lno, chunk) in lookahead(pieces(data)):
            if not self.args.expand:
                if chunk == previous and not last:
                    repetitions += 1
                    continue
                elif repetitions > 0:
                    line = F' repeats {repetitions} times '
                    line = F'{line:=^{hex_width*columns-1}}  {"":=<{columns}}'
                    if addr_width:
                        line = F'{".":.>{addr_width}}: {line}'
                    yield line
                    repetitions = 0

            dump = separator.join(F'{b:02X}' for b in chunk)
            read = re.sub(B'[^!-~]', B'.', chunk).decode('ascii')
            line = F'{dump:<{hex_width*columns}} {read:<{columns}}'

            if addr_width:
                line = F'{lno*columns:0{addr_width}X}: {line}'
            yield line

            if not self.args.expand:
                previous = chunk
