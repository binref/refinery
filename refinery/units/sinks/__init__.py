#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import NamedTuple, Optional

from .. import arg, Unit
from ...lib.types import INF
from ...lib.tools import get_terminal_size, lookahead


class HexDumpMetrics(NamedTuple):
    width: int
    addr_width: int
    line_count: int
    columns: int


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

    @property
    def _hex_width(self):
        return 2 if self.args.dense else 3

    def _get_full_width(self, addr_width):
        width = self.args.width
        if not width:
            return get_terminal_size() or 75
        width *= (self._hex_width + 1)
        width += 2
        if self.args.hexaddr:
            width += addr_width + 1
        return width

    def _columns_to_width(self, columns: int, padding: int = 0):
        return columns * (self._hex_width + 1) + 2 + padding

    def _width_to_columns(self, width: int, padding: int = 0):
        return (width - padding - 2) // (self._hex_width + 1)

    def _get_metrics(self, data_size: int, line_count: int, padding: int = 0) -> HexDumpMetrics:
        if self.args.width:
            columns = self.args.width
            width = self._columns_to_width(columns)
        else:
            width = (get_terminal_size() - 1) or 75
            columns = self._width_to_columns(width)
        if not self.args.hexaddr:
            addr_width = 0
        else:
            addr_limit = abs(line_count * columns) or data_size
            addr_width = len(F'{addr_limit:X}') + 1
            if self.args.width:
                width = self._columns_to_width(columns, addr_width)
            else:
                columns = self._width_to_columns(width, addr_width)
        if padding:
            width -= padding
            columns = self._width_to_columns(width)
        return HexDumpMetrics(width, addr_width, line_count, columns)

    def hexdump(self, data, metrics: Optional[HexDumpMetrics] = None):
        import re

        separator = _EMPTY if self.args.dense else _SPACE
        hex_width = self._hex_width
        metrics = metrics or self._get_metrics(len(data), INF)
        width, addr_width, line_count, columns = metrics

        if columns <= 0:
            raise RuntimeError('Requested width is too small.')

        def pieces(data):
            view = memoryview(data)
            for lno, offset in enumerate(range(0, len(data), columns)):
                if lno >= line_count:
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
                    line = F'{line:=^{width-1}}  {"":=<{width}}'
                    if self.args.hexaddr:
                        line = F'{".":.>{addr_width}}: {line}'
                    yield line
                    repetitions = 0

            dump = separator.join(F'{b:02X}' for b in chunk)
            read = re.sub(B'[^!-~]', B'.', chunk).decode('ascii')
            line = F'{dump:<{hex_width*columns}}{read:<{columns}}'

            if self.args.hexaddr:
                line = F'{lno*columns:0{addr_width}X}: {line}'
            yield line

            if not self.args.expand:
                previous = chunk
