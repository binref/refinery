#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

from typing import NamedTuple, Optional

from .. import arg, Unit
from ...lib.types import INF
from ...lib.tools import get_terminal_size, lookahead


class HexDumpMetrics(NamedTuple):
    argument: int
    hexdump_width: int
    address_width: int
    line_count: int
    hex_columns: int


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

    def _get_metrics(self, data_size: int, line_count: int, padding: int = 0) -> HexDumpMetrics:

        def c2w(c: int, p: int = 0):
            return (c * hw) + 1 + p

        def w2c(w: int, p: int = 0):
            return (w - p - 1) // hw

        hw = self._hex_width + 1
        argument = self.args.width

        if argument:
            columns = argument
        else:
            width = get_terminal_size()
            width = width and width - 1 or 75
            columns = w2c(width)
        if not self.args.hexaddr:
            addr_width = 0
            width = c2w(columns)
        else:
            addr_limit = abs(line_count * columns) or data_size
            addr_width = len(F'{addr_limit:X}')
            if self.args.width:
                width = c2w(columns, addr_width + 2)
            else:
                columns = w2c(width, addr_width + 2)
                width = c2w(columns, addr_width + 2)
        if padding:
            width = width - padding
            columns = w2c(width)
        return HexDumpMetrics(argument, width, addr_width, line_count, columns)

    def hexdump(self, data, metrics: Optional[HexDumpMetrics] = None):
        separator = _EMPTY if self.args.dense else _SPACE
        hex_width = self._hex_width
        metrics = metrics or self._get_metrics(len(data), INF)
        _, _, addr_width, line_count, columns = metrics

        if columns <= 0:
            raise RuntimeError('Requested width is too small.')

        def pieces(data):
            view = memoryview(data)
            for lno, offset in enumerate(range(0, len(data), columns)):
                if lno > line_count:
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
