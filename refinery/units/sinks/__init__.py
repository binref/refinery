"""
This module contains units who are primarily intended to sit at the end of a pipeline where they
perform a final operation such as visualizing the incoming data in some way, or e.g. dumping it to
disk.
"""
from __future__ import annotations

import dataclasses
import io
import re

from refinery.lib import chunks
from refinery.lib.tools import get_terminal_size, lookahead
from refinery.lib.types import Iterable, Param, buf
from refinery.units import Arg, Unit


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
    hex_char_prefix: str = ''
    hex_char_spacer: str = ' '
    txt_char_spacer: str = ' '
    hex_addr_spacer: str = ': '

    @property
    def hex_char_format(self):
        return F'{self.hex_char_prefix}{{:0{2 * self.block_size}X}}'

    @property
    def hex_column_width(self):
        return len(self.hex_char_format.format(0)) + len(self.hex_char_spacer)

    @property
    def txt_column_width(self):
        return self.block_size + (self.block_size > 1) * len(self.txt_char_spacer)

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
        width_required_per_column = self.hex_column_width + self.txt_column_width
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
        width = self.hex_columns * (self.hex_column_width + self.txt_column_width)
        width -= len(self.hex_char_spacer)
        width += len(self.txt_separator)
        if self.address_width:
            width += self.address_width + len(self.hex_addr_spacer)
        if self.block_size > 1:
            width -= 1
        return width


def hexdump(data: buf, metrics: HexDumpMetrics, colorize=False) -> Iterable[str]:
    hex_separator = metrics.hex_char_spacer
    txt_separator = metrics.txt_char_spacer
    hex_width = metrics.hex_column_width
    addr_width = metrics.address_width
    columns = metrics.hex_columns
    hexformat = metrics.hex_char_format
    printable = range(0x21, 0x7F)

    from colorama import Fore as FG
    color_reset = FG.RESET

    if columns <= 0:
        raise RuntimeError('Requested width is too small.')

    view = memoryview(data)
    step = columns * metrics.block_size
    previous = None
    repetitions = 0
    skipped = 0

    for last, (lno, offset) in lookahead(enumerate(range(0, len(data), step))):
        chunk = view[offset:offset + step]
        if not metrics.expand:
            if chunk == previous and not last:
                repetitions += 1
                continue
            elif repetitions > 0:
                format = ' {} repetitions'
                message = format.format(repetitions)
                pad = (hex_width * columns - len(format) + 1) // 2
                pad = pad - len(message) + len(format)
                line = ' ' * pad + message
                if colorize:
                    line = F'{FG.LIGHTBLACK_EX}{line}{color_reset}'
                if addr_width:
                    line = F'{".":.>{addr_width}}{metrics.hex_addr_spacer}{line}'
                yield line
                skipped += repetitions - 1
                repetitions = 0

        if 0 < metrics.line_count <= lno - skipped:
            break

        blocks = chunks.unpack(chunk, metrics.block_size, metrics.big_endian)

        if not colorize:
            color_prefix = ''
            dump = hex_separator.join(hexformat.format(b) for b in blocks)
            ascii_preview = re.sub(B'[^!-~]', B'.', chunk).decode('ascii')
            if (bs := metrics.block_size) > 1:
                temp = []
                for k in range(0, len(ascii_preview), bs):
                    temp.append(ascii_preview[k:k + bs])
                ascii_preview = txt_separator.join(temp)
            line = (
                F'{dump:<{hex_width * columns - len(hex_separator)}}'
                F'{metrics.txt_separator}{ascii_preview:<{columns}}'
            )
        else:
            def byte_color(value: int):
                if not value:
                    return FG.LIGHTBLACK_EX
                elif value in B'\x20\t\n\r':
                    return FG.CYAN
                elif value not in printable:
                    return FG.LIGHTRED_EX
                else:
                    return color_reset
            color_prefix = current_color = color_reset
            with io.StringIO() as _hex, io.StringIO() as _asc:
                block_size = metrics.block_size
                prefix = metrics.hex_char_prefix
                remaining_hex_width = hex_width * columns - len(hex_separator)
                for k, b in enumerate(chunk):
                    if k % block_size == 0:
                        if block_size > 1 and k != 0:
                            _asc.write(txt_separator)
                        if k != 0:
                            _hex.write(hex_separator)
                            remaining_hex_width -= len(hex_separator)
                        if prefix:
                            _hex.write(prefix)
                            remaining_hex_width -= len(prefix)
                    color = byte_color(b)
                    if color != current_color:
                        _hex.write(color)
                        _asc.write(color)
                        current_color = color
                    _hex.write(F'{b:02X}')
                    remaining_hex_width -= 2
                    _asc.write(chr(b) if b in printable else '.')
                _hex.write(color_reset)
                _hex.write(' ' * remaining_hex_width)
                _asc.write(color_reset)
                line = F'{_hex.getvalue()}{metrics.txt_separator}{_asc.getvalue():<{columns}}'

        if addr_width:
            line = F'{color_prefix}{lno * columns:0{addr_width}X}: {line}'

        yield line

        if not metrics.expand:
            previous = chunk


class HexViewer(Unit, abstract=True):

    def __init__(
        self,
        blocks: Param[int, Arg.Number('-B', help='Group hexadecimal bytes in blocks of the given size; default is {default}.')] = 1,
        dense: Param[bool, Arg.Switch('-D', help='Do not insert spaces in hexdump.')] = False,
        expand: Param[bool, Arg.Switch('-E', help='Do not compress sequences of identical lines in hexdump')] = False,
        narrow: Param[bool, Arg.Switch('-N', help='Do not show addresses in hexdump')] = False,
        width: Param[int, Arg.Number('-W', help='Specify the number of hexadecimal characters to use in preview.')] = 0,
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

    def _get_metrics(self, data_size: int, line_count: int = 0, padding: int = 0) -> HexDumpMetrics:
        blocks = self.args.blocks
        metrics = HexDumpMetrics(
            self.args.width,
            line_count=line_count,
            padding=padding,
            expand=self.args.expand,
            block_size=blocks,
        )
        if not self.args.narrow:
            metrics.address_width = len(F'{data_size:X}')
        if self.args.dense:
            metrics.hex_char_spacer = ''
        if not metrics.hex_columns:
            metrics.fit_to_width()
        return metrics

    def hexdump(self, data: buf, metrics: HexDumpMetrics | None = None, colorize=False):
        metrics = metrics or self._get_metrics(len(data))
        yield from hexdump(data, metrics, colorize)
