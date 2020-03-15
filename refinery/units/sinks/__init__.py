#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import itertools

from .. import arg, Unit
from ...lib.tools import get_terminal_size, lookahead


class HexViewer(Unit, abstract=True):

    def __init__(
        self,
        hexaddr : arg.switch('-A', '--no-addr', help='Do not show addresses in hexdump', off=True) = True,
        width   : arg.number('-W', help='Specify the number of hexadecimal characters to use in preview.') = 0,
        expand  : arg.switch('-E', help='Do not compress sequences of identical lines in hexdump') = False,
        **kwargs
    ):
        super().__init__(hexaddr=hexaddr, width=width, expand=expand, **kwargs)

    def hexaddr_size(self, total):
        addr_width = 16
        for k in range(1, 16):
            if total < (1 << (k << 2)):
                addr_width = k
                break
        return addr_width

    def hexdump(self, data, total=None):
        import re

        total = total or len(data)

        if self.args.width:
            columns = self.args.width
        else:
            # this will default to 16 byte wide output if
            # stdout is not a terminal or if its width can
            # not be determined for other reasons.
            try:
                columns = get_terminal_size() or 75
            except OSError:
                columns = 16
            else:
                if self.args.hexaddr:
                    columns -= self.hexaddr_size(total)
                    columns -= 1  # for the separator
                columns = (columns - 2) // 4

        columns = min(columns, len(data))
        lines = itertools.zip_longest(*([iter(data)] * columns))
        address_width = max(self.hexaddr_size(total), 4)
        previous = None
        prevcount = 0

        for k, (last, line) in enumerate(lookahead(lines)):
            chunk = bytes(b for b in line if b is not None)

            if not self.args.expand:
                if chunk == previous and not last:
                    prevcount += 1
                    continue
                elif prevcount > 0:
                    msg = F' repeats {prevcount} times '
                    yield F'{".":.>{address_width}}: {msg:=^{3*columns-1}}  {"":=<{columns}}'
                    prevcount = 0

            dump = ' '.join(F'{b:02X}' for b in chunk)
            read = re.sub(B'[^!-~]', B'.', chunk).decode('ascii')

            yield F'{k*columns:0{address_width}X}: {dump:<{3*columns}} {read:<{columns}}'

            if not self.args.expand:
                previous = chunk
