#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import itertools
from typing import Optional

from .. import arg, Unit
from ...lib.tools import get_terminal_size, lookahead


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

    def hexaddr_size(self, total):
        addr_width = 16
        for k in range(1, 16):
            if total < (1 << (k << 2)):
                addr_width = k
                break
        return addr_width

    def hexdump(self, data, total=None, width: Optional[int] = None):
        import re

        total = total or len(data)
        item_width = 2 if self.args.dense else 3

        if width is None:
            width = self.args.width
        if not width:
            width = max(2, get_terminal_size() or 16)
            if self.args.hexaddr:
                width -= self.hexaddr_size(total)
                width -= 1  # for the separator
            width = (width - 2) // (item_width + 1)

        lines = itertools.zip_longest(*([iter(data)] * width))
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
                    msg = F'{msg:=^{3*width-1}}  {"":=<{width}}'
                    if self.args.hexaddr:
                        msg = F'{".":.>{address_width}}: {msg}'
                    yield msg
                    prevcount = 0

            sepr = '' if self.args.dense else ' '
            dump = sepr.join(F'{b:02X}' for b in chunk)
            read = re.sub(B'[^!-~]', B'.', chunk).decode('ascii')

            msg = F'{dump:<{item_width*width}} {read:<{width}}'

            if self.args.hexaddr:
                msg = F'{k*width:0{address_width}X}: {msg}'
            yield msg

            if not self.args.expand:
                previous = chunk
