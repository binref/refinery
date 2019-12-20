#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import itertools

from ...lib.tools import get_terminal_size, lookahead

try:
    from winmagic import magic
except ModuleNotFoundError:
    import os
    if os.name == 'nt':
        # Attempting to import magic on Windows without winmagic being
        # installed may result in an uncontrolled crash.
        magic = None
    else:
        try:
            import magic
        except ModuleNotFoundError:
            magic = None


class HexViewerMixin:

    def hexviewer_interface(self, argp):
        from ...lib.argformats import number
        argp.add_argument('-A', '--no-addr', dest='hexaddr', action='store_false',
            help='Do not show byte offsets in hexdump.')
        argp.add_argument('-W', '--width', metavar='N', type=number, default=0,
            help='Specify the number of hexadecimal characters to use in preview.')
        argp.add_argument('-E', '--expand', action='store_true',
            help='Do not compress sequences of identical lines in hexdump')
        return argp

    def hexaddr_size(self, data):
        addr_width = 16
        for k in range(1, 16):
            if len(data) < (1 << (k << 2)):
                addr_width = k
                break
        return addr_width

    def hexdump(self, data):
        import re

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
                    columns -= self.hexaddr_size(data)
                    columns -= 1  # for the separator
                columns = (columns - 2) // 4

        columns = min(columns, len(data))
        lines = itertools.zip_longest(*([iter(data)] * columns))
        address_width = max(self.hexaddr_size(data), 4)
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
