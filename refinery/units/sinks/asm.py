#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units.formats.exe.opc import opc
from refinery.units.sinks import Arg, hexdump, HexDumpMetrics
from refinery.lib.tools import one


class asm(opc):
    """
    Disassembles the input data using capstone and produces a human-readable disassembly listing.
    It internally uses the `refinery.opc` unit for this, which is an alternative option if you are
    looking for more programmatic disassembly.
    """
    def __init__(
        self, mode='x32', *, count=None, until=None,
        no_address: Arg.Switch('-A', help='Disable address display.') = False,
        no_hexdump: Arg.Switch('-H', help='Disable opcodes hexdump.') = False,
    ):
        super().__init__(
            mode=mode,
            nvar='_name',
            avar='_addr',
            ovar='_arg',
            count=count,
            until=until,
            no_address=no_address,
            no_hexdump=no_hexdump,
        )

    def process(self, data):
        insns = list(super().process(data))
        if not insns:
            return

        no_address = self.args.no_address
        no_hexdump = self.args.no_hexdump

        def _hl(x): return len(hex(x))

        args_width = max(len(insn['_args']) for insn in insns)
        memo_width = max(len(insn['_name']) for insn in insns)
        addr_width = max(_hl(insn['_addr']) for insn in insns)

        if no_address:
            addr_width = 0
            memo_width = memo_width + 2

        max_data_bytes_count = max(len(c) for c in insns)

        padding = addr_width + memo_width + args_width + 10
        metrics_opc = HexDumpMetrics(max_data_bytes_count, padding=padding)

        for insn in insns:
            hd = one(hexdump(insn, metrics_opc))
            name = insn.meta.pop('_name')
            args = insn.meta.pop('_args')
            addr = insn.meta.pop('_addr')
            msg = F' {name:<{memo_width}}  {args:<{args_width}}'
            if not no_hexdump:
                msg = F'{msg}  ; {hd}'
            if not no_address:
                msg = F'{addr:0{addr_width}X}: {msg}'
            yield msg.encode(self.codec)
