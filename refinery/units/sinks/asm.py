#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, TYPE_CHECKING

from refinery.units.sinks import arg, hexdump, HexDumpMetrics, Unit
from refinery.lib.tools import NoLogging

if TYPE_CHECKING:
    from angr.analyses.cfg.cfg_fast import CFGFast
    from angr.knowledge_plugins.functions.function import Function
    from angr.block import Block, CapstoneInsn, DisassemblerInsn
    from capstone import CsInsn


@dataclass
class _BasicBlock:
    block: Block
    users: List[Function] = field(default_factory=list)


class asm(Unit):
    """
    Disassembles the input data using angr & the capstone disassembly library.
    """
    def __init__(
        self,
        mode: arg.choice(
            help='Machine code architecture, default is {default}. Select from the following list: {choices}.',
            choices=['x32', 'x64', 'armcortexm', 'armHF', 'armEL', 'aarch64', 'avr8', 'ppc32', 'ppc64', 'mips32', 'mips64', 's390x'],
            metavar='[x32|x64|..]',
        ) = 'x32',
    ):
        mode = {'x32': 'x86', 'x64': 'amd64'}.get(mode, mode)
        archmap = {arch[3].name.lower(): arch[3] for arch in self._angr_archinfo.arch_id_map}
        super().__init__(mode=archmap[mode.lower()])

    @Unit.Requires('angr')
    def _angr_project():
        import angr.project
        return angr.project

    @Unit.Requires('angr')
    def _angr_archinfo():
        import archinfo
        return archinfo

    def process(self, data):
        show_progress = self.log_info()

        with NoLogging:
            pr = self._angr_project.load_shellcode(data, self.args.mode.name)
            cfg: CFGFast = pr.analyses.CFGFast(show_progressbar=show_progress)
            cfg.normalize()

        functions: List[Function] = list(cfg.functions.values())
        blocks: Dict[int, _BasicBlock] = {}

        def all_insns() -> Iterable[DisassemblerInsn]:
            for function in functions:
                for block in function.blocks:
                    yield from block.disassembly.insns

        def opcodes(insn: CapstoneInsn) -> str:
            csi: CsInsn = insn.insn
            return '\x20'.join(F'{b:02X}' for b in csi.bytes)

        addr_width = max(len(hex(insn.address)) for insn in all_insns())
        memo_width = max(len(insn.mnemonic) for insn in all_insns())
        code_width = max(len(opcodes(insn)) for insn in all_insns())
        args_width = max(len(insn.op_str) for insn in all_insns())
        full_width = addr_width + memo_width + code_width + args_width + 5

        metrics = HexDumpMetrics()
        metrics.padding = 2 + addr_width
        metrics.fit_to_width(full_width)
        metrics.hex_columns += 1
        full_width = metrics.hexdump_width + metrics.padding

        for function in functions:
            for block in function.blocks:
                try:
                    bb = blocks[block.addr]
                except KeyError:
                    blocks[block.addr] = bb = _BasicBlock(block)
                if bb.block != block:
                    self.log_warn(F'conflicting blocks at 0x{block.addr:0{addr_width}X}')
                bb.users.append(function)

        addresses = list(blocks.keys())
        addresses.sort()
        tail = 0
        tearline = full_width * B'-'
        opcspace = code_width * R' '

        for address in addresses:
            def pprint(msg: str, addr: int = address) -> bytes:
                return F'{addr:0{addr_width}X}: {msg}'.encode(self.codec)
            if address > tail:
                db = data[tail:address]
                yield tearline
                for line in hexdump(db, metrics):
                    yield pprint(line, tail)
                    tail += metrics.hex_columns
            bb = blocks[address]
            for function in bb.users:
                if function.addr == address:
                    yield tearline
                    yield pprint(F'{opcspace}proc {function.name}:')
                    break
            for insn in bb.block.disassembly.insns:
                insn: CapstoneInsn
                yield (
                    F'{insn.address:0{addr_width}X}: '
                    F'{opcodes(insn):<{code_width}}  '
                    F'{insn.mnemonic:<{memo_width}} {insn.op_str}'
                ).encode(self.codec)
            tail = address + bb.block.size
