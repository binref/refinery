#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Type, TYPE_CHECKING

from refinery.units.sinks import arg, hexdump, HexDumpMetrics, Unit
from refinery.lib.tools import NoLogging, one
from refinery.lib.structures import MemoryFile

if TYPE_CHECKING:
    from angr.analyses.cfg.cfg_fast import CFGFast
    from angr.knowledge_plugins.functions.function import Function
    from archinfo.arch import Arch
    from capstone import CsInsn, Cs


@dataclass
class _BasicBlock:
    size: int
    block: List[CsInsn]
    users: List[Function] = field(default_factory=list)


class asm(Unit):
    """
    Disassembles the input data using angr & the capstone disassembly library.
    """
    def __init__(
        self,
        mode: arg.choice(
            help='Machine code architecture, default is {default}. Select from the following list: {choices}.',
            choices=['x16', 'x32', 'x64', 'ppc32', 'ppc64', 'mips32', 'mips64'],
            metavar='[x32|x64|..]',
        ) = 'x32',
        *,
        angr: arg.switch('-a', help='Force use of Angr to perform a CFG computation before disassembly.') = False,
        no_address: arg.switch('-A', help='Disable address display.') = False,
        no_hexdump: arg.switch('-H', help='Disable opcodes hexdump.') = False,
    ):
        super().__init__(
            mode=mode,
            angr=angr,
            no_address=no_address,
            no_hexdump=no_hexdump
        )

    @Unit.Requires('angr')
    def _angr():
        import angr
        import angr.project
        import angr.engines
        return angr

    @Unit.Requires('angr')
    def _archinfo():
        import archinfo
        return archinfo

    @Unit.Requires('capstone', optional=False)
    def _capstone():
        import capstone
        return capstone

    @property
    def _angr_mode(self) -> str:
        mode = self.args.mode.lower()
        return {'x32': 'x86', 'x64': 'amd64'}.get(mode, mode)

    @property
    def _angr_arch(self) -> Type[Arch]:
        mode = self._angr_mode
        for archid in self._archinfo.arch_id_map:
            arch: Type[Arch] = archid[3]
            if arch.name.lower() == mode:
                return arch
        else:
            raise ValueError(F'unknown arch: {mode}')

    @property
    def _capstone_engine(self) -> Cs:
        cs = self._capstone
        return cs.Cs(*{
            'arm'    : (cs.CS_ARCH_ARM, cs.CS_MODE_ARM),
            'mips32' : (cs.CS_ARCH_MIPS, cs.CS_MODE_MIPS32),
            'mips64' : (cs.CS_ARCH_MIPS, cs.CS_MODE_MIPS64),
            'ppc32'  : (cs.CS_ARCH_PPC, cs.CS_MODE_32),
            'ppc64'  : (cs.CS_ARCH_PPC, cs.CS_MODE_64),
            'x16'    : (cs.CS_ARCH_X86, cs.CS_MODE_16),
            'x32'    : (cs.CS_ARCH_X86, cs.CS_MODE_32),
            'x64'    : (cs.CS_ARCH_X86, cs.CS_MODE_64),
        }.get(self.args.mode.lower()))

    def _get_angry_blocks(self, data) -> Dict[int, _BasicBlock]:

        self.log_debug('loading angr project')

        class TheFastArch(self._angr_arch):
            def get_register_by_name(self, reg_name):
                try:
                    rmap = self.rmap
                except AttributeError:
                    self.rmap = rmap = {}
                    for register in self.register_list:
                        rmap[register.name] = register
                        for alias in register.alias_names:
                            rmap[alias] = register
                return rmap[reg_name]

        with NoLogging():
            pr = self._angr.project.Project(
                MemoryFile(data),
                default_analysis_mode='static',
                auto_load_libs=False,
                main_opts=dict(
                    backend='blob',
                    arch=TheFastArch,
                    entry_point=0,
                    base_addr=0,
                ),
            )

        self.log_debug('computing control flow graph')

        with NoLogging():
            cfg: CFGFast = pr.analyses.CFGFast()
            cfg.normalize()

        functions: List[Function] = list(cfg.functions.values())
        blocks: Dict[int, _BasicBlock] = {}

        for function in functions:
            for block in function.blocks:
                try:
                    bb = blocks[block.addr]
                except KeyError:
                    blocks[block.addr] = bb = _BasicBlock(block.size, [
                        opc.insn for opc in block.disassembly.insns
                    ])
                if bb.size != block.size:
                    self.log_warn(F'conflicting blocks at 0x{block.addr:08X}')
                bb.users.append(function)

        return blocks

    def process(self, data):

        blocks: Optional[Dict[int, _BasicBlock]] = None

        if not self.args.angr:
            try:
                blocks = {0: _BasicBlock(len(data), list(self._capstone_engine.disasm(data, 0)))}
            except Exception:
                blocks = None
        if blocks is None:
            blocks = self._get_angry_blocks(data)

        def all_insns() -> Iterable[CsInsn]:
            for bb in blocks.values():
                yield from bb.block

        no_address = self.args.no_address
        no_hexdump = self.args.no_hexdump

        addr_width = max(len(hex(insn.address)) for insn in all_insns())
        memo_width = max(len(insn.mnemonic) for insn in all_insns())
        args_width = max(len(insn.op_str) for insn in all_insns())

        if no_address:
            addr_width = 0
            memo_width = memo_width + 2

        addresses = list(blocks.keys())
        addresses.sort()
        max_data_bytes_count = 0

        for address in addresses:
            for insn in blocks[address].block:
                max_data_bytes_count = max(max_data_bytes_count, insn.size)

        self.log_debug(F'computed hex column count for data dump: {max_data_bytes_count}')

        dbword = '  db'

        padding = addr_width + memo_width + args_width + 2 + 1 + 4
        metrics_opc = HexDumpMetrics(max_data_bytes_count, padding=padding)
        full_width = metrics_opc.hexdump_width + metrics_opc.padding

        metrics_hex = HexDumpMetrics(padding=addr_width + len(dbword) + 1)
        metrics_hex.txt_separator += '; '
        metrics_hex.hex_char_format = '0x{:02X}'
        metrics_hex.hex_char_spacer = ','
        metrics_hex.fit_to_width(full_width, allow_increase=True)
        gap = full_width - addr_width - len(dbword) - 3 - metrics_hex.hexdump_width
        metrics_hex.txt_separator = gap * ' ' + metrics_hex.txt_separator
        self.log_debug(F'full width of dump: {metrics_hex.hexdump_width}')

        first_tearline = True
        tearline = '; ' + (metrics_hex.hexdump_width + len(dbword)) * '-'
        tail = 0

        for address in addresses:
            def pprint(msg: str, addr: int = address) -> bytes:
                if not no_address:
                    msg = F'{addr:0{addr_width}X}: {msg}'
                return msg.encode(self.codec)
            if address > tail:
                db = data[tail:address]
                if not db:
                    break
                if not first_tearline:
                    yield pprint(tearline, tail)
                first_tearline = False
                for line in hexdump(db, metrics_hex):
                    yield pprint(F'{dbword} {line}', tail)
                    tail += metrics_hex.hex_columns
            bb = blocks[address]
            for function in bb.users:
                if not function.size:
                    continue
                if function.addr == address:
                    if not first_tearline:
                        yield pprint(tearline)
                    first_tearline = False
                    yield pprint(F'{function.name}:')
                    break
            for insn in bb.block:
                hd = one(hexdump(insn.bytes, metrics_opc))
                msg = F'  {insn.mnemonic:<{memo_width}} {insn.op_str:<{args_width}}'
                if not no_hexdump:
                    msg = F'{msg}  ; {hd}'
                yield pprint(msg, insn.address)
            tail = address + bb.size
