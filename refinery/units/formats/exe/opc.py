#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
from typing import TYPE_CHECKING
from refinery.units.sinks import Arg, Unit

if TYPE_CHECKING:
    from capstone import Cs


_ARCHES = ['x16', 'x32', 'x64', 'ppc32', 'ppc64', 'mips32', 'mips64']


class opc(Unit):
    """
    Disassembles the input data using capstone and generates opcodes with metadata as output. This
    is useful for programmatic disassembly, while the `refinery.asm` unit outputs a human-readable
    representation. Internally, `refinery.asm` uses this unit and pretty-prints the output.
    """
    def __init__(
        self,
        mode: Arg.Choice(
            help='Machine code architecture, default is {default}. Select from the following list: {choices}.',
            choices=_ARCHES, metavar='[x32|x64|..]') = 'x32', *,
        count: Arg.Number('-c', help='Maximum number of bytes to disassemble, infinite by default.') = None,
        until: Arg.String('-u', help='Disassemble until the given string appears among the disassembly.') = None,
        nvar: Arg.String('-n', help=(
            'Variable to receive the disassembled mnemonic. Default is "{default}".')) = 'name',
        avar: Arg.String('-a', help=(
            'Variable to receive the address of the instruction. Default is "{default}".')) = 'addr',
        ovar: Arg.String('-o', help=(
            'Variable prefix for instruction operands. Default is "{default}". The complete operand '
            'string will be in {default}s, the first argument in {default}1, the second in {default}2, '
            'and so on.')) = 'arg',
        **more
    ):
        super().__init__(
            mode=mode,
            count=count,
            until=until,
            nvar=nvar,
            avar=avar,
            ovar=ovar,
            **more)

    @Unit.Requires('capstone')
    def _capstone():
        import capstone
        return capstone

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

    def process(self, data):
        count = self.args.count or 0
        until = self.args.until
        nvar = self.args.nvar
        avar = self.args.avar
        ovar = self.args.ovar
        if isinstance(until, str):
            until = until.lower()
        for insn in self._capstone_engine.disasm(data, 0, count):
            kwargs = {
                avar: insn.address,
                nvar: insn.mnemonic,
            }
            try:
                ops = insn.op_str
                operands = [op.strip() for op in ops.split(',')]
            except Exception:
                operands = []
            else:
                kwargs[F'{ovar}s'] = ops
            for k, op in enumerate(operands, 1):
                if not op:
                    break
                try:
                    op = int(op, 0)
                except Exception:
                    pass
                kwargs[F'{ovar}{k}'] = op
            yield self.labelled(insn.bytes, **kwargs)
            if until is None:
                continue
            if until in ops.lower() or until in insn.mnemonic.lower():
                break
