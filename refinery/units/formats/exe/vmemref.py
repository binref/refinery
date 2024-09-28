#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

from typing import TYPE_CHECKING, Container

from refinery.units import Arg, Unit
from refinery.lib.executable import Executable
from refinery.lib.tools import NoLogging
from refinery.lib.types import AST

if TYPE_CHECKING:
    from smda.common.SmdaFunction import SmdaFunction


class vmemref(Unit):
    """
    The unit expects an executable as input (PE/ELF/MachO) and scans a function at a given virtual
    address for memory references. For each memory reference, the unit looks up the corresponding
    section and file offset for the reference. It then returns all data from that section starting
    at the given offset. If no address is given, all detected functions are scanned.
    """

    @Unit.Requires('smda', 'all')
    def _smda():
        import smda
        import smda.Disassembler
        return smda

    @Unit.Requires('lief', 'all')
    def _lief():
        import lief
        return lief

    def __init__(
        self,
        *addresses: Arg.Number(metavar='ADDR', help='The address of a function to scan.'),
        base: Arg.Number('-b', metavar='ADDR', help='A custom base address B.') = None,
        size: Arg.Number('-n', help='Optionally specify a number of bytes to read from each address.') = None,
    ):
        super().__init__(addresses=addresses, base=base, size=size)

    def process(self, data):
        executable = Executable.Load(data, self.args.base)
        size = self.args.size
        ps_n = executable.pointer_size // 4
        ps_b = executable.pointer_size // 8

        self.log_info('discovering functions')

        with NoLogging():
            dasm = self._smda.Disassembler.Disassembler()
            out = dasm.disassembleUnmappedBuffer(bytes(data))

        def dereference(address):
            return int.from_bytes(executable[address:address + ps_b], executable.byte_order())

        def references(constants: Container[int], max_dereference: int = 2):
            for address in constants:
                try:
                    address = int(address)
                except Exception:
                    continue
                times_dereferenced = 0
                while isinstance(address, int) and address in executable:
                    yield address
                    times_dereferenced += 1
                    if max_dereference and max_dereference > 0 and times_dereferenced > max_dereference:
                        break
                    try:
                        address = dereference(address)
                    except Exception:
                        break

        def refs(sf: SmdaFunction):
            with NoLogging():
                init = [dr for insn in sf.getInstructions() for dr in insn.getDataRefs()]
            yield from references(init)

        check = self.args.addresses or AST
        self.log_info('searching for data references')

        for function in out.getFunctions():
            if function.offset not in check:
                continue
            self.log_debug(F'scanning function 0x{function.offset:0{ps_n}X}')
            for ref in refs(function):
                try:
                    end = ref + size if size else None
                    yield executable[ref:end]
                except LookupError:
                    self.log_debug(F'memory reference could not be resolved: 0x{ref:0{ps_n}X}')
