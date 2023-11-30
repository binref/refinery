#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
from typing import TYPE_CHECKING, Container

from refinery.units import Arg, Unit
from refinery.lib.executable import Executable, ET, CompartmentNotFound
from refinery.lib.structures import MemoryFile
from refinery.lib.tools import NoLogging


if TYPE_CHECKING:
    from angr.project import Project
    from angr.analyses.cfg.cfg_emulated import CFGEmulated
    from angr.knowledge_plugins.functions.function import Function
    from cle.memory import Clemory


class vmemref(Unit):
    """
    The unit expects an executable as input (PE/ELF/MachO) and scans a function at a given virtual
    address for memory references. For each memory reference, the unit looks up the corresponding
    section and file offset for the reference. It then returns all data from that section starting
    at the given offset.
    """

    @Unit.Requires('angr', 'all')
    def _angr():
        import angr
        import angr.project
        import angr.engines
        return angr

    def _memory_references(
        self,
        function: Function,
        memory: Clemory,
        functions: Container[int],
        pointer_size: int,
        max_dereference: int = 1
    ):
        pointer_size //= 8
        references = []
        code = set()
        for block in function.blocks:
            code.update(block.instruction_addrs)
        try:
            constants = function.code_constants
        except Exception:
            pass
        else:
            def is_valid_data_address(address):
                if not isinstance(address, int):
                    return False
                if address not in memory:
                    return False
                if address in code:
                    return False
                if address in functions:
                    return False
                return True

            def dereference(address):
                data = bytes(memory[k] for k in range(address, address + pointer_size))
                return int.from_bytes(data, 'little')

            for address in constants:
                try:
                    address = int(address)
                except Exception:
                    continue
                times_dereferenced = 0
                while is_valid_data_address(address) and address not in references:
                    references.append(address)
                    times_dereferenced += 1
                    if max_dereference and max_dereference > 0 and times_dereferenced > max_dereference:
                        break
                    try:
                        address = dereference(address)
                    except Exception:
                        break

        return references

    def __init__(
        self,
        address: Arg.Number(metavar='ADDR', help='Specify the address of a function to scan.'),
        base: Arg.Number('-b', metavar='ADDR', help='Optionally specify a custom base address B.') = None,
    ):
        super().__init__(address=address, base=base)

    def process(self, data):
        address = self.args.address
        executable = Executable.Load(data, self.args.base)
        code = executable.location_from_address(address).virtual.box

        self.log_info(R'loading project into angr')
        with NoLogging():
            project: Project = self._angr.Project(MemoryFile(data), load_options={'auto_load_libs': False})

        self.log_info(F'scanning function at 0x{address:X}')
        with NoLogging():
            cfg: CFGEmulated = project.analyses.CFGEmulated(
                call_depth=0,
                starts=[address],
                enable_symbolic_back_traversal=True,
                address_whitelist=code.range(),
            )

        function = cfg.functions[address]
        code_addresses = cfg.functions

        if executable.type is ET.PE:
            code_addresses = code

        self.log_info(R'extracting memory references from lifted function')
        for ref in self._memory_references(
            function,
            project.loader.memory,
            code_addresses,
            executable.pointer_size
        ):
            try:
                yield executable[ref:]
            except CompartmentNotFound:
                self.log_info(F'memory reference could not be resolved: 0x{ref:0{executable.pointer_size // 4}X}')
