#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
from typing import TYPE_CHECKING

from refinery.units import Arg, Unit
from refinery.lib.executable import align, Arch, Executable
from refinery.lib.types import INF

from dataclasses import dataclass

if TYPE_CHECKING:
    from typing import Tuple, Optional, Iterator
    from capstone import Cs
    from unicorn import Uc
    from intervaltree import IntervalTree, Interval


@dataclass
class EmuState:
    executable: Executable
    address: int
    writes: IntervalTree
    disassembler: Optional[Cs] = None
    waiting: int = 0
    calling: bool = False


class vstack(Unit):
    """
    The unit emulates instructions at a given address in the input executable (PE/ELF/MachO) and
    extracts data patches that are written to the stack during emulation. Emulation is halted as
    soon as a certain number of instructions has not performed any memory writes, or when an error
    occurs.
    """

    @Unit.Requires('intervaltree')
    def _intervaltree():
        import intervaltree
        return intervaltree

    @Unit.Requires('unicorn')
    def _unicorn():
        import unicorn
        import unicorn.x86_const
        import unicorn.arm64_const
        import unicorn.mips_const
        import unicorn.sparc_const
        return unicorn

    @Unit.Requires('capstone')
    def _capstone():
        import capstone
        return capstone

    def __init__(
        self,
        address: Arg.Number(metavar='address', help='Specify the (virtual) address of a stack string instruction sequence.'),
        base: Arg.Number('-b', metavar='ADDR', help='Optionally specify a custom base address B.') = None,
        min: Arg.Number('-n', help='Minimum size of a memory patch, default is {default}.') = 10,
        max: Arg.Number('-m', help='Maximum size of a memory patch, default is {default}.') = INF,
        halt_after: Arg.Number('-a', help=(
            'When this many instructions did not write to memory, emulation is halted. The default is {default}.')) = 5,
        stack_size: Arg.Number('-s', help='Optionally specify the stack size. The default is 0x{default:X}.') = 0x10000,
        block_size: Arg.Number('-k', help='Standard memory block size for the emulator, 0x{default:X} by default.') = 0x1000,
    ):
        super().__init__(
            address=address,
            base=base,
            min=min,
            max=max,
            halt_after=halt_after,
            stack_size=stack_size,
            block_size=block_size,
        )

    def _find_stack_location(self, exe: Executable):
        stack_size = self.args.stack_size
        memory_max = 1 << exe.pointer_size
        space = exe.image_defined_address_space()
        aligned = align(stack_size, space.upper)
        if aligned + stack_size < memory_max:
            return aligned
        aligned = align(stack_size, space.lower - stack_size, down=True)
        if aligned > 0:
            return aligned
        raise RuntimeError('The primitive method used to map stack memory has failed.')

    def process(self, data):
        uc = self._unicorn
        exe = Executable.Load(data, self.args.base)
        arch = exe.arch()
        emulator = uc.Uc(*self._uc_arch(arch))
        tree = self._intervaltree.IntervalTree()
        block_size = self.args.block_size
        stack_size = self.args.stack_size
        stack_addr = self._find_stack_location(exe)
        address = self.args.address
        image = memoryview(data)

        if self.log_debug():
            disassembler = self._capstone.Cs(*self._cs_arch(arch))
        else:
            disassembler = None

        state = EmuState(exe, address, tree, disassembler)

        emulator.mem_map(stack_addr, stack_size * 3)
        emulator.reg_write({
            Arch.X8632   : uc.x86_const.UC_X86_REG_ESP,
            Arch.X8664   : uc.x86_const.UC_X86_REG_RSP,
            Arch.ARM32   : uc.arm_const.UC_ARM_REG_SP,
            Arch.ARM32   : uc.arm_const.UC_ARM_REG_SP,
            Arch.MIPS16  : uc.mips_const.UC_MIPS_REG_SP,
            Arch.MIPS32  : uc.mips_const.UC_MIPS_REG_SP,
            Arch.MIPS64  : uc.mips_const.UC_MIPS_REG_SP,
            Arch.SPARC32 : uc.sparc_const.UC_SPARC_REG_SP,
            Arch.SPARC64 : uc.sparc_const.UC_SPARC_REG_SP,
        }[arch], stack_addr + 2 * stack_size)

        if arch is Arch.X8632:
            for reg in [
                uc.x86_const.UC_X86_REG_EAX,
                uc.x86_const.UC_X86_REG_EBX,
                uc.x86_const.UC_X86_REG_ECX,
                uc.x86_const.UC_X86_REG_EDX,
                uc.x86_const.UC_X86_REG_ESI,
                uc.x86_const.UC_X86_REG_EDI,
                uc.x86_const.UC_X86_REG_EBP,
            ]:
                emulator.reg_write(reg, stack_addr + stack_size)
        if arch is Arch.X8664:
            for reg in [
                uc.x86_const.UC_X86_REG_RAX,
                uc.x86_const.UC_X86_REG_RBX,
                uc.x86_const.UC_X86_REG_RCX,
                uc.x86_const.UC_X86_REG_RDX,
                uc.x86_const.UC_X86_REG_RSI,
                uc.x86_const.UC_X86_REG_RDI,
                uc.x86_const.UC_X86_REG_RBP,
                uc.x86_const.UC_X86_REG_R8,
                uc.x86_const.UC_X86_REG_R9,
                uc.x86_const.UC_X86_REG_R10,
                uc.x86_const.UC_X86_REG_R11,
                uc.x86_const.UC_X86_REG_R12,
                uc.x86_const.UC_X86_REG_R13,
                uc.x86_const.UC_X86_REG_R14,
                uc.x86_const.UC_X86_REG_R15,
            ]:
                emulator.reg_write(reg, stack_addr + stack_size)

        for segment in exe.segments():
            pmem = segment.physical
            vmem = segment.virtual
            try:
                emulator.mem_map(vmem.lower, align(block_size, len(vmem)))
                emulator.mem_write(vmem.lower, bytes(image[pmem.slice()]))
            except Exception as error:
                if address in vmem:
                    raise
                width = exe.pointer_size // 4
                self.log_info(F'error mapping segment [{vmem.lower:0{width}X}-{vmem.upper:0{width}X}]: {error!s}')

        end_of_code = exe.location_from_address(address).virtual.box.upper

        emulator.hook_add(uc.UC_HOOK_CODE, self._hook_code, user_data=state)
        emulator.hook_add(uc.UC_HOOK_MEM_WRITE, self._hook_mem_write, user_data=state)
        emulator.hook_add(uc.UC_HOOK_INSN_INVALID, self._hook_insn_error, user_data=state)
        emulator.hook_add(uc.UC_HOOK_MEM_INVALID, self._hook_mem_error, user_data=state)

        try:
            emulator.emu_start(address, end_of_code)
        except uc.UcError:
            pass

        it: Iterator[Interval] = iter(tree)
        for interval in it:
            size = interval.end - interval.begin - 1
            if size > self.args.max:
                continue
            if size < self.args.min:
                continue
            self.log_info(F'memory patch at 0x{interval.begin:0{exe.pointer_size//4}X} of size {size}')
            yield emulator.mem_read(interval.begin, size)

    def _hook_mem_write(self, emu: Uc, access: int, address: int, size: int, value: int, state: EmuState):
        if not state.calling:
            state.waiting = 0
            state.writes.addi(address, address + size + 1)
            state.writes.merge_overlaps()
            self.log_info(F'memory write to 0x{address:0{state.executable.pointer_size//4}X}: {value:0{size*2}X}')

    def _hook_insn_error(self, emu: Uc, state: EmuState):
        self.log_debug('aborting emulation; instruction error')
        emu.emu_stop()
        return False

    def _hook_mem_error(self, emu: Uc, access: int, address: int, size: int, value: int, state: EmuState):
        self.log_debug(
            R'aborting emulation; access error '
            F'at 0x{address:0{state.executable.pointer_size//4}X}; '
            F'value={value:0{size*2}X}; code={access}')
        emu.emu_stop()
        return False

    def _hook_code(self, emu: Uc, address: int, size: int, state: EmuState):
        waiting = state.waiting

        if address == state.address:
            if waiting > self.args.halt_after:
                emu.emu_stop()
                return False
            state.waiting += 1
            state.address += size
            state.calling = False
        else:
            state.calling = True

        def debug_message():
            pos = state.executable.location_from_address(address).physical.position
            end = pos + size
            instruction = next(state.disassembler.disasm(bytes(state.executable.data[pos:end]), address, 1))
            flags = 'C' if state.calling else ' '
            return (
                F'emulating [wait={waiting}] [{flags}] 0x{address:0{state.executable.pointer_size//4}X}: '
                F'{instruction.mnemonic} {instruction.op_str}'
            )

        self.log_debug(debug_message)

    def _uc_arch(self, arch: Arch) -> Tuple[int, int]:
        uc = self._unicorn
        return {
            Arch.X8632   : (uc.UC_ARCH_X86,   uc.UC_MODE_32),     # noqa
            Arch.X8664   : (uc.UC_ARCH_X86,   uc.UC_MODE_64),     # noqa
            Arch.ARM32   : (uc.UC_ARCH_ARM,   uc.UC_MODE_ARM),    # noqa
            Arch.ARM64   : (uc.UC_ARCH_ARM,   uc.UC_MODE_THUMB),  # noqa
            Arch.MIPS16  : (uc.UC_ARCH_MIPS,  uc.UC_MODE_16),     # noqa
            Arch.MIPS32  : (uc.UC_ARCH_MIPS,  uc.UC_MODE_32),     # noqa
            Arch.MIPS64  : (uc.UC_ARCH_MIPS,  uc.UC_MODE_64),     # noqa
            Arch.PPC32   : (uc.UC_ARCH_PPC,   uc.UC_MODE_32),     # noqa
            Arch.PPC64   : (uc.UC_ARCH_PPC,   uc.UC_MODE_64),     # noqa
            Arch.SPARC32 : (uc.UC_ARCH_SPARC, uc.UC_MODE_32),     # noqa
            Arch.SPARC64 : (uc.UC_ARCH_SPARC, uc.UC_MODE_V9),     # noqa
        }[arch]

    def _cs_arch(self, arch: Arch) -> Tuple[int, int]:
        cs = self._capstone
        return {
            Arch.X8632   : (cs.CS_ARCH_X86,   cs.CS_MODE_32),     # noqa
            Arch.X8664   : (cs.CS_ARCH_X86,   cs.CS_MODE_64),     # noqa
            Arch.ARM32   : (cs.CS_ARCH_ARM,   cs.CS_MODE_ARM),    # noqa
            Arch.ARM64   : (cs.CS_ARCH_ARM,   cs.CS_MODE_THUMB),  # noqa
            Arch.MIPS16  : (cs.CS_ARCH_MIPS,  cs.CS_MODE_16),     # noqa
            Arch.MIPS32  : (cs.CS_ARCH_MIPS,  cs.CS_MODE_32),     # noqa
            Arch.MIPS64  : (cs.CS_ARCH_MIPS,  cs.CS_MODE_64),     # noqa
            Arch.PPC32   : (cs.CS_ARCH_PPC,   cs.CS_MODE_32),     # noqa
            Arch.PPC64   : (cs.CS_ARCH_PPC,   cs.CS_MODE_64),     # noqa
            Arch.SPARC32 : (cs.CS_ARCH_SPARC, cs.CS_MODE_32),     # noqa
            Arch.SPARC64 : (cs.CS_ARCH_SPARC, cs.CS_MODE_V9),     # noqa
        }[arch]
