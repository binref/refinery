#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
from typing import List, Dict, Any, TYPE_CHECKING

import re

from refinery.units import Arg, Unit
from refinery.lib.executable import align, Arch, BO, Executable, Range, ExecutableCodeBlob
from refinery.lib.types import bounds, INF
from refinery.lib.meta import SizeInt
from refinery.lib.tools import isbuffer, NoLogging

from dataclasses import dataclass, field
from collections import defaultdict

if TYPE_CHECKING:
    from typing import Tuple, Optional, Iterator
    from capstone import Cs
    from unicorn import Uc
    from intervaltree import IntervalTree, Interval


def _get_reg_size(mu: Uc, reg: int):
    # props to Matthieu Walter
    backup = mu.reg_read(reg)
    mu.reg_write(reg, (1 << 512) - 1)
    size = mu.reg_read(reg).bit_length()
    q, r = divmod(size, 8)
    assert r == 0
    mu.reg_write(reg, backup)
    return q


@dataclass
class EmuConfig:
    wait_calls: bool
    skip_calls: bool
    write_range: slice
    wait: int
    block_size: int
    stack_size: int
    log_stack_cookies: bool
    log_writes_in_calls: bool
    log_stack_addresses: bool
    log_other_addresses: bool
    log_zero_overwrites: bool


@dataclass
class EmuState:
    cfg: EmuConfig
    executable: Executable
    writes: IntervalTree
    expected_address: int
    stack: Range
    blob: bool
    disassembler: Optional[Cs] = None
    waiting: int = 0
    callstack: List[int] = field(default_factory=list)
    retaddr: Optional[int] = None
    stop: Optional[int] = None
    previous_address: int = 0
    sp_register: int = 0
    ip_register: int = 0
    rv_register: int = 0
    callstack_ceiling: int = 0
    allocations: List[Range] = field(default_factory=list)
    ticks: int = field(default_factory=lambda: INF)
    max_wait: int = 0
    max_loop: int = 0
    visits: Dict[int, int] = field(default_factory=lambda: defaultdict(int))
    last_read: Optional[int] = None

    def disassemble(self, address: int, size: int):
        if self.disassembler is None:
            return None
        try:
            pos = self.executable.location_from_address(address).physical.position
            end = pos + size
            return next(self.disassembler.disasm(
                bytes(self.executable.data[pos:end]), address, 1))
        except Exception:
            return None

    def log(self, msg: str) -> str:
        _width = len(str(self.max_wait))
        _depth = len(self.callstack)
        return F'[wait={self.waiting:0{_width}d}] [call={_depth}] {self.fmt(self.previous_address)}: {msg}'

    def fmt(self, address: int) -> str:
        return F'0x{address:0{self.executable.pointer_size // 4}X}'


class vstack(Unit):
    """
    The unit emulates instructions at a given address in the input executable (PE/ELF/MachO) and
    extracts data patches that are written to the stack during emulation. Emulation is halted as
    soon as a certain number of instructions has not performed any memory writes, or when an error
    occurs. By default, most registers are set to the current location in the emulated stack.
    However, if you want to initialize certain registers differently, you can set an environment
    variable to the desired value.
    """

    @Unit.Requires('intervaltree', 'default', 'extended')
    def _intervaltree():
        import intervaltree
        return intervaltree

    @Unit.Requires('unicorn==2.0.1.post1', 'default', 'extended')
    def _unicorn():
        with NoLogging():
            import unicorn
        import unicorn.x86_const
        import unicorn.arm64_const
        import unicorn.mips_const
        import unicorn.sparc_const
        try:
            import unicorn.ppc_const
        except ImportError:
            pass
        return unicorn

    @Unit.Requires('capstone', 'default', 'extended')
    def _capstone():
        import capstone
        return capstone

    def __init__(
        self,
        *address: Arg.Number(metavar='start', help='Specify the (virtual) addresses of a stack string instruction sequences.'),
        stop: Arg.Number('-s', metavar='stop', help='Optional: Stop when reaching this address.') = None,
        base: Arg.Number('-b', metavar='Addr', help='Optionally specify a custom base address B.') = None,
        arch: Arg.Option('-a', help='Specify for blob inputs: {choices}', choices=Arch) = Arch.X32,
        meta_registers: Arg.Switch('-r', help=(
            'Consume register initialization values from the chunk\'s metadata. If the value is a byte string, '
            'the data will be mapped.')) = False,
        timeout: Arg.Number('-t', help='Optionally stop emulating after a given number of instructions.') = None,
        patch_range: Arg.Bounds('-p', metavar='MIN:MAX',
            help='Extract only patches that are in the given range, default is {default}.') = slice(5, None),
        write_range: Arg.Bounds('-n', metavar='MIN:MAX',
            help='Log only writes whose size is in the given range, default is {default}.') = slice(1, None),
        wait: Arg.Number('-w', help=(
            'When this many instructions did not write to memory, emulation is halted. The default is {default}.')) = 20,
        wait_calls: Arg.Switch('-c', group='CALL',
            help='Wait indefinitely when inside a function call.') = False,
        skip_calls: Arg.Counts('-C', group='CALL',
            help='Skip function calls entirely. Use twice to treat each call as allocating memory.') = 0,
        stack_size: Arg.Number('-S', help='Optionally specify the stack size. The default is 0x{default:X}.') = 0x10000,
        stack_push: Arg('-u', action='append', type=str, metavar='REG',
            help='Push the value of a register to the stack before beginning emulation; implies -r.') = None,
        block_size: Arg.Number('-B', help='Standard memory block size for the emulator, 0x{default:X} by default.') = 0x1000,
        max_visits: Arg.Number('-V', help='Maximum number of times a code address is visited. Default is {default}.') = 0x1000,
        log_writes_in_calls: Arg.Switch('-W', help='Log writes of values that occur in functions calls.') = False,
        log_stack_addresses: Arg.Switch('-X', help='Log writes of values that are stack addresses.') = False,
        log_other_addresses: Arg.Switch('-Y', help='Log writes of values that are addresses to mapped segments.') = False,
        log_zero_overwrites: Arg.Switch('-Z', help='Log writes of zeros to memory that contained nonzero values.') = False,
        log_stack_cookies  : Arg.Switch('-E', help='Log writes that look like stack cookies.') = False,
    ):
        super().__init__(
            address=address or [0],
            stop=stop,
            base=base,
            arch=Arg.AsOption(arch, Arch),
            meta_registers=meta_registers,
            timeout=timeout,
            patch_range=patch_range,
            write_range=write_range,
            wait=wait,
            stack_size=stack_size,
            stack_push=stack_push,
            wait_calls=wait_calls,
            skip_calls=skip_calls,
            block_size=block_size,
            max_visits=max_visits,
            log_writes_in_calls=log_writes_in_calls,
            log_stack_addresses=log_stack_addresses,
            log_other_addresses=log_other_addresses,
            log_zero_overwrites=log_zero_overwrites,
            log_stack_cookies=log_stack_cookies
        )

    def _find_stack_and_heap(self, exe: Executable):
        stack_size = self.args.stack_size
        block_size = self.args.block_size
        memory_max = 1 << exe.pointer_size
        space = exe.image_defined_address_space()
        heap = align(block_size, space.upper)
        stack = align(stack_size, memory_max - (4 * stack_size), down=True)
        if heap < stack:
            return stack, heap
        raise RuntimeError('The primitive method used to map heap and stack has failed.')

    def process(self, data):
        uc = self._unicorn
        blob = False
        try:
            exe = Executable.Load(data, self.args.base)
        except ValueError:
            exe = ExecutableCodeBlob(data, self.args.base, self.args.arch)
            blob = True
        arch = exe.arch()
        width = exe.pointer_size // 4
        block_size = self.args.block_size
        stack_size = self.args.stack_size
        stack_addr, alloc = self._find_stack_and_heap(exe)
        self.log_info(F'mapping {SizeInt(stack_size)!r} of stack at 0x{stack_addr:X}')
        image = memoryview(data)
        disassembler = self._capstone.Cs(*self._cs_arch(arch, exe.byte_order()))
        register_values = {}

        if arch in (Arch.PPC32, Arch.PPC64):
            try:
                sp = uc.ppc_const.UC_PPC_REG_1
                rv = uc.ppc_const.UC_PPC_REG_3
                ip = uc.ppc_const.UC_PPC_REG_PC
            except AttributeError:
                raise RuntimeError('The installed unicorn version does not support the PPC architecture.')
        else:
            sp, ip, rv = {
                Arch.X32     : (
                    uc.x86_const.UC_X86_REG_ESP,
                    uc.x86_const.UC_X86_REG_EIP,
                    uc.x86_const.UC_X86_REG_EAX,
                ),
                Arch.X64     : (
                    uc.x86_const.UC_X86_REG_RSP,
                    uc.x86_const.UC_X86_REG_RIP,
                    uc.x86_const.UC_X86_REG_RAX,
                ),
                Arch.ARM32   : (
                    uc.arm_const.UC_ARM_REG_SP,
                    uc.arm_const.UC_ARM_REG_IP,
                    uc.arm_const.UC_ARM_REG_R0,
                ),
                Arch.ARM64   : (
                    uc.arm_const.UC_ARM_REG_SP,
                    uc.arm_const.UC_ARM_REG_IP,
                    uc.arm_const.UC_ARM_REG_R0,
                ),
                Arch.MIPS16  : (
                    uc.mips_const.UC_MIPS_REG_SP,
                    uc.mips_const.UC_MIPS_REG_PC,
                    uc.mips_const.UC_MIPS_REG_0,
                ),
                Arch.MIPS32  : (
                    uc.mips_const.UC_MIPS_REG_SP,
                    uc.mips_const.UC_MIPS_REG_PC,
                    uc.mips_const.UC_MIPS_REG_V0,
                ),
                Arch.MIPS64  : (
                    uc.mips_const.UC_MIPS_REG_SP,
                    uc.mips_const.UC_MIPS_REG_PC,
                    uc.mips_const.UC_MIPS_REG_V0,
                ),
                Arch.SPARC32 : (
                    uc.sparc_const.UC_SPARC_REG_SP,
                    uc.sparc_const.UC_SPARC_REG_PC,
                    uc.sparc_const.UC_SPARC_REG_O0,
                ),
                Arch.SPARC64 : (
                    uc.sparc_const.UC_SPARC_REG_SP,
                    uc.sparc_const.UC_SPARC_REG_PC,
                    uc.sparc_const.UC_SPARC_REG_O0,
                ),
            }[arch]

        def get_register_id(var: str):
            var = var.upper()
            for module in [uc.x86_const, uc.arm_const, uc.mips_const, uc.sparc_const]:
                md: Dict[str, Any] = module.__dict__
                for name, register in md.items():
                    try:
                        u, *_, kind, name = name.split('_')
                    except Exception:
                        continue
                    if kind != 'REG' or u != 'UC':
                        continue
                    if name.upper() == var:
                        return register

        if self.args.meta_registers or self.args.stack_push:
            from refinery.lib.meta import metavars
            meta = metavars(data)
            for var, value in list(meta.items()):
                register = get_register_id(var)
                if register is None:
                    continue
                meta.discard(var)
                register_values[register] = var, value

        for address in self.args.address:

            emulator = uc.Uc(*self._uc_arch(arch, exe.byte_order()))
            stack = Range(stack_addr, stack_addr + 3 * stack_size)

            tos = stack.lower + 2 * len(stack) // 3
            emulator.mem_map(stack.lower, len(stack))

            if arch is Arch.X32:
                for reg in [
                    uc.x86_const.UC_X86_REG_EAX,
                    uc.x86_const.UC_X86_REG_EBX,
                    uc.x86_const.UC_X86_REG_ECX,
                    uc.x86_const.UC_X86_REG_EDX,
                    uc.x86_const.UC_X86_REG_ESI,
                    uc.x86_const.UC_X86_REG_EDI,
                    uc.x86_const.UC_X86_REG_EBP,
                ]:
                    if reg not in register_values:
                        emulator.reg_write(reg, stack_addr + stack_size)
            if arch is Arch.X64:
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
                    if reg not in register_values:
                        emulator.reg_write(reg, stack_addr + stack_size)

            for reg, (var, value) in register_values.items():
                if isinstance(value, int):
                    self.log_info(F'setting {var} to integer value 0x{value:X}')
                    emulator.reg_write(reg, value)
                    continue
                if isinstance(value, str):
                    value = value.encode()
                if isbuffer(value):
                    size = align(block_size, len(value))
                    emulator.mem_map(alloc, size)
                    emulator.mem_write(alloc, bytes(value))
                    emulator.reg_write(reg, alloc)
                    self.log_info(F'setting {var} to mapped buffer of size 0x{size:X}')
                    alloc += size
                    continue
                _tn = value.__class__.__name__
                self.log_warn(F'canot interpret value of type {_tn} for register {var}')

            if push := self.args.stack_push:
                for reg in push:
                    rid = get_register_id(reg)
                    if (rid is None) or not (size := _get_reg_size(emulator, rid)):
                        raise ValueError(F'unkown register in push: {reg}')
                    val = emulator.reg_read(rid)
                    tos = tos - size
                    emulator.mem_write(tos, val.to_bytes(size, exe.byte_order().value))

            emulator.reg_write(sp, tos)

            for segment in exe.segments():
                pmem = segment.physical
                vmem = segment.virtual
                try:
                    emulator.mem_map(vmem.lower, align(block_size, len(vmem)))
                    emulator.mem_write(vmem.lower, bytes(image[pmem.slice()]))
                except KeyboardInterrupt:
                    raise
                except Exception as error:
                    if address in vmem:
                        raise
                    self.log_info(F'error mapping segment [{vmem.lower:0{width}X}-{vmem.upper:0{width}X}]: {error!s}')

            tree = self._intervaltree.IntervalTree()
            args = self.args

            cfg = EmuConfig(
                args.wait_calls,
                args.skip_calls,
                args.write_range,
                args.wait,
                args.block_size,
                args.stack_size,
                args.log_stack_cookies,
                args.log_writes_in_calls,
                args.log_stack_addresses,
                args.log_other_addresses,
                args.log_zero_overwrites,
            )

            state = EmuState(
                cfg, exe, tree, address, stack, blob, disassembler,
                stop=self.args.stop,
                sp_register=sp,
                ip_register=ip,
                rv_register=rv,
                allocations=[stack],
                max_wait=self.args.wait,
                max_loop=self.args.max_visits,
            )

            timeout = self.args.timeout
            if timeout is not None:
                self.log_info(F'setting timeout of {timeout} steps')
                state.ticks = timeout

            emulator.hook_add(uc.UC_HOOK_CODE, self._hook_code, user_data=state)
            emulator.hook_add(uc.UC_HOOK_MEM_WRITE, self._hook_mem_write, user_data=state, )
            emulator.hook_add(uc.UC_HOOK_MEM_READ_AFTER, self._hook_mem_read, user_data=state, )
            emulator.hook_add(uc.UC_HOOK_INSN_INVALID, self._hook_insn_error, user_data=state)
            emulator.hook_add(uc.UC_HOOK_MEM_INVALID, self._hook_mem_error, user_data=state)

            end_of_code = exe.location_from_address(address).virtual.box.upper

            try:
                emulator.emu_start(address, end_of_code)
            except uc.UcError:
                pass

            tree.merge_overlaps()
            it: Iterator[Interval] = iter(tree)
            for interval in it:
                size = interval.end - interval.begin - 1
                if size not in bounds[self.args.patch_range]:
                    continue
                try:
                    patch = emulator.mem_read(interval.begin, size)
                except uc.UcError as error:
                    self.log_info(F'error reading 0x{interval.begin:0{width}X}:{size}: {error!s}')
                    continue
                if not any(patch):
                    continue
                self.log_info(F'memory patch at {state.fmt(interval.begin)} of size {size}')
                yield patch

    def _hook_mem_read(self, emu: Uc, access: int, address: int, size: int, value: int, state: EmuState):
        mask = (1 << (size * 8)) - 1
        state.last_read = value & mask

    def _hook_mem_write(self, emu: Uc, access: int, address: int, size: int, value: int, state: EmuState):
        try:
            mask = (1 << (size * 8)) - 1
            unsigned_value = value & mask

            if unsigned_value == state.expected_address:
                callstack = state.callstack
                state.retaddr = unsigned_value
                if not state.cfg.skip_calls:
                    if not callstack:
                        state.callstack_ceiling = emu.reg_read(state.sp_register)
                    callstack.append(unsigned_value)
                return
            else:
                state.retaddr = None

            skipped = False

            if (
                not state.cfg.log_stack_cookies
                and emu.reg_read(state.sp_register) ^ unsigned_value == state.last_read
            ):
                skipped = 'stack cookie'
            elif size not in bounds[state.cfg.write_range]:
                skipped = 'size excluded'
            elif (
                state.callstack_ceiling > 0
                and not state.cfg.log_writes_in_calls
                and address in range(state.callstack_ceiling - 0x200, state.callstack_ceiling)
            ):
                skipped = 'inside call'
            elif not state.cfg.log_stack_addresses and unsigned_value in state.stack:
                skipped = 'stack address'
            elif not state.cfg.log_other_addresses and not state.blob:
                for s in state.executable.sections():
                    if address in s.virtual:
                        skipped = F'write to section {s.name}'
                        break

            if (
                not skipped
                and unsigned_value == 0
                and state.writes.at(address) is not None
                and state.cfg.log_zero_overwrites is False
            ):
                try:
                    if any(emu.mem_read(address, size)):
                        skipped = 'zero overwrite'
                except Exception:
                    pass

            if not skipped:
                state.writes.addi(address, address + size + 1)
                state.waiting = 0

            def info():
                data = unsigned_value.to_bytes(size, state.executable.byte_order().value)
                ph = state.executable.pointer_size // 4
                pt = state.executable.pointer_size // 8
                h = data.hex().upper()
                t = re.sub('[^!-~]', '.', data.decode('latin1'))
                msg = state.log(F'{state.fmt(address)} <- {h:_<{ph}} {t:_<{pt}}')
                if skipped:
                    msg = F'{msg} (ignored: {skipped})'
                return msg

            self.log_info(info)

        except KeyboardInterrupt:
            emu.emu_stop()
            return False

    def _hook_insn_error(self, emu: Uc, state: EmuState):
        self.log_debug('aborting emulation; instruction error')
        emu.emu_stop()
        return False

    def _hook_mem_error(self, emu: Uc, access: int, address: int, size: int, value: int, state: EmuState):
        bs = state.cfg.block_size
        try:
            emu.mem_map(align(bs, address, down=True), 2 * bs)
        except Exception:
            self.log_info(state.log(F'{state.fmt(address)} :: MEMORY ERROR'))
            return False
        else:
            return True

    def _hook_code(self, emu: Uc, address: int, size: int, state: EmuState):
        try:
            state.ticks -= 1
            state.visits[address] += 1
            if state.visits[address] > state.max_loop > 0:
                self.log_info(
                    F'aborting emulation: 0x{address:0{state.executable.pointer_size // 8}X}'
                    F' was visited more than {state.max_loop} times.')
                emu.emu_stop()
                return False
            if address == state.stop or state.ticks == 0:
                emu.emu_stop()
                return False
            waiting = state.waiting
            callstack = state.callstack
            depth = len(callstack)
            state.previous_address = address
            retaddr = state.retaddr
            state.retaddr = None

            if address != state.expected_address:
                if retaddr is not None and state.cfg.skip_calls:
                    if state.cfg.skip_calls > 1:
                        stack_size = state.cfg.stack_size
                        block_size = state.cfg.block_size
                        rv = state.rv_register
                        alloc_addr = align(block_size, state.allocations[-1].upper)
                        state.allocations.append(Range(alloc_addr, alloc_addr + stack_size))
                        emu.mem_map(alloc_addr, stack_size)
                        emu.reg_write(rv, alloc_addr)
                    ip = state.ip_register
                    sp = state.sp_register
                    ps = state.executable.pointer_size // 8
                    emu.reg_write(ip, retaddr)
                    emu.reg_write(sp, emu.reg_read(sp) + ps)
                    return
                if depth and address == callstack[-1]:
                    depth -= 1
                    state.callstack.pop()
                    if depth == 0:
                        state.callstack_ceiling = 0
                state.expected_address = address
            elif retaddr is not None and not state.cfg.skip_calls:
                # The present address was moved to the stack but we did not branch.
                # This is not quite accurate, of course: We could be calling the
                # next instruction. However, that sort of code is usually not really
                # a function call anyway, but rather a way to get the IP.
                callstack.pop()

            if waiting > state.cfg.wait:
                emu.emu_stop()
                return False
            if not depth or not state.cfg.wait_calls:
                state.waiting += 1
            state.expected_address += size

            def _log():
                instruction = state.disassemble(address, size)
                if instruction:
                    return F'{instruction.mnemonic} {instruction.op_str}'
                return 'unrecognized instruction'
            self.log_debug(lambda: state.log(_log()))

        except KeyboardInterrupt:
            emu.emu_stop()
            return False

    def _uc_arch(self, arch: Arch, bo: Optional[BO] = None) -> Tuple[int, int]:
        uc = self._unicorn
        arch, mode = {
            Arch.X32     : (uc.UC_ARCH_X86,   uc.UC_MODE_32),     # noqa
            Arch.X64     : (uc.UC_ARCH_X86,   uc.UC_MODE_64),     # noqa
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
        if bo is not None:
            mode |= {
                BO.BE: uc.UC_MODE_BIG_ENDIAN,
                BO.LE: uc.UC_MODE_LITTLE_ENDIAN,
            }[bo]
        return arch, mode

    def _cs_arch(self, arch: Arch, bo: Optional[BO] = None) -> Tuple[int, int]:
        cs = self._capstone
        arch, mode = {
            Arch.X32     : (cs.CS_ARCH_X86,   cs.CS_MODE_32),     # noqa
            Arch.X64     : (cs.CS_ARCH_X86,   cs.CS_MODE_64),     # noqa
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
        if bo is not None:
            mode |= {
                BO.BE: cs.CS_MODE_BIG_ENDIAN,
                BO.LE: cs.CS_MODE_LITTLE_ENDIAN,
            }[bo]
        return arch, mode
