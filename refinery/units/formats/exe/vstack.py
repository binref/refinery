from __future__ import annotations

from refinery.lib.types import Param

if True:
    import colorama
    colorama.init()
    FG = colorama.Fore
    RS = colorama.Style.RESET_ALL

import functools
import re

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable, Literal, Type, TypeVar, cast

from refinery.lib.emulator import (
    EmulationError,
    Emulator,
    Hook,
    Register,
)
from refinery.lib.executable import Arch, Range
from refinery.lib.intervals import MemoryIntervalUnion
from refinery.lib.meta import metavars
from refinery.lib.structures import StructReader
from refinery.lib.tools import bounds, exception_to_string, isbuffer
from refinery.lib.types import INF
from refinery.units import Arg, Chunk
from refinery.units.formats.exe import EmulatingUnit, Engine


@dataclass
class EmuConfig:
    __slots__ = (
        'wait_calls',
        'skip_calls',
        'write_range',
        'wait',
        'block_size',
        'stack_size',
        'max_visits',
        'log_stack_cookies',
        'log_writes_in_calls',
        'log_stack_addresses',
        'log_other_addresses',
        'log_zero_overwrites',
        'show_apis',
        'show_code',
        'show_memory',
    )
    wait_calls: bool
    skip_calls: bool
    write_range: slice
    wait: int
    block_size: int
    stack_size: int
    max_visits: int
    log_stack_cookies: bool
    log_writes_in_calls: bool
    log_stack_addresses: bool
    log_other_addresses: bool
    log_zero_overwrites: bool
    show_apis: bool
    show_code: bool
    show_memory: bool


@dataclass
class EmuState:
    cfg: EmuConfig
    expected_address: int
    address_width: int
    waiting: int = 0
    callstack: list[int] = field(default_factory=list)
    retaddr: int | None = None
    stop: int | None = None
    previous_address: int = 0
    callstack_ceiling: int = 0
    invalid_instructions: int = 0
    synthesized: dict[bytes, str] = field(default_factory=dict)
    ticks: int | Literal[INF] = field(default_factory=lambda: INF)
    visits: dict[int, int] = field(default_factory=lambda: defaultdict(int))
    memory: MemoryIntervalUnion = field(default_factory=MemoryIntervalUnion)
    init_registers: list[Register] = field(default_factory=list)
    last_read: int | None = None
    last_api: int | None = None

    def log(self, msg: str) -> str:
        _width = len(str(w)) if (w := self.cfg.wait) else 8
        _depth = len(self.callstack)
        return F'[wait={self.waiting:0{_width}d}] [depth={_depth}] {self.fmt(self.previous_address)}: {msg}'

    def contains(self, address: int):
        return self.memory.overlaps(address)

    def write(self, address: int, data: bytes):
        self.memory.addi(address, data)

    def fmt(self, address: int) -> str:
        return F'0x{address:0{self.address_width}X}'


FN = TypeVar('FN', bound=Callable)
ET = TypeVar('ET', bound=Type[Emulator])


def EmuFactory(base: ET) -> ET:

    def inject_state_argument(pfn: FN) -> FN:
        @functools.wraps(pfn)
        def wrapped(self: VStackEmulator, *args, **kwargs):
            if 'state' in kwargs:
                kwargs.update(state=self.state)
            else:
                *head, state = args
                if state is None:
                    args = *head, self.state
            try:
                return pfn(self, *args, **kwargs)
            except KeyboardInterrupt:
                self.halt()
                return False
        return cast(FN, wrapped)

    class VStackEmulator(base):

        state: EmuState

        def stackrange(self):
            return Range(self.stack_base, self.stack_base + self.stack_size)

        def disassemble(self, address: int):
            try:
                return self.disassemble_instruction(address)
            except Exception:
                return None

        def hook_api_call(self, emu, name: str, cb=None, args: tuple[int, ...] = ()):
            def _repr(x):
                if not isinstance(x, int):
                    return repr(x)
                try:
                    data = self.mem_read(x, 0x200)
                except Exception:
                    data = None
                else:
                    read = StructReader(data)
                    try:
                        utf16 = read.read_w_string('utf-16le')
                    except UnicodeDecodeError:
                        utf16 = ''
                    try:
                        read.seek(0)
                        ascii = read.read_c_string('latin1')
                    except UnicodeDecodeError:
                        ascii = ''
                    string = utf16
                    if not symbol.endswith('W') and len(ascii) > 1 and ascii.isprintable():
                        string = ascii
                    if len(string) in range(5, 80):
                        return repr(string)
                return F'0x{x:X}'

            self.state.last_api = self.ip
            module, _, symbol = name.rpartition('.')
            symbol = symbol.lstrip('_')
            if module:
                module, _, _ = module.lower().partition('.')
                name = F'{module}::{symbol}'
            logged_args = [_repr(a) for a in args]
            if symbol == 'connect' and args:
                sockaddr = StructReader(self.mem_read(args[1], 8))
                if sockaddr.u16() in (0x02, 0x0200):
                    sockaddr.bigendian = True
                    port = sockaddr.u16()
                    host = '.'.join(map(str, sockaddr.read(4)))
                    self.state.synthesized[F'{host}:{port}'.encode(vstack.codec)] = name
                    logged_args[1] = F'sockaddr_in{{AF_INET, {host!r}, {port}}}'
            if self.state.cfg.show_apis:
                for k, arg in enumerate(logged_args):
                    if arg.startswith('"') or arg.startswith("'"):
                        logged_args[k] = F'{FG.LIGHTRED_EX}{arg}{RS}'
                vstack.log_always(
                    F'{FG.LIGHTCYAN_EX}{name}{RS}({", ".join(logged_args)}){RS}')
            if cb is None:
                retval = True
            else:
                try:
                    retval = cb(args)
                except Exception as e:
                    if self.state.cfg.skip_calls > 1:
                        retval = self.malloc(self.alloc_size)
                        what = F'empty buffer at 0x{retval:X}'
                    else:
                        retval = 0
                        what = '0'
                    vstack.log_debug(F'exception of type {e.__class__.__name__} while emulating api routine, returning {what}')
                    self.ip = self.pop()
            return retval

        @inject_state_argument
        def hook_mem_read(self, emu, access: int, address: int, size: int, value: int, state: EmuState):
            mask = (1 << (size * 8)) - 1
            state.last_read = value & mask

        @inject_state_argument
        def hook_mem_write(self, emu, access: int, address: int, size: int, value: int, state: EmuState):
            mask = (1 << (size * 8)) - 1
            unsigned_value = value & mask

            if unsigned_value == state.expected_address:
                callstack = state.callstack
                state.retaddr = unsigned_value
                if not state.cfg.skip_calls:
                    if not callstack:
                        state.callstack_ceiling = self.sp
                    callstack.append(unsigned_value)
                return
            else:
                state.retaddr = None

            skipped = False

            if (
                not state.cfg.log_stack_cookies
                and self.sp ^ unsigned_value == state.last_read
            ):
                skipped = 'no -E and stack cookie written'
            elif size not in bounds[state.cfg.write_range]:
                skipped = 'size excluded'
            elif (
                state.callstack_ceiling > 0
                and not state.cfg.log_writes_in_calls
                and address in range(state.callstack_ceiling - 0x200, state.callstack_ceiling)
            ):
                skipped = 'no -W and inside call'
            elif not state.cfg.log_stack_addresses and unsigned_value in self.stackrange():
                skipped = 'no -X and stack address written'
            elif not state.cfg.log_other_addresses and not self.exe.blob:
                for s in self.exe.sections():
                    if address in s.virtual:
                        skipped = F'no -Y and write to section {s.name}'
                        break

            if (
                not skipped
                and unsigned_value == 0
                and state.cfg.log_zero_overwrites is False
                and state.memory.overlaps(address, size)
            ):
                skipped = 'no -Z and zero overwrite detected'

            if not skipped:
                state.write(address, unsigned_value.to_bytes(size, 'little'))
                state.waiting = 0

            if state.cfg.show_memory:
                data = unsigned_value.to_bytes(size, self.exe.byte_order().value)
                ph = self.exe.pointer_size // 4
                pt = self.exe.pointer_size // 8
                h = data.hex().upper()
                t = re.sub('[^!-~]', '.', data.decode('latin1'))
                msg = state.log(F'{state.fmt(address)} <- {h:_<{ph}} {t:_<{pt}}')
                if skipped:
                    msg = F'{msg} (ignored: {skipped})'
                    vstack.log_debug(msg)
                else:
                    vstack.log_always(msg)

        @inject_state_argument
        def hook_mem_error(self, _, access: int, address: int, size: int, value: int, state: EmuState) -> bool:
            if address == self.state.last_api:
                self.state.last_api = None
                return True
            if address == (1 << self.exe.pointer_size) - 1:
                self.halt()
                return False
            msg = F'{state.fmt(address)}:{size:02X} memory error'
            if self.is_mapped(address, size):
                vstack.log_info(self.state.log(F'{msg}; fatal, this area was already mapped'))
            else:
                try:
                    self.map(self.align(address, down=True), self.alloc_size)
                except Exception as error:
                    vstack.log_info(self.state.log(F'{msg}; fatal, {exception_to_string(error)}'))
                else:
                    vstack.log_debug(self.state.log(F'{msg}; recovery, space mapped'))
            return True

        def hook_code_error(self, emu, state: EmuState):
            vstack.log_debug('aborting emulation; instruction error')
            self.halt()
            return False

        @inject_state_argument
        def hook_code_execute(self, emu, address: int, size: int, state: EmuState):

            if _init := state.init_registers:
                tos = self.sp
                for reg in _init:
                    self.set_register(reg, tos)
                _init.clear()

            if (max_visits := state.cfg.max_visits) > 0:
                state.visits[address] += 1
                if state.visits[address] > max_visits:
                    vstack.log_info(
                        F'aborting emulation: 0x{address:0{self.exe.pointer_size // 8}X}'
                        F' was visited more than {state.cfg.max_visits} times.')
                    self.halt()
                    return False

            if address == state.stop or (ticks := state.ticks - 1) <= 0:
                self.halt()
                return False
            else:
                state.ticks = ticks

            waiting = state.waiting
            callstack = state.callstack
            depth = len(callstack)
            state.previous_address = address
            retaddr = state.retaddr
            state.retaddr = None

            if address != state.expected_address:
                if retaddr is not None and state.cfg.skip_calls:
                    if state.cfg.skip_calls > 1:
                        self.rv = self.malloc(state.cfg.block_size)
                    self.ip = _ip = self.pop()
                    if _ip != retaddr:
                        raise RuntimeError(
                            'Trying to return from call: top of stack was not the execpted return address.')
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

            if waiting > state.cfg.wait > 0:
                self.halt()
                return False
            if not depth or not state.cfg.wait_calls:
                state.waiting += 1
            state.expected_address += size

            instruction = self.disassemble(address)
            if instruction:
                state.invalid_instructions = 0
                if state.cfg.show_code:
                    vstack.log_always(state.log(F'{instruction.mnemonic} {instruction.op_str}'))
            else:
                iv = state.invalid_instructions + 1
                state.invalid_instructions += iv
                vstack.log_debug(state.log('unrecognized instruction'))
                if iv > 2:
                    self.halt()

    return cast(ET, VStackEmulator)


class vstack(EmulatingUnit):
    """
    The unit emulates instructions at a given address in the input executable (PE/ELF/MachO) and
    extracts data patches that are written to memory during emulation. The unit can also be used
    to emulate shellcode blobs, in which case it defaults to emulating 32bit x86 instructions.

    Emulation is halted as soon as a certain number of instructions have not performed any memory
    writes, or when an error occurs. By default, most registers are set to the current location in
    the emulated stack. If you want to initialize some of them differently, the `-r` switch maes
    the unit initialize register values from meta variables:

        emit shellcode [| put eax 0x2000 | vstack -r ]

    In this pipeline, the eax register is set to `0x2000` before emulation begins.
    """
    def __init__(
        self,
        *address: Param[str, Arg.String(metavar='a[:end|::size]',
            help='Specify a symbol name or the (virtual) addresses of what to emulate; optionally specify a stop address or a length.')],
        base=None, arch=Arch.X32, engine=Engine.unicorn, se=False, ic=False, uc=False,
        registers: Param[bool, Arg.Switch('-r', help=(
            'Consume register initialization values from the chunk\'s metadata. If the value is a byte string, '
            'the data will be mapped.'))] = False,
        timeout: Param[int, Arg.Number('-t', help='Optionally stop emulating after a given number of instructions.')] = 0,
        patch_range: Param[slice, Arg.Bounds('-p', metavar='MIN:MAX',
            help='Extract only patches that are in the given range, default is {default}.')] = slice(5, None),
        write_range: Param[slice, Arg.Bounds('-n', metavar='MIN:MAX',
            help='Log only writes whose size is in the given range, default is {default}.')] = slice(1, None),
        wait: Param[int, Arg.Number('-w', help=(
            'When this many instructions did not write to memory, emulation is halted. The default is {default}.'))] = 20,
        wait_calls: Param[bool, Arg.Switch('-c', group='CALL',
            help='Wait indefinitely when inside a function call.')] = False,
        skip_calls: Param[int, Arg.Counts('-C', group='CALL',
            help='Skip function calls entirely. Use twice to treat each call as allocating memory.')] = 0,
        stack_size: Param[int, Arg.Number('-S', help='Optionally specify the stack size. The default is 0x{default:X}.')] = 0x10000,
        stack_push: Param[tuple[str] | None, Arg('-u', action='append', metavar='REG',
            help='Push the value of a register to the stack before beginning emulation; implies -r.')] = None,
        show_apis: Param[bool, Arg.Switch('-A', help='Show API calls in the debug log.')] = False,
        show_code: Param[bool, Arg.Switch('-I', help='Show all executed instructions in the debug log.')] = False,
        show_memory: Param[bool, Arg.Switch('-M', help='Show all memory writes in the debug log.')] = False,
        block_size: Param[int, Arg.Number('-B', help='Standard memory block size for the emulator, 0x{default:X} by default.')] = 0x1000,
        max_visits: Param[int, Arg.Number('-V', help='Maximum number of times a code address is visited. Default is {default}.')] = 0x10000,
        log_writes_in_calls: Param[bool, Arg.Switch('-W', help='Log writes of values that occur in functions calls.')] = False,
        log_stack_addresses: Param[bool, Arg.Switch('-X', help='Log writes of values that are stack addresses.')] = False,
        log_other_addresses: Param[bool, Arg.Switch('-Y', help='Log writes of values that are addresses to mapped segments.')] = False,
        log_zero_overwrites: Param[bool, Arg.Switch('-Z', help='Log writes of zeros to memory that contained nonzero values.')] = False,
        log_stack_cookies: Param[bool, Arg.Switch('-E', help='Log writes that look like stack cookies.')] = False,
    ):
        super().__init__(
            base=base,
            arch=arch,
            engine=engine,
            se=se,
            ic=ic,
            uc=uc,
            address=address,
            registers=registers,
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
            show_apis=show_apis,
            show_code=show_code,
            show_memory=show_memory,
            log_writes_in_calls=log_writes_in_calls,
            log_stack_addresses=log_stack_addresses,
            log_other_addresses=log_other_addresses,
            log_zero_overwrites=log_zero_overwrites,
            log_stack_cookies=log_stack_cookies
        )

    def process(self, data: Chunk):
        meta = metavars(data)
        args = self.args

        engine = self._engine()
        flags = Hook.Default | Hook.ApiCall
        self.log_debug(F'attempting to use {engine.name}')

        Emu = EmuFactory(engine.value)

        emu = Emu(
            data,
            args.base,
            args.arch,
            flags,
            args.block_size,
            args.stack_size,
        )

        cfg = EmuConfig(
            args.wait_calls,
            args.skip_calls,
            args.write_range,
            args.wait,
            args.block_size,
            args.stack_size,
            args.max_visits,
            args.log_stack_cookies,
            args.log_writes_in_calls,
            args.log_stack_addresses,
            args.log_other_addresses,
            args.log_zero_overwrites,
            args.show_apis,
            args.show_code,
            args.show_memory,
        )

        register_values: dict[Register, int | str | bytes] = {}
        emu.reset(None)

        if args.registers or args.stack_push:
            for var, value in list(meta.items()):
                try:
                    register = emu.lookup_register(var)
                except LookupError:
                    continue
                meta.discard(var)
                register_values[register] = value

        if not (addresses := [
            self._parse_address(data, emu.exe, a) for a in args.address
        ]):
            for symbol in emu.exe.symbols():
                if symbol.name is None:
                    addresses.append(slice(symbol.address, None))
                    break

        for cursor in addresses:
            state = EmuState(cfg, cursor.start, emu.exe.pointer_size // 4, stop=cursor.stop)
            emu.reset(state)

            for reg in emu.general_purpose_registers():
                emu.set_register(reg, 0)

            for reg in register_values:
                # check if we are tainting a general purpose register
                emu.set_register(reg, 1)

            for reg in emu.general_purpose_registers():
                if emu.get_register(reg) == 0:
                    state.init_registers.append(reg)

            for reg, value in register_values.items():
                if isinstance(value, int):
                    self.log_info(F'setting {reg.name} to integer value 0x{value:X}')
                    emu.set_register(reg, value)
                    continue
                if isinstance(value, str):
                    value = value.encode()
                if isbuffer(value):
                    start = emu.malloc(len(value))
                    emu.mem_write(start, bytes(value))
                    emu.set_register(reg, start)
                    self.log_info(F'setting {reg.name} to mapped buffer of size 0x{len(value):X}')
                    continue
                _tn = value.__class__.__name__
                self.log_warn(F'canot interpret value of type {_tn} for register {reg.name}')

            if push := args.stack_push:
                for reg in push:
                    emu.push_register(reg)

            timeout = args.timeout
            if timeout:
                self.log_info(F'setting timeout of {timeout} steps')
                state.ticks = timeout

            try:
                emu.emulate(
                    emu.base_exe_to_emu(cursor.start),
                    emu.base_exe_to_emu(cursor.stop),
                )
            except EmulationError:
                pass

            for patch, api in state.synthesized.items():
                chunk = self.labelled(patch, src=api)
                yield chunk

            valid = bounds[args.patch_range]
            for base, patch in state.memory:
                if len(patch) not in valid or not any(patch):
                    continue
                self.log_info(F'memory patch at {state.fmt(base)} of size {len(patch)}')
                chunk = self.labelled(patch, src=base)
                yield chunk
