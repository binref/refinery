#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

if True:
    import colorama
    colorama.init()
    FG = colorama.Fore
    RS = colorama.Style.RESET_ALL

from typing import Any, Union, List, Dict, TYPE_CHECKING

import enum
import functools
import re

from refinery.units import Arg, Unit
from refinery.lib.executable import Arch, Range
from refinery.lib.types import bounds, INF
from refinery.lib.meta import metavars
from refinery.lib.tools import isbuffer, exception_to_string, NoLogging
from refinery.lib.emulator import Emulator, SpeakeasyEmulator, UnicornEmulator, IcicleEmulator, Hook, EmulationError
from refinery.lib.argformats import PythonExpression, ParserVariableMissing
from refinery.lib.structures import StructReader

from dataclasses import dataclass, field
from collections import defaultdict

if TYPE_CHECKING:
    from typing import Optional, Iterator, TypeVar
    from intervaltree import IntervalTree, Interval
    FN = TypeVar('FN')


class _engine(enum.Enum):
    speakeasy = SpeakeasyEmulator
    icicle = IcicleEmulator
    unicorn = UnicornEmulator


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


@dataclass
class EmuState:
    cfg: EmuConfig
    writes: IntervalTree
    expected_address: int
    address_width: int
    waiting: int = 0
    callstack: List[int] = field(default_factory=list)
    retaddr: Optional[int] = None
    stop: Optional[int] = None
    previous_address: int = 0
    callstack_ceiling: int = 0
    invalid_instructions: int = 0
    synthesized: dict[bytes, str] = field(default_factory=dict)
    ticks: int = field(default_factory=lambda: INF)
    visits: Dict[int, int] = field(default_factory=lambda: defaultdict(int))
    init_registers: List[int] = field(default_factory=list)
    last_read: Optional[int] = None
    last_api: Optional[int] = None

    def log(self, msg: str) -> str:
        _width = len(str(self.cfg.wait))
        _depth = len(self.callstack)
        return F'[wait={self.waiting:0{_width}d}] [depth={_depth}] {self.fmt(self.previous_address)}: {msg}'

    def fmt(self, address: int) -> str:
        return F'0x{address:0{self.address_width}X}'


def inject_state_argument(pfn: FN) -> FN:
    @functools.wraps(pfn)
    def wrapped(self: VStackEmulatorMixin, *args, **kwargs):
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
    return wrapped


class VStackEmulatorMixin(Emulator[Any, Any, EmuState]):

    def stackrange(self):
        return Range(self.stack_base, self.stack_base + self.stack_size)

    def disassemble(self, address: int):
        try:
            return self.disassemble_instruction(address)
        except Exception:
            return None

    def hook_api_call(self, _, name: str, function, args: tuple[int, ...], **ka) -> bool:
        def _repr(x):
            stack = range(self.stack_base, self.stack_base + self.stack_size)
            if isinstance(x, int) and (x in stack or x in self.exe):
                return F'0x{x:X}'
            return repr(x)
        self.state.last_api = self.ip
        module, dot, symbol = name.partition('.')
        if dot != '.':
            return
        module, _, _ = module.lower().partition('.')
        logged_args = [_repr(a) for a in args]
        if symbol == 'connect':
            sockaddr = StructReader(self.mem_read(args[1], 8))
            if sockaddr.u16() == 2:
                sockaddr.bigendian = True
                port = sockaddr.u16()
                host = '.'.join(map(str, sockaddr.read(4)))
                self.state.synthesized[F'{host}:{port}'.encode(vstack.codec)] = F'{module}::{symbol}'
                logged_args[1] = F'sockaddr_in{{AF_INET, {host!r}, {port}}}'
        logged_args = [F'{FG.LIGHTCYAN_EX}{x}{RS}' for x in logged_args]
        vstack.log_info(F'{FG.LIGHTCYAN_EX}{module}{RS}::{FG.LIGHTYELLOW_EX}{symbol}{RS}({", ".join(logged_args)}){RS}')
        try:
            retval = function(args)
        except Exception as e:
            if self.state.cfg.skip_calls > 1:
                retval = self.malloc(self.alloc_size)
                what = F'empty buffer at 0x{retval:X}'
            else:
                retval = 0
                what = U'0'
            vstack.log_debug(F'exception of type {e.__class__.__name__} while emulating api routine, returning {what}')
            self.ip = self.pop()
        return retval

    @inject_state_argument
    def hook_mem_read(self, _, access: int, address: int, size: int, value: int, state: EmuState):
        mask = (1 << (size * 8)) - 1
        state.last_read = value & mask

    @inject_state_argument
    def hook_mem_write(self, _, access: int, address: int, size: int, value: int, state: EmuState):
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
            skipped = 'stack cookie'
        elif size not in bounds[state.cfg.write_range]:
            skipped = 'size excluded'
        elif (
            state.callstack_ceiling > 0
            and not state.cfg.log_writes_in_calls
            and address in range(state.callstack_ceiling - 0x200, state.callstack_ceiling)
        ):
            skipped = 'inside call'
        elif not state.cfg.log_stack_addresses and unsigned_value in self.stackrange():
            skipped = 'stack address'
        elif not state.cfg.log_other_addresses and not self.exe.blob:
            for s in self.exe.sections():
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
                if any(self.mem_read(address, size)):
                    skipped = 'zero overwrite'
            except Exception:
                pass

        if not skipped:
            state.writes.addi(address, address + size + 1)
            state.waiting = 0

        def info():
            data = unsigned_value.to_bytes(size, self.exe.byte_order().value)
            ph = self.exe.pointer_size // 4
            pt = self.exe.pointer_size // 8
            h = data.hex().upper()
            t = re.sub('[^!-~]', '.', data.decode('latin1'))
            msg = state.log(F'{state.fmt(address)} <- {h:_<{ph}} {t:_<{pt}}')
            if skipped:
                msg = F'{msg} (ignored: {skipped})'
            return msg

        vstack.log_info(info)

    @inject_state_argument
    def hook_mem_error(self, _, access: int, address: int, size: int, value: int, state: EmuState) -> bool:
        if address == self.state.last_api:
            self.state.last_api = None
            return True
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

    def hook_code_error(self, _, state: EmuState):
        vstack.log_debug('aborting emulation; instruction error')
        self.halt()
        return False

    @inject_state_argument
    def hook_code_execute(self, _, address: int, size: int, state: EmuState):

        if _init := state.init_registers:
            tos = self.sp
            for reg in _init:
                self.set_register(reg, tos)
            _init.clear()

        state.ticks -= 1
        state.visits[address] += 1
        if state.visits[address] > state.cfg.max_visits > 0:
            vstack.log_info(
                F'aborting emulation: 0x{address:0{self.exe.pointer_size // 8}X}'
                F' was visited more than {state.cfg.max_visits} times.')
            self.halt()
            return False
        if address == state.stop or state.ticks == 0:
            self.halt()
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
                    self.rv = self.malloc(state.cfg.block_size)
                self.ip = retaddr
                self.sp = self.sp + (self.exe.pointer_size // 8)
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
            self.halt()
            return False
        if not depth or not state.cfg.wait_calls:
            state.waiting += 1
        state.expected_address += size

        instruction = self.disassemble(address)
        if instruction:
            state.invalid_instructions = 0
            vstack.log_debug(state.log(F'{instruction.mnemonic} {instruction.op_str}'))
        else:
            iv = state.invalid_instructions + 1
            state.invalid_instructions += iv
            vstack.log_debug(state.log('unrecognized instruction'))
            if iv > 2:
                self.halt()


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

    @Unit.Requires('capstone', 'default', 'extended')
    def _capstone():
        import capstone
        return capstone

    @Unit.Requires('unicorn==2.0.1.post1', 'default', 'extended')
    def _unicorn():
        import importlib
        importlib.import_module('setuptools')
        with NoLogging():
            import unicorn
            return unicorn

    @Unit.Requires('speakeasy-emulator-refined', 'extended')
    def _speakeasy():
        import speakeasy
        return speakeasy

    @Unit.Requires('icicle-emu', 'all')
    def _icicle():
        import icicle
        return icicle

    def __init__(
        self,
        *address: Arg.NumSeq(metavar='start', help='Specify the (virtual) addresses of a stack string instruction sequences.'),
        stop: Arg.Number('-s', metavar='stop', help='Optional: Stop when reaching this address.') = None,
        base: Arg.Number('-b', metavar='Addr', help='Optionally specify a custom base address B.') = None,
        arch: Arg.Option('-a', help='Specify for blob inputs: {choices}', choices=Arch) = Arch.X32,
        engine: Arg.Option('-e', group='EMU', choices=_engine, metavar='E',
            help='The emulator engine. The default is {default}, options are: {choices}') = _engine.unicorn,
        se: Arg.Switch(group='EMU', help='Equivalent to --engine=speakeasy') = False,
        ic: Arg.Switch(group='EMU', help='Equivalent to --engine=icicle') = False,
        uc: Arg.Switch(group='EMU', help='Equivalent to --engine=unicorn') = False,
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
        max_visits: Arg.Number('-V', help='Maximum number of times a code address is visited. Default is {default}.') = 0x10000,
        log_writes_in_calls: Arg.Switch('-W', help='Log writes of values that occur in functions calls.') = False,
        log_stack_addresses: Arg.Switch('-X', help='Log writes of values that are stack addresses.') = False,
        log_other_addresses: Arg.Switch('-Y', help='Log writes of values that are addresses to mapped segments.') = False,
        log_zero_overwrites: Arg.Switch('-Z', help='Log writes of zeros to memory that contained nonzero values.') = False,
        log_stack_cookies  : Arg.Switch('-E', help='Log writes that look like stack cookies.') = False,
    ):
        if sum((se, uc, ic)) > 1:
            raise ValueError('Too many emulators selected.')
        elif se:
            engine = _engine.speakeasy
        elif ic:
            engine = _engine.icicle
        elif uc:
            engine = _engine.unicorn

        super().__init__(
            address=address,
            stop=stop,
            base=base,
            arch=Arg.AsOption(arch, Arch),
            engine=Arg.AsOption(engine, _engine),
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

    def process(self, data):
        meta = metavars(data)
        args = self.args

        engine: _engine = args.engine
        flags = Hook.Default
        self.log_debug(F'attempting to use {engine.name}')
        getattr(self, F'_{engine.name}')

        if engine is _engine.speakeasy:
            flags |= Hook.ApiCall

        class Emu(engine.value, VStackEmulatorMixin):
            pass

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
        )

        register_values = {}
        emu.reset(None)

        if args.meta_registers or args.stack_push:
            for var, value in list(meta.items()):
                try:
                    register = emu.lookup_register(var)
                except LookupError:
                    continue
                meta.discard(var)
                register_values[register] = var, value

        def parse_address(a: Union[int, bytes]):
            if isinstance(a, int):
                return a
            a = a.decode(self.codec)
            if m := re.fullmatch('(?i)(?:sub_|fun_|0x)?([A-F0-9]+)H?', a):
                return int(m[1], 16)
            try:
                return PythonExpression.Evaluate(a, meta)
            except ParserVariableMissing:
                pass
            symbols = list(emu.exe.symbols())
            for filter in [
                lambda s: s.get_name().casefold() == a.casefold(),
                lambda s: s.name == a,
                lambda s: s.code,
                lambda s: s.exported
            ]:
                symbols = [s for s in symbols if filter(s)]
                if len(symbols) == 1:
                    return symbols[0].address
            if len(symbols) > 1:
                raise RuntimeError(F'there are {len(symbols)} exported function symbol named "{a}", please specify the address')
            if not symbols:
                raise LookupError(F'no symbol with name "{a}" was found')

        addresses = [parse_address(a) for a in args.address]

        if not addresses:
            for symbol in emu.exe.symbols():
                if symbol.name is None:
                    addresses.append(symbol.address)
                    break

        for address in addresses:
            tree = self._intervaltree.IntervalTree()
            state = EmuState(cfg, tree, address, emu.exe.pointer_size // 4, stop=args.stop)
            emu.reset(state)

            for reg in emu.general_purpose_registers():
                if reg not in register_values:
                    state.init_registers.append(reg)

            for reg, (var, value) in register_values.items():
                if isinstance(value, int):
                    self.log_info(F'setting {var} to integer value 0x{value:X}')
                    emu.set_register(reg, value)
                    continue
                if isinstance(value, str):
                    value = value.encode()
                if isbuffer(value):
                    base = emu.malloc(len(value))
                    emu.mem_write(base, bytes(value))
                    emu.set_register(reg, base)
                    self.log_info(F'setting {var} to mapped buffer of size 0x{len(value):X}')
                    continue
                _tn = value.__class__.__name__
                self.log_warn(F'canot interpret value of type {_tn} for register {var}')

            if push := args.stack_push:
                for reg in push:
                    emu.push_register(reg)

            timeout = args.timeout
            if timeout is not None:
                self.log_info(F'setting timeout of {timeout} steps')
                state.ticks = timeout

            try:
                emu.emulate(address, args.stop)
            except EmulationError:
                pass

            for patch, api in state.synthesized.items():
                chunk = self.labelled(patch, src=api)
                yield chunk

            tree.merge_overlaps()
            it: Iterator[Interval] = iter(tree)
            for interval in it:
                size = interval.end - interval.begin - 1
                if size not in bounds[args.patch_range]:
                    continue
                try:
                    patch = emu.mem_read(interval.begin, size)
                except Exception as error:
                    width = emu.exe.pointer_size // 4
                    self.log_info(F'error reading 0x{interval.begin:0{width}X}:{size}: {error!s}')
                    continue
                if not any(patch):
                    continue
                self.log_info(F'memory patch at {state.fmt(interval.begin)} of size {size}')
                chunk = self.labelled(patch, src=interval.begin)
                yield chunk
