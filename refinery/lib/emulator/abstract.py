"""
This module defines the refinery emulator abstraction layer interface.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum, IntFlag
from functools import cached_property
from typing import Any, Generic, TypeVar

from refinery.lib.executable import Arch, Executable, ExecutableCodeBlob, align
from refinery.lib.intervals import IntIntervalUnion
from refinery.lib.structures import FlagAccessMixin
from refinery.lib.tools import asbuffer
from refinery.lib.types import buf

_T = TypeVar('_T')
_E = TypeVar('_E')
_R = TypeVar('_R', str, int)


class EmulationError(Exception):
    """
    Base class for any exceptions raised by emulators.
    """


class FailedRead(EmulationError):
    """
    The emulator failed to read memory from a given address.
    """
    def __init__(self, addr: int, size: int) -> None:
        self.addr = addr
        self.size = size


class FailedWrite(EmulationError):
    """
    The emulator failed to write to a given address.
    """
    def __init__(self, addr: int, data: buf) -> None:
        self.addr = addr
        self.data = data


class CC(str, Enum):
    """
    A selection of x86 calling conventions.
    """
    CDecl = '__cdecl'
    FastCall = '__fastcall'
    StdCall = '__stdcall'
    ThisCall = '__thiscall'


class Register(Generic[_R]):
    """
    Represents an arbitrary CPU register.
    """
    __slots__ = (
        'name',
        'code',
        'size',
    )
    name: str
    """
    This is the common name of the register, like "eax" on x86.
    """
    code: _R
    """
    The code of a register is any emulator-specific internal identifier for the register.
    """
    size: int | None
    """
    If not `None`, this property contains the size of the register in bytes.
    """

    def __repr__(self):
        return self.name

    def __init__(self, name: str, code: _R, size: int | None = 0):
        self.name = name
        self.code = code
        self.size = size

    def __eq__(self, other):
        if not isinstance(other, Register):
            return False
        return self.code == other.code and self.size == other.size

    def __hash__(self):
        return hash((self.code, self.size))


class Hook(FlagAccessMixin, IntFlag):
    """
    A bit mask flag for the types of hooks that are requested from an emulator.
    """
    CodeExecute  = 0b000_00001  # noqa
    CodeError    = 0b000_00010  # noqa
    MemoryRead   = 0b000_00100  # noqa
    MemoryWrite  = 0b000_01000  # noqa
    MemoryError  = 0b000_10000  # noqa
    ApiCall      = 0b001_00000  # noqa

    Errors       = 0b000_10010  # noqa
    Default      = 0b000_11111  # noqa
    Everything   = 0b111_11111  # noqa
    Nothing      = 0b000_00000  # noqa
    MemoryAccess = 0b000_01100  # noqa
    Memory       = 0b000_11100  # noqa
    NoErrors     = 0b001_01101  # noqa


NopCodeByArch = {
    Arch.X32    : B'\x90',
    Arch.X64    : B'\x90',
    Arch.ARM32  : B'\x00\xF0\x20\xE3',
    Arch.ARM64  : B'\x1F\x20\x03\xD5',
    Arch.MIPS16 : B'\x65\x00',
    Arch.MIPS32 : B'\x00\x00\x00\x00',
    Arch.MIPS64 : B'\x00\x00\x00\x00',
    Arch.PPC32  : B'\x60\x00\x00\x00',
    Arch.PPC64  : B'\x60\x00\x00\x00',
    Arch.SPARC32: B'\x01\x00\x00\x00',
    Arch.SPARC64: B'\x01\x00\x00\x00',
}

RetCodeByArch = {
    Arch.X32    : B'\xC3',
    Arch.X64    : B'\xC3',
    Arch.ARM32  : B'\x1E\xFF\x2F\xE1',
    Arch.ARM64  : B'\xC0\x03\x5F\xD6',
    Arch.MIPS16 : B'\xE0\x7E',
    Arch.MIPS32 : B'\x08\x00\xE0\x03',
    Arch.MIPS64 : B'\x08\x00\xE0\x03',
    Arch.PPC32  : B'\x4E\x80\x00\x20',
    Arch.PPC64  : B'\x4E\x80\x00\x20',
    Arch.SPARC32: B'\x81\xC3\xE0\x08',
    Arch.SPARC64: B'\x81\xC3\xE0\x08',
}

NopCodeMaxLen = max(len(c) for c in NopCodeByArch.values())
RetCodeMaxLen = max(len(c) for c in RetCodeByArch.values())


class Emulator(ABC, Generic[_E, _R, _T]):
    """
    The emulator base class.
    """
    stack_base: int
    stack_size: int
    alloc_base: int

    state: _T | None

    def __init__(
        self,
        data: Executable | buf,
        base: int | None = None,
        arch: Arch | None = None,
        hooks: Hook = Hook.Errors,
        align_size: int = 0x1000,
        alloc_size: int = 0x1000,
    ):
        if isinstance(data, Executable):
            exe = data
            raw = False
        else:
            try:
                exe = Executable.Load(data, base)
            except ValueError:
                exe = ExecutableCodeBlob(data, base, arch or Arch.X32)
                raw = True
            else:
                raw = False

        self.exe = exe
        self.raw = raw

        self.hooks = hooks
        self.base = exe.base

        self.align_size = align_size
        self.alloc_size = alloc_size
        self._resetonce = False

        self._sp, self._ip, self._rv = {
            Arch.PPC32   : ('1',   'pc',  '3'  ), # noqa
            Arch.PPC64   : ('1',   'pc',  '3'  ), # noqa
            Arch.X32     : ('esp', 'eip', 'eax'), # noqa
            Arch.X64     : ('rsp', 'rip', 'rax'), # noqa
            Arch.ARM32   : ('sp',  'pc',  'r0' ), # noqa
            Arch.ARM64   : ('sp',  'pc',  'x0' ), # noqa
            Arch.MIPS16  : ('sp',  'pc',  '0'  ), # noqa
            Arch.MIPS32  : ('sp',  'pc',  'v0' ), # noqa
            Arch.MIPS64  : ('sp',  'pc',  'v0' ), # noqa
            Arch.SPARC32 : ('sp',  'pc',  'o0' ), # noqa
            Arch.SPARC64 : ('sp',  'pc',  'o0' ), # noqa
        }[exe.arch()]

        self._init()

    def call(
        self,
        address: int,
        *args: buf | int,
        until: int | None = None,
        cc: CC = CC.StdCall,
    ):
        if until is None:
            try:
                until = self._return_trap
            except AttributeError:
                nopcode = NopCodeByArch[self.exe.arch()]
                self._return_trap = until = self.malloc(len(nopcode))
                self.mem_write(until, nopcode)

        self.set_return_address(until)

        for k, value in enumerate(args):
            if b := asbuffer(value):
                b = bytes(b)
                value = self.malloc(len(b))
                self.mem_write(value, b)
            self.callarg(k, cc, value=value)

        self.emulate(address, until)
        return self.rv

    def callarg(
        self,
        index: int,
        cc: CC = CC.StdCall,
        size: int | None = None,
        value: int | None = None,
    ) -> int:
        arch = self.exe.arch()
        if index < 0:
            raise ValueError(index)
        if arch == Arch.X32:
            if cc == CC.FastCall:
                regs = ('ecx', 'edx')
            elif cc == CC.ThisCall:
                regs = ('ecx',)
            else:
                regs = ()
        elif arch == Arch.X64:
            regs = ('rcx', 'rdx', 'r8', 'r9')
        elif arch == Arch.ARM32:
            regs = ('r0', 'r1', 'r2', 'r3')
        elif arch == Arch.ARM64:
            regs = ('x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7')
        else:
            raise NotImplementedError(F'Calling convention {cc.value} is not implemented for {arch.name}')
        try:
            reg = regs[index]
        except IndexError:
            address = self.sp + (index - len(regs)) * self.exe.pointer_size_in_bytes
            if value is None:
                return self.mem_read_int(address)
            else:
                self.mem_write_int(address, value)
                return value
        else:
            if value is None:
                arg = self.get_register(reg)
                if size is not None:
                    arg &= (1 << (size << 3)) - 1
                return arg
            else:
                self.set_register(reg, value)
                return value

    @cached_property
    def _reg_sp(self):
        return self._lookup_register(self._sp).code

    @cached_property
    def _reg_ip(self):
        return self._lookup_register(self._ip).code

    @cached_property
    def _reg_rv(self):
        return self._lookup_register(self._rv).code

    def reset(self, state: _T | None = None):
        """
        This function resets the emulator to an initial state. This will create a new instance of
        the underlying emulator engine, map the input executable to memory, and install any of the
        requested hooks.
        """
        self._resetonce = True
        self._memorymap = IntIntervalUnion()
        self.state = state
        self._reset()
        for rd in self.exe.relocations():
            self.mem_write_int(rd.address, rd.value, rd.size)
        return self

    def step(self, address: int, count: int = 1) -> int:
        """
        This method emulates `count` many instructions starting at `address`. Returns the current
        instruction pointer value after stepping.
        """
        if not self._resetonce:
            self.reset()
        try:
            self._enable_single_step()
            for _ in range(count):
                self.emulate(address)
                address = self.ip
            return address
        finally:
            self._disable_single_step()

    def base_exe_to_emu(self, address: int | None):
        """
        Rebase a virtual address from the base executable's address space to the one used by the
        emulator.
        """
        if address is not None:
            address = address - self.exe.base + self.base
        return address

    def base_emu_to_exe(self, address: int | None):
        """
        Rebase a virtual address from the emulator's address space to the one used by the base
        executable.
        """
        if address is not None:
            address = address + self.exe.base - self.base
        return address

    def emulate(self, start: int, end: int | None = None):
        """
        Call this function to begin emulation. The `start` parameter is the address where execution
        should begin, the `end` parameter is an optional address to halt at.
        """
        if not self._resetonce:
            self.reset()
        return self._emulate(start, end)

    def mem_read_int(self, address: int, size: int | None = None):
        """
        Read an integer from memory at the given address. The default for the size parameter is
        the pointer size of the emulated executable.
        """
        if size is None:
            size = self.exe.pointer_size_in_bytes
        return int.from_bytes(self.mem_read(address, size), self.exe.byte_order().value)

    def mem_write_int(self, address: int, value: int, size: int | None = None):
        """
        Read an integer from memory at the given address. The default for the size parameter is
        the pointer size of the emulated executable.
        """
        if size is None:
            size = self.exe.pointer_size_in_bytes
        return self.mem_write(address, value.to_bytes(size, self.exe.byte_order().value))

    @abstractmethod
    def _reset(self):
        """
        Called as part of `refinery.lib.emulator.Emulator.reset`.
        """

    def _init(self):
        """
        Called at the very end of the object initializer. Can be overridden by child classes to
        initialize variables that do not depend on the emulator engine to be ready.
        """

    @abstractmethod
    def _emulate(self, start: int, end: int | None = None):
        """
        This is the tail call of `refinery.lib.emulator.Emulator.emulate`.
        """

    @abstractmethod
    def halt(self):
        """
        Causes the emulation to halt, usually when called from a hook.
        """

    @abstractmethod
    def _set_register(self, register: _R, v: int):
        """
        Called as part of `refinery.lib.emulator.Emulator.set_register`.
        """

    @abstractmethod
    def _get_register(self, register: _R) -> int:
        """
        Called as part of `refinery.lib.emulator.Emulator.get_register`.
        """

    @abstractmethod
    def _lookup_register(self, var: str | _R) -> Register[_R]:
        """
        Called as part of `refinery.lib.emulator.Emulator.lookup_register`.
        """

    @abstractmethod
    def _map(self, address: int, size: int):
        """
        Called as part of `refinery.lib.emulator.Emulator.map`.
        """

    @abstractmethod
    def _mem_write(self, address: int, data: bytes):
        ...

    @abstractmethod
    def _mem_read(self, address: int, size: int) -> bytes:
        ...

    @abstractmethod
    def malloc(self, size: int) -> int:
        """
        Allocate (i.e. map) the given amount of memory in the emulator's memory space.
        """

    @abstractmethod
    def _enable_single_step(self):
        """
        Enable single stepping.
        """

    @abstractmethod
    def _disable_single_step(self):
        """
        Disable single stepping.
        """

    @abstractmethod
    def morestack(self):
        """
        Allocate more memory for the stack to grow into.
        """

    def mem_write(self, address: int, data: bytes):
        """
        Write data to already mapped memory.
        """
        for retry in (False, True):
            try:
                return self._mem_write(address, data)
            except Exception as E:
                size = len(data)
                if retry or not self.hooks.MemoryError or not self.hook_mem_error(
                    None, 0, address, size, 0, self.state
                ):
                    raise FailedWrite(address, data) from E

    def mem_read(self, address: int, size: int) -> bytes:
        """
        Read data from the emulator's mapped memory.
        """
        for retry in (False, True):
            try:
                return self._mem_read(address, size)
            except Exception as E:
                if retry or not self.hooks.MemoryError or not self.hook_mem_error(
                    None, 0, address, size, 0, self.state
                ):
                    raise FailedRead(address, size) from E
        assert False

    def lookup_register(self, var: str | _R | Register[_R]):
        """
        Return the `refinery.lib.emulator.Register` for the given name or code. `Register` type
        inputs are passed through unaltered.
        """
        if isinstance(var, Register):
            return var
        return self._lookup_register(var)

    def _map_update(self):
        """
        This function can be implemented by a child class to update the internal memory maps before
        resizing a requested mapping to fit with the already existing maps.
        """

    def is_mapped(self, address: int, size: int = 1):
        """
        Can be used to test whether a certain amount of memory at a given address is already mapped.
        """
        self._map_update()
        for interval in self._memorymap.overlap(address, size):
            if sum(interval) >= address + size:
                return True
        return False

    def map(self, address: int, size: int, update_map=True):
        """
        Map memory of the given size at the given address. This function does not fail when part
        of the memory is already mapped; it will instead map only the missing pieces.
        """
        if size <= 0:
            return
        if update_map:
            self._map_update()
        lower = address
        upper = address + size
        for start, value in self._memorymap.overlap(address, size):
            pivot = start + value
            a = start - lower
            b = upper - pivot
            if a >= 0 and b >= 0:
                self.map(lower, a, update_map=False)
                self.map(pivot, b, update_map=False)
                return
            if a >= 0:
                upper = start
            if b >= 0:
                lower = pivot
            if lower >= upper:
                return
        self._map(lower, upper - lower)
        self._memorymap.addi(address, size)

    @property
    def sp(self):
        """
        The stack pointer.
        """
        return self.get_register(self._reg_sp)

    @sp.setter
    def sp(self, value: int):
        return self.set_register(self._reg_sp, value)

    @property
    def rv(self):
        """
        The return value.
        """
        return self.get_register(self._reg_rv)

    @rv.setter
    def rv(self, value: int):
        return self.set_register(self._reg_rv, value)

    @property
    def ip(self):
        """
        The instruction pointer.
        """
        return self.get_register(self._reg_ip)

    @ip.setter
    def ip(self, value: int):
        return self.set_register(self._reg_ip, value)

    def measure_register_size(self, reg: _R) -> int:
        """
        Measures the size of a register by writing a very large number to it with all bits set,
        subsequently reading the register value, and counting the number of bits in the
        measurement. Props for this one go to Matthieu Walter who originally proposed it as a
        joke; I have not found a better way to do this for uncooperative emulators.
        """
        val = self._get_register(reg)
        self._set_register(reg, (1 << 512) - 1)
        q, r = divmod(self._get_register(reg).bit_length(), 8)
        assert r == 0
        self._set_register(reg, val)
        return q

    def set_return_address(self, address: int):
        if (arch := self.exe.arch()) in (Arch.X32, Arch.X64):
            self.push(address)
        elif arch == Arch.ARM64:
            self.set_register('x30', address)
        elif arch == Arch.ARM32:
            self.set_register('r14', address)
        elif arch in (Arch.PPC32, Arch.PPC64):
            self.set_register('lr', address)
        elif arch in (Arch.MIPS16, Arch.MIPS32, Arch.MIPS64):
            self.set_register('re', address)
        elif arch in (Arch.SPARC32, Arch.SPARC64):
            self.set_register('i7', address)

    def push(self, val: int, size: int | None = None):
        """
        Push the given integer value to the stack. If the `size` parameter is missing, the function
        will push a machine word sized value.
        """
        if size is None:
            size = self.exe.pointer_size // 8
        tos = self.sp - size
        for already_retried_once in (False, True):
            try:
                self.mem_write(tos, val.to_bytes(size, self.exe.byte_order().value))
            except Exception:
                if already_retried_once:
                    raise
                self.morestack()
            else:
                self.sp = tos
                break

    def pop(self, size: int | None = None):
        """
        Pop an integer value from the stack. If the `size` parameter is missing, the function will
        pop a machine word sized value.
        """
        if size is None:
            size = self.exe.pointer_size // 8
        sp = self.sp
        sv = int.from_bytes(self.mem_read(sp, size), self.exe.byte_order().value)
        self.sp = sp + size
        return sv

    def push_register(self, reg: str | _R | Register[_R]):
        """
        Push the contents of the given register to the stack.
        """
        reg = self.lookup_register(reg)
        val = self.get_register(reg.code)
        self.push(val, reg.size)

    def align(self, value, down=False):
        """
        Align the given value according to the emulator's alignment setting. If the `down` parameter
        is set, it will return the nearest lower address instead of the nearest higher one.
        """
        return align(self.align_size, value, down=down)

    def set_register(self, register: str | _R | Register[_R], value: int):
        """
        Write the given value to the given CPU register.
        """
        r = self.lookup_register(register)
        return self._set_register(r.code, value)

    def get_register(self, register: str | _R | Register[_R]) -> int:
        """
        Read the contents of the given CPU register.
        """
        r = self.lookup_register(register)
        return self._get_register(r.code)

    def hook_code_execute(self, emu: _E, address: int, size: int, state: _T | None = None) -> bool:
        """
        Called when code execution is hooked.
        """
        return True

    def hook_code_error(self, emu: _E, state: _T | None = None) -> bool:
        """
        Called when code errors are hooked.
        """
        self.halt()
        return False

    def hook_mem_read(self, emu: _E, access: int, address: int, size: int, value: int, state: _T | None = None) -> bool:
        """
        Called when memory reads are hooked.
        """
        return True

    def hook_mem_write(self, emu: _E, access: int, address: int, size: int, value: int, state: _T | None = None) -> bool:
        """
        Called when memory writes are hooked.
        """
        return True

    def hook_mem_error(self, emu: _E | None, access: int, address: int, size: int, value: int, state: _T | None = None) -> bool:
        """
        Called when memory errors are hooked.
        """
        try:
            self.map(self.align(address, down=True), self.alloc_size)
        except Exception:
            pass
        return True

    def hook_api_call(self, emu: _E, name: str, cb=None, args=()) -> Any:
        return None

    def disassemble_instruction(self, address: int):
        """
        Disassemble a single instruction at the given address.
        """
        if not self._resetonce:
            self.reset()
        cs = self.exe.disassembler()
        cs.detail = True
        data = self.mem_read(address, 0x20)
        return next(cs.disasm(data, address, 1))

    def general_purpose_registers(self):
        """
        A generator that lists the general purpose registers for the current architecture. The
        implementation is currently incomplete and only has support for the Intel architectures.
        For other architectures, this is an empty generator.
        """
        arch = self.exe.arch()
        regs = []
        if arch is Arch.X32:
            regs = ('eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp')
        elif arch is Arch.X64:
            regs = ('rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15')
        for reg in regs:
            yield self._lookup_register(reg)


class RawMetalEmulator(Emulator[_E, _R, _T]):
    """
    The base class for emulators whose engine does not provide any abstraction layer on top of the
    CPU itself. This class implements helper functions to map the associated executable segments
    to memory, and implements the heap and stack.
    """

    def _map_stack_and_heap(self):
        alloc = self.alloc_size
        limit = 1 << (self.exe.pointer_size - 1)
        # unknown and not fully understood bug in unicorn
        limit = min(0x10000000000000, limit)
        limit = limit - alloc
        image = self.exe.image_defined_address_space()
        upper = self.align(image.upper)
        lower = self.align(image.lower, down=True)
        stack_size = 3 * alloc
        if upper + 5 * alloc < limit:
            self.stack_base = limit - stack_size
            self.alloc_base = upper
        elif lower > 5 * alloc:
            self.stack_base = lower - stack_size
            self.alloc_base = 0
        elif upper + 3 * alloc < limit and lower > 2 * alloc:
            self.stack_base = limit - stack_size
            self.alloc_base = 0
        else:
            raise RuntimeError(
                'Unable to find sufficient space for heap and stack with '
                F'allocation size of 0x{alloc:X}.')
        self.stack_size = stack_size
        self.map(self.stack_base, self.stack_size)
        self.sp = self.stack_base + self.stack_size - self.alloc_size

    def _map_segments(self):
        exe = self.exe
        img = exe.data
        mem = IntIntervalUnion()
        for segment in exe.segments():
            if not segment.virtual:
                continue
            base = self.align(segment.virtual.lower, down=True)
            size = self.align(segment.virtual.upper) - base
            size = max(size, len(segment.physical))
            mem.addi(base, size)
        it = iter(mem)
        nc = NopCodeByArch[exe.arch()]
        for addr, size in it:
            sled = nc * (size // len(nc))
            self.map(addr, size)
            self.mem_write(addr, sled)
        for segment in exe.segments():
            pm = segment.physical
            vm = segment.virtual
            if len(pm) <= 0:
                continue
            self.mem_write(vm.lower, bytes(img[pm.slice()]))

    def _init(self):
        self.trampoline = None
        self.imports = [symbol
            for symbol in self.exe.symbols() if symbol.function and symbol.imported]

    def _reset(self):
        self.trampoline = None

    def _install_api_trampoline(self):
        if self.trampoline is None:
            symbol_count = len(self.imports)
            t = self.malloc(symbol_count)
            c = RetCodeByArch[self.exe.arch()].ljust(RetCodeMaxLen, B'\0')
            self.mem_write(t, c * symbol_count)
            for k, symbol in enumerate(self.imports):
                self.mem_write_int(symbol.address, t + (k * RetCodeMaxLen))
            self.trampoline = t

    def _hook_api_call_check(self, emu: _E, address: int, size: int, state: _T | None = None) -> bool:
        if (t := self.trampoline) is None:
            return True
        index, misaligned = divmod(address - t, RetCodeMaxLen)
        if misaligned:
            return True
        if not 0 <= index < len(symbols := self.imports):
            return True
        symbol = symbols[index]
        if name := symbol.name:
            if name.endswith('IsDebuggerPresent'):
                self.rv = 0
            self.hook_api_call(emu, name, None, ())
        return True

    def morestack(self):
        self.stack_base -= self.alloc_size
        self.stack_size += self.alloc_size
        self.map(self.stack_base, self.alloc_size)

    def malloc(self, size: int) -> int:
        size = self.align(size)
        self.map(self.alloc_base, size)
        addr = self.alloc_base
        self.alloc_base += size
        return addr
