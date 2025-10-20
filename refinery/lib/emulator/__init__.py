"""
This module implements an emulator abstraction layer.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from enum import IntFlag, Enum
from functools import cached_property, partial
from typing import TYPE_CHECKING, Any, Generic, TypeVar

from refinery.lib.executable import BO, ET, Arch, Executable, ExecutableCodeBlob, align
from refinery.lib.intervals import IntIntervalUnion
from refinery.lib.shared import icicle as ic
from refinery.lib.shared import speakeasy as se
from refinery.lib.shared import unicorn as uc
from refinery.lib.vfs import VirtualFileSystem

if TYPE_CHECKING:
    from icicle import Icicle as Ic
    from speakeasy import Speakeasy as Se
    from speakeasy.common import CodeHook
    from speakeasy.common import Hook as SeHook
    from speakeasy.memmgr import MemMap
    from unicorn import Uc
else:
    class Uc: pass
    class Ic: pass
    class Se: pass


_T = TypeVar('_T')
_E = TypeVar('_E')
_R = TypeVar('_R')


class EmulationError(Exception):
    """
    Base class for any exceptions raised by emulators.
    """


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


class Hook(IntFlag):
    """
    A bit mask flag for the types of hooks that are requested from an emulator.
    """
    CodeExecute  = 0b000_00001  # noqa
    CodeError    = 0b000_00010  # noqa
    MemoryRead   = 0b000_00100  # noqa
    MemoryWrite  = 0b000_01000  # noqa
    MemoryError  = 0b000_10000  # noqa
    ApiCall      = 0b001_00000  # noqa

    OnlyErrors   = 0b000_10010  # noqa
    Default      = 0b000_11111  # noqa
    Everything   = 0b111_11111  # noqa
    Nothing      = 0b000_00000  # noqa
    MemoryAccess = 0b000_01100  # noqa
    Memory       = 0b000_11100  # noqa
    NoErrors     = 0b001_01101  # noqa


_NOP_CODE = {
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

_RET_CODE = {
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

_NOP_SIZE = max(len(c) for c in _NOP_CODE.values())
_RET_SIZE = max(len(c) for c in _RET_CODE.values())


class Emulator(ABC, Generic[_E, _R, _T]):
    """
    The emulator base class.
    """

    state: _T

    def __init__(
        self,
        data: Executable | bytes | bytearray | memoryview,
        base: int | None = None,
        arch: Arch | None = None,
        hooks: Hook = Hook.OnlyErrors,
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

    def get_function_argument(self, k: int, cc: CC = CC.StdCall, size: int | None = None) -> int:
        arch = self.exe.arch()
        if k < 0:
            raise ValueError(k)
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
            reg = regs[k]
        except IndexError:
            return self.mem_read_int(self.sp + (k - len(regs)) * self.exe.pointer_size_in_bytes)
        else:
            arg = self.get_register(reg)
            if size is not None:
                arg &= (1 << (size << 3)) - 1
            return arg

    @cached_property
    def _reg_sp(self):
        return self._lookup_register(self._sp).code

    @cached_property
    def _reg_ip(self):
        return self._lookup_register(self._ip).code

    @cached_property
    def _reg_rv(self):
        return self._lookup_register(self._rv).code

    def hooked(self, hook: Hook) -> bool:
        """
        Return whether the given hook is (supposed to be) set.
        """
        return self.hooks & hook == hook

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

    def call(self, function: int):
        """
        Call the function at the given address. When the function returns, emulation will halt.
        """
        try:
            tp = self._trampoline
        except AttributeError:
            rs = self.exe.pointer_size // 8
            tp = self._trampoline = self.malloc(rs)
            self.mem_write(tp, B'\x90' * rs)
        self.push(tp)
        self.emulate(function, tp)

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
        ...

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
        ...

    @abstractmethod
    def halt(self):
        """
        Causes the emulation to halt, usually when called from a hook.
        """
        ...

    @abstractmethod
    def _set_register(self, register: _R, v: int):
        """
        Called as part of `refinery.lib.emulator.Emulator.set_register`.
        """
        ...

    @abstractmethod
    def _get_register(self, register: _R) -> int:
        """
        Called as part of `refinery.lib.emulator.Emulator.get_register`.
        """
        ...

    @abstractmethod
    def _lookup_register(self, var: _R | int) -> Register[_R]:
        """
        Called as part of `refinery.lib.emulator.Emulator.lookup_register`.
        """
        ...

    @abstractmethod
    def _map(self, address: int, size: int):
        """
        Called as part of `refinery.lib.emulator.Emulator.map`.
        """
        ...

    @abstractmethod
    def mem_write(self, address: int, data: bytes):
        """
        Write data to already mapped memory.
        """
        ...

    @abstractmethod
    def mem_read(self, address: int, size: int) -> bytes:
        """
        Read data from the emulator's mapped memory.
        """
        ...

    @abstractmethod
    def malloc(self, size: int) -> int:
        """
        Allocate (i.e. map) the given amount of memory in the emulator's memory space.
        """
        ...

    @abstractmethod
    def _enable_single_step(self):
        """
        Enable single stepping.
        """
        ...

    @abstractmethod
    def _disable_single_step(self):
        """
        Enable single stepping.
        """
        ...

    @abstractmethod
    def morestack(self):
        """
        Allocate more memory for the stack to grow into.
        """
        ...

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

    def push_register(self, reg: int | str | Register[_R]):
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

    def set_register(self, register: int | str | Register[_R], value: int):
        """
        Write the given value to the given CPU register.
        """
        register = self.lookup_register(register)
        return self._set_register(register.code, value)

    def get_register(self, register: int | str | Register[_R]) -> int:
        """
        Read the contents of the given CPU register.
        """
        register = self.lookup_register(register)
        return self._get_register(register.code)

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

    def hook_mem_error(self, emu: _E, access: int, address: int, size: int, value: int, state: _T | None = None) -> bool:
        """
        Called when memory errors are hooked.
        """
        try:
            self.map(self.align(address, down=True), self.alloc_size)
        except Exception:
            pass
        return True

    def hook_api_call(self, emu: _E, api_name: str, cb=None, args=()) -> Any:
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

    stack_base: int
    stack_size: int
    alloc_base: int

    def _map_stack_and_heap(self):
        alloc = self.alloc_size
        limit = 1 << self.exe.pointer_size
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
        for interval in it:
            self.map(*interval)
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
            c = _RET_CODE[self.exe.arch()].ljust(_RET_SIZE, B'\0')
            self.mem_write(t, c * symbol_count)
            for k, symbol in enumerate(self.imports):
                self.mem_write_int(symbol.address, t + (k * _RET_SIZE))
            self.trampoline = t

    def _hook_api_call_check(self, emu: _E, address: int, size: int, state: _T | None = None) -> bool:
        if (t := self.trampoline) is None:
            return True
        index, misaligned = divmod(address - t, _RET_SIZE)
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


class UnicornEmulator(RawMetalEmulator[Uc, int, _T]):
    """
    A Unicorn-based emulator.
    """

    unicorn: Uc

    def _reset(self):
        super()._reset()

        uc_arch, uc_mode = {
            Arch.X32     : (uc.UC_ARCH_X86,   uc.UC_MODE_32),     # noqa
            Arch.X64     : (uc.UC_ARCH_X86,   uc.UC_MODE_64),     # noqa
            Arch.ARM32   : (uc.UC_ARCH_ARM,   uc.UC_MODE_ARM),    # noqa
            Arch.ARM64   : (uc.UC_ARCH_ARM64, uc.UC_MODE_ARM),  # noqa
            Arch.MIPS16  : (uc.UC_ARCH_MIPS,  uc.UC_MODE_16),     # noqa
            Arch.MIPS32  : (uc.UC_ARCH_MIPS,  uc.UC_MODE_32),     # noqa
            Arch.MIPS64  : (uc.UC_ARCH_MIPS,  uc.UC_MODE_64),     # noqa
            Arch.PPC32   : (uc.UC_ARCH_PPC,   uc.UC_MODE_32),     # noqa
            Arch.PPC64   : (uc.UC_ARCH_PPC,   uc.UC_MODE_64),     # noqa
            Arch.SPARC32 : (uc.UC_ARCH_SPARC, uc.UC_MODE_32),     # noqa
            Arch.SPARC64 : (uc.UC_ARCH_SPARC, uc.UC_MODE_V9),     # noqa
        }[self.exe.arch()]

        uc_mode |= {
            BO.BE: uc.UC_MODE_BIG_ENDIAN,
            BO.LE: uc.UC_MODE_LITTLE_ENDIAN,
        }[self.exe.byte_order()]

        self.unicorn = uc.Uc(uc_arch, uc_mode)
        self._single_step_hook = None

        self._map_segments()
        self._map_stack_and_heap()

        if self.hooked(Hook.ApiCall):
            self._install_api_trampoline()
            self.unicorn.hook_add(uc.UC_HOOK_CODE, self._hook_api_call_check, user_data=self.state)

        for hook, flag, callback in [
            (uc.UC_HOOK_CODE,           Hook.CodeExecute, self.hook_code_execute ),  # noqa
            (uc.UC_HOOK_INSN_INVALID,   Hook.CodeError,   self.hook_code_error   ),  # noqa
            (uc.UC_HOOK_MEM_READ_AFTER, Hook.MemoryRead,  self.hook_mem_read     ),  # noqa
            (uc.UC_HOOK_MEM_WRITE,      Hook.MemoryWrite, self.hook_mem_write    ),  # noqa
            (uc.UC_HOOK_MEM_INVALID,    Hook.MemoryError, self.hook_mem_error    ),  # noqa
        ]:
            if self.hooked(flag):
                self.unicorn.hook_add(hook, callback, user_data=self.state)

    class _singlestep:
        def __init__(self):
            self.stepped = False

        def __call__(self, uc: Uc, *_, **kw):
            if self.stepped:
                self.stepped = False
                uc.emu_stop()
            else:
                self.stepped = True

    def _enable_single_step(self):
        if self._single_step_hook is not None:
            return
        self._single_step_hook = self.unicorn.hook_add(uc.UC_HOOK_CODE, self._singlestep())

    def _disable_single_step(self):
        if hook := self._single_step_hook:
            self.unicorn.hook_del(hook)
            self._single_step_hook = None

    def _init(self):
        super()._init()
        self._reg_by_name: dict[Arch, dict[str, Register[int]]] = {}
        self._reg_by_code: dict[Arch, dict[int, Register[int]]] = {}
        for archs, module in [
            ((Arch.X32, Arch.X64), uc.x86_const),
            ((Arch.ARM32,), uc.arm_const),
            ((Arch.ARM64,), uc.arm64_const),
            ((Arch.SPARC32, Arch.SPARC64), uc.sparc_const),
            ((Arch.MIPS16, Arch.MIPS32, Arch.MIPS64), uc.mips_const),
        ]:
            md: dict[str, Any] = module.__dict__
            reg_by_name: dict[str, Register[int]] = {}
            reg_by_code: dict[int, Register[int]] = {}
            for name, code in md.items():
                try:
                    u, *_, kind, name = name.split('_')
                except Exception:
                    continue
                if kind != 'REG' or u != 'UC':
                    continue
                name = name.casefold()
                reg = Register(name, code)
                reg_by_name[name] = reg
                reg_by_code[code] = reg
            for arch in archs:
                self._reg_by_code[arch] = reg_by_code
                self._reg_by_name[arch] = reg_by_name

    def _emulate(self, start: int, end: int | None = None):
        if end is None:
            end = self.exe.location_from_address(start).virtual.box.upper
        try:
            self.unicorn.emu_start(start, end)
        except uc.UcError as E:
            raise EmulationError(str(E)) from E

    def halt(self):
        self.unicorn.emu_stop()

    def _lookup_register(self, var: str | int) -> Register[int]:
        reg = None
        arch = self.exe.arch()
        if isinstance(var, str):
            reg = self._reg_by_name[arch][var.casefold()]
        if isinstance(var, int):
            reg = self._reg_by_code[arch][var]
        if reg is None:
            raise TypeError(var)
        if reg.size is None:
            reg.size = self.measure_register_size(reg.code)
        return reg

    def _map(self, address: int, size: int):
        return self.unicorn.mem_map(address, size)

    def _set_register(self, reg: int, value: int) -> None:
        return self.unicorn.reg_write(reg, value)

    def _get_register(self, reg: int) -> int:
        return self.unicorn.reg_read(reg)

    def mem_write(self, address: int, data: bytes):
        return self.unicorn.mem_write(address, data)

    def mem_read(self, address: int, size: int):
        return self.unicorn.mem_read(address, size)


class IcicleEmulator(RawMetalEmulator[Ic, str, _T]):
    """
    An Icicle-based emulator. Icicle is a more recent emulator engine and not yet as mature as
    Unicorn. There are some compelling arguments for its robustness, but with the current
    interface it is completely lacking any memory write hook support, which makes it difficult
    to use for most of our applications. See also the [Icicle paper][ICE].

    [ICE]: https://arxiv.org/pdf/2301.13346
    """

    icicle: Ic

    def _init(self):
        super()._init()
        self._single_step = False

    def _reset(self):
        super()._reset()
        exe = self.exe

        try:
            arch = {
                Arch.X32: 'i686',
                Arch.X64: 'x86_64',
            }[exe.arch()]
        except KeyError:
            arch = None
        if arch not in ic.architectures():
            raise NotImplementedError(F'Icicle cannot handle executables of arch {exe.arch().name}')

        if self.hooked(Hook.ApiCall):
            self._install_api_trampoline()

        self.icicle = ice = ic.Icicle(arch)
        self.regmap = {reg.casefold(): val[1] for reg, val in ice.reg_list().items()}

        self._map_segments()
        self._map_stack_and_heap()

    def _enable_single_step(self):
        self._single_step = True

    def _disable_single_step(self):
        self._single_step = False

    def _emulate(self, start: int, end: int | None = None):
        RS = ic.RunStatus
        MP = ic.MemoryProtection
        ice = self.icicle

        code_hooked = self.hooked(Hook.CodeExecute)
        apis_hooked = self.hooked(Hook.ApiCall)
        mm_e_hooked = self.hooked(Hook.MemoryError)
        mm_w_hooked = self.hooked(Hook.MemoryWrite)
        mm_r_hooked = self.hooked(Hook.MemoryRead)

        halt = self._single_step
        dasm = self.exe.disassembler()
        dasm.detail = True

        if code_hooked or halt:
            step = partial(ice.step, 1)
        elif end is not None:
            step = partial(ice.run_until, end)
        else:
            step = ice.run

        self.ip = ip = start
        mprotect = []
        cb_write = None
        retrying = 0

        while True:
            insn = None
            self.ip = ip

            if (code_hooked or apis_hooked) and not retrying:
                insn = next(dasm.disasm(self.mem_read(ip, 20), 1))
                args = (ice, ip, insn.size, self.state)
                if apis_hooked:
                    self._hook_api_call_check(*args)
                if code_hooked:
                    self.hook_code_execute(*args)
            if mprotect:
                ice.mem_protect(*mprotect[-1], MP.ExecuteReadWrite)
            if (status := step()) == RS.InstructionLimit:
                for p in mprotect:
                    ice.mem_protect(*p, MP.ExecuteOnly)
                if cb_write:
                    addr, size = cb_write
                    value = self.mem_read_int(addr, size)
                    if self.hook_mem_write(ice, 0, addr, size, value, self.state) is False:
                        break
                    cb_write = None
                mprotect.clear()
                retrying = 0
                ip = self.ip
            elif status in (
                RS.Breakpoint,
                RS.Halt,
                RS.Killed,
            ):
                break
            elif status == RS.UnhandledException:
                insn = insn or next(dasm.disasm(self.mem_read(ip, 20), 1))
                size = max((op.size for op in insn.operands), default=insn.addr_size)
                EC = ic.ExceptionCode
                ea = ice.exception_value
                ec = ice.exception_code
                if ec in (EC.ReadUnmapped, EC.WriteUnmapped) and mm_e_hooked:
                    if self.hook_mem_error(ice, 0, ea, size, 0, self.state) is not False:
                        retrying += 1
                        continue
                elif ec == EC.ReadPerm and mm_r_hooked:
                    value = self.mem_read_int(ea, size)
                    if self.hook_mem_read(ice, 0, ea, size, value, self.state) is not False:
                        mprotect.append((ea, size))
                        retrying += 1
                        continue
                elif ec == EC.WritePerm and mm_w_hooked:
                    cb_write = (ea, size)
                    mprotect.append(cb_write)
                    retrying += 1
                    continue
                else:
                    raise EmulationError(ec.name)
            elif status != RS.Running:
                raise EmulationError(status.name)
            if halt:
                break

    def halt(self):
        self.icicle.add_breakpoint(self.ip)

    def _lookup_register(self, var: str) -> Register[str]:
        name = var.casefold()
        size = self.regmap[name]
        return Register(name, name, size)

    def _map(self, address: int, size: int):
        MP = ic.MemoryProtection
        if self.hooks & Hook.MemoryAccess:
            perm = MP.ExecuteOnly
        else:
            perm = MP.ExecuteReadWrite
        return self.icicle.mem_map(address, size, perm)

    def _set_register(self, register: str, v: int) -> None:
        return self.icicle.reg_write(register, v)

    def _get_register(self, register: str) -> int:
        return self.icicle.reg_read(register)

    def mem_write(self, address: int, data: bytes):
        return self.icicle.mem_write(address, data)

    def mem_read(self, address: int, size: int):
        return self.icicle.mem_read(address, size)


class SpeakeasyEmulator(Emulator[Se, str, _T]):
    """
    A Speakeasy-based emulator. Speakeasy only supports PE files, but it has support for several
    Windows API routines which can be an advantage.
    """

    speakeasy: Se

    def _init(self):
        self._regs: dict[str, Register[str]] = {}

    class _singlestep:
        def __init__(self):
            self.stepped = False

        def __call__(self, se: Se, *_, **kw):
            if self.stepped:
                self.stepped = False
                se.stop()
            else:
                self.stepped = True
            return True

    class _stackfix:
        hook: CodeHook | None

        def __init__(self, parent: SpeakeasyEmulator):
            self.hook = None
            self.parent = parent

        def __call__(self, base_emu: Se, address: int, size: int, ctx: list):
            if hook := self.hook:
                emu = self.parent
                stack = emu.stack_region
                emu.sp = stack.base + stack.size // 3
                hook.disable()

    def _reset(self):
        exe = self.exe
        if exe.type not in (ET.PE, ET.BLOB):
            raise NotImplementedError(F'Speakeasy cannot handle executables of type {exe.type.name}.')
        try:
            arch = {
                Arch.X32: 'x86',
                Arch.X64: 'x64',
            }[exe.arch()]
        except KeyError as KE:
            raise NotImplementedError(F'Speakeasy cannot handle executables of arch {exe.arch().name}') from KE

        emu = self.speakeasy = se.Speakeasy()

        with VirtualFileSystem() as vfs:
            db = bytes(exe.data)
            vf = vfs.new(db)
            if exe.blob:
                self.base = emu.load_shellcode(vf.path, data=db, arch=arch)
            else:
                self.base = emu.load_module(vf.path, data=db).get_base()

        if emu.emu is None:
            raise RuntimeError('emulator failed to initialize')

        self._end_hook_s = None
        self._end_hook_d = None

        self._single_step_hook_s = emu.add_code_hook(self._singlestep())
        self._single_step_hook_d = emu.add_dyn_code_hook(self._singlestep())
        self._disable_single_step()

        stackfix = self._stackfix(self)
        stackfix.hook = emu.add_code_hook(stackfix)

        emu.emu.timeout = 0

        # prevent memory hook from being overridden, this is a bug in speakeasy
        emu.emu.add_interrupt_hook(cb=emu.emu._hook_interrupt)
        emu.emu.builtin_hooks_set = True

        if self.hooked(Hook.CodeExecute):
            emu.add_code_hook(self.hook_code_execute, ctx=self.state)
            emu.add_dyn_code_hook(self.hook_code_execute, ctx=self.state)

        if self.hooked(Hook.MemoryRead):
            emu.add_mem_read_hook(self.hook_mem_read)

        if self.hooked(Hook.MemoryWrite):
            emu.add_mem_write_hook(self.hook_mem_write)

        if self.hooked(Hook.MemoryError):
            emu.add_mem_invalid_hook(self.hook_mem_error)

        if self.hooked(Hook.ApiCall):
            emu.add_api_hook(self.hook_api_call, '*', '*')

    def _enable_single_step(self):
        hd = self._single_step_hook_d
        hs = self._single_step_hook_s
        if hd is None or hs is None:
            raise RuntimeError('single stepping hooks failed to be installed')
        hd.cb.stepped = False
        hs.cb.stepped = False
        hd.enable()
        hs.enable()

    def _disable_single_step(self):
        if hook := self._single_step_hook_d:
            hook.disable()
        if hook := self._single_step_hook_s:
            hook.disable()

    @property
    def stack_region(self):
        emu = self.speakeasy
        tos = self.sp
        mms: list[MemMap] = emu.get_mem_maps()
        if tos != emu.get_stack_ptr():
            raise EmulationError('Unexpected stack pointer misalignment')
        try:
            sm, = (mm for mm in mms if tos in range(mm.base, mm.base + mm.size))
        except Exception:
            raise EmulationError('Ambiguous memory, unable to locate the stack.')
        return sm

    @property
    def stack_base(self):
        return self.stack_region.base

    @stack_base.setter
    def stack_base(self, value):
        raise AttributeError

    @property
    def stack_size(self):
        return self.stack_region.size

    @stack_size.setter
    def stack_size(self, value):
        raise AttributeError

    def _map_update(self):
        self._memorymap.clear()
        for a, b, _ in self.speakeasy.emu.emu_eng.emu.mem_regions():
            self._memorymap.addi(a, b - a + 1)

    def malloc(self, size: int) -> int:
        return self.speakeasy.mem_alloc(size)

    def morestack(self):
        spksy = self.speakeasy
        stack = self.stack_region
        base = stack.base - self.alloc_size
        spksy.emu.mem_map(self.alloc_size, base)
        stack.base = base
        stack.size = stack.size + self.alloc_size

    class _stop:
        hook: SeHook | None
        address: int | None

        def __init__(self, address: int | None = None):
            self.address = address
            self.hook = None

        def __call__(self, spky: Se, address: int, size: int, ctx: list):
            if hook := self.hook:
                if address == self.address:
                    spky.stop()
                    hook.disable()

    _end_hook_s: _stop | None
    _end_hook_d: _stop | None

    def _remove_hook(self, hook: SeHook | None):
        if hook is None:
            return
        hook.emu_eng.hook_del(hook.handle)
        emu = self.speakeasy.emu
        assert emu is not None
        for hooklist in emu.hooks.values():
            assert isinstance(hooklist, list)
            for k, h in enumerate(hooklist):
                if h is hook:
                    del hooklist[k]
                    break

    def _set_end(self, end: int | None):
        if h := self._end_hook_s:
            self._remove_hook(h.hook)
        if h := self._end_hook_d:
            self._remove_hook(h.hook)
        if end is None:
            self._end_hook_s = None
            self._end_hook_d = None
        else:
            self._end_hook_s = h = self._stop(end)
            h.hook = self.speakeasy.add_code_hook(h, end, end + 1)
            self._end_hook_d = h = self._stop(end)
            h.hook = self.speakeasy.add_dyn_code_hook(h)

    def _emulate(self, start: int, end: int | None = None):
        spk = self.speakeasy
        inner = spk.emu
        assert inner
        self._set_end(end)

        if inner.get_current_run():
            return spk.resume(start)

        if self.exe.blob:
            offset = start - self.base
            if offset < 0:
                raise ValueError(F'invalid offset 0x{start:X} specified; base address is 0x{self.base:X}')
            spk.run_shellcode(self.base, offset=offset)
        else:

            inner.stack_base, stack_addr = inner.alloc_stack(self.stack_size)
            inner.set_func_args(inner.stack_base, inner.return_hook)

            run = se.profiler.Run()
            run.type = 'thread'
            run.start_addr = start
            run.instr_cnt = 0
            run.args = ()

            inner.add_run(run)

            if not (p := inner.init_container_process()):
                p = se.windows.objman.Process(self)

            inner.processes.append(p)
            inner.curr_process = p
            if mm := inner.get_address_map(start):
                mm.set_process(inner.curr_process)

            t = se.windows.objman.Thread(inner, stack_base=inner.stack_base, stack_commit=self.stack_size)

            inner.om.objects.update({t.address: t})
            inner.curr_process.threads.append(t)
            inner.curr_thread = t
            peb = inner.alloc_peb(p)
            inner.init_teb(t, peb)
            inner.start()

    def halt(self):
        return self.speakeasy.stop()

    def _set_register(self, register: str, v: int):
        return self.speakeasy.reg_write(register, v)

    def _get_register(self, register: str) -> int:
        return self.speakeasy.reg_read(register)

    def _lookup_register(self, var: str) -> Register[str]:
        try:
            reg = self._regs[var]
        except KeyError:
            try:
                size = self.measure_register_size(var)
            except Exception:
                raise LookupError(var)
            else:
                reg = self._regs[var] = Register(var, var, size)
        return reg

    def _map(self, base: int, size: int):
        spksy = self.speakeasy
        if spksy.emu.get_address_map(base):
            raise ValueError(base)
        if mm := spksy.emu.get_reserve_map(base):
            mm: MemMap = spksy.emu.get_address_map(spksy.emu.mem_map_reserve(mm.base))
            if base not in range(mm.base, mm.base + mm.size):
                raise RuntimeError(F'Speakeasy claimed to map 0x{base:X} in map 0x{mm.base:X}-0x{mm.base + mm.size:X}.')
            map_size = mm.size
            map_base = mm.base
            _new_size = size - map_size + base - map_base
            _new_base = base + map_size
            if _new_size > 0 and self._map(_new_base, _new_size) != _new_base:
                raise RuntimeError(F'Attempting to remain rest of size 0x{_new_size:X} at 0x{_new_base:X} failed.')
            return base
        else:
            alloc = spksy.mem_alloc(size, base)
            if alloc != base:
                spksy.mem_free(alloc)
                raise LookupError(F'Unable to allocate {size} bytes at address 0x{base:X} because Speakeasy has reserved this region.')
            return alloc

    def mem_write(self, address: int, data: bytes):
        return self.speakeasy.mem_write(address, data)

    def mem_read(self, address: int, size: int):
        return self.speakeasy.mem_read(address, size)
