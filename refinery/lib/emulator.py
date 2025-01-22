#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
This module implements an emulator abstraction layer.
"""
from __future__ import annotations
from typing import Dict, List, Any, Generic, TypeVar, Optional, Iterator, Union
from typing import TYPE_CHECKING

from abc import ABC, abstractmethod
from enum import IntFlag
from functools import lru_cache, cached_property, partial

from refinery.lib.executable import align, Arch, ET, BO, Executable, ExecutableCodeBlob
from refinery.lib.tools import NoLogging
from refinery.lib.vfs import VirtualFileSystem
from refinery.units import RefineryImportMissing

if TYPE_CHECKING:
    from capstone import Cs
    from speakeasy import Speakeasy as Se
    from speakeasy.memmgr import MemMap
    from unicorn import Uc
    from icicle import Icicle as Ic
    from intervaltree import Interval
else:
    class Cs: pass
    class Uc: pass
    class Ic: pass
    class Se: pass


_T = TypeVar('_T')
_E = TypeVar('_E')
_R = TypeVar('_R')


class MissingModule:
    """
    This class can wrap a module import that is currently missing. If any attribute of the missing
    module is accessed, it raises `refinery.units.RefineryImportMissing`.
    """
    def __init__(self, name, dist=None):
        self.name = name
        self.dist = dist or name

    def __getattr__(self, key: str):
        if key.startswith('__') and key.endswith('__'):
            raise AttributeError(key)
        raise RefineryImportMissing(self.name, self.dist)


try:
    with NoLogging():
        import unicorn as uc
    # import unicorn.x86_const
    # import unicorn.arm64_const
    # import unicorn.mips_const
    # import unicorn.sparc_const
    # try:
    #     import unicorn.ppc_const
    # except ImportError:
    #     pass
except ImportError:
    uc = MissingModule('unicorn')
try:
    import speakeasy.profiler as se_profiler
    import speakeasy.windows.objman as se_objman
    import speakeasy as se
except ImportError:
    se = MissingModule('speakeasy-emulator')
try:
    import icicle as ic
except ImportError:
    ic = MissingModule('icicle-emu')
try:
    import capstone as cs
except ImportError:
    cs = MissingModule('capstone')
try:
    import intervaltree
except ImportError:
    intervaltree = MissingModule('intervaltree')


class EmulationError(Exception):
    """
    Base class for any exceptions raised by emulators.
    """
    pass


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
    size: Optional[int]
    """
    If not `None`, this property contains the size of the register in bytes.
    """

    def __init__(self, name: str, code: _R, size: Optional[int] = 0):
        self.name = name
        self.code = code
        self.size = size

    def __eq__(self, other: Register):
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


class Emulator(ABC, Generic[_E, _R, _T]):
    """
    The emulator base class.
    """

    state: _T

    def __init__(
        self,
        data: Union[Executable, bytes, bytearray, memoryview],
        base: Optional[int] = None,
        arch: Optional[Arch] = None,
        hooks: Hook = Hook.OnlyErrors,
        align_size: int = 0x1000,
        alloc_size: int = 0x1000,
    ):
        if isinstance(data, Executable):
            exe = data
        try:
            exe = Executable.Load(data)
        except ValueError:
            exe = ExecutableCodeBlob(data, base, arch)
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
            Arch.ARM32   : ('sp',  'ip',  'r0' ), # noqa
            Arch.ARM64   : ('sp',  'ip',  'r0' ), # noqa
            Arch.MIPS16  : ('sp',  'pc',  '0'  ), # noqa
            Arch.MIPS32  : ('sp',  'pc',  'v0' ), # noqa
            Arch.MIPS64  : ('sp',  'pc',  'v0' ), # noqa
            Arch.SPARC32 : ('sp',  'pc',  'o0' ), # noqa
            Arch.SPARC64 : ('sp',  'pc',  'o0' ), # noqa
        }[exe.arch()]

        self._init()

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

    def reset(self, state: Optional[_T] = None):
        """
        This function resets the emulator to an initial state. This will create a new instance of
        the underlying emulator engine, map the input executable to memory, and install any of the
        requested hooks.
        """
        self._resetonce = True
        self._memorymap = intervaltree.IntervalTree()
        self.state = state
        self._reset()

    def emulate(self, start: int, end: Optional[int] = None):
        """
        Call this function to begin emulation. The `start` parameter is the address where execution
        should begin, the `end` parameter is an optional address to halt at.
        """
        if not self._resetonce:
            self.reset()
        exe = self.exe
        start = start - exe.base + self.base
        if end is not None:
            end = end - exe.base + self.base
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
        pass

    @abstractmethod
    def _emulate(self, start: int, end: Optional[int] = None):
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
    def _lookup_register(self, var: Union[_R, int]) -> Register[_R]:
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
    def morestack(self):
        """
        Allocate more memory for the stack to grow into.
        """
        ...

    def lookup_register(self, var: Union[str, _R, Register[_R]]):
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
        pass

    def is_mapped(self, address: int, size: int = 1):
        """
        Can be used to test whether a certain amount of memory at a given address is already mapped.
        """
        self._map_update()
        for interval in self._memorymap.overlap(address, address + size - 1):
            interval: Interval
            if address in range(interval.begin, interval.end + 1):
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
        for interval in self._memorymap.overlap(lower, upper - 1):
            interval: Interval
            ivend = interval.end + 1
            a = interval.begin - lower
            b = upper - ivend
            if a >= 0 and b >= 0:
                self.map(lower, a, update_map=False)
                self.map(ivend, b, update_map=False)
                return
            if a >= 0:
                upper = interval.begin
            if b >= 0:
                lower = ivend
            if lower >= upper:
                return
        self._memorymap.addi(lower, upper - 1)
        self._map(lower, upper - lower)

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

    def push(self, val: int, size: Optional[int] = None):
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

    def pop(self, size: Optional[int] = None):
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

    def push_register(self, reg: Union[int, str, Register[_R]]):
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

    def set_register(self, register: Union[int, str, Register[_R]], value: int):
        """
        Write the given value to the given CPU register.
        """
        register = self.lookup_register(register)
        return self._set_register(register.code, value)

    def get_register(self, register: Union[int, str, Register[_R]]) -> int:
        """
        Read the contents of the given CPU register.
        """
        register = self.lookup_register(register)
        return self._get_register(register.code)

    def hook_code_execute(self, emu: _E, address: int, size: int, state: Optional[_T] = None) -> bool:
        """
        Called when code execution is hooked.
        """
        return True

    def hook_code_error(self, emu: _E, state: Optional[_T] = None) -> bool:
        """
        Called when code errors are hooked.
        """
        self.halt()
        return False

    def hook_mem_read(self, emu: _E, access: int, address: int, size: int, value: int, state: Optional[_T] = None) -> bool:
        """
        Called when memory reads are hooked.
        """
        return True

    def hook_mem_write(self, emu: _E, access: int, address: int, size: int, value: int, state: Optional[_T] = None) -> bool:
        """
        Called when memory writes are hooked.
        """
        return True

    def hook_mem_error(self, emu: _E, access: int, address: int, size: int, value: int, state: Optional[_T] = None) -> bool:
        """
        Called when memory errors are hooked.
        """
        try:
            self.map(self.align(address, down=True), self.alloc_size)
        except Exception:
            pass
        return True

    def hook_api_call(self, emu: _E, api_name: str, func: str, *args, **kwargs) -> bool:
        return True

    def disassemble_instruction(self, address: int):
        """
        Disassemble a single instruction at the given address.
        """
        ea = address - self.base + self.exe.base
        cs = self.disassembler()
        cs.detail = True
        pa = self.exe.location_from_address(ea).physical.position
        return next(cs.disasm(bytes(self.exe.data[pa:pa + 0x20]), address, 1))

    @lru_cache
    def disassembler(self) -> Cs:
        """
        Create a capstone disassembler that matches the emulator's architecture.
        """
        cs_arch, cs_mode = {
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
        }[self.exe.arch()]

        cs_mode |= {
            BO.BE: cs.CS_MODE_BIG_ENDIAN,
            BO.LE: cs.CS_MODE_LITTLE_ENDIAN,
        }[self.exe.byte_order()]

        return cs.Cs(cs_arch, cs_mode)

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
                U'Unable to find sufficient space for heap and stack with '
                F'allocation size of 0x{alloc:X}.')
        self.stack_size = stack_size
        self.map(self.stack_base, self.stack_size)
        self.sp = self.stack_base + self.stack_size - self.alloc_size

    def _map_segments(self):
        exe = self.exe
        img = exe.data
        mem = intervaltree.IntervalTree()
        for segment in exe.segments():
            if not segment.virtual:
                continue
            mem.addi(
                self.align(segment.virtual.lower, down=True),
                self.align(segment.virtual.upper))
        mem.merge_overlaps()
        it: Iterator[Interval] = iter(mem)
        for interval in it:
            self.map(interval.begin, interval.end - interval.begin)
        for segment in exe.segments():
            pm = segment.physical
            vm = segment.virtual
            if len(pm) <= 0:
                continue
            self.mem_write(vm.lower, bytes(img[pm.slice()]))

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
        uc_arch, uc_mode = {
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
        }[self.exe.arch()]

        uc_mode |= {
            BO.BE: uc.UC_MODE_BIG_ENDIAN,
            BO.LE: uc.UC_MODE_LITTLE_ENDIAN,
        }[self.exe.byte_order()]

        self.unicorn = uc.Uc(uc_arch, uc_mode)

        self._map_segments()
        self._map_stack_and_heap()

        if self.hooked(Hook.ApiCall):
            raise NotImplementedError(F'{self.__class__.__name__} cannot hook API calls.')

        for hook, flag, callback in [
            (uc.UC_HOOK_CODE,           Hook.CodeExecute, self.hook_code_execute ),  # noqa
            (uc.UC_HOOK_INSN_INVALID,   Hook.CodeError,   self.hook_code_error   ),  # noqa
            (uc.UC_HOOK_MEM_READ_AFTER, Hook.MemoryRead,  self.hook_mem_read     ),  # noqa
            (uc.UC_HOOK_MEM_WRITE,      Hook.MemoryWrite, self.hook_mem_write    ),  # noqa
            (uc.UC_HOOK_MEM_INVALID,    Hook.MemoryError, self.hook_mem_error    ),  # noqa
        ]:
            if self.hooked(flag):
                self.unicorn.hook_add(hook, callback, user_data=self.state)

    def _init(self):
        self._reg_by_name: Dict[str, Register[int]] = {}
        self._reg_by_code: Dict[int, Register[int]] = {}
        for module in [
            uc.x86_const,
            uc.arm_const,
            uc.sparc_const,
            uc.mips_const,
        ]:
            md: Dict[str, Any] = module.__dict__
            for name, code in md.items():
                try:
                    u, *_, kind, name = name.split('_')
                except Exception:
                    continue
                if kind != 'REG' or u != 'UC':
                    continue
                name = name.casefold()
                reg = Register(name, code)
                self._reg_by_name[name] = reg
                self._reg_by_code[code] = reg

    def _emulate(self, start: int, end: Optional[int] = None):
        if end is None:
            end = self.exe.location_from_address(start).virtual.box.upper
        try:
            self.unicorn.emu_start(start, end)
        except uc.UcError as E:
            raise EmulationError(str(E)) from E

    def halt(self):
        self.unicorn.emu_stop()

    def _lookup_register(self, var: Union[str, int]) -> Register[int]:
        reg = None
        if isinstance(var, str):
            reg = self._reg_by_name[var.casefold()]
        if isinstance(var, int):
            reg = self._reg_by_code[var]
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
        ...

    def _reset(self):
        exe = self.exe

        try:
            arch = {
                Arch.X32   : 'i686',
                Arch.X64   : 'x86_64',
            }[exe.arch()]
        except KeyError:
            arch = None
        if arch not in ic.architectures():
            raise NotImplementedError(F'Icicle cannot handle executables of arch {exe.arch().name}')

        if self.hooked(Hook.ApiCall):
            raise NotImplementedError(F'{self.__class__.__name__} cannot hook API calls.')

        if self.hooks & Hook.Memory:
            raise NotImplementedError(U'Icicle does not support memory hooks yet.')

        self.icicle = ice = ic.Icicle(arch)
        self.regmap = {reg.casefold(): val[1] for reg, val in ice.reg_list().items()}

        self._map_segments()
        self._map_stack_and_heap()

    def _emulate(self, start: int, end: Optional[int] = None):
        dasm = self.disassembler()
        code = False
        RS = ic.RunStatus
        emu = self.icicle

        if self.hooked(Hook.CodeExecute):
            code = True
            step = partial(emu.step, 1)
        elif end is not None:
            step = partial(emu.run_until, end)
        else:
            step = emu.run

        self.ip = ip = start

        while True:
            if code:
                op = next(dasm.disasm(self.exe[ip:ip + 12], ip, 1))
                self.hook_code_execute(emu, ip, op._raw.size, self.state)

            status = step()

            if status == RS.InstructionLimit:
                ip = self.ip
                continue

            if status in (
                RS.Breakpoint,
                RS.Halt,
                RS.Killed,
            ):
                break
            if status == RS.UnhandledException:
                raise EmulationError(emu.exception_code.name)
            if status != RS.Running:
                raise EmulationError(status.name)

    def halt(self):
        self.icicle.add_breakpoint(self.ip)

    def _lookup_register(self, var: str) -> Register[str]:
        name = var.casefold()
        size = self.regmap[name]
        return Register(name, name, size)

    def _map(self, address: int, size: int):
        MP = ic.MemoryProtection
        if self.hooked(Hook.MemoryRead):
            perm = MP.ExecuteRead
        elif self.hooked(Hook.MemoryWrite):
            perm = MP.ExecuteRead
        else:
            perm = MP.ExecuteReadWrite
        return self.icicle.mem_map(address, size, perm)

    def _set_register(self, reg: str, value: int) -> None:
        return self.icicle.reg_write(reg, value)

    def _get_register(self, reg: str) -> int:
        return self.icicle.reg_read(reg)

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
        self._regs: Dict[str, Register[str]] = {}

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

        emu.emu.timeout = 0

        if self.hooked(Hook.CodeExecute):
            emu.add_code_hook(self.hook_code_execute, ctx=self.state)

        if self.hooked(Hook.MemoryRead):
            emu.add_mem_read_hook(self.hook_mem_read)

        if self.hooked(Hook.MemoryWrite):
            emu.add_mem_write_hook(self.hook_mem_write)

        if self.hooked(Hook.MemoryError):
            emu.add_mem_invalid_hook(self.hook_mem_error)

        if self.hooked(Hook.ApiCall):
            emu.add_api_hook(self.hook_api_call, '*', '*')

    @property
    def stack_region(self):
        emu = self.speakeasy
        tos = self.sp
        mms: List[MemMap] = emu.get_mem_maps()
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
            self._memorymap.addi(a, b)

    def malloc(self, size: int) -> int:
        return self.speakeasy.mem_alloc(size)

    def morestack(self):
        spksy = self.speakeasy
        stack = self.stack_region
        base = stack.base - self.alloc_size
        spksy.emu.mem_map(self.alloc_size, base)
        stack.base = base
        stack.size = stack.size + self.alloc_size

    def _emulate(self, start: int, end: Optional[int] = None):
        emu = self.speakeasy

        def stackfix(emu, address: int, size: int, ctx: list):
            if not ctx:
                stack = self.stack_region
                self.sp = stack.base + stack.size // 3
                ctx.append(True)
            return True

        emu.add_code_hook(stackfix, start, start, ctx=[])

        if end is not None:
            def _terminate(*_):
                emu.stop()
            emu.add_code_hook(_terminate, end, end + 1)

        if self.exe.blob:
            emu.run_shellcode(start)
        else:
            inner = emu.emu
            inner.stack_base, stack_addr = inner.alloc_stack(self.stack_size)
            inner.set_func_args(inner.stack_base, inner.return_hook)
            run = se_profiler.Run()
            run.type = 'thread'
            run.start_addr = start
            run.instr_cnt = 0
            run.args = ()
            inner.add_run(run)
            if not (p := inner.init_container_process()):
                p = se_objman.Process(self)
            inner.processes.append(p)
            inner.curr_process = p
            if mm := inner.get_address_map(start):
                mm.set_process(inner.curr_process)
            t = se_objman.Thread(inner, stack_base=inner.stack_base, stack_commit=self.stack_size)
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
