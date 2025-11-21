"""
Implements `refinery.lib.emulator.interface.RawMetalEmulator` for the unicorn backend.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, TypeVar

from refinery.lib.emulator.abstract import EmulationError, RawMetalEmulator, Register
from refinery.lib.executable import BO, Arch
from refinery.lib.shared import unicorn as uc

if TYPE_CHECKING:
    from unicorn.unicorn import Uc
else:
    class Uc:
        pass

_T = TypeVar('_T')


class UnicornEmulator(RawMetalEmulator[Uc, int, _T]):
    """
    A Unicorn-based emulator.
    """

    unicorn: Uc

    def _reset(self):
        super()._reset()

        uc_arch, uc_mode = {
            Arch.X32     : (uc.UC_ARCH_X86,   uc.UC_MODE_32),  # noqa
            Arch.X64     : (uc.UC_ARCH_X86,   uc.UC_MODE_64),  # noqa
            Arch.ARM32   : (uc.UC_ARCH_ARM,   uc.UC_MODE_ARM), # noqa
            Arch.ARM64   : (uc.UC_ARCH_ARM64, uc.UC_MODE_ARM), # noqa
            Arch.MIPS16  : (uc.UC_ARCH_MIPS,  uc.UC_MODE_16),  # noqa
            Arch.MIPS32  : (uc.UC_ARCH_MIPS,  uc.UC_MODE_32),  # noqa
            Arch.MIPS64  : (uc.UC_ARCH_MIPS,  uc.UC_MODE_64),  # noqa
            Arch.PPC32   : (uc.UC_ARCH_PPC,   uc.UC_MODE_32),  # noqa
            Arch.PPC64   : (uc.UC_ARCH_PPC,   uc.UC_MODE_64),  # noqa
            Arch.SPARC32 : (uc.UC_ARCH_SPARC, uc.UC_MODE_32),  # noqa
            Arch.SPARC64 : (uc.UC_ARCH_SPARC, uc.UC_MODE_V9),  # noqa
        }[self.exe.arch()]

        uc_mode |= {
            BO.BE: uc.UC_MODE_BIG_ENDIAN,
            BO.LE: uc.UC_MODE_LITTLE_ENDIAN,
        }[self.exe.byte_order()]

        self.unicorn = uc.unicorn.Uc(uc_arch, uc_mode)
        self._single_step_hook = None

        self._map_segments()
        self._map_stack_and_heap()

        if self.hooks.ApiCall:
            self._install_api_trampoline()
            self.unicorn.hook_add(uc.UC_HOOK_CODE, self._hook_api_call_check, user_data=self.state)

        for hook, hooked, callback in [
            (uc.UC_HOOK_CODE,           self.hooks.CodeExecute, self.hook_code_execute ),  # noqa
            (uc.UC_HOOK_INSN_INVALID,   self.hooks.CodeError,   self.hook_code_error   ),  # noqa
            (uc.UC_HOOK_MEM_READ,       self.hooks.MemoryRead,  self.hook_mem_read     ),  # noqa
            (uc.UC_HOOK_MEM_WRITE,      self.hooks.MemoryWrite, self.hook_mem_write    ),  # noqa
            (uc.UC_HOOK_MEM_INVALID,    self.hooks.MemoryError, self.hook_mem_error    ),  # noqa
        ]:
            if hooked:
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

    def _set_register(self, register: int, v: int) -> None:
        return self.unicorn.reg_write(register, v)

    def _get_register(self, register: int) -> int:
        value = self.unicorn.reg_read(register)
        if isinstance(value, int):
            return value
        else:
            combined = 0
            for v in reversed(value):
                combined <<= 64
                combined |= v
            return combined

    def _mem_write(self, address: int, data: bytes):
        return self.unicorn.mem_write(address, data)

    def _mem_read(self, address: int, size: int):
        return self.unicorn.mem_read(address, size)
