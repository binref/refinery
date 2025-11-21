"""
Implements `refinery.lib.emulator.interface.Emulator` for the speakeasy backend.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, TypeVar

from refinery.lib.emulator.abstract import EmulationError, Emulator, Register
from refinery.lib.executable import ET, Arch
from refinery.lib.shared import speakeasy as se
from refinery.lib.vfs import VirtualFileSystem

if TYPE_CHECKING:
    from speakeasy import Speakeasy as Se
    from speakeasy.common import Hook as SeHook
    from speakeasy.memmgr import MemMap
else:
    class Se:
        pass


class SpeakeasyNotInitialized(EmulationError):
    def __init__(self) -> None:
        super().__init__('Speakeasy was unexpectedly not initialized.')


_T = TypeVar('_T')


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

        emu.emu.timeout = 0

        # prevent memory hook from being overridden, this is a bug in speakeasy
        emu.emu.add_interrupt_hook(cb=emu.emu._hook_interrupt)
        emu.emu.builtin_hooks_set = True

        if self.hooks.CodeExecute:
            emu.add_code_hook(self.hook_code_execute, ctx=self.state)
            emu.add_dyn_code_hook(self.hook_code_execute, ctx=self.state)

        if self.hooks.MemoryRead:
            emu.add_mem_read_hook(self.hook_mem_read)

        if self.hooks.MemoryWrite:
            emu.add_mem_write_hook(self.hook_mem_write)

        if self.hooks.MemoryError:
            emu.add_mem_invalid_hook(self.hook_mem_error)

        if self.hooks.ApiCall:
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

    def _map_update(self):
        self._memorymap.clear()
        if (e := self.speakeasy.emu) and (eng := e.emu_eng) and (emu := eng.emu):
            for a, b, _ in emu.mem_regions():
                self._memorymap.addi(a, b - a + 1)
        else:
            raise SpeakeasyNotInitialized

    def malloc(self, size: int) -> int:
        return self.speakeasy.mem_alloc(size)

    def push(self, val: int, size: int | None = None):
        if size is None:
            size = self.exe.pointer_size_in_bytes
        easy = self.speakeasy
        easy.push_stack
        sp = easy.get_stack_ptr()
        bv = val.to_bytes(size, self.exe.byte_order().value)
        sp -= size
        easy.mem_write(sp, bv)
        easy.set_stack_ptr(sp)

    def morestack(self):
        raise NotImplementedError

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

        if (inner := spk.emu) is None:
            raise SpeakeasyNotInitialized

        win32 = isinstance(inner, se.Win32Emulator)
        self._set_end(end)

        if inner.get_current_run():
            return spk.resume(start)

        if self.exe.blob:
            offset = start - self.base
            if offset < 0:
                raise ValueError(F'invalid offset 0x{start:X} specified; base address is 0x{self.base:X}')
            spk.run_shellcode(self.base, offset=offset)
        else:
            inner.stack_base, _ = inner.alloc_stack(self.stack_size)
            inner.set_func_args(inner.stack_base, inner.return_hook)

            run = se.profiler.Run()
            run.type = 'thread'         # type:ignore
            run.start_addr = start      # type:ignore
            run.instr_cnt = 0           # type:ignore
            run.args = ()               # type:ignore

            inner.add_run(run)

            if win32:
                if not (process := inner.init_container_process()):
                    process = se.windows.objman.Process(self)
                inner.processes.append(process)
                inner.curr_process = process
            else:
                process = None

            if mm := inner.get_address_map(start): # type:ignore
                mm: MemMap
                mm.set_process(inner.curr_process)

            t = se.windows.objman.Thread(inner, stack_base=inner.stack_base, stack_commit=self.stack_size)

            inner.om.objects.update({t.address: t})
            inner.curr_process.threads.append(t)
            inner.curr_thread = t

            if win32:
                peb = inner.alloc_peb(process)
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

    def _map(self, address: int, size: int):
        spksy = self.speakeasy
        if (emu := spksy.emu) is None:
            raise SpeakeasyNotInitialized
        if emu.get_address_map(address):
            raise ValueError(address)
        if mm := emu.get_reserve_map(address):
            mm: MemMap = emu.get_address_map(emu.mem_map_reserve(mm.base))
            if address not in range(mm.base, mm.base + mm.size):
                raise RuntimeError(F'Speakeasy claimed to map 0x{address:X} in map 0x{mm.base:X}-0x{mm.base + mm.size:X}.')
            map_size = mm.size
            map_base = mm.base
            _new_size = size - map_size + address - map_base
            _new_base = address + map_size
            if _new_size > 0 and self._map(_new_base, _new_size) != _new_base:
                raise RuntimeError(F'Attempting to remain rest of size 0x{_new_size:X} at 0x{_new_base:X} failed.')
            return address
        else:
            alloc = spksy.mem_alloc(size, address)
            if alloc != address:
                spksy.mem_free(alloc)
                raise LookupError(F'Unable to allocate {size} bytes at address 0x{address:X} because Speakeasy has reserved this region.')
            return alloc

    def _mem_write(self, address: int, data: bytes):
        return self.speakeasy.mem_write(address, data)

    def _mem_read(self, address: int, size: int):
        return self.speakeasy.mem_read(address, size)
