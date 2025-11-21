"""
Implements `refinery.lib.emulator.interface.RawMetalEmulator` for the icicle backend.
"""
from __future__ import annotations

from functools import partial
from typing import TYPE_CHECKING, TypeVar

from refinery.lib.emulator.abstract import EmulationError, RawMetalEmulator, Register
from refinery.lib.executable import Arch
from refinery.lib.shared import icicle as ic

if TYPE_CHECKING:
    from icicle import Icicle as Ic
else:
    class Ic:
        pass


_T = TypeVar('_T')


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

        self.icicle = ice = ic.Icicle(arch)
        self.regmap = {reg.casefold(): val[1] for reg, val in ice.reg_list().items()}

        self._map_segments()
        self._map_stack_and_heap()

        if self.hooks.ApiCall:
            self._install_api_trampoline()

    def _enable_single_step(self):
        self._single_step = True

    def _disable_single_step(self):
        self._single_step = False

    def _emulate(self, start: int, end: int | None = None):
        RS = ic.RunStatus
        MP = ic.MemoryProtection
        ice = self.icicle

        code_hooked = self.hooks.CodeExecute
        apis_hooked = self.hooks.ApiCall
        mm_e_hooked = self.hooks.MemoryError
        mm_w_hooked = self.hooks.MemoryWrite
        mm_r_hooked = self.hooks.MemoryRead
        mm_x_hooked = mm_r_hooked or mm_r_hooked

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
        mprotect: list[tuple[int, int, MP]] = []
        retrying = 0

        while True:
            if end is not None and ip == end:
                break
            if (code_hooked or apis_hooked) and not retrying:
                insn = next(dasm.disasm(self.mem_read(ip, 20), ip, 1))
                args = (ice, ip, insn.size, self.state)
                if apis_hooked:
                    self._hook_api_call_check(*args)
                if code_hooked:
                    self.hook_code_execute(*args)
            else:
                insn = None
            if mprotect:
                ice.mem_protect(*mprotect[-1])
            if (status := step()) == RS.InstructionLimit:
                for p in mprotect:
                    addr, size, prot = p
                    ice.mem_protect(addr, size, MP.ExecuteOnly)
                    if mm_w_hooked and prot == MP.ExecuteReadWrite:
                        value = self.mem_read_int(addr, size)
                        if self.hook_mem_write(ice, 0, addr, size, value, self.state) is False:
                            break
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
                insn = insn or next(dasm.disasm(self.mem_read(ip, 20), ip, 1))
                size = max((op.size for op in insn.operands), default=insn.addr_size)
                EC = ic.ExceptionCode
                ea = ice.exception_value
                ec = ice.exception_code
                if ec in (EC.ReadUnmapped, EC.WriteUnmapped) and mm_e_hooked:
                    if self.hook_mem_error(ice, 0, ea, size, 0, self.state) is not False:
                        retrying += 1
                        continue
                elif ec == EC.ReadPerm and mm_x_hooked:
                    value = self.mem_read_int(ea, size)
                    if self.hook_mem_read(ice, 0, ea, size, value, self.state) is not False:
                        prot = MP.ExecuteRead if mm_w_hooked else MP.ExecuteReadWrite
                        mprotect.append((ea, size, prot))
                        retrying += 1
                        continue
                elif ec == EC.WritePerm and mm_x_hooked:
                    mprotect.append((ea, size, MP.ExecuteReadWrite))
                    retrying += 1
                    continue
                else:
                    raise EmulationError(repr(ec))
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
        if self.hooks.MemoryAccess:
            perm = MP.ExecuteOnly
        else:
            perm = MP.ExecuteReadWrite
        return self.icicle.mem_map(address, size, perm)

    def _set_register(self, register: str, v: int) -> None:
        return self.icicle.reg_write(register, v)

    def _get_register(self, register: str) -> int:
        return self.icicle.reg_read(register)

    def _mem_write(self, address: int, data: bytes):
        return self.icicle.mem_write(address, data)

    def _mem_read(self, address: int, size: int):
        return self.icicle.mem_read(address, size)
