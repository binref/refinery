from __future__ import annotations

import base64
import lzma

from refinery.lib.emulator import (
    CC,
    Arch,
    Hook,
    EmulationError,
    EmulationTimeout,
    UnicornEmulator,
    SpeakeasyEmulator,
    IcicleEmulator,
)
from .. import TestBase

# An x64 native-subsystem kernel driver whose DriverEntry returns STATUS_SUCCESS, stored
# lzma-compressed and base85-encoded. It is never loaded, only parsed and emulated. It was built
# with MSVC alone (no WDK) and can be regenerated from the following source:
#
#   tiny.c:
#     typedef long NTSTATUS; typedef void *PVOID;
#     __declspec(dllimport) unsigned long DbgPrint(const char *Format, ...);
#     NTSTATUS DriverEntry(PVOID DriverObject, PVOID RegistryPath) {
#         volatile PVOID keep = (PVOID)(&DbgPrint);   /* forces an ntoskrnl.exe import */
#         (void)DriverObject; (void)RegistryPath; (void)keep; return 0; }
#   ntoskrnl.def:  "LIBRARY ntoskrnl.exe" / "EXPORTS" / "DbgPrint"
#   lib  /def:ntoskrnl.def /machine:x64 /out:ntoskrnl.lib
#   cl   /c /GS- /O1 tiny.c
#   link tiny.obj ntoskrnl.lib /OUT:tiny.sys /SUBSYSTEM:NATIVE /DRIVER /ENTRY:DriverEntry \
#        /NODEFAULTLIB /MACHINE:X64
_DRIVER_SYS = (
    b'{Wp48S^xk9=GL@E0stWa8~^|S5YJf5;0gZ$m0bWPmX2@$7x(N1yXy4+lmRb9?|kO<p8YTc%hBk2*4dwEXwB>N8E~_-?jlNPn'
    b'42$#*Cx&K8g59$s3aFyb>fH#6c|$*{{=&9WT1&Y=77Z%;O6gvI*7rr106)`)eW}k=YV;+;Fb!!Ko{nuHngLtr|X2sR^xRAOq'
    b'{#gU#(_0u6k_mUFY0Ip*do7bxkk*6q&8L+ck`_R}DoN;2qfTDrb5MOw(<0P-=S*%3;<jh^l$9BJ`v)blE~RAjO)vBp8Qtoeu'
    b'SmYF6Ns4@(M&iMJLgvtFKoEE|jsr;-a@Wg7_-{TP9pCFV&gmR!K)A$Bv6<Xiz`#hD_d3GjG)vg8J<5~`5Uso)t9t+0H-M+E?'
    b'Gb>5VIHQt5Tn=hY?dbLRo;05LXlzp|9`!B}e-QP_BuwwCAj>!2AijP~d+XZ8ylInraJn<Xq5E;o*){vjg;vVsM3?U_Mb}x)$'
    b'#<sX7<bXFkH44h&?3~ltL0e48vj5F2sieHtB^i=f^&zkmC5N5XNSTcv!BjVJ2%W(I00000?y^e6p6vW<00FTBfD`}#O4Ajiv'
    b'BYQl0ssI200dcD'
)


def _driver_sys() -> bytes:
    return lzma.decompress(base64.b85decode(_DRIVER_SYS))


# A minimal user-mode x64 console EXE (no CRT) whose entry point returns 0x1337, stored
# lzma-compressed and base85-encoded; never executed, only parsed and emulated. Regenerate with:
#   exe.c:  int entry(void) { return 0x1337; }
#   cl   /c /GS- /O1 exe.c
#   link exe.obj /OUT:tiny.exe /SUBSYSTEM:CONSOLE /ENTRY:entry /NODEFAULTLIB /MACHINE:X64
_MODULE_EXE = (
    b'{Wp48S^xk9=GL@E0stWa8~^|S5YJf5;06By99;k=mX2@$7x(N1yXy4+lmRb9?|kO<WM^LnoW$=mf=y$E9fj#W?9z4(=N#bMZ'
    b'p@wgn7lHMzd|-nF^bQr>wCR;c{C}@o`_1_{5LD3krrSU4KsNnN79+HlRdlk$|!9Lme6+IEu?=~3q=!R240~g)Q%sgu*^mV29'
    b'!hgAj~wyDa0XXJHy9<dxpAdm{-=wDh17q@Z!&Do(`BVCXDAl5r?hBKq*UDI+~72uQJQ9t)5W4r&J&z=~b#bx4I%%wg{>Cc5D'
    b'^{E0(iAJ%EuGSUc%4(@1bMZt^46m?W+Sm1RnYyuC$gW}T5#KhS;w{2iu0YG{0lx@Q081l)5l61H8XYYKF@n*oZ_tR*K{23<<'
    b'aIH6|0L7D&nL~=N&G)l7000FoHfD8Zt`dLq_vBYQl0ssI200dcD'
)


def _module_exe() -> bytes:
    return lzma.decompress(base64.b85decode(_MODULE_EXE))


def _makeEmulator(e: type[UnicornEmulator]):
    class Emu(e):
        writes = []

        def hook_mem_error(self, emu, access: int, address: int, size: int, value: int, state=None):
            aligned = self.align(address, down=True)
            alloc_size = 0
            while address + size >= aligned + alloc_size:
                alloc_size += self.alloc_size
            self.map(aligned, alloc_size)
            return True

        def hook_mem_write(self, emu, access: int, address: int, size: int, value: int, state=None):
            self.writes.append(value)
            return True

    return Emu


class TestEmulator(TestBase):

    def _test_single_stepping_x32(self, base_emu):

        data = bytes.fromhex(
            'A1 FF FF 01 00'        # mov     eax, [0x1FFFF]
            'B8 02 00 00 00'        # mov     eax, 2
            '66 A3 A0 B3 01 10'     # mov     [0x1001B3A0], ax
            '68 BB 01 00 00'        # push    1BBh
            'FF 15 2C 31 01 10'     # call    htons
            '66 A3 A2 B3 01 10'     # mov     [0x1001B3A2], ax
        )

        emulator = _makeEmulator(base_emu)(data, arch=Arch.X32, hooks=Hook.Memory)
        emulator.reset()
        ip = emulator.base

        ea = emulator.step(ip)
        self.assertEqual(emulator.get_register('eax'), 0)
        self.assertEqual(ea, ip := ip + 5)

        ea = emulator.step(ip)
        self.assertEqual(emulator.get_register('eax'), 2)
        self.assertEqual(ea, ip := ip + 5)

        ea = emulator.step(ip)
        self.assertEqual(emulator.mem_read(0x1001B3A0, 2), B'\x02\x00')
        self.assertEqual(ea, ip := ip + 6)

        ea = emulator.step(ip, 2)
        self.assertEqual(emulator.pop(), ip + 11)
        self.assertEqual(emulator.pop(), 0x1BB)
        self.assertNotEqual(ea, ip := ip + 11)
        emulator.set_register('eax', 0x1BB)

        ea = emulator.step(ip)
        self.assertEqual(emulator.mem_read(0x1001B3A2, 2), B'\xBB\x01')

        self.assertEqual(emulator.writes.pop(), 443)
        emulator.writes.pop()
        self.assertListEqual(emulator.writes, [2, 443])

    def test_single_stepping_x32_ic(self):
        self._test_single_stepping_x32(IcicleEmulator)

    def test_single_stepping_x32_uc(self):
        self._test_single_stepping_x32(UnicornEmulator)

    def test_single_stepping_x32_se(self):
        self._test_single_stepping_x32(SpeakeasyEmulator)

    def _test_single_stepping_x64(self, base_emu):

        data = bytes.fromhex(
            'B8 02 00 00 00'        # mov     eax, 2
            '66 89 05 19 DC 01 00'  # mov     [rip+0x1DC19], ax
            '66 B9 92 13'           # mov     cx, 0x1392
            'FF 15 AF 11 01 00'     # call    htons
            '66 89 05 0A DC 01 00'  # mov     [rip+0x1DC0A], ax
        )

        emulator = _makeEmulator(base_emu)(data, arch=Arch.X64, hooks=Hook.Memory)
        emulator.reset()

        ip = base = emulator.base

        ea = emulator.step(ip)
        self.assertEqual(emulator.get_register('eax'), 2)
        self.assertEqual(ea, ip := ip + 5)

        ea = emulator.step(ip)
        self.assertEqual(emulator.mem_read(base + 0x1dc25, 2), B'\x02\x00')
        self.assertEqual(ea, ip := ip + 7)

        ea = emulator.step(ip, 2)
        self.assertEqual(emulator.pop(), ip := ip + 10)
        self.assertEqual(emulator.get_register('ecx') & 0xFFFF, 0x1392)
        emulator.set_register('eax', 0x1BB)

        ea = emulator.step(ip)
        self.assertEqual(emulator.mem_read(base + 0x1dc27, 2), B'\xBB\x01')

        self.assertEqual(emulator.writes.pop(), 443)
        emulator.writes.pop()
        self.assertListEqual(emulator.writes, [2])

    def test_single_stepping_x64_ic(self):
        self._test_single_stepping_x64(IcicleEmulator)

    def test_single_stepping_x64_uc(self):
        self._test_single_stepping_x64(UnicornEmulator)

    def test_single_stepping_x64_se(self):
        self._test_single_stepping_x64(SpeakeasyEmulator)

    def _test_registers(self, base_emu):
        code = (
            b'\x55'                       # push   rbp
            b'\x53'                       # push   rbx
            b'\x48\x83\xec\x28'           # sub    rsp, 0x28
            b'\x48\x8d\x6c\x24\x20'       # lea    rbp, [rsp + 0x20]
            b'\x83\xfa\x01'               # cmp    edx, 1
            b'\x0f\x85\x0e\x00\x00\x00'   # jne    +0xE
            b'\x48\xb8\x52\x45\x46\x49'   # movabs rax, 0x5952454E49464552
            b'\x4E\x45\x52\x59'
            B'\x48\x89\x04\x24'           # mov    [rsp], rax
            b'\x90'                       # nop
        )

        emulator = _makeEmulator(base_emu)(code, arch=Arch.X64)
        emulator.reset()
        emulator.set_register('edx', 1)
        emulator.emulate(emulator.base, emulator.base + len(code))
        value = emulator.pop().to_bytes(8, 'little')
        self.assertEqual(value, B'REFINERY')

    def test_register_ic(self):
        self._test_registers(IcicleEmulator)

    def test_register_uc(self):
        self._test_registers(UnicornEmulator)

    def test_register_se(self):
        self._test_registers(SpeakeasyEmulator)

    def _test_call_with_stack_argument(self, base_emu):
        code = bytes.fromhex(
            '8B 44 24 04'   # mov     eax, [esp + 4]
            'C3'            # ret
        )
        emulator = base_emu(code, arch=Arch.X32)
        emulator.reset()
        self.assertEqual(emulator.call(emulator.base, 0x4243A1B0, cc=CC.CDecl), 0x4243A1B0)

    def test_call_with_stack_argument_uc(self):
        self._test_call_with_stack_argument(UnicornEmulator)

    def test_call_with_stack_argument_ic(self):
        self._test_call_with_stack_argument(IcicleEmulator)

    def _test_call_with_two_stack_arguments(self, base_emu):
        code = bytes.fromhex(
            '8B 44 24 04'   # mov     eax, [esp + 4]   ; first argument
            '2B 44 24 08'   # sub     eax, [esp + 8]   ; minus second argument
            'C3'            # ret
        )
        emulator = base_emu(code, arch=Arch.X32)
        emulator.reset()
        result = emulator.call(emulator.base, 0x64, 0x0A, cc=CC.CDecl)
        self.assertEqual(result & 0xFFFFFFFF, 0x5A)

    def test_call_with_two_stack_arguments_uc(self):
        self._test_call_with_two_stack_arguments(UnicornEmulator)

    def test_call_with_two_stack_arguments_ic(self):
        self._test_call_with_two_stack_arguments(IcicleEmulator)

    def _test_push_register(self, base_emu):
        emulator = base_emu(bytes.fromhex('90'), arch=Arch.X32)  # nop
        emulator.reset()
        emulator.set_register('eax', 0xBAADF00D)
        tos = emulator.sp
        emulator.push_register('eax')
        self.assertEqual(emulator.sp, tos - 4)
        self.assertEqual(emulator.mem_read_int(emulator.sp, 4), 0xBAADF00D)

    def test_push_register_uc(self):
        self._test_push_register(UnicornEmulator)

    def test_push_register_ic(self):
        self._test_push_register(IcicleEmulator)

    def test_fault_access_size_ic(self):
        sizes = []

        class Emu(IcicleEmulator):
            def hook_mem_error(self, emu, access, address, size, value, state=None):
                sizes.append(size)
                self.map(self.align(address, down=True), self.alloc_size)
                return True

        code = bytes.fromhex(
            '0F B6 05 00 00 66 06'   # movzx eax, byte ptr [0x6660000]
        )
        emu = Emu(code, arch=Arch.X32, hooks=Hook.MemoryError)
        emu.reset()
        emu.step(emu.base)
        self.assertEqual(sizes, [1])

    def test_no_progress_guard_ic(self):
        class Emu(IcicleEmulator):
            def hook_mem_error(self, emu, access, address, size, value, state=None):
                return True

        code = bytes.fromhex(
            '0F B6 05 00 00 66 06'   # movzx eax, byte ptr [0x6660000]
        )
        emu = Emu(code, arch=Arch.X32, hooks=Hook.MemoryError)
        emu.reset()
        with self.assertRaises(EmulationError):
            emu.step(emu.base)

    def test_write_hook_stop_ic(self):
        class Emu(IcicleEmulator):
            def hook_mem_error(self, emu, access, address, size, value, state=None):
                self.map(self.align(address, down=True), self.alloc_size)
                return True

            def hook_mem_write(self, emu, access, address, size, value, state=None):
                return False

        code = bytes.fromhex(
            'C6 05 00 00 66 06 11'   # mov byte ptr [0x6660000], 0x11
            'C6 05 00 00 66 06 22'   # mov byte ptr [0x6660000], 0x22
        )
        emu = Emu(code, arch=Arch.X32, hooks=Hook.Memory | Hook.CodeExecute)
        emu.reset()
        emu.emulate(emu.base, emu.base + len(code))
        self.assertEqual(emu.mem_read(0x6660000, 1), b'\x11')

    def test_driver_entry_se(self):
        emu = SpeakeasyEmulator(_driver_sys())
        emu.reset()
        emu.emulate(emu._module.base + emu._module.ep)
        self.assertEqual(emu.rv, 0)
        self.assertEqual(emu.ip, emu.speakeasy.emu.return_hook)

    def test_module_entry_se(self):
        emu = SpeakeasyEmulator(_module_exe())
        emu.reset()
        emu.emulate(emu._module.base + emu._module.ep)
        self.assertEqual(emu.rv, 0x1337)
        self.assertEqual(emu.ip, emu.speakeasy.emu.return_hook)

    def test_code_hook_se(self):
        seen = []

        class Emu(SpeakeasyEmulator):
            def hook_code_execute(self, emu, address, size, state=None):
                seen.append((address - self.base, size))
                return True

        code = bytes.fromhex(
            'B8 02 00 00 00'   # mov eax, 2
            '90'               # nop
        )
        emu = Emu(code, arch=Arch.X64, hooks=Hook.CodeExecute)
        emu.reset()
        emu.emulate(emu.base, emu.base + len(code))
        self.assertEqual(emu.get_register('eax'), 2)
        self.assertEqual(seen[0], (0, 5))
        self.assertEqual(seen[1], (5, 1))

    def _test_timeout_unbounded_loop(self, base_emu):
        code = bytes.fromhex('EBFE')  # jmp $ : a one-instruction infinite loop
        emulator = base_emu(code, arch=Arch.X32)
        emulator.reset()
        with self.assertRaises(EmulationTimeout) as cm:
            emulator.emulate(emulator.base, timeout=100)
        self.assertEqual(cm.exception.count, 100)

    def test_timeout_unbounded_loop_uc(self):
        self._test_timeout_unbounded_loop(UnicornEmulator)

    def test_timeout_unbounded_loop_ic(self):
        self._test_timeout_unbounded_loop(IcicleEmulator)

    def test_timeout_unbounded_loop_se(self):
        self._test_timeout_unbounded_loop(SpeakeasyEmulator)

    def _test_timeout_boundary(self, base_emu):
        code = bytes.fromhex('90' * 5 + 'F4' * 4)  # five NOPs reach end after exactly five steps
        end = 5
        emulator = base_emu(code, arch=Arch.X32)
        emulator.reset()
        emulator.emulate(emulator.base, emulator.base + end, timeout=end)
        self.assertEqual(emulator.ip, emulator.base + end)
        emulator.reset()
        with self.assertRaises(EmulationTimeout) as cm:
            emulator.emulate(emulator.base, emulator.base + end, timeout=end - 1)
        self.assertEqual(cm.exception.count, end - 1)

    def test_timeout_boundary_uc(self):
        self._test_timeout_boundary(UnicornEmulator)

    def test_timeout_boundary_ic(self):
        self._test_timeout_boundary(IcicleEmulator)

    def test_timeout_boundary_se(self):
        self._test_timeout_boundary(SpeakeasyEmulator)

    def _test_timeout_none_completes(self, base_emu):
        code = bytes.fromhex('B82A000000' + '90' * 4)  # mov eax, 0x2A ; then padding
        emulator = base_emu(code, arch=Arch.X32)
        emulator.reset()
        emulator.emulate(emulator.base, emulator.base + 5, timeout=None)
        self.assertEqual(emulator.get_register('eax'), 0x2A)

    def test_timeout_none_completes_uc(self):
        self._test_timeout_none_completes(UnicornEmulator)

    def test_timeout_none_completes_ic(self):
        self._test_timeout_none_completes(IcicleEmulator)

    def test_timeout_none_completes_se(self):
        self._test_timeout_none_completes(SpeakeasyEmulator)

    def test_timeout_ignores_explicit_halt_uc(self):
        code = bytes.fromhex('90' * 16)

        class Emu(UnicornEmulator):
            seen = 0

            def hook_code_execute(self, emu, address, size, state=None):
                self.seen += 1
                if self.seen == 3:
                    self.halt()
                return True

        emulator = Emu(code, arch=Arch.X32, hooks=Hook.CodeExecute)
        emulator.reset()
        emulator.emulate(emulator.base, emulator.base + 16, timeout=1000)
        self.assertEqual(emulator.seen, 3)
        self.assertEqual(emulator.ip, emulator.base + 2)
