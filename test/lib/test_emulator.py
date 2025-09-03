from __future__ import annotations

from refinery.lib.emulator import Arch, Hook, Emulator, UnicornEmulator, SpeakeasyEmulator
from .. import TestBase


def _makeEmulator(e: type[Emulator]) -> type[Emulator]:
    class Emu(e):
        def hook_mem_error(self, emu, access, address, size, value, state=None):
            aligned = self.align(address, down=True)
            alloc_size = 0
            while address + size >= aligned + alloc_size:
                alloc_size += self.alloc_size
            self.map(aligned, alloc_size)
            return True
    return Emu


class TestEmulator(TestBase):

    def test_single_stepping_x32(self):

        data = bytes.fromhex(
            'A1 FF FF 01 00'        # mov     eax, [0x1FFFF]
            'B8 02 00 00 00'        # mov     eax, 2
            '66 A3 A0 B3 01 10'     # mov     [0x1001B3A0], ax
            '68 BB 01 00 00'        # push    1BBh
            'FF 15 2C 31 01 10'     # call    htons
            '66 A3 A2 B3 01 10'     # mov     [0x1001B3A2], ax
        )

        for BaseEmulator in (
            SpeakeasyEmulator,
            UnicornEmulator,
        ):
            emulator = _makeEmulator(BaseEmulator)(data, arch=Arch.X32, hooks=Hook.MemoryError)
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

    def test_single_stepping_x64(self):

        data = bytes.fromhex(
            'B8 02 00 00 00'        # mov     eax, 2
            '66 89 05 19 DC 01 00'  # mov     [eip+0x1DC19], ax
            '66 B9 92 13'           # mov     cx, 0x1392
            'FF 15 AF 11 01 00'     # call    htons
            '66 89 05 0A DC 01 00'  # mov     [eip+0x1DC0A], ax
        )

        for BaseEmulator in (
            SpeakeasyEmulator,
            UnicornEmulator,
        ):
            emulator = _makeEmulator(BaseEmulator)(data, arch=Arch.X64, hooks=Hook.MemoryError)
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
