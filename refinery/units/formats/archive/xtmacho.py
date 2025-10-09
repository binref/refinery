from __future__ import annotations

from enum import IntFlag

from refinery.lib.structures import StreamDetour, Struct, StructReader
from refinery.units.formats.archive import ArchiveUnit


class CPUType(IntFlag):
    any         = 0xFFFFFFFF  # noqa
    vax         = 0x00000001  # noqa
    mc680x0     = 0x00000006  # noqa
    x32         = 0x00000007  # noqa
    x64         = 0x01000007  # noqa
    mips        = 0x00000008  # noqa
    mc98000     = 0x0000000A  # noqa
    hppa        = 0x0000000B  # noqa
    arm32       = 0x0000000C  # noqa
    arm64       = 0x0100000C  # noqa
    mc880000    = 0x0000000D  # noqa
    sparc       = 0x0000000E  # noqa
    i860        = 0x0000000F  # noqa
    alpha       = 0x00000010  # noqa
    ppc32       = 0x00000012  # noqa
    ppc64       = 0x01000012  # noqa


class FatArch(Struct):
    def __init__(self, reader: StructReader):
        self.cputype = CPUType(reader.u32())
        self.machine = reader.u32()
        offset = reader.u32()
        size = reader.u32()
        self.is64bit = (self.cputype >> 24) & 1
        with StreamDetour(reader, offset):
            self.data = reader.read(size)
        self.align = reader.u32()


class xtmacho(ArchiveUnit):
    """
    Extract the individual executables from a MachO universal binary (sometimes called a MachO fat file)."
    """
    _SIGNATURE_BE = B'\xCA\xFE\xBA\xBE'
    _SIGNATURE_LE = B'\xBE\xBA\xFE\xCA'

    def unpack(self, data: bytearray):
        view = memoryview(data)
        signature = bytes(view[:4])
        try:
            reader = StructReader(view, bigendian={
                self._SIGNATURE_BE: True,
                self._SIGNATURE_LE: False,
            }[signature])
        except KeyError as KE:
            raise ValueError('Not a MachO universal binary; invalid magic header bytes.') from KE
        else:
            reader.seekset(4)
        count = reader.u32()
        self.log_info(F'reading {count} embedded executables')
        while count > 0:
            fa = FatArch(reader)
            self.log_info(F'reading item of size 0x{len(fa.data):08X}, arch {fa.cputype.name}')
            yield self._pack(fa.cputype.name, None, fa.data)
            count -= 1

    @classmethod
    def handles(cls, data):
        return data[:4] in (
            cls._SIGNATURE_BE,
            cls._SIGNATURE_LE,
        )
