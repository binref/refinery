from __future__ import annotations

from enum import Enum

from refinery.lib.executable import align
from refinery.lib.shared import pefile
from refinery.lib.structures import StructReader
from refinery.lib.types import Param
from refinery.units import Arg, Unit


class ImgState(bytes, Enum):
    x32 = B'\x0B\x01'
    x64 = B'\x0B\x02'
    ROM = B'\x07\x01'


class MachineType(int, Enum):
    UNKNOWN     = 0x0000 # noqa
    I386        = 0x014C # noqa
    R3000       = 0x0162 # noqa
    R4000       = 0x0166 # noqa
    R10000      = 0x0168 # noqa
    WCEMIPSV2   = 0x0169 # noqa
    ALPHA       = 0x0184 # noqa
    SH3         = 0x01A2 # noqa
    SH3DSP      = 0x01A3 # noqa
    SH3E        = 0x01A4 # noqa
    SH4         = 0x01A6 # noqa
    SH5         = 0x01A8 # noqa
    ARM         = 0x01C0 # noqa
    THUMB       = 0x01C2 # noqa
    ARMNT       = 0x01C4 # noqa
    AM33        = 0x01D3 # noqa
    POWERPC     = 0x01F0 # noqa
    POWERPCFP   = 0x01F1 # noqa
    IA64        = 0x0200 # noqa
    MIPS16      = 0x0266 # noqa
    ALPHA64     = 0x0284 # noqa
    AXP64       = 0x0284 # noqa
    MIPSFPU     = 0x0366 # noqa
    MIPSFPU16   = 0x0466 # noqa
    TRICORE     = 0x0520 # noqa
    CEF         = 0x0CEF # noqa
    EBC         = 0x0EBC # noqa
    RISCV32     = 0x5032 # noqa
    RISCV64     = 0x5064 # noqa
    RISCV128    = 0x5128 # noqa
    LOONGARCH32 = 0x6232 # noqa
    LOONGARCH64 = 0x6264 # noqa
    AMD64       = 0x8664 # noqa
    M32R        = 0x9041 # noqa
    ARM64       = 0xAA64 # noqa
    CEE         = 0xC0EE # noqa


class pefix(Unit):
    """
    Take as input a buffer that represents a stripped PE file, i.e. magic numbers and other
    relevant parts of the header have been stripped. The unit attempts to repair the damage
    and return something that can be parsed.
    """
    def __init__(self, unmap: Param[bool, Arg.Switch('-u', help=(
        'Overwrite all section file start offsets with the virtual offset.'
    ))]):
        super().__init__(unmap=unmap)

    def process(self, data):
        sr = StructReader(data)
        sr.write(B'MZ')
        sr.seekset(0x3C)
        nt = sr.u16()
        oh = nt + 0x18
        sr.seekset(nt)
        sr.write(B'PE')
        sr.seekrel(2)
        mt = sr.u16()

        try:
            mt = MachineType(mt)
        except Exception:
            mt = None

        sr.seekset(oh)
        ms = bytes(sr.peek(2))

        try:
            ms = ImgState(ms)
        except ValueError:
            ms = {
                None: None,
                MachineType.I386  : ImgState.x32,
                MachineType.IA64  : ImgState.x64,
                MachineType.AMD64 : ImgState.x64,
            }.get(mt)

        if ms is None:
            self.log_warn('could not determine image state; nulling field')
            sr.write(B'\0\0')
        else:
            sr.write(ms.value)

        if mt is None:
            if mt := {
                None: None,
                ImgState.x32: MachineType.I386,
                ImgState.x64: MachineType.AMD64,
            }.get(ms):
                assert isinstance(mt, MachineType)
                sr.seekset(nt + 4)
                sr.write(mt.value.to_bytes(2, 'little'))

        pe = pefile.PE(data=data, fast_load=True)

        if (alignment := pe.OPTIONAL_HEADER.FileAlignment) not in {1 << k for k in range(9, 16)}:
            for k in range(9, 16):
                alignment = 1 << k
                size_of_headers = 0x28 * len(pe.sections) + oh + 0xF0
                soh = align(alignment, size_of_headers)
                if any(data[size_of_headers:soh]):
                    raise ValueError('nonzero bytes in what must be header padding')
                if any(data[soh:soh + 8]):
                    pe.OPTIONAL_HEADER.SizeOfHeaders = soh
                    break
            else:
                raise ValueError('unable to find a valid file alignment')

        pe.OPTIONAL_HEADER.FileAlignment = alignment
        pe.OPTIONAL_HEADER.SectionAlignment = max(pe.OPTIONAL_HEADER.SectionAlignment, alignment)

        if self.args.unmap:
            last = pe.OPTIONAL_HEADER.SizeOfImage
            for section in pe.sections:
                section.PointerToRawData = section.VirtualAddress
                section.SizeOfRawData = section.Misc_VirtualSize
                last = section.VirtualAddress + section.Misc_VirtualSize
            pe.OPTIONAL_HEADER.SizeOfImage = last

        return pe.write()
