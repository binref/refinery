from __future__ import annotations

from refinery.lib.structures import StructReader
from refinery.units import Unit


class carve_elf(Unit):
    """
    Extracts anything from the input data that looks like an ELF (Executable and Linkable Format)
    file.

    The unit scans for the magic ELF signature and then parses the ELF header to compute the file
    size from program headers, section headers, and segment file ranges.
    """
    def process(self, data):
        cursor = 0
        mv = memoryview(data)

        while True:
            offset = data.find(b'\x7fELF', cursor)
            if offset < 0:
                break
            cursor = offset + 4
            try:
                size = self._get_elf_size(mv[offset:])
            except Exception as e:
                self.log_debug(F'parsing ELF header at 0x{offset:08X} failed: {e!s}')
                continue
            if size is None or size < 16:
                continue
            yield self.labelled(mv[offset:offset + size], offset=offset)
            self.log_info(F'extracted ELF file of size 0x{size:08X} from 0x{offset:08X}')
            cursor = offset + size

    @staticmethod
    def _get_elf_size(data: memoryview) -> int | None:
        if len(data) < 64:
            return None

        ei_class = data[4]
        ei_data = data[5]

        if ei_class == 1:
            is64 = False
        elif ei_class == 2:
            is64 = True
        else:
            return None

        if ei_data == 1:
            bigendian = False
        elif ei_data == 2:
            bigendian = True
        else:
            return None

        reader = StructReader(data, bigendian=bigendian)

        try:
            if is64:
                h, uint = 32, reader.u64
            else:
                h, uint = 28, reader.u32
            reader.skip(h)
            e_phoff = uint()
            e_shoff = uint()
            reader.skip(6)
            e_phentsize = reader.u16()
            e_phnum = reader.u16()
            e_shentsize = reader.u16()
            e_shnum = reader.u16()
        except EOFError:
            return None

        size = 0

        if e_shoff and e_shnum:
            size = max(size, e_shoff + e_shnum * e_shentsize)

        if e_phoff and e_phnum:
            size = max(size, e_phoff + e_phnum * e_phentsize)
            for i in range(e_phnum):
                ph_start = e_phoff + i * e_phentsize
                if ph_start + e_phentsize > len(data):
                    break
                reader.seekset(ph_start)
                reader.skip(4 << is64)
                p_offset = uint()
                reader.seekset(ph_start + (16 << is64))
                p_filesz = uint()
                size = max(size, p_offset + p_filesz)

        if e_shoff and e_shnum:
            for i in range(e_shnum):
                sh_start = e_shoff + i * e_shentsize
                if sh_start + e_shentsize > len(data):
                    break
                reader.seekset(sh_start + 4)
                sh_type = reader.u32()
                reader.seekset(sh_start)
                reader.skip(16)
                if is64:
                    reader.skip(8)
                sh_offset = uint()
                sh_size = uint()
                # SHT_NOBITS (type 8) sections don't occupy file space
                if sh_type != 8:
                    size = max(size, sh_offset + sh_size)

        if size == 0:
            size = 64 if is64 else 52

        size = min(size, len(data))
        return size
