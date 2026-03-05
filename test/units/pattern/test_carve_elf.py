import struct
from .. import TestUnitBase


class TestCarveElf(TestUnitBase):

    @staticmethod
    def _make_minimal_elf(is64=True, little_endian=True):
        endian = '<' if little_endian else '>'
        magic = b'\x7fELF'
        ei_class = 2 if is64 else 1
        ei_data = 1 if little_endian else 2
        ei_version = 1
        ei_osabi = 0
        ei_padding = bytes(8)
        ident = magic + bytes([ei_class, ei_data, ei_version, ei_osabi]) + ei_padding

        if is64:
            # ELF64 header (64 bytes total)
            e_type = 2       # ET_EXEC
            e_machine = 0x3E # EM_X86_64
            e_version = 1
            e_entry = 0x400000
            e_phoff = 64     # program header right after ELF header
            e_shoff = 0      # no section headers
            e_flags = 0
            e_ehsize = 64
            e_phentsize = 56
            e_phnum = 1
            e_shentsize = 64
            e_shnum = 0
            e_shstrndx = 0
            header = struct.pack(endian + 'HHIQQQIHHHHHH',
                e_type, e_machine, e_version, e_entry,
                e_phoff, e_shoff, e_flags, e_ehsize,
                e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx)
            # Program header: LOAD segment
            p_type = 1       # PT_LOAD
            p_flags = 5      # PF_R | PF_X
            p_offset = 0
            p_vaddr = 0x400000
            p_paddr = 0x400000
            p_filesz = 64 + 56 + 16  # header + phdr + some payload
            p_memsz = p_filesz
            p_align = 0x200000
            phdr = struct.pack(endian + 'IIQQQQQQ',
                p_type, p_flags, p_offset, p_vaddr, p_paddr,
                p_filesz, p_memsz, p_align)
            payload = b'\xCC' * 16  # INT3 sled
            return ident + header + phdr + payload
        else:
            # ELF32 header (52 bytes total)
            e_type = 2
            e_machine = 3    # EM_386
            e_version = 1
            e_entry = 0x08048000
            e_phoff = 52
            e_shoff = 0
            e_flags = 0
            e_ehsize = 52
            e_phentsize = 32
            e_phnum = 1
            e_shentsize = 40
            e_shnum = 0
            e_shstrndx = 0
            header = struct.pack(endian + 'HHIIIIIHHHHHH',
                e_type, e_machine, e_version, e_entry,
                e_phoff, e_shoff, e_flags, e_ehsize,
                e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx)
            p_type = 1
            p_offset = 0
            p_vaddr = 0x08048000
            p_paddr = 0x08048000
            p_filesz = 52 + 32 + 16
            p_memsz = p_filesz
            p_flags = 5
            p_align = 0x1000
            phdr = struct.pack(endian + 'IIIIIIII',
                p_type, p_offset, p_vaddr, p_paddr,
                p_filesz, p_memsz, p_flags, p_align)
            payload = b'\xCC' * 16
            return ident + header + phdr + payload

    @staticmethod
    def _make_elf_with_sections(is64=True, little_endian=True):
        endian = '<' if little_endian else '>'
        magic = b'\x7fELF'
        ei_class = 2 if is64 else 1
        ei_data = 1 if little_endian else 2
        ei_version = 1
        ei_osabi = 0
        ei_padding = bytes(8)
        ident = magic + bytes([ei_class, ei_data, ei_version, ei_osabi]) + ei_padding

        text_data = b'\x90' * 64  # NOP sled as .text

        if is64:
            ehdr_size = 64
            phdr_size = 56
            shdr_size = 64
            phdr_off = ehdr_size
            text_off = ehdr_size + phdr_size
            shdr_off = text_off + len(text_data)

            header = struct.pack(endian + 'HHIQQQIHHHHHH',
                2, 0x3E, 1, 0x400000,
                phdr_off, shdr_off, 0, ehdr_size,
                phdr_size, 1, shdr_size, 2, 0)

            phdr = struct.pack(endian + 'IIQQQQQQ',
                1, 5, 0, 0x400000, 0x400000,
                text_off + len(text_data), text_off + len(text_data), 0x200000)

            # Section 0: SHT_NULL
            shdr0 = struct.pack(endian + 'IIQQQQIIQQ',
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

            # Section 1: .text (SHT_PROGBITS = 1)
            shdr1 = struct.pack(endian + 'IIQQQQIIQQ',
                1, 1, 6, 0x401000, text_off, len(text_data), 0, 0, 16, 0)

            return ident + header + phdr + text_data + shdr0 + shdr1
        else:
            ehdr_size = 52
            phdr_size = 32
            shdr_size = 40
            phdr_off = ehdr_size
            text_off = ehdr_size + phdr_size
            shdr_off = text_off + len(text_data)

            header = struct.pack(endian + 'HHIIIIIHHHHHH',
                2, 3, 1, 0x08048000,
                phdr_off, shdr_off, 0, ehdr_size,
                phdr_size, 1, shdr_size, 2, 0)

            phdr = struct.pack(endian + 'IIIIIIII',
                1, 0, 0x08048000, 0x08048000,
                text_off + len(text_data), text_off + len(text_data), 5, 0x1000)

            # Section 0: SHT_NULL
            shdr0 = struct.pack(endian + 'IIIIIIIIII',
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

            # Section 1: .text (SHT_PROGBITS = 1)
            shdr1 = struct.pack(endian + 'IIIIIIIIII',
                1, 1, 6, 0x08049000, text_off, len(text_data), 0, 0, 16, 0)

            return ident + header + phdr + text_data + shdr0 + shdr1

    @staticmethod
    def _make_elf_with_nobits(little_endian=True):
        endian = '<' if little_endian else '>'
        magic = b'\x7fELF'
        ident = magic + bytes([2, 1 if little_endian else 2, 1, 0]) + bytes(8)

        text_data = b'\x90' * 32
        ehdr_size = 64
        phdr_size = 56
        shdr_size = 64
        phdr_off = ehdr_size
        text_off = ehdr_size + phdr_size
        shdr_off = text_off + len(text_data)

        header = struct.pack(endian + 'HHIQQQIHHHHHH',
            2, 0x3E, 1, 0x400000,
            phdr_off, shdr_off, 0, ehdr_size,
            phdr_size, 1, shdr_size, 2, 0)

        phdr = struct.pack(endian + 'IIQQQQQQ',
            1, 5, 0, 0x400000, 0x400000,
            text_off + len(text_data), text_off + len(text_data), 0x200000)

        # Section 0: SHT_NULL
        shdr0 = struct.pack(endian + 'IIQQQQIIQQ',
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

        # Section 1: SHT_NOBITS (type 8) = .bss, doesn't occupy file space
        shdr1 = struct.pack(endian + 'IIQQQQIIQQ',
            1, 8, 3, 0x600000, 0, 0x10000, 0, 0, 16, 0)

        return ident + header + phdr + text_data + shdr0 + shdr1

    def test_single_elf64(self):
        elf = self._make_minimal_elf(is64=True)
        data = b'junk' * 10 + elf + b'trailing' * 5
        unit = self.load()
        results = data | unit | []
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0], elf)

    def test_single_elf32(self):
        elf = self._make_minimal_elf(is64=False)
        data = b'prefix' + elf + b'suffix'
        unit = self.load()
        results = data | unit | []
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0], elf)

    def test_multiple_elfs(self):
        elf64 = self._make_minimal_elf(is64=True)
        elf32 = self._make_minimal_elf(is64=False)
        data = b'aaa' + elf64 + b'bbb' + elf32 + b'ccc'
        unit = self.load()
        results = data | unit | []
        self.assertEqual(len(results), 2)

    def test_no_elf(self):
        data = b'This does not contain any ELF files.'
        unit = self.load()
        results = data | unit | []
        self.assertEqual(len(results), 0)

    def test_offset_metadata(self):
        padding = b'X' * 200
        elf = self._make_minimal_elf()
        data = padding + elf
        unit = self.load()
        results = data | unit | []
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].meta['offset'], 200)

    def test_big_endian_elf(self):
        elf = self._make_minimal_elf(is64=True, little_endian=False)
        data = b'pre' + elf + b'post'
        unit = self.load()
        results = data | unit | []
        self.assertEqual(len(results), 1)

    def test_truncated_header_ignored(self):
        data = b'\x7fELF' + b'\x00' * 8
        unit = self.load()
        results = data | unit | []
        self.assertEqual(len(results), 0)

    def test_invalid_ei_class(self):
        elf = bytearray(self._make_minimal_elf())
        elf[4] = 3  # invalid class
        data = bytes(elf)
        unit = self.load()
        results = data | unit | []
        self.assertEqual(len(results), 0)

    def test_invalid_ei_data(self):
        elf = bytearray(self._make_minimal_elf())
        elf[5] = 0  # invalid endianness
        data = bytes(elf)
        unit = self.load()
        results = data | unit | []
        self.assertEqual(len(results), 0)

    def test_elf64_with_sections(self):
        elf = self._make_elf_with_sections(is64=True)
        data = b'pad' + elf + b'\x00' * 100
        unit = self.load()
        results = data | unit | []
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0], elf)

    def test_elf32_with_sections(self):
        elf = self._make_elf_with_sections(is64=False)
        data = b'pad' + elf + b'\x00' * 100
        unit = self.load()
        results = data | unit | []
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0], elf)

    def test_elf_with_nobits_section(self):
        elf = self._make_elf_with_nobits()
        data = elf + b'\x00' * 200
        unit = self.load()
        results = data | unit | []
        self.assertEqual(len(results), 1)
        # The carved size should not include the .bss virtual region
        self.assertEqual(results[0], elf)

    def test_big_endian_elf32(self):
        elf = self._make_minimal_elf(is64=False, little_endian=False)
        data = b'junk' + elf + b'more'
        unit = self.load()
        results = data | unit | []
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0], elf)

    def test_elf_no_program_headers(self):
        endian = '<'
        ident = b'\x7fELF' + bytes([2, 1, 1, 0]) + bytes(8)
        header = struct.pack(endian + 'HHIQQQIHHHHHH',
            1, 0x3E, 1, 0,  # ET_REL, no entry
            0, 0, 0, 64,    # no phdr, no shdr
            0, 0, 0, 0, 0)
        elf = ident + header
        data = elf + b'\x00' * 100
        unit = self.load()
        results = data | unit | []
        self.assertEqual(len(results), 1)
        # Fallback to ELF header size (64 bytes for ELF64)
        self.assertEqual(len(results[0]), 64)

    def test_elf32_short_data(self):
        ident = b'\x7fELF' + bytes([1, 1, 1, 0]) + bytes(8)  # 16 bytes
        data = ident + b'\x00' * 30  # total 46 bytes, less than 52
        unit = self.load()
        results = data | unit | []
        self.assertEqual(len(results), 0)
