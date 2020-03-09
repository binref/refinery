#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import io
from elftools.elf.elffile import ELFFile

from .. import MemoryExtractorUnit


class elfslice(MemoryExtractorUnit):
    """
    Extract data from ELF executables based on virtual offsets.
    """

    def _get_file_offset(self, elf, offset):
        addr = offset.address
        if offset.section:
            for section in elf.iter_sections():
                if section.name == offset.section:
                    addr = section['sh_offset'] + addr
                    return addr, addr + section.size
            else:
                raise ValueError(F'unable to find section {offset.section}.')
        for segment in elf.iter_segments():
            begin = segment.header.p_vaddr
            size = segment.header.p_memsz
            delta = addr - begin
            if delta in range(size + 1):
                return segment.header.p_offset + delta, None
        else:
            raise ValueError('unable to find offset.')

    def _slice(self, off):
        end = off + self.args.limit if self.args.limit else None
        return slice(off, end)

    def process(self, data):
        try:
            elf = ELFFile(io.BytesIO(data))
        except Exception:
            raise ValueError('unable to parse input as ELF file')

        return self._read_from_memory(data,
            lambda addr: self._get_file_offset(elf, addr))
