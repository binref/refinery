#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from elftools.elf.elffile import ELFFile

from .. import MemoryExtractorUnit
from ....lib.structures import MemoryFile


class elfslice(MemoryExtractorUnit):
    """
    Extract data from ELF executables based on virtual offsets.
    """
    @staticmethod
    def _get_buffer_range(data, offset):
        try:
            elf = ELFFile(MemoryFile(data))
        except Exception:
            raise ValueError('unable to parse input as ELF file')
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
