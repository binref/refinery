#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import pefile

from .. import MemoryExtractorUnit


class peslice(MemoryExtractorUnit):
    """
    Extract data from PE files based on virtual offsets.
    """

    def _get_file_offset(self, pe, offset):
        addr = offset.address
        end = None
        if offset.section:
            name = offset.section.encode('latin-1')
            for section in pe.sections:
                if section.Name.find(name) in (0, 1, 2):
                    addr += section.PointerToRawData
                    end = addr + section.SizeOfRawData
                    self.log_debug('found section', name, F'at offset 0x{addr:08X}')
                    break
            else:
                raise ValueError(F'section {offset.section} was not found.')
        else:
            addr = pe.get_offset_from_rva(addr - pe.OPTIONAL_HEADER.ImageBase)
        return addr, end

    def process(self, data):
        try:
            pe = pefile.PE(data=data, fast_load=True)
        except Exception:
            raise ValueError('unable to parse input as PE file')

        return self._read_from_memory(data,
            lambda addr: self._get_file_offset(pe, addr))
