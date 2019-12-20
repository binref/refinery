#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import io

from elftools.elf.elffile import ELFFile

from ... import Unit
from ....lib.argformats import number, virtualaddr


class elfslice(Unit):
    """
    Extract data from ELF executables based on virtual offsets.
    """

    def interface(self, argp):
        argp.add_argument('offset', type=virtualaddr,
            help='Specify virtual offset as either .section:OFFSET or just a virtual address in hex.')
        argp.add_argument('limit', type=number[1:], nargs='?', default=0,
            help='Optionally specify a number of bytes to read, default is to read until the end of input.')
        return super().interface(argp)

    def _data_offset(self, elf, addr):
        for segment in elf.iter_segments():
            begin = segment.header.p_vaddr
            size = segment.header.p_memsz
            delta = addr - begin
            if delta in range(size + 1):
                return segment.header.p_offset + delta
        else:
            raise ValueError('unable to find offset.')

    def _slice(self, off):
        end = off + self.args.limit if self.args.limit else None
        return slice(off, end)

    def process(self, data):
        try:
            elf = ELFFile(io.BytesIO(data))
        except Exception:
            elf = None
        if not elf:
            raise ValueError('unable to parse input as ELF file')
        if not self.args.offset.section:
            return data[self._slice(self._data_offset(elf, self.args.offset.address))]
        for k in range(elf.num_sections()):
            section = elf.get_section(k)
            if self.args.offset.section == section.name:
                section_data = section.get_data()
                return section_data[self._slice(self.args.offset.address)]
        else:
            raise ValueError(F'unable to find section {self.args.offset.section}')
