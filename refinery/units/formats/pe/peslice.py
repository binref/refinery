#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import pefile

from ... import Unit
from ....lib.argformats import number, virtualaddr


class EndOfStringNotFound(ValueError):
    def __init__(self):
        super().__init__('end of string could not be determined')


class peslice(Unit):
    """
    Extract data from PE files based on virtual offsets.
    """

    def interface(self, argp):
        limit = argp.add_mutually_exclusive_group()
        limit.add_argument('-t', '--take', type=number[1:], default=0,
            help='The number of bytes to read.')
        limit.add_argument('-e', '--end', type=virtualaddr, default=None,
            help='Read bytes until this offset, which has to be located after the starting offset.')
        limit.add_argument('-a', '--ascii', action='store_true',
            help='Read the memory at the given offset as an ASCII string.')
        limit.add_argument('-u', '--utf16', action='store_true',
            help='Read the memory at the given offset as an UTF16 string.')
        argp.add_argument('offset', type=virtualaddr,
            help='Specify virtual offset as either .section:OFFSET or just a virtual address in hex.')
        return super().interface(argp)

    def _get_file_offset(self, pe, offset):
        addr = offset.address
        if offset.section:
            name = offset.section.encode('latin-1')
            for section in pe.sections:
                if section.Name.find(name) in (0, 1, 2):
                    addr += section.PointerToRawData
                    self.log_debug('found section', name, F'at offset 0x{addr:08X}')
                    break
            else:
                raise ValueError(F'section {offset.section} was not found.')
        else:
            addr = pe.get_offset_from_rva(addr - pe.OPTIONAL_HEADER.ImageBase)
        return addr

    def process(self, data):
        try:
            pe = pefile.PE(data=data, fast_load=True)
        except Exception:
            raise ValueError('unable to parse input as PE file')

        start = self._get_file_offset(pe, self.args.offset)

        if self.args.end:
            end = self._get_file_offset(pe, self.args.end)
            if end > start:
                raise ValueError(
                    F'The end offset 0x{end:08X} lies {end-start} bytes '
                    F'before the start offset 0x{start:08X}.'
                )
        elif self.args.take:
            end = start + self.args.take
        elif self.args.ascii:
            end = data.find(B'\0', start)
            if end < 0:
                raise EndOfStringNotFound
        elif self.args.utf16:
            for end in range(start, len(data), 2):
                if not data[end] and not data[end + 1]:
                    break
            else:
                raise EndOfStringNotFound
        else:
            end = None

        return data[start:end]
