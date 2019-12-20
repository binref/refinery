#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pefile import PE, PEFormatError, DIRECTORY_ENTRY
from struct import unpack

from ... import Unit


class carve_pe(Unit):
    """
    Extracts anything from the input data that looks like a Portable
    Executable (PE) file.
    """

    def _pesize(self, pe: PE) -> int:
        overlay = pe.get_overlay_data_start_offset() or 0
        maxaddr = max(
            s.PointerToRawData + s.SizeOfRawData
            for s in pe.sections
        )
        maxdata = max(
            pe.get_offset_from_rva(d.VirtualAddress) + d.Size
            for d in pe.OPTIONAL_HEADER.DATA_DIRECTORY
        )
        # The certificate overlay is given as a file offset
        # rather than a virtual address.
        cert = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
        certend = cert.VirtualAddress + cert.Size
        self.log_debug(F'overlay at 0x{overlay:08X}')
        self.log_debug(F'maxaddr at 0x{maxaddr:08X}')
        self.log_debug(F'maxdata at 0x{maxdata:08X}')
        self.log_debug(F'certend at 0x{certend:08X}')
        return max(overlay, maxaddr, maxdata, certend)

    def process(self, data):
        cursor = 0
        while True:
            p = data.find(B'MZ', cursor)
            if p < cursor: break
            cursor = p + 2
            k, = unpack('H', data[p + 0x3C:p + 0x3E])
            if data[p + k:p + k + 2] != B'PE':
                continue
            try:
                pe = PE(data=data[p:])
            except PEFormatError as err:
                self.log_debug('parsing of PE header at 0x{p:08X} failed:', err)
                continue
            pesize = self._pesize(pe)
            self.log_info(F'extracted PE file of size 0x{pesize:08X} from 0x{p:08X}')
            yield data[p:p + pesize]
            cursor = pe.OPTIONAL_HEADER.SizeOfHeaders + p
