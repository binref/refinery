#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from . import exeroute
from .. import UnpackResult, PathExtractorUnit


class vsect(PathExtractorUnit):
    """
    Extract sections/segments from PE, ELF, and MachO executables.
    """
    def unpack(self, data):
        mv = memoryview(data)
        for name, start, size in exeroute(
            data,
            self._unpack_elf,
            self._unpack_macho,
            self._unpack_pe
        ):
            end = start + size
            yield UnpackResult(name, mv[start:end])

    @staticmethod
    def _ascii(string: bytes) -> str:
        term = string.find(0)
        if term >= 0:
            string = string[:term]
        return string.decode('latin-1')

    def _unpack_pe(self, pe):
        for section in pe.sections:
            yield self._ascii(section.Name), section.PointerToRawData, section.SizeOfRawData

    def _unpack_elf(self, elf):
        for section in elf.iter_sections():
            if section.is_null():
                continue
            yield section.name, section['sh_offset'], section.data_size

    def _unpack_macho(self, macho):
        for header in macho.headers:
            for command in header.commands:
                header, segment, sections = command
                if not header.get_cmd_name().startswith('LC_SEGMENT'):
                    continue
                segname = self._ascii(segment.segname)
                yield segname, segment.fileoff, segment.filesize
                for section in sections:
                    secname = F'{segname}/{self._ascii(section.sectname)}'
                    yield secname, section.offset, section.size
