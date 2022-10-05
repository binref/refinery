#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units.formats.exe import exeroute
from refinery.units.formats import UnpackResult, PathExtractorUnit, Arg


class vsect(PathExtractorUnit):
    """
    Extract sections/segments from PE, ELF, and MachO executables.
    """
    def __init__(
        self, *paths,
        enrich: Arg.Switch('-e', help=(
            'Populates the metadata variables vaddr and vsize containing the virtual address and size '
            'of each section, respectively.')) = False,
        **keywords
    ):
        super().__init__(*paths, enrich=enrich, **keywords)

    def unpack(self, data):
        mv = memoryview(data)
        for name, start, size, va, vs in exeroute(
            data,
            self._unpack_elf,
            self._unpack_macho,
            self._unpack_pe
        ):
            end = start + size
            kwargs = {'offset': start}
            if self.args.enrich:
                if va is not None:
                    kwargs['vaddr'] = va
                if vs is not None:
                    kwargs['vsize'] = vs
            yield UnpackResult(name, mv[start:end], **kwargs)

    @staticmethod
    def _ascii(string: bytes) -> str:
        term = string.find(0)
        if term >= 0:
            string = string[:term]
        return string.decode('latin-1')

    def _unpack_pe(self, pe):
        for section in pe.sections:
            yield (
                self._ascii(section.Name),
                section.PointerToRawData,
                section.SizeOfRawData,
                section.VirtualAddress,
                section.Misc_VirtualSize,
            )

    def _unpack_elf(self, elf):
        for section in elf.iter_sections():
            if section.is_null():
                continue
            alignment = section['sh_addralign']
            virtual_size = section.data_size
            if alignment >= 2:
                incomplete_chunk_count = virtual_size % alignment
                if incomplete_chunk_count > 0:
                    virtual_size += alignment - incomplete_chunk_count
            yield section.name, section['sh_offset'], section.data_size, section['sh_addr'], virtual_size

    def _unpack_macho(self, macho):
        for header in macho.headers:
            for command in header.commands:
                header, segment, sections = command
                if not header.get_cmd_name().startswith('LC_SEGMENT'):
                    continue
                segname = self._ascii(segment.segname)
                yield segname, segment.fileoff, segment.filesize, segment.vmaddr, segment.vmsize
                for section in sections:
                    secname = F'{segname}/{self._ascii(section.sectname)}'
                    yield secname, section.offset, section.size, None, None
