#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from . import exeroute
from .... import arg, Unit


class EndOfStringNotFound(ValueError):
    def __init__(self):
        super().__init__('end of string could not be determined')


class CompartmentNotFound(ValueError):
    def __init__(self, addr, kind='segment'):
        super().__init__(F'could not find any {kind} containing address 0x{addr:X}.')


class vsnip(Unit):
    """
    Extract data from PE, ELF, and MachO files based on virtual offsets.
    """

    def __init__(
        self, address: arg.number(metavar='address', help='Specify the virtual address of the data as a number.'),
        count: arg.number(metavar='count', help='The maximum number of bytes to read.') = 0,
        align: arg.number('-g', help='Only stop reading if the number of bytes is a multiple of {varname}.') = 1,
        until: arg.binary('-t', group='END', help='Read until sequence {varname} is read.') = B'',
        ascii: arg.switch('-a', group='END', help='Read an ASCII string; equivalent to -th:00') = False,
        utf16: arg.switch('-u', group='END', help='Read an UTF16 string; equivalent to -g2 -th:0000') = False,
        base : arg.number('-b', metavar='B', help='Optionally specify a custom base address B.') = None,
    ):
        if sum(1 for t in (until, utf16, ascii) if t) > 1:
            raise ValueError('Only one of utf16, ascii, and until can be specified.')
        if ascii:
            until = B'\0'
        if utf16:
            align = 2
            until = B'\0\0'
        return super().__init__(address=address, count=count, align=align, until=until, base=base)

    def process(self, data):
        offset, lbound = exeroute(
            data,
            self._get_buffer_range_elf,
            self._get_buffer_range_macho,
            self._get_buffer_range_pe
        )

        lbound = lbound or len(data)

        if not self.args.until:
            end = lbound
        else:
            end = offset - 1
            align = self.args.align
            while True:
                end = data.find(self.args.until, end + 1)
                if end not in range(offset, lbound):
                    raise EndOfStringNotFound
                if (end - offset) % align == 0:
                    break

        if self.args.count:
            end = min(end, offset + self.args.count)

        return data[offset:end]

    def _rebase(self, addr, truebase):
        self.log_info(F'using base address: 0x{truebase:X}')
        if self.args.base is None:
            return addr
        rebased = addr - self.args.base + truebase
        self.log_info(F'rebased to address: 0x{rebased:X}')
        return rebased

    def _get_buffer_range_elf(self, elf):
        addr = self._rebase(
            self.args.address,
            min(s.header.p_vaddr for s in elf.iter_segments() if s.header.p_type == 'PT_LOAD')
        )
        for segment in elf.iter_segments():
            begin = segment.header.p_vaddr
            size = segment.header.p_memsz
            delta = addr - begin
            if delta in range(size + 1):
                offset = segment.header.p_offset
                return offset + delta, offset + segment.header.p_filesz
        raise CompartmentNotFound(addr)

    def _get_buffer_range_macho(self, macho):
        for header in macho.headers:
            segments = [segment for header, segment, sections in header.commands
                if header.get_cmd_name().startswith('LC_SEGMENT') and segment.filesize > 0]
            addr = self._rebase(self.args.address, min(segment.vmaddr for segment in segments))
            for segment in segments:
                if addr in range(segment.vmaddr, segment.vmaddr + segment.vmsize):
                    offset = addr - segment.vmaddr
                    return offset + segment.fileoff, segment.fileoff + segment.filesize
        raise CompartmentNotFound(addr)

    def _get_buffer_range_pe(self, pe):
        base = pe.OPTIONAL_HEADER.ImageBase
        addr = self._rebase(self.args.address, base) - base
        offset = pe.get_offset_from_rva(addr)
        for section in pe.sections:
            if offset in range(section.PointerToRawData, section.PointerToRawData + section.SizeOfRawData):
                return offset, section.PointerToRawData + section.SizeOfRawData
        raise CompartmentNotFound(addr, 'section')
