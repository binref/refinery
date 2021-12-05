#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
from typing import TYPE_CHECKING

from refinery.units import arg, Unit
from refinery.units.formats.exe import exeroute
from refinery.lib.argformats import sliceobj

if TYPE_CHECKING:
    from macholib.MachO import MachO
    from pefile import PE as PEFile
    from elftools.elf.elffile import ELFFile


class EndOfStringNotFound(ValueError):
    def __init__(self):
        super().__init__('end of string could not be determined')


class CompartmentNotFound(ValueError):
    def __init__(self, addr, kind='segment'):
        super().__init__(F'could not find any {kind} containing address 0x{addr:X}.')


class MemoryArea:
    def __init__(self, slice: slice):
        if slice.start is None:
            self.start = slice.stop
            self.count = None
            self.align = 1
        else:
            self.start = slice.start
            self.count = slice.stop
            self.align = slice.step or 1


class vsnip(Unit):
    """
    Extract data from PE, ELF, and MachO files based on virtual offsets.
    """

    def __init__(
        self, addresses: arg(type=sliceobj, nargs='+', metavar='start:count:align', help=(
            'Use Python slice syntax to describe an area of virtual memory to read. If a chunksize is '
            'specified, then the unit will always read a multiple of that number of bytes')),
        ascii: arg.switch('-a', group='END', help='Read ASCII strings; equivalent to -th:00') = False,
        utf16: arg.switch('-u', group='END', help='Read UTF16 strings; equivalent to -th:0000 (also sets chunksize to 2)') = False,
        until: arg.binary('-t', group='END', help='Read until sequence {varname} is read.') = B'',
        base : arg.number('-b', metavar='ADDR', help='Optionally specify a custom base address B.') = None,
    ):
        if sum(1 for t in (until, utf16, ascii) if t) > 1:
            raise ValueError('Only one of utf16, ascii, and until can be specified.')
        return super().__init__(addresses=addresses, utf16=utf16, ascii=ascii, until=until, base=base)

    def process(self, data):
        until = self.args.until
        addrs = self.args.addresses
        if self.args.ascii:
            until = B'\0'
        if self.args.utf16:
            until = B'\0\0'
            addrs = (slice(a.start, a.stop, 2) for a in addrs)

        for addr in addrs:
            area = MemoryArea(addr)
            offset, lbound = exeroute(
                data,
                self._get_buffer_range_elf,
                self._get_buffer_range_macho,
                self._get_buffer_range_pe,
                area.start
            )

            lbound = lbound or len(data)

            if not until:
                end = lbound
            else:
                end = offset - 1
                align = area.align
                while True:
                    end = data.find(until, end + 1)
                    if end not in range(offset, lbound):
                        raise EndOfStringNotFound
                    if (end - offset) % align == 0:
                        break

            if area.count:
                end = min(end, offset + area.count)

            yield data[offset:end]

    def _rebase(self, addr, truebase):
        self.log_info(F'using base address: 0x{truebase:X}')
        if self.args.base is None:
            return addr
        rebased = addr - self.args.base + truebase
        self.log_info(F'rebased to address: 0x{rebased:X}')
        return rebased

    def _get_buffer_range_elf(self, elf: ELFFile, address: int):
        PT_LOAD = {}
        if not elf.num_segments():
            raise LookupError('The elftools parser did not find any segments in this file.')
        for segment in elf.iter_segments():
            if segment.header.p_type == 'PT_LOAD':
                PT_LOAD[segment.header.p_vaddr] = segment
                self.log_info(F'Found PT_LOAD segment with base address 0x{segment.header.p_vaddr:x}')
        if not PT_LOAD:
            raise LookupError(F'Could not find any PT_LOAD segment containing 0x{address:x}.')
        addr = self._rebase(address, min(PT_LOAD))
        for segment in elf.iter_segments():
            begin = segment.header.p_vaddr
            size = segment.header.p_memsz
            delta = addr - begin
            if delta in range(size + 1):
                offset = segment.header.p_offset
                return offset + delta, offset + segment.header.p_filesz
        raise CompartmentNotFound(address)

    def _get_buffer_range_macho(self, macho: MachO, address: int):
        for header in macho.headers:
            segments = [segment for header, segment, sections in header.commands
                if header.get_cmd_name().startswith('LC_SEGMENT') and segment.filesize > 0]
            addr = self._rebase(address, min(segment.vmaddr for segment in segments))
            for segment in segments:
                if addr in range(segment.vmaddr, segment.vmaddr + segment.vmsize):
                    offset = addr - segment.vmaddr
                    return offset + segment.fileoff, segment.fileoff + segment.filesize
        raise CompartmentNotFound(address)

    def _get_buffer_range_pe(self, pe: PEFile, address: int):
        base = pe.OPTIONAL_HEADER.ImageBase
        addr = self._rebase(address, base) - base
        offset = pe.get_offset_from_rva(addr)
        for section in pe.sections:
            if offset in range(section.PointerToRawData, section.PointerToRawData + section.SizeOfRawData):
                return offset, section.PointerToRawData + section.SizeOfRawData
        raise CompartmentNotFound(address, 'section')
