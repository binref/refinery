#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
from typing import TYPE_CHECKING

from refinery.units import Arg, Unit
from refinery.units.formats.exe import exeroute
from refinery.lib.argformats import metavars


if TYPE_CHECKING:
    from macholib.MachO import MachO
    from pefile import PE as PEFile
    from elftools.elf.elffile import ELFFile


class vaddr(Unit):
    """
    Converts a metadata variable holding a file offset to a virtual address. This unit only works when the
    chunk body contains a PE, ELF, or MachO executable. The variable will be substituted in place. If you
    would like to retain the original value, it is recommended to use the `refinery.put` unit first to create
    a copy of an already existing variable, and then convert the copy.
    """

    def __init__(
        self, *name: Arg(type=str, help='The name of a metadata variable holding an integer.'),
        base : Arg.Number('-b', metavar='ADDR', help='Optionally specify a custom base address B.') = None
    ):
        return super().__init__(names=name, base=base)

    def process(self, data):
        meta = metavars(data)
        for name in self.args.names:
            meta[name] = exeroute(
                data,
                self._convert_ELF,
                self._convert_Macho,
                self._convert_PE,
                meta[name], True
            )
        return data

    def reverse(self, data):
        meta = metavars(data)
        for name in self.args.names:
            meta[name] = exeroute(
                data,
                self._convert_ELF,
                self._convert_Macho,
                self._convert_PE,
                meta[name], False
            )
        return data

    def _unbase(self, addr, truebase):
        self.log_info(F'using base address: 0x{truebase:X}')
        if self.args.base is None:
            return addr
        rebased = addr - truebase + self.args.base
        self.log_info(F'unbased to address: 0x{rebased:X}')
        return rebased

    def _rebase(self, addr, truebase):
        self.log_info(F'using base address: 0x{truebase:X}')
        if self.args.base is None:
            return addr
        rebased = addr - self.args.base + truebase
        self.log_info(F'rebased to address: 0x{rebased:X}')
        return rebased

    def _convert_ELF(self, elf: ELFFile, offset_or_address: int, offset: bool):
        PT_LOAD = {}
        if not elf.num_segments():
            raise LookupError('The elftools parser did not find any segments in this file.')
        for segment in elf.iter_segments():
            if segment.header.p_type == 'PT_LOAD':
                PT_LOAD[segment.header.p_vaddr] = segment
                self.log_info(F'Found PT_LOAD segment with base address 0x{segment.header.p_vaddr:x}')
        if not PT_LOAD:
            raise LookupError('Could not find any PT_LOAD segment.')
        if not offset:
            offset_or_address = self._rebase(offset_or_address, min(PT_LOAD))
        for segment in elf.iter_segments():
            if offset:
                delta = offset_or_address - segment.header.p_offset
                if delta in range(segment.header.p_filesz + 1):
                    address = segment.header.p_vaddr + delta
                    return self._unbase(address, min(PT_LOAD))
            else:
                delta = offset_or_address - segment.header.p_vaddr
                if delta in range(segment.header.p_memsz + 1):
                    return segment.header.p_offset + delta
        raise LookupError(offset_or_address)

    def _convert_Macho(self, macho: MachO, offset_or_address: int, offset: bool):
        def segments():
            for header in macho.headers:
                segments = [segment for header, segment, sections in header.commands
                    if header.get_cmd_name().startswith('LC_SEGMENT') and segment.filesize > 0]
                yield from segments
        truebase = min(segment.vmaddr for segment in segments())
        if not offset:
            offset_or_address = self._rebase(offset_or_address, truebase)
        for segment in segments():
            if offset:
                if offset_or_address in range(segment.fileoff, segment.fileoff + segment.filesize):
                    return self._unbase(segment.vmaddr + offset_or_address - segment.fileoff, truebase)
            else:
                if offset_or_address in range(segment.vmaddr, segment.vmaddr + segment.vmsize):
                    return segment.fileoff + offset_or_address - segment.vmaddr
        raise LookupError(offset_or_address)

    def _convert_PE(self, pe: PEFile, offset_or_address: int, offset: bool):
        base = pe.OPTIONAL_HEADER.ImageBase
        if offset:
            return self._unbase(pe.get_rva_from_offset(offset_or_address) + base, base)
        else:
            return pe.get_offset_from_rva(self._rebase(offset_or_address, base) - base)
