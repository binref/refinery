#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
from typing import Generator, Iterable, Optional

from refinery.units.formats.pe import OverlayUnit, Arg
from refinery.units.formats.pe.perc import RSRC
from refinery.lib.executable import Executable
from refinery.lib.tools import entropy
from refinery.lib.meta import TerseSizeInt as TI, SizeInt

from fnmatch import fnmatch
from pefile import PE, Structure, SectionStructure, DIRECTORY_ENTRY

_KB = 1000
_MB = _KB * _KB

_ASCII = Executable.ascii


class pestrip(OverlayUnit):
    """
    Removes the overlay of a PE file and returns the stipped executable. Use `refinery.peoverlay`
    to extract the overlay. The unit can also remove resources and entire sections that exceed a
    certain size, or trim low-entropy excess data from them.
    """
    def __init__(
        self,
        *names: Arg(type=str),
        certificate=False,
        directories=False,
        memdump=False,
        resources: Arg.Switch('-r', help='Strip large resources.') = False,
        sections: Arg.Switch('-s', help='Strip large sections.') = False,
        entropy: Arg('-e', metavar='E', type=float, help=(
            'Trailing data from resources and sections with entropy lower than this value is '
            'removed. The default value is {default}. Set this to 1 to ignore the entropy limit '
            'entirely and trim every structure as much as possible without violating alignment. '
            'Setting this value to 0 will strip all occurrences of the last byte.')) = 0.05,
        size_limit: Arg.Number('-l',
            help='Structures below this size are not stripped. The default is {default}.') = TI(10 * _MB),
        aggressive: Arg.Switch('-a',
            help='Equivalent to -sre1: Entirely strip all large sections and resources.') = False,
    ):
        if aggressive:
            sections = True
            resources = True
            entropy = 1

        super().__init__(
            certificate,
            directories,
            memdump,
            sections=sections,
            resources=resources,
            size_limit=size_limit,
            entropy=entropy,
            names=names,
        )

    def _right_strip_low_entropy(self, pe: PE, data: memoryview, block_size=_MB) -> int:
        threshold = self.args.entropy
        alignment = pe.OPTIONAL_HEADER.FileAlignment
        data_overhang = len(data) % alignment
        result = data_overhang
        if not data:
            return 0
        if not threshold:
            import re
            match = re.search(B'(?s).(?=\\x%02x+$)' % data[-1], data)
            if match is not None:
                result = match.start() + 1
        elif threshold < 1:
            for k in reversed(range(0, len(data), block_size)):
                if entropy(data[k:k + block_size]) > threshold:
                    result = k + block_size
                    break
        result = max(result, data_overhang)
        result += (data_overhang - result) % alignment
        while result > len(data):
            result -= alignment
        return result

    def _adjust_offsets(self, pe: PE, gap_offset: int, gap_size: int):
        base = pe.OPTIONAL_HEADER.ImageBase
        alignment = pe.OPTIONAL_HEADER.FileAlignment
        rva_offset = pe.get_rva_from_offset(gap_offset)
        tva_offset = rva_offset + base

        section = pe.get_section_by_offset(gap_offset)
        new_section_size = section.SizeOfRawData - gap_size
        if new_section_size % alignment != 0:
            raise RuntimeError(
                F'trimming 0x{gap_size:X} bytes from section {_ASCII(section.Name)} of size 0x{section.SizeOfRawData:X} '
                F'violates required section alignment of 0x{alignment:X} bytes')
        inside_section_offset = gap_offset - section.PointerToRawData
        if inside_section_offset > new_section_size:
            overlap = inside_section_offset - new_section_size
            raise RuntimeError(F'trimming from section {_ASCII(section.Name)}; data extends {overlap} beyond section')

        rva_lbound = section.VirtualAddress
        rva_ubound = section.VirtualAddress + section.Misc_VirtualSize - 1
        tva_lbound = rva_lbound + base
        tva_ubound = rva_ubound + base

        def adjust_attributes_of_structure(
            structure: Structure,
            threshold: int,
            lbound: Optional[int],
            ubound: Optional[int],
            attributes: Iterable[str]
        ):
            for attribute in attributes:
                old_value = getattr(structure, attribute, 0)
                if old_value <= threshold:
                    continue
                if lbound is not None and old_value < lbound:
                    continue
                if ubound is not None and old_value > ubound:
                    continue
                new_value = old_value - gap_size
                if new_value < 0:
                    raise RuntimeError(F'adjusting attribute {attribute} of {structure.name} would result in negative value: {new_value}')
                self.log_info(F'adjusting field in {structure.name}: {attribute}')
                setattr(structure, attribute, new_value)

        it: Iterable[Structure] = iter(pe.__structures__)

        for structure in it:
            old_offset = structure.get_file_offset()
            new_offset = old_offset - gap_offset

            if old_offset > gap_offset:
                if isinstance(structure, SectionStructure) and new_offset % alignment != 0:
                    raise RuntimeError(
                        F'section {_ASCII(structure.Name)} would be moved to offset 0x{new_offset:X}, '
                        F'violating section alignment value 0x{alignment:X}.')
                if old_offset < gap_offset + gap_size:
                    raise RuntimeError(
                        F'structure starts inside removed region: {structure}')
                structure.set_file_offset(new_offset)

            adjust_attributes_of_structure(structure, rva_offset, rva_lbound, rva_ubound, (
                'OffsetToData',
                'AddressOfData',
                'VirtualAddress',
                'AddressOfNames',
                'AddressOfNameOrdinals',
                'AddressOfFunctions',
                'AddressOfEntryPoint',
                'AddressOfRawData',
                'BaseOfCode',
                'BaseOfData',
            ))
            adjust_attributes_of_structure(structure, tva_offset, tva_lbound, tva_ubound, (
                'StartAddressOfRawData',
                'EndAddressOfRawData',
                'AddressOfIndex',
                'AddressOfCallBacks',
            ))
            adjust_attributes_of_structure(structure, gap_offset, None, None, (
                'OffsetModuleName',
                'PointerToRawData',
            ))
            for attribute in (
                'CvHeaderOffset'
                'OffsetIn2Qwords'
                'OffsetInQwords'
                'Offset'
                'OffsetLow'
                'OffsetHigh'
            ):
                if not hasattr(structure, attribute):
                    continue
                self.log_warn(F'potential offset in structure {structure.name} ignored: {attribute}')

        section.SizeOfRawData = new_section_size

    def _trim_sections(self, pe: PE, data: bytearray) -> int:
        S = self.args.size_limit
        P = self.args.names
        trimmed = 0
        for section in pe.sections:
            section: SectionStructure
            offset = section.PointerToRawData
            name = _ASCII(section.Name)
            old_size = section.SizeOfRawData
            if old_size <= S and not any(fnmatch(name, p) for p in P):
                self.log_debug(F'criteria not satisfied for section: {SizeInt(old_size)!r} {name}')
                continue
            new_size = self._right_strip_low_entropy(pe, memoryview(data)[offset:offset + old_size])
            self.log_info(F'stripping section {name} from {old_size} to {new_size}')
            gap_size = old_size - new_size
            gap_offset = offset + new_size
            if gap_size <= 0:
                continue
            self._adjust_offsets(pe, gap_offset, gap_size)
            trimmed += gap_size
            data[gap_offset:gap_offset + gap_size] = []
        return trimmed

    def _trim_resources(self, pe: PE, data: bytearray) -> int:
        S = self.args.size_limit
        P = self.args.names
        trimmed = 0

        def find_bloated_resources(pe: PE, directory, level: int = 0, *path) -> Generator[Structure, None, None]:
            for entry in directory.entries:
                name = getattr(entry, 'name')
                numeric = getattr(entry, 'id')
                if not name:
                    if level == 0 and numeric in iter(RSRC):
                        name = RSRC(entry.id)
                    elif numeric is not None:
                        name = str(numeric)
                name = name and str(name) or '?'
                if entry.struct.DataIsDirectory:
                    yield from find_bloated_resources(pe, entry.directory, level + 1, *path, name)
                    continue
                struct: Structure = entry.data.struct
                name = '/'.join((*path, name))
                if struct.Size <= S and not any(fnmatch(name, p) for p in P):
                    self.log_debug(F'criteria not satisfied for resource: {SizeInt(struct.Size)!r} {name}')
                    continue
                yield name, struct

        pe.parse_data_directories(directories=[DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])

        for name, resource in find_bloated_resources(pe, pe.DIRECTORY_ENTRY_RESOURCE):
            offset = pe.get_offset_from_rva(resource.OffsetToData)
            old_size = resource.Size
            new_size = self._right_strip_low_entropy(pe, memoryview(data)[offset:offset + old_size])
            self.log_info(F'stripping resource {name} from {old_size} to {new_size}')
            gap_size = old_size - new_size
            gap_offset = offset + new_size
            if gap_size <= 0:
                continue
            resource.Size = new_size
            self._adjust_offsets(pe, gap_offset, gap_size)
            trimmed += gap_size
            data[gap_offset:gap_offset + gap_size] = []

        return trimmed

    def process(self, data: bytearray) -> bytearray:
        body_size = self._get_size(data)
        if body_size < len(data):
            if isinstance(data, bytearray):
                data[body_size:] = []
            else:
                data = data[:body_size]
        if not self.args.resources and not self.args.sections:
            return data
        pe = PE(data=data, fast_load=True)
        total = len(data)
        trimmed = 0
        view = pe.__data__
        copy = False
        if not isinstance(view, bytearray):
            view = memoryview(view)
            try:
                view[0] = 0x4D
            except Exception:
                copy = True
                view = bytearray(pe.__data__)
        if self.args.resources:
            trimmed += self._trim_resources(pe, view)
        if self.args.sections:
            trimmed += self._trim_sections(pe, view)
        if copy:
            pe.__data__ = view
        data = pe.write()
        end = total - trimmed
        if end < len(data):
            self.log_warn(F'output contains {end-len(data)} trailing bytes')
        return data
