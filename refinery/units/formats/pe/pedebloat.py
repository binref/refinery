#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
from typing import Generator, Iterable, Optional

from refinery.units.formats.pe import OverlayUnit, Arg
from refinery.units.formats.pe.perc import RSRC
from refinery.lib.executable import Executable
from refinery.lib.argformats import percent
from refinery.lib.meta import TerseSizeInt as TI, SizeInt

import zlib

from fnmatch import fnmatch
from pefile import PE, Structure, SectionStructure, DIRECTORY_ENTRY

_KB = 1000
_MB = _KB * _KB

_STRIP = TI(10 * _MB)
_ASCII = Executable.ascii


class BrokenLink(Exception):
    pass


class pedebloat(OverlayUnit):
    """
    Removes junk or excess data from PE files and returns the stripped executable. By default, only
    the PE overlay is considered; use the flags `-r` and `-s` to also consider resources and entire
    sections. Any buffer is only considered for removal if it exceeds a certain size. If this
    condition is met, a binary search is performed to determine the offset inside the buffer up to
    which the compression ratio is above a certain threshold; everything beyond that point is then
    removed. By setting the threshold compression ratio to 1, each large buffer is removed entirely.
    """
    def __init__(
        self,
        *names: Arg(type=str),
        certificate=False,
        directories=False,
        memdump=False,
        resources: Arg.Switch('-r', help='Strip large resources.') = False,
        sections : Arg.Switch('-s', help='Strip large sections.') = False,
        trim_text: Arg.Switch('-X', help='Lift the exception on .TEXT section for stripping.') = False,
        trim_rsrc: Arg.Switch('-Y', help='Lift the exception on .RSRC section for stripping.') = False,
        threshold: Arg('-t', metavar='T', type=percent, help=(
            'Trailing data from resources and sections is stripped until the compression ratio '
            'of the remaining data rises above this threshold. The default value is {default}. '
            'Set this to 1 to ignore the limit entirely and trim every structure as much as '
            'possible without violating alignment. Setting this value to 0 will only strip repeated '
            'occurrences of the last byte.')) = 0.05,
        size_limit: Arg.Number('-l', help=(
            'Structures below this size are not stripped. Default is {default!r}.')) = _STRIP,
        keep_limit: Arg.Switch('-k', help=(
            'Do not strip structures to below the above size limit.')) = False,
        aggressive: Arg.Switch('-a', help=(
            'Equivalent to -srt1: Strip large sections and resources aggressively.')) = False,
    ):
        if aggressive:
            sections = True
            resources = True
            threshold = 1

        super().__init__(
            certificate,
            directories,
            memdump,
            sections=sections,
            resources=resources,
            size_limit=size_limit,
            keep_limit=keep_limit,
            threshold=threshold,
            trim_rsrc=trim_rsrc,
            trim_text=trim_text,
            names=names,
        )

    def _right_strip_data(self, data: memoryview, alignment=1, block_size=_MB) -> int:
        if not data:
            return 0
        threshold = self.args.threshold
        data_overhang = len(data) % alignment
        result = data_overhang

        if 0 < threshold < 1:
            def compression_ratio(offset: int):
                ratio = len(zlib.compress(data[:offset], level=1)) / offset
                self.log_debug(F'compressing {SizeInt(offset)!r} ratio={ratio:6.4f}')
                return ratio
            upper = len(data)
            lower = result
            if compression_ratio(upper) <= threshold:
                while block_size < upper - lower:
                    pivot = (lower + upper) // 2
                    ratio = compression_ratio(pivot)
                    if ratio > threshold:
                        lower = pivot + 1
                        continue
                    upper = pivot
                    if abs(ratio - threshold) < 1e-10:
                        break
            result = upper
        elif threshold == 0:
            result = len(data)
        elif threshold == 1:
            result = 0

        while result > 1 and data[result - 2] == data[result - 1]:
            result -= 1

        result = max(result, data_overhang)

        if self.args.keep_limit:
            result = max(result, self.args.size_limit)

        result = result + (data_overhang - result) % alignment

        if result > len(data):
            excess = result - len(data)
            excess = excess + (-excess % alignment)
            result = result - excess

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
            gap_offset: int,
            valid_values_lower_bound: Optional[int],
            valid_values_upper_bound: Optional[int],
            attributes: Iterable[str]
        ):
            for attribute in attributes:
                old_value = getattr(structure, attribute, 0)
                if old_value <= gap_offset:
                    continue
                if valid_values_lower_bound is not None and old_value < valid_values_lower_bound:
                    continue
                if valid_values_upper_bound is not None and old_value > valid_values_upper_bound:
                    continue
                new_value = old_value - gap_size
                if new_value < gap_offset:
                    raise BrokenLink(F'attribute {attribute} points into removed region')
                self.log_debug(F'adjusting field in {structure.name}: {attribute}')
                setattr(structure, attribute, new_value)

        it: Iterable[Structure] = iter(pe.__structures__)
        remove = []

        for index, structure in enumerate(it):
            old_offset = structure.get_file_offset()
            new_offset = old_offset - gap_offset

            if old_offset > gap_offset:
                if old_offset < gap_offset + gap_size:
                    self.log_debug(F'removing structure {structure.name}; starts inside removed region')
                    remove.append(index)
                    continue
                if isinstance(structure, SectionStructure) and new_offset % alignment != 0:
                    raise RuntimeError(
                        F'structure {structure.name} would be moved to offset 0x{new_offset:X}, '
                        F'violating section alignment value 0x{alignment:X}.')
                structure.set_file_offset(new_offset)

            try:
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
            except BrokenLink as error:
                self.log_debug(F'removing structure {structure.name}; {error!s}')
                remove.append(index)
                continue

            for attribute in (
                'CvHeaderOffset',
                'OffsetIn2Qwords',
                'OffsetInQwords',
                'Offset',
                'OffsetLow',
                'OffsetHigh'
            ):
                if not hasattr(structure, attribute):
                    continue
                self.log_warn(F'potential offset in structure {structure.name} ignored: {attribute}')

        while remove:
            index = remove.pop()
            pe.__structures__[index:index + 1] = []

        section.SizeOfRawData = new_section_size

    def _trim_sections(self, pe: PE, data: bytearray) -> int:
        S = self.args.size_limit
        P = self.args.names
        trimmed = 0
        for section in pe.sections:
            section: SectionStructure
            offset = section.PointerToRawData
            name = _ASCII(section.Name)
            if not self.args.trim_text and name.lower() in ('.text', '.code'):
                self.log_info(F'skipping code section {name}')
                continue
            if not self.args.trim_rsrc and name.lower() == '.rsrc':
                self.log_info(F'skipping rsrc section {name}')
                continue
            old_size = section.SizeOfRawData
            if old_size <= S and not any(fnmatch(name, p) for p in P):
                self.log_debug(F'criteria not satisfied for section: {SizeInt(old_size)!r} {name}')
                continue
            new_size = self._right_strip_data(
                memoryview(data)[offset:offset + old_size],
                pe.OPTIONAL_HEADER.FileAlignment)
            self.log_info(F'stripping section {name} from {TI(old_size)!r} to {TI(new_size)!r}')
            gap_size = old_size - new_size
            gap_offset = offset + new_size
            if gap_size <= 0:
                continue
            self._adjust_offsets(pe, gap_offset, gap_size)
            trimmed += gap_size
            data[gap_offset:gap_offset + gap_size] = []
        return trimmed

    def _trim_pe_resources(self, pe: PE, data: bytearray) -> int:
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

        RSRC_INDEX = DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']
        pe.parse_data_directories(directories=[RSRC_INDEX])

        try:
            resources = pe.DIRECTORY_ENTRY_RESOURCE
        except AttributeError:
            return 0
        for name, resource in find_bloated_resources(pe, resources):
            offset = pe.get_offset_from_rva(resource.OffsetToData)
            old_size = resource.Size
            new_size = self._right_strip_data(
                memoryview(data)[offset:offset + old_size],
                pe.OPTIONAL_HEADER.FileAlignment)
            self.log_info(F'stripping resource {name} from {old_size} to {new_size}')
            gap_size = old_size - new_size
            gap_offset = offset + new_size
            if gap_size <= 0:
                continue
            resource.Size = new_size
            self._adjust_offsets(pe, gap_offset, gap_size)
            trimmed += gap_size
            data[gap_offset:gap_offset + gap_size] = []

        pe.OPTIONAL_HEADER.DATA_DIRECTORY[RSRC_INDEX].Size -= trimmed
        self.log_info(F'trimming size of resource data directory by {TI(trimmed)!r}')
        return trimmed

    def process(self, data: bytearray) -> bytearray:
        overlay_offset = self._get_size(data)
        if len(data) - overlay_offset >= self.args.size_limit:
            view = memoryview(data)
            overlay_length = self._right_strip_data(view[overlay_offset:])
            body_size = overlay_offset + overlay_length
            try:
                data[body_size:] = []
            except Exception:
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
            trimmed += self._trim_pe_resources(pe, view)
        if self.args.sections:
            trimmed += self._trim_sections(pe, view)
        if copy:
            pe.__data__ = view
        data = pe.write()
        end = total - trimmed
        if end < len(data):
            self.log_warn(F'output contains {len(data)-end} trailing bytes')
        return data
