from __future__ import annotations

import codecs
import math

from dataclasses import dataclass, field
from functools import cached_property
from typing import ClassVar
from uuid import UUID

from refinery.lib.lcid import DEFAULT_CODEPAGE, LCID
from refinery.lib.seven.lzx import LzxDecoder
from refinery.lib.structures import Struct, StructReader

_LZX_HLP = UUID('0a9007c6-4076-11d3-8789-0000f8105754')
_LZX_CHM = UUID('7fc28940-9d31-11d0-9b27-00a0c91e9c7c')


class SectionHeader(Struct):
    def __init__(self, reader: StructReader[memoryview]):
        self.offset = reader.u64()
        self.length = reader.u64()


class LanguageMixin:
    language: int

    @cached_property
    def codepage(self):
        return DEFAULT_CODEPAGE.get(self.language, None)

    @cached_property
    def language_name(self):
        return LCID.get(self.language, 'Unknown')


class ChmStruct(Struct):
    Magic: ClassVar[bytes]

    def _check_magic(self, reader: StructReader):
        if (s := reader.peek(len(self.Magic))) != self.Magic:
            raise InvalidMagic(self, s)


class InvalidMagic(ValueError):
    def __init__(self, who: ChmStruct, magic: memoryview):
        super().__init__(
            F'Invalid {who.__class__.__name__} signature {magic.hex(":").upper()}, '
            F'should be {who.Magic.hex(":").upper()}.')


class ChmHeader(ChmStruct, LanguageMixin):

    Magic = B'ITSF'
    Guid = UUID('7C01FD10-7BAA-11D0-9E0C-00A0-C922-E6EC')

    def __init__(self, reader: StructReader[memoryview]):
        self._check_magic(reader)
        self.signature = reader.read_bytes(4)
        self.version = v = reader.u32()
        if v < 3:
            raise NotImplementedError(F'Parsing of HelpV{v} not yet implemented.')
        self.header_size = reader.u32()
        self.unknown = reader.u32()
        self.timestamp = reader.u32()
        self.language = reader.u32()
        self.guid1 = reader.read_guid()
        self.guid2 = reader.read_guid()
        self.section_file_size = SectionHeader(reader)
        self.section_directory = SectionHeader(reader)
        self.content_offset = reader.u64() if v >= 3 else None


class FileSizeHeader(ChmStruct):

    Magic = B'\xFE\x01\0\0'

    def __init__(self, reader: StructReader[memoryview]):
        self._check_magic(reader)
        self.signature = reader.u32()
        reader.skip(4)
        self.file_size = reader.u64()
        reader.skip(8)


class DirectoryHeader(ChmStruct, LanguageMixin):

    Magic = B'ITSP\x01\0\0\0'
    Guid = UUID('5D02926A-212E-11D0-9DF9-00A0C922E6EC')

    def __init__(self, reader: StructReader[memoryview]):
        self._check_magic(reader)
        self.signature = reader.read_bytes(4)
        self.version = reader.u32()
        if self.version != 1:
            raise NotImplementedError
        self.header_length_1 = reader.u32()
        reader.skip(4)
        self.chunk_size = reader.u32()
        self.density = reader.u32()
        self.tree_depth = reader.u32()
        self.root_chunk = reader.u32()
        self.listing1st = reader.u32()
        self.listingLst = reader.u32()
        reader.skip(4)
        self.total_chunks = reader.u32()
        self.language = reader.u32()
        if reader.read_guid() != self.Guid:
            raise NotImplementedError
        self.header_length_2 = reader.u32()
        reader.skip(12)


class QuickRefArea(Struct):
    def __init__(self, reader: StructReader, n: int, count: int):
        self.offsets = {
            (k * n): reader.u16() for k in range(count, 0, -1)
        }
        self.num_entries = reader.u16()


class DirectoryListingEntry(Struct):

    def __init__(self, reader: StructReader):
        ns = reader.read_7bit_encoded_int(64, bigendian=True)
        self.name = reader.read_bytes(ns).decode('utf8')
        self.section_index = reader.read_7bit_encoded_int(64, bigendian=True)
        self.offset = reader.read_7bit_encoded_int(64, bigendian=True)
        self.length = reader.read_7bit_encoded_int(64, bigendian=True)


class Chunk(ChmStruct):

    def __init__(self, reader: StructReader, density: int):
        self._check_magic(reader)
        self.density = density
        with reader.detour_from_end(-2):
            self.num_entries = reader.u16()
        self.signature = reader.read_bytes(4)
        self.extra_size = reader.u32()

    def _quick_refs(self, reader: StructReader, density: int):
        n = 1 + (1 << density)
        count = self.num_entries // n
        skips = reader.remaining_bytes - 2 * (count + 1)
        while skips < 0:
            count -= 1
            skips += 2
        reader.skip(skips)
        self.quickref = QuickRefArea(reader, n, count)
        if self.quickref.num_entries != self.num_entries:
            raise ValueError


class IndexChunk(Chunk):

    Magic = B'PMGI'

    def __init__(self, reader: StructReader, density: int):
        super().__init__(reader, density)
        self._quick_refs(reader, density)


class ListingChunk(Chunk):

    Magic = B'PMGL'

    def __init__(self, reader: StructReader, density: int):
        super().__init__(reader, density)
        reader.skip(4)
        self.nr_prev = reader.u32()
        self.nr_next = reader.u32()
        self.entries = [
            DirectoryListingEntry(reader) for _ in range(self.num_entries)]
        self._quick_refs(reader, density)


class ContentSectionsName(Struct):
    def __init__(self, reader: StructReader):
        name = reader.read_length_prefixed(16, block_size=2)
        self.name = codecs.decode(name, 'utf-16le')
        if (t := reader.u16()) != 0:
            raise ValueError(F'Expected a zero WORD after content section name, got 0x{t:X}.')

    @property
    def path(self):
        return F'::DataSpace/Storage/{self.name}/'

    @property
    def path_content(self):
        return F'{self.path}Content'

    @property
    def path_ctrl_data(self):
        return F'{self.path}ControlData'

    @property
    def path_span_info(self):
        return F'{self.path}SpanInfo'

    def path_reset_table(self, guid: UUID):
        return F'{self.path}Transform/{{{str(guid).upper()}}}/InstanceData/ResetTable'


class ContentSections(Struct):
    def __init__(self, reader: StructReader):
        self.file_size = reader.u16()
        self.sections = [ContentSectionsName(reader) for _ in range(reader.u16())]


class ContentSectionsControlData(ChmStruct):

    Magic = b'LZXC'

    def __init__(self, reader: StructReader[memoryview]):
        # Number of DWORDs following 'LZXC': Must be 6 if version is 2
        self.field_count = reader.u32()
        self._check_magic(reader)
        self.signature = reader.read_bytes(4)
        self.version = reader.u32()
        self.reset_interval = reader.u32()
        self.window_size = reader.u32()
        self.cache_size = reader.u32()
        if (unknowns := self.field_count - 5) > 0:
            self.extra = [reader.u32() for _ in range(unknowns)]


class ContentSectionsResetTable(Struct):

    def __init__(self, reader: StructReader[memoryview]):
        start = reader.tell()
        self.version = reader.u32()
        if self.version not in {2, 3}:
            raise NotImplementedError
        n = reader.u32()
        if reader.u32() != 8:
            raise NotImplementedError
        self.header_size = reader.u32()
        self.size_uncompressed = reader.u64()
        self.size_compressed = reader.u64()
        self.block_size = reader.u64()
        if reader.tell() != self.header_size + start:
            raise NotImplementedError
        self.entries = [reader.u64() for _ in range(n)]


@dataclass
class ContentSection:
    offset: int
    length: int
    base_section: int | None = None
    uncompressed: int | None = None
    window_size: int = 0
    reset_interval: int = 0
    block_size: int = 0
    block_offsets: list = field(default_factory=list)


class CHM(Struct):

    def read_section(self, index: int) -> memoryview:
        try:
            return self.section_data[index]
        except KeyError:
            cs = self.sections[index]
        if cs.base_section is None:
            with self.reader.detour(cs.offset):
                data = self.reader.read(cs.length)
        else:
            data = self.read_section(cs.base_section)[cs.offset:][:cs.length]
        if cs.window_size and cs.block_offsets:
            lzx = LzxDecoder()
            out = bytearray()
            lzx.set_params_and_alloc(cs.window_size)
            for nr, offset in enumerate(cs.block_offsets):
                if nr % cs.reset_interval == 0:
                    lzx.keep_history = False
                if nr < len(cs.block_offsets) - 1:
                    length = cs.block_offsets[nr + 1] - offset
                else:
                    length = len(data) - offset
                out.extend(lzx.decompress(data[offset:][:length], cs.block_size))
                lzx.keep_history = True
            data = memoryview(out)
        self.section_data[index] = data
        return data

    def read(self, entry: DirectoryListingEntry):
        data = self.read_section(entry.section_index)
        return data[entry.offset:][:entry.length]

    def seekto(self, reader: StructReader, path: str):
        if content := self.filesystem.get(path):
            reader.seekset(self.sections[content.section_index].offset + content.offset)
            return True
        else:
            return False

    def __init__(self, reader: StructReader[memoryview], *args, **kwargs):
        self.filesystem: dict[str, DirectoryListingEntry] = {}
        self.sections: list[ContentSection] = []
        self.section_data: dict[int, memoryview] = {}

        self.reader = reader
        self.header = header = ChmHeader(reader)

        with reader.detour_absolute(header.section_file_size.offset):
            self.file_size = FileSizeHeader(reader)

        with reader.detour_absolute(header.section_directory.offset):
            self.directory = dh = DirectoryHeader(reader)
            self.index = []

            d = dh.density
            m = dh.chunk_size

            self.listing: list[ListingChunk] = []

            for k in range(dh.total_chunks):
                body = reader.read_exactly(m)
                if body[:4] == IndexChunk.Magic:
                    self.index.append(IndexChunk.Parse(body, d))
                    continue
                if body[:4] == ListingChunk.Magic:
                    if not (dh.listing1st <= k <= dh.listingLst):
                        raise ValueError(F'Chunk {k} has magic {ListingChunk.Magic.decode()} but is out of listing range.')
                    chunk = ListingChunk.Parse(body, d)
                    for entry in chunk.entries:
                        name = entry.name
                        if name.startswith('/#') or name.startswith('/$'):
                            name = F'/$CHM{name}'
                        self.filesystem[name] = entry
                    self.listing.append(chunk)
                    continue
                raise ValueError(F'Unknown chunk magic: {body[:4].hex(":")}')

        if (co := header.content_offset) is None:
            co = reader.tell()

        reader.seekset(co)
        total_size = reader.remaining_bytes
        reader.seekset(co + self.filesystem['::DataSpace/NameList'].offset)
        self.content_sections = ContentSections(reader)

        for section in self.content_sections.sections:
            if section.name.lower() == 'uncompressed':
                self.sections.append(ContentSection(co, total_size))
                continue
            try:
                content = self.filesystem[section.path_content]
            except KeyError as KE:
                raise LookupError(F'could not find content file for section {section.name}') from KE

            cs = ContentSection(content.offset, content.length)
            cs.base_section = s = content.section_index
            reader.seekset(self.sections[s].offset + cs.offset)

            if self.seekto(reader, section.path_ctrl_data):
                control_data = ContentSectionsControlData(reader)
                cs.reset_interval = control_data.reset_interval
                cs.window_size = 15 + int(math.log2(control_data.window_size))

            if self.seekto(reader, section.path_span_info):
                cs.uncompressed = reader.u64()

            if any(
                self.seekto(reader, section.path_reset_table(guid))
                for guid in (_LZX_CHM, _LZX_HLP)
            ):
                reset_table = ContentSectionsResetTable(reader)
                cs.block_offsets = reset_table.entries
                cs.block_size = reset_table.block_size

            if cs.base_section != 0:
                raise ValueError(F'Invalid base section {cs.base_section}')

            self.sections.append(cs)
