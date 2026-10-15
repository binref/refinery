from __future__ import annotations

import codecs
import math
import weakref

from dataclasses import dataclass, field
from functools import cached_property, partial
from typing import Callable, ClassVar, Iterator
from uuid import UUID

from refinery.lib.lcid import DEFAULT_CODEPAGE, LCID
from refinery.lib.seven.lzx import LzxDecoder
from refinery.lib.solid import SolidStream, SolidStreamTruncated
from refinery.lib.structures import Struct, StructReader
from refinery.lib.types import buf

_LZX_HLP = UUID('0a9007c6-4076-11d3-8789-0000f8105754')
_LZX_CHM = UUID('7fc28940-9d31-11d0-9b27-00a0c91e9c7c')


class SectionHeader(Struct):
    def __init__(self, reader: StructReader[memoryview]):
        self.offset = reader.u64()
        self.length = reader.u64()


def _caseless(name: str) -> bytes:
    return name.encode('utf8').lower()


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
        end = reader.tell() + reader.remaining_bytes
        super().__init__(reader, density)
        end -= self.extra_size
        self.entries: list[tuple[str, int]] = []
        while reader.tell() < end:
            ns = reader.read_7bit_encoded_int(64, bigendian=True)
            name = reader.read_bytes(ns).decode('utf8')
            self.entries.append((name, reader.read_7bit_encoded_int(64, bigendian=True)))
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

    def _stored(self, index: int) -> memoryview:
        cs = self.sections[index]
        if cs.base_section is None:
            with self.reader.detour(cs.offset):
                return self.reader.read(cs.length)
        return self._stored(cs.base_section)[cs.offset:][:cs.length]

    def _restart(self, index: int, offset: int) -> int:
        cs = self.sections[index]
        block = offset // cs.block_size
        return (block - block % cs.reset_interval) * cs.block_size

    def _decode(self, index: int, origin: int) -> Iterator[tuple[int, buf]]:
        cs = self.sections[index]
        data = self._stored(index)
        lzx = LzxDecoder()
        lzx.set_params_and_alloc(cs.window_size)
        offsets = cs.block_offsets
        for nr in range(origin // cs.block_size, len(offsets)):
            lzx.keep_history = nr % cs.reset_interval != 0
            start = offsets[nr]
            end = offsets[nr + 1] if nr + 1 < len(offsets) else len(data)
            yield nr * cs.block_size, lzx.decompress(data[start:end], cs.block_size)

    def extractor(self, entry: DirectoryListingEntry) -> Callable[[], buf]:
        """
        Return a function that returns the data of the given entry. A compressed section is
        decompressed as far as necessary; it keeps the data of other entries only while the
        functions returned for them are alive. Data that the section does not contain is missing
        from the result.
        """
        if (index := entry.section_index) >= len(self.sections):
            return partial(self._missing_section, index)
        cs = self.sections[index]
        if not cs.window_size or not cs.block_offsets:
            return lambda: self._stored(index)[entry.offset:][:entry.length]
        if (stream := self._streams.get(index)) is None:
            stream = self._streams[index] = SolidStream(
                partial(self._decode, index),
                partial(self._restart, index),
                volatile=True,
            )
        claim = stream.claim(entry.offset, entry.length)

        def extract() -> buf:
            try:
                return claim()
            except SolidStreamTruncated as truncated:
                return truncated.partial

        return extract

    def _missing_section(self, index: int) -> buf:
        raise IndexError(F'The archive has no section {index}.')

    def read(self, entry: DirectoryListingEntry) -> buf:
        """
        Return the data of the given entry; see `refinery.lib.chm.CHM.extractor`.
        """
        return self.extractor(entry)()

    def seekto(self, reader: StructReader, path: str):
        if content := self.find(path):
            reader.seekset(self.sections[content.section_index].offset + content.offset)
            return True
        else:
            return False

    @property
    def listing(self) -> list[ListingChunk]:
        """
        The listing chunks of the directory in the order of the file.
        """
        return [chunk for chunk in self.chunks if isinstance(chunk, ListingChunk)]

    def entries(self) -> Iterator[DirectoryListingEntry]:
        """
        Generates every entry of the directory in the order of the file, also when two entries
        have the same name.
        """
        for chunk in self.listing:
            yield from chunk.entries

    def find(self, name: str) -> DirectoryListingEntry | None:
        """
        Find the directory entry with the given name through the directory index: starting at the
        root of the index, every index chunk leads to the chunk of its last entry whose name is not
        greater than the given one, and the first entry with the given name in the listing chunk
        reached this way is returned. Names are compared ignoring the case of ASCII letters. Without
        an index, only the first listing chunk is searched.
        """
        key = _caseless(name)
        number = self.directory.root_chunk
        if number >= len(self.chunks):
            number = self.directory.listing1st
        visited: set[int] = set()
        while 0 <= number < len(self.chunks) and number not in visited:
            visited.add(number)
            chunk = self.chunks[number]
            if isinstance(chunk, ListingChunk):
                for entry in chunk.entries:
                    if _caseless(entry.name) == key:
                        return entry
                return None
            number = -1
            for lower_bound, target in chunk.entries:
                if _caseless(lower_bound) > key:
                    break
                number = target
        return None

    def __init__(self, reader: StructReader[memoryview], *args, **kwargs):
        self.sections: list[ContentSection] = []
        self._streams: weakref.WeakValueDictionary[int, SolidStream] = weakref.WeakValueDictionary()

        self.reader = reader
        self.header = header = ChmHeader(reader)

        with reader.detour_absolute(header.section_file_size.offset):
            self.file_size = FileSizeHeader(reader)

        with reader.detour_absolute(header.section_directory.offset):
            self.directory = dh = DirectoryHeader(reader)
            self.chunks: list[IndexChunk | ListingChunk] = []

            d = dh.density
            m = dh.chunk_size

            for k in range(dh.total_chunks):
                body = reader.read_exactly(m)
                if body[:4] == IndexChunk.Magic:
                    self.chunks.append(IndexChunk.Parse(body, d))
                    continue
                if body[:4] == ListingChunk.Magic:
                    if not (dh.listing1st <= k <= dh.listingLst):
                        raise ValueError(F'Chunk {k} has magic {ListingChunk.Magic.decode()} but is out of listing range.')
                    self.chunks.append(ListingChunk.Parse(body, d))
                    continue
                raise ValueError(F'Unknown chunk magic: {body[:4].hex(":")}')

        if (co := header.content_offset) is None:
            co = reader.tell()

        reader.seekset(co)
        total_size = reader.remaining_bytes
        if (names := self.find('::DataSpace/NameList')) is None:
            raise LookupError('could not find the list of content sections')
        reader.seekset(co + names.offset)
        self.content_sections = ContentSections(reader)

        for section in self.content_sections.sections:
            if section.name.lower() == 'uncompressed':
                self.sections.append(ContentSection(co, total_size))
                continue
            if (content := self.find(section.path_content)) is None:
                raise LookupError(F'could not find content file for section {section.name}')

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
