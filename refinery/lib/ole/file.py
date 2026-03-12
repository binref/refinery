"""
Parser for Microsoft OLE2 Compound Binary Files (CFB).
"""
from __future__ import annotations

import codecs
import datetime
import enum
import itertools
import math
import re
import struct

from typing import TYPE_CHECKING
from uuid import UUID

from refinery.lib.structures import MemoryFile, StructReader

if TYPE_CHECKING:
    from typing import Any


MAGIC = b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'
MINIMAL_OLEFILE_SIZE = 1536

MAXREGSECT = 0xFFFFFFFA
DIFSECT    = 0xFFFFFFFC  # noqa
FATSECT    = 0xFFFFFFFD  # noqa
ENDOFCHAIN = 0xFFFFFFFE  # noqa
FREESECT   = 0xFFFFFFFF  # noqa

MAXREGSID  = 0xFFFFFFFA  # noqa
NOSTREAM   = 0xFFFFFFFF  # noqa


class STGTY(enum.IntEnum):
    EMPTY     = 0  # noqa
    STORAGE   = 1  # noqa
    STREAM    = 2  # noqa
    LOCKBYTES = 3  # noqa
    PROPERTY  = 4  # noqa
    ROOT      = 5  # noqa


VT_EMPTY            =  0  # noqa
VT_NULL             =  1  # noqa
VT_I2               =  2  # noqa
VT_I4               =  3  # noqa
VT_R4               =  4  # noqa
VT_R8               =  5  # noqa
VT_CY               =  6  # noqa
VT_DATE             =  7  # noqa
VT_BSTR             =  8  # noqa
VT_DISPATCH         =  9  # noqa
VT_ERROR            = 10  # noqa
VT_BOOL             = 11  # noqa
VT_VARIANT          = 12  # noqa
VT_UNKNOWN          = 13  # noqa
VT_DECIMAL          = 14  # noqa
VT_I1               = 16  # noqa
VT_UI1              = 17  # noqa
VT_UI2              = 18  # noqa
VT_UI4              = 19  # noqa
VT_I8               = 20  # noqa
VT_UI8              = 21  # noqa
VT_INT              = 22  # noqa
VT_UINT             = 23  # noqa
VT_VOID             = 24  # noqa
VT_HRESULT          = 25  # noqa
VT_PTR              = 26  # noqa
VT_SAFEARRAY        = 27  # noqa
VT_CARRAY           = 28  # noqa
VT_USERDEFINED      = 29  # noqa
VT_LPSTR            = 30  # noqa
VT_LPWSTR           = 31  # noqa
VT_FILETIME         = 64  # noqa
VT_BLOB             = 65  # noqa
VT_STREAM           = 66  # noqa
VT_STORAGE          = 67  # noqa
VT_STREAMED_OBJECT  = 68  # noqa
VT_STORED_OBJECT    = 69  # noqa
VT_BLOB_OBJECT      = 70  # noqa
VT_CF               = 71  # noqa
VT_CLSID            = 72  # noqa
VT_VECTOR           = 0x1000  # noqa

DEFECT_UNSURE       = 10  # noqa
DEFECT_POTENTIAL    = 20  # noqa
DEFECT_INCORRECT    = 30  # noqa
DEFECT_FATAL        = 40  # noqa

_FILETIME_EPOCH = datetime.datetime(1601, 1, 1, 0, 0, 0)


class OleFileError(IOError):
    pass


class NotOleFileError(OleFileError):
    pass


def filetime_to_datetime(filetime: int) -> datetime.datetime | None:
    if filetime <= 0:
        return None
    try:
        return _FILETIME_EPOCH + datetime.timedelta(microseconds=filetime // 10)
    except (ValueError, OverflowError):
        return None


def _clsid(data: bytes | bytearray | memoryview) -> str:
    if len(data) != 16 or not any(data):
        return ''
    if not isinstance(data, bytes):
        data = bytes(data)
    return str(UUID(bytes_le=data))


def is_ole_file(data: bytes | bytearray | memoryview) -> bool:
    return data[:8] == MAGIC


def _i16(data, offset: int = 0) -> int:
    return struct.unpack_from('<H', data, offset)[0]


def _i32(data, offset: int = 0) -> int:
    return struct.unpack_from('<I', data, offset)[0]


class DirectoryEntry:
    """
    Represents a single 128-byte directory entry in an OLE2 file.
    """
    __slots__ = (
        'sid',
        'name',
        'entry_type',
        'color',
        'sid_left',
        'sid_right',
        'sid_child',
        'clsid',
        'user_flags',
        'create_time',
        'modify_time',
        'start',
        'size',
        'is_minifat',
        'kids',
        'kids_dict',
        'used',
    )

    def __init__(
        self,
        sid: int,
        data: bytes | bytearray | memoryview,
        sector_size: int,
        mini_stream_cutoff: int,
    ):
        self.sid = sid
        self.kids: list[DirectoryEntry] = []
        self.kids_dict: dict[str, DirectoryEntry] = {}
        self.used = False

        entry = memoryview(data)
        name_raw = bytes(entry[0:64])
        name_length = _i16(entry, 64)
        self.entry_type = entry[66]
        self.color = entry[67]
        self.sid_left = _i32(entry, 68)
        self.sid_right = _i32(entry, 72)
        self.sid_child = _i32(entry, 76)
        self.clsid = entry[80:96]
        self.user_flags = _i32(entry, 96)
        self.create_time = struct.unpack_from('<Q', entry, 100)[0]
        self.modify_time = struct.unpack_from('<Q', entry, 108)[0]
        self.start = _i32(entry, 116)
        size_low = _i32(entry, 120)
        size_high = _i32(entry, 124)

        if name_length > 64:
            name_length = 64
        name_bytes = name_raw[:name_length]
        if name_bytes[-2:] == b'\x00\x00':
            name_bytes = name_bytes[:-2]
        try:
            self.name = codecs.decode(name_bytes, 'utf-16-le')
        except UnicodeDecodeError:
            self.name = codecs.decode(name_bytes, 'utf-16-le', errors='replace')

        if sector_size == 512:
            self.size = size_low
        else:
            self.size = size_low + (size_high << 32)

        self.is_minifat = (
            self.entry_type in (STGTY.STREAM, STGTY.LOCKBYTES, STGTY.PROPERTY)
            and self.size < mini_stream_cutoff
        )

    @property
    def clsid_str(self) -> str:
        return _clsid(self.clsid)

    def build_storage_tree(self, entries: list[DirectoryEntry | None]):
        if self.sid_child != NOSTREAM:
            child = entries[self.sid_child] if self.sid_child < len(entries) else None
            if child is not None:
                self._walk_tree(child, entries)
                self.kids.sort(key=lambda e: e.name.lower())
        for kid in self.kids:
            if kid.entry_type in (STGTY.STORAGE, STGTY.ROOT):
                kid.build_storage_tree(entries)

    def _walk_tree(self, node: DirectoryEntry, entries: list[DirectoryEntry | None]):
        if node.used:
            return
        node.used = True
        if node.sid_left != NOSTREAM and node.sid_left < len(entries):
            left = entries[node.sid_left]
            if left is not None:
                self._walk_tree(left, entries)
        self.kids.append(node)
        self.kids_dict[node.name.lower()] = node
        if node.sid_right != NOSTREAM and node.sid_right < len(entries):
            right = entries[node.sid_right]
            if right is not None:
                self._walk_tree(right, entries)


def _read_chain(
    fp: MemoryFile[memoryview],
    fat: list[int],
    start_sector: int,
    sector_size: int,
    sector_offset: int,
    declared_size: int,
    max_sectors: int,
) -> bytearray:
    if declared_size == 0:
        return bytearray()
    if declared_size >= 0:
        nb_sectors = math.ceil(declared_size / sector_size)
    else:
        nb_sectors = max_sectors
    result = bytearray()
    sect = start_sector
    visited = set()
    for _ in range(nb_sectors):
        if sect > MAXREGSECT:
            break
        if sect in visited:
            break
        visited.add(sect)
        offset = sector_offset + sect * sector_size
        fp.seek(offset)
        result.extend(fp.read(sector_size))
        if sect >= len(fat):
            break
        sect = fat[sect]
        if sect == ENDOFCHAIN or sect == FREESECT:
            break
    if declared_size >= 0 and len(result) > declared_size:
        del result[declared_size:]
    return result


SUMMARY_ATTRIBS = [
    None,
    'codepage',
    'title',
    'subject',
    'author',
    'keywords',
    'comments',
    'template',
    'last_saved_by',
    'revision_number',
    'total_edit_time',
    'last_printed',
    'create_time',
    'last_saved_time',
    'num_pages',
    'num_words',
    'num_chars',
    'thumbnail',
    'creating_application',
    'security',
]

DOCSUM_ATTRIBS = [
    None,
    'codepage_doc',
    'category',
    'presentation_target',
    'bytes',
    'lines',
    'paragraphs',
    'slides',
    'notes',
    'hidden_slides',
    'mm_clips',
    'scale_crop',
    'heading_pairs',
    'titles_of_parts',
    'manager',
    'company',
    'links_dirty',
    'chars_with_spaces',
    'unused',
    'shared_doc',
    'link_base',
    'hlinks',
    'hlinks_changed',
    'version',
    'dig_sig',
    'content_type',
    'content_status',
    'language',
    'doc_version',
]


class OleMetadata:
    """
    Parses standard OLE metadata from SummaryInformation and DocumentSummaryInformation
    property streams.
    """
    def __init__(self):
        for attr in SUMMARY_ATTRIBS[1:]:
            setattr(self, attr, None)
        for attr in DOCSUM_ATTRIBS[1:]:
            setattr(self, attr, None)

    def parse(self, ole: OleFile):
        for stream_name, attribs in (
            ('\x05SummaryInformation', SUMMARY_ATTRIBS),
            ('\x05DocumentSummaryInformation', DOCSUM_ATTRIBS),
        ):
            if not ole.exists(stream_name):
                continue
            no_conversion = [10] if attribs is SUMMARY_ATTRIBS else []
            try:
                props = ole.getproperties(
                    stream_name,
                    convert_time=True,
                    no_conversion=no_conversion,
                )
            except Exception:
                continue
            for prop_id, attr_name in enumerate(attribs):
                if attr_name is None:
                    continue
                value = props.get(prop_id)
                if value is not None:
                    setattr(self, attr_name, value)

    def dump(self) -> dict[str, Any]:
        result = {}
        for attr in SUMMARY_ATTRIBS[1:]:
            value = getattr(self, attr, None)
            if value is not None:
                result[attr] = value
        for attr in DOCSUM_ATTRIBS[1:]:
            value = getattr(self, attr, None)
            if value is not None:
                result[attr] = value
        return result


class OleFile:
    """
    Parser for OLE2 Compound Binary Files with in-place stream writing support.
    """

    def __init__(self, data: bytes | bytearray | memoryview | MemoryFile[memoryview]):
        if isinstance(data, MemoryFile):
            fp = data
            mv = data.getbuffer()
        elif isinstance(data, (bytes, bytearray)):
            mv = memoryview(data)
            fp = MemoryFile(mv)
        elif isinstance(data, memoryview):
            mv = data
            fp = MemoryFile(mv)
        else:
            raise TypeError(
                F'Expected bytes, bytearray, memoryview, or MemoryFile,'
                F' got {type(data).__name__}')

        if len(data) < MINIMAL_OLEFILE_SIZE:
            raise NotOleFileError('Data too small to be an OLE2 file.')
        if data[:8] != MAGIC:
            raise NotOleFileError('Not an OLE2 file (invalid magic bytes).')

        self._mv = mv
        self._fp = fp
        self._raise_defects_level = DEFECT_FATAL
        self._metadata: OleMetadata | None = None

        self._parse_header()
        self._load_fat()
        self._load_directory()

        self._minifat: list[int] | None = None
        self._ministream: bytearray | None = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def _raise_defect(self, level: int, message: str):
        if level >= self._raise_defects_level:
            raise OleFileError(message)

    def _parse_header(self):
        reader = StructReader(self._mv[:512])
        reader.seekset(8)
        self._header_clsid = reader.read_bytes(16)
        self._minor_version = reader.u16()
        self._dll_version = reader.u16()
        byte_order = reader.u16()
        if byte_order != 0xFFFE:
            self._raise_defect(DEFECT_INCORRECT, F'Invalid byte order: {byte_order:#06x}')
        sector_shift = reader.u16()
        self._sector_size = 1 << sector_shift
        mini_sector_shift = reader.u16()
        self._mini_sector_size = 1 << mini_sector_shift

        reader.seekrel(6)

        if self._dll_version == 4:
            self._num_dir_sectors = reader.u32()
        else:
            reader.seekrel(4)
            self._num_dir_sectors = 0

        self._num_fat_sectors = reader.u32()
        self._first_dir_sector = reader.u32()
        self._transaction_sig = reader.u32()
        self._mini_stream_cutoff = reader.u32()
        self._first_mini_fat_sector = reader.u32()
        self._num_mini_fat_sectors = reader.u32()
        self._first_difat_sector = reader.u32()
        self._num_difat_sectors = reader.u32()

        self._initial_difat: list[int] = list(
            struct.unpack_from('<109I', self._mv, 76))

        self._nb_sect = (len(self._mv) - self._sector_size) // self._sector_size

    def _getsect(self, sect: int):
        offset = self._sector_size * (sect + 1)
        end = offset + self._sector_size
        if end > len(self._mv):
            out = bytearray(self._mv[offset:])
            out.extend(itertools.repeat(0, end - len(self._mv)))
            return out
        return self._mv[offset:end]

    def _load_fat(self):
        fat: list[int] = []
        sector_ints = self._sector_size // 4

        for i in range(109):
            sect_index = self._initial_difat[i]
            if sect_index == FREESECT or sect_index == ENDOFCHAIN:
                break
            if sect_index > MAXREGSECT:
                continue
            sect_data = self._getsect(sect_index)
            fat.extend(struct.unpack_from(F'<{sector_ints}I', sect_data))

        if self._num_difat_sectors > 0:
            difat_sect = self._first_difat_sector
            visited_difat = set()
            for _ in range(self._num_difat_sectors):
                if difat_sect == ENDOFCHAIN or difat_sect == FREESECT:
                    break
                if difat_sect in visited_difat:
                    break
                visited_difat.add(difat_sect)
                difat_data = self._getsect(difat_sect)
                entries_per_difat = sector_ints - 1
                entries = struct.unpack_from(F'<{entries_per_difat}I', difat_data)
                for sect_index in entries:
                    if sect_index == FREESECT or sect_index == ENDOFCHAIN:
                        continue
                    if sect_index > MAXREGSECT:
                        continue
                    sect_data = self._getsect(sect_index)
                    fat.extend(struct.unpack_from(F'<{sector_ints}I', sect_data))
                difat_sect = struct.unpack_from('<I', difat_data, entries_per_difat * 4)[0]

        if len(fat) > self._nb_sect:
            fat = fat[:self._nb_sect]
        self._fat = fat

    def _load_ministream(self):
        if self._minifat is not None:
            return
        if self._first_mini_fat_sector == ENDOFCHAIN or self._num_mini_fat_sectors == 0:
            self._minifat = []
            self._ministream = bytearray()
            return

        minifat_data = _read_chain(
            self._fp,
            self._fat,
            self._first_mini_fat_sector,
            self._sector_size,
            self._sector_size,
            self._num_mini_fat_sectors * self._sector_size,
            self._nb_sect,
        )

        minifat: list[int] = []
        count = len(minifat_data) // 4
        if count > 0:
            minifat = list(struct.unpack_from(F'<{count}I', minifat_data))

        root = self._root
        if root.size > 0:
            used_entries = root.size // self._mini_sector_size
            if len(minifat) > used_entries:
                minifat = minifat[:used_entries]

        self._minifat = minifat

        mini_data = _read_chain(
            self._fp,
            self._fat,
            root.start,
            self._sector_size,
            self._sector_size,
            root.size,
            self._nb_sect,
        )
        self._ministream = mini_data

    def _load_directory(self):
        dir_data = _read_chain(
            self._fp,
            self._fat,
            self._first_dir_sector,
            self._sector_size,
            self._sector_size,
            -1,
            self._nb_sect,
        )

        max_entries = len(dir_data) // 128
        entries: list[DirectoryEntry | None] = [None] * max_entries

        for sid in range(max_entries):
            offset = sid * 128
            chunk = dir_data[offset:offset + 128]
            if len(chunk) < 128:
                break
            entry_type = chunk[66]
            if entry_type == STGTY.EMPTY:
                continue
            entry = DirectoryEntry(sid, chunk, self._sector_size, self._mini_stream_cutoff)
            entries[sid] = entry

        if entries[0] is None:
            raise OleFileError('Root directory entry not found.')

        self._root = entries[0]
        self._entries = entries
        self._root.build_storage_tree(entries)

    def _open_stream(self, entry: DirectoryEntry):
        if entry.is_minifat:
            self._load_ministream()
            if (ms := self._ministream) is None or (mf := self._minifat) is None:
                raise RuntimeError('Ministream was not read.')
            ms = MemoryFile(memoryview(ms))
            data = _read_chain(
                ms,
                mf,
                entry.start,
                self._mini_sector_size,
                0,
                entry.size,
                len(self._minifat) if self._minifat else 0,
            )
        else:
            data = _read_chain(
                self._fp,
                self._fat,
                entry.start,
                self._sector_size,
                self._sector_size,
                entry.size,
                self._nb_sect,
            )
        return MemoryFile(memoryview(data))

    def _find(self, filename: str) -> DirectoryEntry | None:
        node = self._root
        for part in re.split(r'[\\/]+', filename):
            key = part.lower()
            child = node.kids_dict.get(key)
            if child is None:
                return None
            node = child
        return node

    def listdir(self, streams: bool = True, storages: bool = False) -> list[list[str]]:
        result: list[list[str]] = []
        self._list_recursive(self._root, [], result, streams, storages)
        return result

    def _list_recursive(
        self,
        node: DirectoryEntry,
        path: list[str],
        result: list[list[str]],
        streams: bool,
        storages: bool,
    ):
        for kid in node.kids:
            current_path = path + [kid.name]
            if kid.entry_type == STGTY.STREAM and streams:
                result.append(current_path)
            elif kid.entry_type in (STGTY.STORAGE, STGTY.ROOT):
                if storages:
                    result.append(current_path)
                self._list_recursive(kid, current_path, result, streams, storages)

    def openstream(self, filename: str) -> MemoryFile[memoryview]:
        entry = self._find(filename)
        if entry is None:
            raise OleFileError(F'Stream not found: {filename!r}')
        if entry.entry_type != STGTY.STREAM:
            raise OleFileError(F'Not a stream: {filename!r}')
        return self._open_stream(entry)

    def exists(self, filename: str) -> bool:
        return self._find(filename) is not None

    def get_type(self, path: str) -> int:
        entry = self._find(path)
        if entry is None:
            return STGTY.EMPTY
        return entry.entry_type

    def get_size(self, filename: str) -> int:
        entry = self._find(filename)
        if entry is None:
            raise OleFileError(F'Entry not found: {filename!r}')
        return entry.size

    def get_rootentry_name(self) -> str:
        return self._root.name

    def getclsid(self, filename: str) -> str:
        entry = self._find(filename)
        if entry is None:
            raise OleFileError(F'Entry not found: {filename!r}')
        return entry.clsid_str

    def getmtime(self, filename: str) -> datetime.datetime | None:
        entry = self._find(filename)
        if entry is None:
            return None
        return filetime_to_datetime(entry.modify_time)

    def getctime(self, filename: str) -> datetime.datetime | None:
        entry = self._find(filename)
        if entry is None:
            return None
        return filetime_to_datetime(entry.create_time)

    def getproperties(
        self,
        filename: str,
        convert_time: bool = False,
        no_conversion: list[int] | None = None,
    ) -> dict[int, Any]:
        if no_conversion is None:
            no_conversion = []
        raw = self.openstream(filename).read()
        if len(raw) < 28:
            return {}
        try:
            return _parse_property_set(memoryview(raw), convert_time, no_conversion)
        except Exception:
            return {}

    def get_metadata(self) -> OleMetadata:
        if self._metadata is None:
            self._metadata = OleMetadata()
            self._metadata.parse(self)
        return self._metadata

    def write_stream(self, filename: str, data: bytes | bytearray | memoryview) -> None:
        """
        Overwrite an existing stream's data in-place. The new data must be the same length as the
        existing stream. The underlying buffer must be mutable (i.e. the OleFile was constructed
        from a bytearray).
        """
        entry = self._find(filename)
        if entry is None:
            raise OleFileError(F'Stream not found: {filename!r}')
        if entry.entry_type != STGTY.STREAM:
            raise OleFileError(F'Not a stream: {filename!r}')
        if len(data) != entry.size:
            raise OleFileError(F'Data length {len(data)} does not match stream size {entry.size}')
        if not data:
            return
        if entry.is_minifat:
            self._write_mini_stream(entry, data)
        else:
            self._write_regular_stream(entry, data)

    def _write_regular_stream(self, entry: DirectoryEntry, data: bytes | bytearray | memoryview):
        sect = entry.start
        offset = 0
        remaining = len(data)
        visited: set[int] = set()
        while remaining > 0 and sect <= MAXREGSECT and sect not in visited:
            visited.add(sect)
            chunk_size = min(self._sector_size, remaining)
            file_offset = self._sector_size * (sect + 1)
            self._mv[file_offset:file_offset + chunk_size] = data[offset:offset + chunk_size]
            offset += chunk_size
            remaining -= chunk_size
            if sect < len(self._fat):
                sect = self._fat[sect]
            else:
                break

    def _write_mini_stream(self, entry: DirectoryEntry, data: bytes | bytearray | memoryview):
        self._load_ministream()
        if self._ministream is None or self._minifat is None:
            raise RuntimeError('Ministream was not loaded.')
        sect = entry.start
        offset = 0
        remaining = len(data)
        visited: set[int] = set()
        while remaining > 0 and sect <= MAXREGSECT and sect not in visited:
            visited.add(sect)
            chunk_size = min(self._mini_sector_size, remaining)
            ms_offset = sect * self._mini_sector_size
            self._ministream[ms_offset:ms_offset + chunk_size] = data[offset:offset + chunk_size]
            offset += chunk_size
            remaining -= chunk_size
            if sect < len(self._minifat):
                sect = self._minifat[sect]
            else:
                break
        self._flush_ministream()

    def _flush_ministream(self):
        """
        Write the in-memory ministream back to the underlying file buffer by following the root
        entry's FAT chain.
        """
        if self._ministream is None:
            return
        root = self._root
        sect = root.start
        offset = 0
        remaining = len(self._ministream)
        visited: set[int] = set()
        while remaining > 0 and sect <= MAXREGSECT and sect not in visited:
            visited.add(sect)
            chunk_size = min(self._sector_size, remaining)
            file_offset = self._sector_size * (sect + 1)
            self._mv[file_offset:file_offset + chunk_size] = \
                self._ministream[offset:offset + chunk_size]
            offset += chunk_size
            remaining -= chunk_size
            if sect < len(self._fat):
                sect = self._fat[sect]
            else:
                break


def _parse_property_set(
    data: memoryview,
    convert_time: bool,
    no_conversion: list[int],
) -> dict[int, Any]:
    if len(data) < 28:
        return {}

    num_sections = _i32(data, 24)
    if num_sections < 1:
        return {}

    section_offset = _i32(data, 44)
    if section_offset >= len(data):
        return {}

    section_data = data[section_offset:]
    if len(section_data) < 8:
        return {}

    num_props = _i32(section_data, 4)

    props: dict[int, Any] = {}
    codepage = None

    for i in range(num_props):
        entry_offset = 8 + i * 8
        if entry_offset + 8 > len(section_data):
            break
        prop_id = _i32(section_data, entry_offset)
        prop_offset = _i32(section_data, entry_offset + 4)

        if prop_offset + 4 > len(section_data):
            continue

        prop_type = _i32(section_data, prop_offset) & 0xFFFF
        value = _parse_property_value(
            section_data, prop_offset, prop_type, prop_id,
            convert_time, no_conversion, codepage)
        if value is not None:
            props[prop_id] = value
        if prop_id == 1 and isinstance(value, int):
            codepage = value

    return props


def _parse_property_value(
    data: memoryview,
    offset: int,
    prop_type: int,
    prop_id: int,
    convert_time: bool,
    no_conversion: list[int],
    codepage: int | None,
) -> Any:
    base_type = prop_type & 0x0FFF
    is_vector = bool(prop_type & VT_VECTOR)

    if is_vector:
        return _parse_vector_property(
            data, offset, base_type, prop_id,
            convert_time, no_conversion, codepage)

    return _parse_basic_property(
        data, offset + 4, base_type, prop_id,
        convert_time, no_conversion, codepage)


def _parse_vector_property(
    data: memoryview,
    offset: int,
    base_type: int,
    prop_id: int,
    convert_time: bool,
    no_conversion: list[int],
    codepage: int | None,
) -> list | None:
    value_offset = offset + 4
    if value_offset + 4 > len(data):
        return None
    count = _i32(data, value_offset)
    value_offset += 4

    result = []
    for _ in range(count):
        if base_type == VT_VARIANT:
            if value_offset + 4 > len(data):
                break
            variant_type = _i32(data, value_offset) & 0xFFFF
            val = _parse_basic_property(
                data, value_offset + 4, variant_type, prop_id,
                convert_time, no_conversion, codepage)
            size = _property_size(data, value_offset + 4, variant_type, codepage)
            value_offset += 4 + size
        else:
            val = _parse_basic_property(
                data, value_offset, base_type, prop_id,
                convert_time, no_conversion, codepage)
            size = _property_size(data, value_offset, base_type, codepage)
            value_offset += size
        result.append(val)
        pad = (4 - (value_offset % 4)) % 4
        value_offset += pad

    return result


def _property_size(
    data: bytes | bytearray | memoryview,
    offset: int,
    vt: int,
    codepage: int | None,
) -> int:
    if vt in (VT_I2, VT_UI2, VT_BOOL):
        return 2
    if vt in (VT_I4, VT_UI4, VT_INT, VT_UINT, VT_ERROR, VT_R4):
        return 4
    if vt in (VT_I8, VT_UI8, VT_R8, VT_CY, VT_FILETIME):
        return 8
    if vt == VT_UI1:
        return 1
    if vt == VT_CLSID:
        return 16
    if vt in (VT_BSTR, VT_LPSTR, VT_BLOB, VT_CF):
        if offset + 4 > len(data):
            return 4
        length = _i32(data, offset)
        return 4 + length
    if vt == VT_LPWSTR:
        if offset + 4 > len(data):
            return 4
        char_count = _i32(data, offset)
        return 4 + char_count * 2
    return 0


def _parse_basic_property(
    data: memoryview,
    offset: int,
    vt: int,
    prop_id: int,
    convert_time: bool,
    no_conversion: list[int],
    codepage: int | None,
) -> Any:
    def _remove_trailing_nullbytes(m: memoryview):
        end = len(m)
        for end in range(end, 0, -1):
            if m[end - 1]:
                break
        return m[:end]

    if vt in (VT_EMPTY, VT_NULL):
        return None

    if vt == VT_I2:
        if offset + 2 > len(data):
            return None
        val = _i16(data, offset)
        if val >= 0x8000:
            val -= 0x10000
        return val

    if vt == VT_UI2:
        if offset + 2 > len(data):
            return None
        return _i16(data, offset)

    if vt in (VT_I4, VT_INT, VT_ERROR):
        if offset + 4 > len(data):
            return None
        val = _i32(data, offset)
        if vt != VT_ERROR and val >= 0x80000000:
            val -= 0x100000000
        return val

    if vt in (VT_UI4, VT_UINT):
        if offset + 4 > len(data):
            return None
        return _i32(data, offset)

    if vt == VT_I8:
        if offset + 8 > len(data):
            return None
        return struct.unpack_from('<q', data, offset)[0]

    if vt == VT_UI8:
        if offset + 8 > len(data):
            return None
        return struct.unpack_from('<Q', data, offset)[0]

    if vt == VT_R4:
        if offset + 4 > len(data):
            return None
        return struct.unpack_from('<f', data, offset)[0]

    if vt == VT_R8:
        if offset + 8 > len(data):
            return None
        return struct.unpack_from('<d', data, offset)[0]

    if vt == VT_BOOL:
        if offset + 2 > len(data):
            return None
        return bool(_i16(data, offset))

    if vt in (VT_BSTR, VT_LPSTR):
        if (so := offset + 4) > len(data):
            return None
        length = _i32(data, offset)
        if (end := so + length) > len(data):
            length = len(data) - so
        raw = _remove_trailing_nullbytes(data[so:end])
        if codepage is not None:
            try:
                codec = F'cp{codepage}' if codepage < 65535 else 'utf-8'
                if codepage == 1200:
                    codec = 'utf-16-le'
                elif codepage == 65001:
                    codec = 'utf-8'
                return codecs.decode(raw, codec, errors='replace')
            except (LookupError, UnicodeDecodeError):
                return codecs.decode(raw, 'latin-1', errors='replace')
        return codecs.decode(raw, 'latin-1', errors='replace')

    if vt == VT_LPWSTR:
        if (so := offset + 4) > len(data):
            return None
        length = _i32(data, offset) * 2
        if (end := so + length) > len(data):
            length = len(data) - so
        raw = _remove_trailing_nullbytes(data[so:end])
        return codecs.decode(raw, 'utf-16-le', errors='replace').rstrip('\x00')

    if vt == VT_FILETIME:
        if offset + 8 > len(data):
            return None
        low = _i32(data, offset)
        high = _i32(data, offset + 4)
        filetime = low + (high << 32)
        if convert_time and prop_id not in no_conversion:
            return filetime_to_datetime(filetime)
        return filetime

    if vt == VT_UI1:
        if offset >= len(data):
            return None
        return data[offset]

    if vt == VT_CLSID:
        if offset + 16 > len(data):
            return None
        return _clsid(data[offset:offset + 16])

    if vt in (VT_BLOB, VT_CF):
        if offset + 4 > len(data):
            return None
        length = _i32(data, offset)
        if offset + 4 + length > len(data):
            length = len(data) - offset - 4
        return data[offset + 4:offset + 4 + length]

    return None
