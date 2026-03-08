"""
UDF (ECMA-167) filesystem parser ported from 7zip's Archive/Udf/ implementation.
"""
from __future__ import annotations

import itertools
import struct

from datetime import datetime, timedelta, timezone
from typing import Iterator

DEFAULT_SECTOR_SIZE = 2048
ANCHOR_SECTOR = 256

TAG_ID_PVD = 1
TAG_ID_ANCHOR = 2
TAG_ID_POINTER = 3
TAG_ID_IMPL_USE = 4
TAG_ID_PARTITION = 5
TAG_ID_LOGICAL_VOLUME = 6
TAG_ID_UNALLOC_SPACE = 7
TAG_ID_TERMINATOR = 8
TAG_ID_LOGICAL_VOLUME_INTEGRITY = 9
TAG_ID_FILE_SET = 256
TAG_ID_FILE_ID = 257
TAG_ID_ALLOC_EXTENT = 258
TAG_ID_INDIRECT_ENTRY = 259
TAG_ID_TERMINAL_ENTRY = 260
TAG_ID_FILE_ENTRY = 261
TAG_ID_EXTENDED_ATTR_HEADER = 262
TAG_ID_EXTENDED_FILE_ENTRY = 266

ICB_FILE_TYPE_DIR = 4
ICB_FILE_TYPE_FILE = 5
ICB_FILE_TYPE_SYMLINK = 12

ICB_DESC_TYPE_SHORT = 0
ICB_DESC_TYPE_LONG = 1
ICB_DESC_TYPE_EXTENDED = 2
ICB_DESC_TYPE_INLINE = 3

MAX_DIR_DEPTH = 256
MAX_ITEMS = 0x100000


class LogicalVolumeDescriptor:
    __slots__ = ('block_size', 'fsd_location', 'fsd_length', 'fsd_partition')

    def __init__(
        self,
        block_size: int,
        fsd_location: int,
        fsd_length: int,
        fsd_partition: int,
    ):
        self.block_size = block_size
        self.fsd_location = fsd_location
        self.fsd_length = fsd_length
        self.fsd_partition = fsd_partition


class UDFRef:
    __slots__ = ('path', 'date', 'extents', 'is_dir', 'inline_data', 'file_version', '_info_length')

    def __init__(self, path: str, date: datetime | None, is_dir: bool = False):
        self.path = path
        self.date = date
        self.extents: list[tuple[int, int]] = []
        self.is_dir = is_dir
        self.inline_data: bytes | memoryview | None = None
        self.file_version: int = 0
        self._info_length: int = -1

    @property
    def total_size(self) -> int:
        if self._info_length >= 0:
            return self._info_length
        if self.inline_data is not None:
            return len(self.inline_data)
        return sum(s for _, s in self.extents)


def _read_u16(data: bytes | memoryview, offset: int) -> int:
    return struct.unpack_from('<H', data, offset)[0]


def _read_u32(data: bytes | memoryview, offset: int) -> int:
    return struct.unpack_from('<I', data, offset)[0]


def _read_u64(data: bytes | memoryview, offset: int) -> int:
    return struct.unpack_from('<Q', data, offset)[0]


def _verify_tag(data: bytes | memoryview, offset: int = 0) -> int | None:
    if offset + 16 > len(data):
        return None
    tag_id = _read_u16(data, offset)
    checksum = 0
    for i in range(16):
        if i != 4:
            checksum += data[offset + i]
    checksum &= 0xFF
    if checksum != data[offset + 4]:
        return None
    return tag_id


def _parse_timestamp(data: bytes | memoryview, offset: int) -> datetime | None:
    if offset + 12 > len(data):
        return None
    type_and_tz = _read_u16(data, offset)
    year = struct.unpack_from('<h', data, offset + 2)[0]
    month = data[offset + 4]
    day = data[offset + 5]
    hour = data[offset + 6]
    minute = data[offset + 7]
    second = data[offset + 8]
    if month < 1 or month > 12 or day < 1 or day > 31:
        return None
    tz_raw = type_and_tz & 0x0FFF
    if tz_raw & 0x0800:
        tz_raw = tz_raw - 0x1000
    try:
        if -1440 <= tz_raw <= 1440:
            tz = timezone(timedelta(minutes=tz_raw))
        else:
            tz = timezone.utc
        return datetime(year, month, day, hour, minute, second, tzinfo=tz)
    except (ValueError, OverflowError):
        return None


def _parse_short_ad(data: bytes | memoryview, offset: int) -> tuple[int, int]:
    length = _read_u32(data, offset) & 0x3FFFFFFF
    position = _read_u32(data, offset + 4)
    return (position, length)


def _parse_long_ad(data: bytes | memoryview, offset: int) -> tuple[int, int, int]:
    length = _read_u32(data, offset) & 0x3FFFFFFF
    location = _read_u32(data, offset + 4)
    partition = _read_u16(data, offset + 8)
    return (location, length, partition)


class UDFArchive:
    def __init__(self):
        self.refs: list[UDFRef] = []
        self._data: memoryview = memoryview(b'')
        self._sector_size: int = DEFAULT_SECTOR_SIZE
        self._partitions: dict[int, tuple[int, int]] = {}
        self._logical_volumes: list[LogicalVolumeDescriptor] = []

    def open(self, data: bytes | bytearray | memoryview) -> None:
        self._data = memoryview(data) if not isinstance(data, memoryview) else data

        if not self._find_anchor():
            return

        self._read_volume_descriptor_sequence()
        self._read_file_sets()

    def _find_anchor(self) -> bool:
        for sector_size in (2048, 512, 4096):
            self._sector_size = sector_size
            anchor_pos = ANCHOR_SECTOR * sector_size
            if anchor_pos + 16 > len(self._data):
                continue
            tag_id = _verify_tag(self._data, anchor_pos)
            if tag_id == TAG_ID_ANCHOR:
                return True
        return False

    def _sector_offset(self, sector: int) -> int:
        return sector * self._sector_size

    def _partition_offset(self, partition_num: int, block: int) -> int:
        if partition_num in self._partitions:
            start_sector, _ = self._partitions[partition_num]
            return (start_sector + block) * self._sector_size
        return block * self._sector_size

    def _read_sector(self, sector: int) -> memoryview:
        pos = self._sector_offset(sector)
        end = pos + self._sector_size
        if end > len(self._data):
            return memoryview(b'')
        return self._data[pos:end]

    def _read_volume_descriptor_sequence(self) -> None:
        anchor_pos = ANCHOR_SECTOR * self._sector_size
        anchor_data = self._data[anchor_pos:anchor_pos + 512]
        if len(anchor_data) < 32:
            return
        main_extent_loc = _read_u32(anchor_data, 16)
        main_extent_len = _read_u32(anchor_data, 20)

        sector = main_extent_loc
        sectors_count = main_extent_len // self._sector_size

        for _ in range(sectors_count):
            sector_data = self._read_sector(sector)
            if len(sector_data) < 16:
                break
            tag_id = _verify_tag(sector_data)
            if tag_id is None or tag_id == TAG_ID_TERMINATOR:
                break
            if tag_id == TAG_ID_PARTITION:
                self._parse_partition_descriptor(sector_data)
            elif tag_id == TAG_ID_LOGICAL_VOLUME:
                self._parse_logical_volume_descriptor(sector_data)
            sector += 1

    def _parse_partition_descriptor(self, data: bytes | memoryview) -> None:
        if len(data) < 264:
            return
        partition_number = _read_u16(data, 22)
        start_location = _read_u32(data, 188)
        length = _read_u32(data, 192)
        self._partitions[partition_number] = (start_location, length)

    def _parse_logical_volume_descriptor(self, data: bytes | memoryview) -> None:
        if len(data) < 248:
            return
        block_size = _read_u32(data, 212)
        fsd_length = _read_u32(data, 248)
        fsd_location = _read_u32(data, 252)
        fsd_partition = _read_u16(data, 256)
        self._logical_volumes.append(LogicalVolumeDescriptor(
            block_size=block_size,
            fsd_location=fsd_location,
            fsd_length=fsd_length,
            fsd_partition=fsd_partition,
        ))

    def _read_file_sets(self) -> None:
        for lv in self._logical_volumes:
            fsd_loc = lv.fsd_location
            fsd_part = lv.fsd_partition
            offset = self._partition_offset(fsd_part, fsd_loc)
            if offset + 512 > len(self._data):
                continue
            fsd_data = self._data[offset:offset + 512]
            tag_id = _verify_tag(fsd_data)
            if tag_id != TAG_ID_FILE_SET:
                continue
            if len(fsd_data) < 404:
                continue
            root_icb_loc = _read_u32(fsd_data, 400)
            root_icb_part = _read_u16(fsd_data, 404)
            visited: set[int] = set()
            self._read_directory(root_icb_loc, root_icb_part, '', visited, 0)

    def _read_directory(
        self,
        icb_loc: int,
        icb_part: int,
        parent_path: str,
        visited: set[int],
        depth: int
    ) -> None:
        if depth > MAX_DIR_DEPTH:
            return
        key = (icb_part << 32) | icb_loc
        if key in visited:
            return
        visited.add(key)

        dir_data, _ = self._read_file_entry(icb_loc, icb_part)
        if dir_data is None:
            return

        pos = 0
        item_count = 0
        while pos < len(dir_data) and item_count < MAX_ITEMS:
            if pos + 38 > len(dir_data):
                break
            tag_id = _verify_tag(dir_data, pos)
            if tag_id != TAG_ID_FILE_ID:
                break
            fid_len = self._parse_file_identifier(
                dir_data, pos, parent_path, visited, depth)
            if fid_len <= 0:
                break
            pos += fid_len
            item_count += 1

    def _parse_file_identifier(
        self,
        data: bytes | memoryview,
        offset: int,
        parent_path: str,
        visited: set[int],
        depth: int,
    ) -> int:
        if offset + 38 > len(data):
            return -1
        file_version = _read_u16(data, offset + 16)
        file_char = data[offset + 18]
        icb_loc = _read_u32(data, offset + 20)
        icb_part = _read_u16(data, offset + 24)
        impl_use_len = _read_u16(data, offset + 36)
        name_len = data[offset + 38] if offset + 38 < len(data) else 0

        total_len = 38 + 1 + impl_use_len + name_len
        padding = (4 - (total_len % 4)) % 4
        total_len += padding

        is_parent = bool(file_char & 0x08)
        is_deleted = bool(file_char & 0x04)
        is_dir = bool(file_char & 0x02)

        if is_parent or is_deleted:
            return total_len

        name_start = offset + 38 + 1 + impl_use_len
        if name_start + name_len > len(data):
            return total_len

        raw_name = data[name_start:name_start + name_len]
        name = self._decode_name(raw_name)
        if not name:
            return total_len

        full_path = F'{parent_path}/{name}' if parent_path else name

        if is_dir:
            ref = UDFRef(full_path, None, is_dir=True)
            ref.file_version = file_version
            self.refs.append(ref)
            self._read_directory(icb_loc, icb_part, full_path, visited, depth + 1)
        else:
            file_data, file_date, file_size = self._read_file_entry_metadata(icb_loc, icb_part)
            ref = UDFRef(full_path, file_date)
            ref.file_version = file_version
            ref._info_length = file_size
            if file_data is not None:
                ref.inline_data = file_data
            else:
                extents = self._read_file_entry_extents(icb_loc, icb_part)
                ref.extents = extents
            self.refs.append(ref)

        return total_len

    def _decode_name(self, raw: bytes | memoryview) -> str:
        if not raw:
            return ''
        if raw[0] == 8:
            try:
                return bytes(raw[1:]).decode('utf-8', errors='replace')
            except Exception:
                return bytes(raw[1:]).decode('latin-1')
        elif raw[0] == 16:
            try:
                return bytes(raw[1:]).decode('utf-16-be', errors='replace')
            except Exception:
                return bytes(raw[1:]).decode('latin-1')
        return bytes(raw).decode('latin-1', errors='replace')

    def _read_file_entry(
        self,
        icb_loc: int,
        icb_part: int
    ) -> tuple[bytes | bytearray | memoryview | None, datetime | None]:
        offset = self._partition_offset(icb_part, icb_loc)
        if offset + 176 > len(self._data):
            return None, None
        entry_data = self._data[offset:offset + self._sector_size]
        tag_id = _verify_tag(entry_data)
        is_extended = (tag_id == TAG_ID_EXTENDED_FILE_ENTRY)
        if tag_id != TAG_ID_FILE_ENTRY and not is_extended:
            return None, None

        icb_flags = _read_u16(entry_data, 20) if len(entry_data) > 22 else 0
        desc_type = icb_flags & 0x07
        info_length = _read_u64(entry_data, 56)

        if is_extended:
            ea_length = _read_u32(entry_data, 208)
            ad_length = _read_u32(entry_data, 212)
            ad_offset = 216 + ea_length
        else:
            ea_length = _read_u32(entry_data, 168)
            ad_length = _read_u32(entry_data, 172)
            ad_offset = 176 + ea_length

        date = _parse_timestamp(entry_data, 84) if len(entry_data) > 96 else None

        if ad_offset + ad_length > len(entry_data):
            ad_length = max(0, len(entry_data) - ad_offset)

        if desc_type == ICB_DESC_TYPE_INLINE:
            inline = entry_data[ad_offset:ad_offset + ad_length]
            return inline[:info_length], date

        result = self._resolve_allocations(entry_data, ad_offset, ad_length, desc_type, icb_part)
        return result[:info_length], date

    def _read_file_entry_metadata(
        self,
        icb_loc: int,
        icb_part: int
    ) -> tuple[bytes | bytearray | memoryview | None, datetime | None, int]:
        offset = self._partition_offset(icb_part, icb_loc)
        if offset + 176 > len(self._data):
            return None, None, 0
        entry_data = self._data[offset:offset + self._sector_size]
        tag_id = _verify_tag(entry_data)
        is_extended = (tag_id == TAG_ID_EXTENDED_FILE_ENTRY)
        if tag_id != TAG_ID_FILE_ENTRY and not is_extended:
            return None, None, 0

        icb_flags = _read_u16(entry_data, 20) if len(entry_data) > 22 else 0
        desc_type = icb_flags & 0x07
        info_length = _read_u64(entry_data, 56)

        if is_extended:
            ea_length = _read_u32(entry_data, 208)
            ad_length = _read_u32(entry_data, 212)
            ad_offset = 216 + ea_length
        else:
            ea_length = _read_u32(entry_data, 168)
            ad_length = _read_u32(entry_data, 172)
            ad_offset = 176 + ea_length

        date = _parse_timestamp(entry_data, 84) if len(entry_data) > 96 else None

        if desc_type == ICB_DESC_TYPE_INLINE:
            if ad_offset + ad_length <= len(entry_data):
                return entry_data[ad_offset:ad_offset + ad_length], date, info_length
            return b'', date, info_length

        return None, date, info_length

    def _read_file_entry_extents(
        self,
        icb_loc: int,
        icb_part: int
    ) -> list[tuple[int, int]]:
        offset = self._partition_offset(icb_part, icb_loc)
        if offset + 176 > len(self._data):
            return []
        entry_data = self._data[offset:offset + self._sector_size]
        tag_id = _verify_tag(entry_data)
        is_extended = (tag_id == TAG_ID_EXTENDED_FILE_ENTRY)
        if tag_id != TAG_ID_FILE_ENTRY and not is_extended:
            return []

        icb_flags = _read_u16(entry_data, 20) if len(entry_data) > 22 else 0
        desc_type = icb_flags & 0x07

        if is_extended:
            ea_length = _read_u32(entry_data, 208)
            ad_length = _read_u32(entry_data, 212)
            ad_offset = 216 + ea_length
        else:
            ea_length = _read_u32(entry_data, 168)
            ad_length = _read_u32(entry_data, 172)
            ad_offset = 176 + ea_length

        if ad_offset + ad_length > len(entry_data):
            ad_length = max(0, len(entry_data) - ad_offset)

        return self._collect_extents(entry_data, ad_offset, ad_length, desc_type, icb_part)

    def _resolve_allocations(
        self,
        entry_data: bytes | memoryview,
        ad_offset: int,
        ad_length: int,
        desc_type: int,
        partition: int,
    ) -> bytearray:
        extents = self._collect_extents(entry_data, ad_offset, ad_length, desc_type, partition)
        result = bytearray()
        for byte_offset, length in extents:
            end = byte_offset + length
            if end > len(self._data):
                end = len(self._data)
            if byte_offset < len(self._data):
                result.extend(self._data[byte_offset:end])
            else:
                result.extend(itertools.repeat(0, length))
        return result

    def _collect_extents(
        self,
        entry_data: bytes | memoryview,
        ad_offset: int,
        ad_length: int,
        desc_type: int,
        partition: int,
    ) -> list[tuple[int, int]]:
        extents: list[tuple[int, int]] = []
        pos = ad_offset
        end_pos = ad_offset + ad_length

        if desc_type == ICB_DESC_TYPE_SHORT:
            while pos + 8 <= end_pos:
                block, length = _parse_short_ad(entry_data, pos)
                if length == 0:
                    break
                byte_off = self._partition_offset(partition, block)
                extents.append((byte_off, length))
                pos += 8
        elif desc_type == ICB_DESC_TYPE_LONG:
            while pos + 16 <= end_pos:
                block, length, part = _parse_long_ad(entry_data, pos)
                if length == 0:
                    break
                byte_off = self._partition_offset(part, block)
                extents.append((byte_off, length))
                pos += 16
        elif desc_type == ICB_DESC_TYPE_EXTENDED:
            while pos + 20 <= end_pos:
                length = _read_u32(entry_data, pos) & 0x3FFFFFFF
                block = _read_u32(entry_data, pos + 12)
                part_ref = _read_u16(entry_data, pos + 16)
                if length == 0:
                    break
                byte_off = self._partition_offset(part_ref, block)
                extents.append((byte_off, length))
                pos += 20

        return extents

    def entries(self) -> Iterator[UDFRef]:
        for ref in self.refs:
            if not ref.is_dir:
                yield ref

    def extract(self, ref: UDFRef) -> bytearray:
        if ref.inline_data is None:
            result = bytearray()
            for offset, length in ref.extents:
                end = offset + length
                if end > len(self._data):
                    end = len(self._data)
                if offset >= len(self._data):
                    result.extend(itertools.repeat(0, length))
                else:
                    result.extend(self._data[offset:end])
        else:
            result = bytearray(ref.inline_data)
        if (_r := ref._info_length) >= 0 and len(result) > _r:
            del result[_r:]
        return result
