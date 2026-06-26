"""
A parser for the FAT family of file systems (FAT12, FAT16, and FAT32). The implementation reads
the BIOS parameter block from the boot sector, walks the file allocation table to follow cluster
chains, and recursively traverses directories while assembling long file names (LFN) from the
associated VFAT entries.

The parser operates on a single volume that is provided as a `refinery.lib.vhd.fat.VolumeSource`,
i.e. any object exposing a `read(offset, length)` method. It is independent of any container format
and follows the FAT handler from the 7-Zip source code as its reference.
"""
from __future__ import annotations

import datetime

from dataclasses import dataclass, field
from typing import Iterator, Protocol

_DIR_ENTRY_SIZE = 32

_ATTR_READ_ONLY = 0x01
_ATTR_VOLUME_ID = 0x08
_ATTR_DIRECTORY = 0x10
_ATTR_LONG_NAME = 0x0F

_LFN_LAST_MASK = 0x40
_LFN_INDEX_MASK = 0x3F

_FLAG_NAME_LOWER = 0x08
_FLAG_EXT_LOWER = 0x10


class VolumeSource(Protocol):
    def read(self, offset: int, length: int) -> bytearray:
        ...


class FatError(ValueError):
    pass


@dataclass
class FatFile:
    """
    A file or directory entry within a FAT file system. The `cluster` is the first cluster of the
    file data; the `extract` method follows the cluster chain and returns the file contents
    truncated to `size`. Entries recovered from deleted directory records are flagged via the
    `deleted` field; for these the allocation table no longer describes the chain, so the contents
    are read contiguously from the first cluster as a best effort.
    """
    path: str
    date: datetime.datetime | None
    size: int
    is_dir: bool
    cluster: int
    _volume: FatVolume = field(repr=False)
    btime: datetime.datetime | None = None
    mtime: datetime.datetime | None = None
    atime: datetime.datetime | None = None
    attributes: int = 0
    deleted: bool = False

    @property
    def ctime(self):
        return self.mtime

    def extract(self) -> bytearray:
        if self.deleted:
            return self._volume._read_contiguous(self.cluster, self.size)
        return self._volume._read_chain(self.cluster, self.size)


def _dos_datetime(date: int, time: int, centiseconds: int = 0) -> datetime.datetime | None:
    if date == 0:
        return None
    day = date & 0x1F
    month = (date >> 5) & 0x0F
    year = 1980 + (date >> 9)
    second = (time & 0x1F) * 2
    minute = (time >> 5) & 0x3F
    hour = (time >> 11) & 0x1F
    try:
        result = datetime.datetime(year, month, day, hour, minute, second)
    except ValueError:
        return None
    if centiseconds:
        result += datetime.timedelta(milliseconds=centiseconds * 10)
    return result


class FatVolume:
    """
    Parses a FAT12, FAT16, or FAT32 volume. The bit width is derived from the cluster count exactly
    as specified by the FAT format. The `files` method yields all file and directory entries with
    their full paths.
    """
    def __init__(self, source: VolumeSource):
        self._source = source
        boot = source.read(0, _DIR_ENTRY_SIZE + 512)
        if int.from_bytes(boot[0x1FE:0x200], 'little') != 0xAA55:
            raise FatError('missing boot sector signature')

        self.bytes_per_sector = int.from_bytes(boot[0x0B:0x0D], 'little')
        self.sectors_per_cluster = boot[0x0D]
        reserved_sectors = int.from_bytes(boot[0x0E:0x10], 'little')
        self.num_fats = boot[0x10]
        root_entries = int.from_bytes(boot[0x11:0x13], 'little')
        total_sectors = int.from_bytes(boot[0x13:0x15], 'little')
        fat_size = int.from_bytes(boot[0x16:0x18], 'little')

        if not self.bytes_per_sector or not self.sectors_per_cluster or not self.num_fats:
            raise FatError('invalid FAT BIOS parameter block')

        if total_sectors == 0:
            total_sectors = int.from_bytes(boot[0x20:0x24], 'little')
        if fat_size == 0:
            fat_size = int.from_bytes(boot[0x24:0x28], 'little')
        self.fat_size_sectors = fat_size

        self.root_entries = root_entries
        root_dir_sectors = (root_entries * _DIR_ENTRY_SIZE + self.bytes_per_sector - 1)
        root_dir_sectors //= self.bytes_per_sector
        self.root_dir_sector = reserved_sectors + self.num_fats * fat_size
        self.data_sector = self.root_dir_sector + root_dir_sectors
        self.root_cluster = int.from_bytes(boot[0x2C:0x30], 'little')

        if total_sectors < self.data_sector:
            raise FatError('FAT data region exceeds volume size')
        num_clusters = (total_sectors - self.data_sector) // self.sectors_per_cluster
        if num_clusters < 0xFF5:
            self.bits = 12
        elif num_clusters < 0xFFF5:
            self.bits = 16
        else:
            self.bits = 32
        self.bad_cluster = 0x0FFFFFF7 & ((1 << self.bits) - 1) if self.bits != 32 else 0x0FFFFFF7
        self._fat = self._read_fat(reserved_sectors)

    @property
    def cluster_size(self) -> int:
        return self.bytes_per_sector * self.sectors_per_cluster

    def _read_fat(self, reserved_sectors: int) -> list[int]:
        fat_offset = reserved_sectors * self.bytes_per_sector
        fat_bytes = self._source.read(fat_offset, self.fat_size_sectors * self.bytes_per_sector)
        entries = (len(fat_bytes) * 8) // self.bits
        fat = []
        if self.bits == 16:
            for j in range(entries):
                fat.append(int.from_bytes(fat_bytes[j * 2:j * 2 + 2], 'little'))
        elif self.bits == 32:
            for j in range(entries):
                fat.append(int.from_bytes(fat_bytes[j * 4:j * 4 + 4], 'little') & 0x0FFFFFFF)
        else:
            for j in range(entries):
                pair = int.from_bytes(fat_bytes[j * 3 // 2:j * 3 // 2 + 2], 'little')
                fat.append((pair >> ((j & 1) << 2)) & 0xFFF)
        return fat

    def _is_eoc(self, cluster: int) -> bool:
        return cluster > self.bad_cluster

    def _cluster_offset(self, cluster: int) -> int:
        sector = self.data_sector + (cluster - 2) * self.sectors_per_cluster
        return sector * self.bytes_per_sector

    def _read_chain(self, cluster: int, size: int | None = None) -> bytearray:
        out = bytearray()
        seen = set()
        while 2 <= cluster < len(self._fat) and not self._is_eoc(cluster):
            if cluster in seen:
                break
            seen.add(cluster)
            out.extend(self._source.read(self._cluster_offset(cluster), self.cluster_size))
            cluster = self._fat[cluster]
        if size is not None:
            del out[size:]
        return out

    def _read_contiguous(self, cluster: int, size: int) -> bytearray:
        if cluster < 2 or size <= 0:
            return bytearray()
        count = (size + self.cluster_size - 1) // self.cluster_size
        out = self._source.read(self._cluster_offset(cluster), count * self.cluster_size)
        del out[size:]
        return out

    def files(self, recover: bool = False) -> Iterator[FatFile]:
        if self.bits == 32:
            root = self._read_chain(self.root_cluster)
        else:
            root_offset = self.root_dir_sector * self.bytes_per_sector
            root = self._source.read(root_offset, self.root_entries * _DIR_ENTRY_SIZE)
        yield from self._walk(root, '', set(), recover)

    def _walk(
        self,
        table: bytearray,
        prefix: str,
        seen: set[int],
        recover: bool,
    ) -> Iterator[FatFile]:
        lfn_parts: dict[int, bytes] = {}
        expected = 0
        checksum = -1
        for pos in range(0, len(table) - _DIR_ENTRY_SIZE + 1, _DIR_ENTRY_SIZE):
            entry = table[pos:pos + _DIR_ENTRY_SIZE]
            first = entry[0]
            if first == 0x00:
                break
            attrib = entry[0x0B]
            if first == 0xE5:
                lfn_parts.clear()
                expected = 0
                if recover:
                    recovered = self._recover_entry(entry, prefix)
                    if recovered is not None:
                        yield recovered
                continue
            if (attrib & 0x3F) == _ATTR_LONG_NAME:
                index = first & _LFN_INDEX_MASK
                if first & _LFN_LAST_MASK:
                    lfn_parts.clear()
                    expected = index
                    checksum = entry[0x0D]
                lfn_parts[index] = bytes(entry[1:11]) + bytes(entry[14:26]) + bytes(entry[28:32])
                continue
            if attrib & _ATTR_VOLUME_ID:
                lfn_parts.clear()
                expected = 0
                continue
            name = self._assemble_name(entry, lfn_parts, expected, checksum)
            lfn_parts.clear()
            expected = 0
            checksum = -1
            if name in ('.', '..') or not name:
                continue
            cluster = self._entry_cluster(entry)
            size = int.from_bytes(entry[0x1C:0x20], 'little')
            modified = _dos_datetime(
                int.from_bytes(entry[0x18:0x1A], 'little'),
                int.from_bytes(entry[0x16:0x18], 'little'),
            )
            created = _dos_datetime(
                int.from_bytes(entry[0x10:0x12], 'little'),
                int.from_bytes(entry[0x0E:0x10], 'little'),
                entry[0x0D],
            )
            accessed = _dos_datetime(int.from_bytes(entry[0x12:0x14], 'little'), 0)
            is_dir = bool(attrib & _ATTR_DIRECTORY)
            path = F'{prefix}{name}'
            yield FatFile(
                path, modified, size, is_dir, cluster, self,
                btime=created,
                mtime=modified,
                atime=accessed,
                attributes=attrib,
            )
            if is_dir and cluster >= 2 and cluster not in seen:
                seen.add(cluster)
                table_data = self._read_chain(cluster)
                yield from self._walk(table_data, F'{path}/', seen, recover)

    def _entry_cluster(self, entry: bytearray) -> int:
        cluster = int.from_bytes(entry[0x1A:0x1C], 'little')
        if self.bits > 16:
            cluster |= int.from_bytes(entry[0x14:0x16], 'little') << 16
        return cluster

    def _recover_entry(self, entry: bytearray, prefix: str) -> FatFile | None:
        attrib = entry[0x0B]
        if (attrib & 0x3F) == _ATTR_LONG_NAME or attrib & _ATTR_VOLUME_ID:
            return None
        if attrib & _ATTR_DIRECTORY:
            return None
        name = self._short_name(entry)
        if not name or name in ('.', '..'):
            return None
        name = F'_{name[1:]}' if len(name) > 1 else '_'
        cluster = self._entry_cluster(entry)
        size = int.from_bytes(entry[0x1C:0x20], 'little')
        modified = _dos_datetime(
            int.from_bytes(entry[0x18:0x1A], 'little'),
            int.from_bytes(entry[0x16:0x18], 'little'),
        )
        created = _dos_datetime(
            int.from_bytes(entry[0x10:0x12], 'little'),
            int.from_bytes(entry[0x0E:0x10], 'little'),
            entry[0x0D],
        )
        accessed = _dos_datetime(int.from_bytes(entry[0x12:0x14], 'little'), 0)
        return FatFile(
            F'{prefix}{name}', modified, size, False, cluster, self,
            btime=created,
            mtime=modified,
            atime=accessed,
            attributes=attrib,
            deleted=True,
        )

    def _assemble_name(
        self,
        entry: bytearray,
        lfn_parts: dict[int, bytes],
        expected: int,
        checksum: int,
    ) -> str:
        if expected and len(lfn_parts) == expected and self._short_checksum(entry) == checksum:
            raw = bytearray()
            for index in range(1, expected + 1):
                part = lfn_parts.get(index)
                if part is None:
                    raw.clear()
                    break
                raw.extend(part)
            if raw:
                name = raw.decode('utf-16le', 'replace')
                terminator = name.find('\0')
                if terminator >= 0:
                    name = name[:terminator]
                if name:
                    return name
        return self._short_name(entry)

    @staticmethod
    def _short_checksum(entry: bytearray) -> int:
        checksum = 0
        for index in range(11):
            checksum = ((checksum >> 1) | ((checksum & 1) << 7)) + entry[index]
            checksum &= 0xFF
        return checksum

    @staticmethod
    def _short_name(entry: bytearray) -> str:
        flags = entry[0x0C]
        raw = bytes(entry[:11])
        if raw[0] == 0x05:
            raw = b'\xE5' + raw[1:]
        base = raw[:8].rstrip(b' ').decode('latin1')
        ext = raw[8:11].rstrip(b' ').decode('latin1')
        if flags & _FLAG_NAME_LOWER:
            base = base.lower()
        if flags & _FLAG_EXT_LOWER:
            ext = ext.lower()
        if ext:
            return F'{base}.{ext}'
        return base


def is_fat(data: bytearray) -> bool:
    """
    Check whether the start of a volume looks like a FAT boot sector. The check validates the boot
    signature and the presence of a plausible bytes-per-sector value.
    """
    if len(data) < 512:
        return False
    if int.from_bytes(data[0x1FE:0x200], 'little') != 0xAA55:
        return False
    bytes_per_sector = int.from_bytes(data[0x0B:0x0D], 'little')
    return bytes_per_sector in (512, 1024, 2048, 4096) and data[0x0D] != 0
