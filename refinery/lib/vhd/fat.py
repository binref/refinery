"""
A parser for the FAT family of file systems (FAT12, FAT16, and FAT32). The implementation reads
the BIOS parameter block from the boot sector, follows cluster chains by reading the file
allocation table one entry at a time, and traverses directories while assembling long file names
(LFN) from the associated VFAT entries. Directories are read one cluster at a time up to their end
marker and files only up to their size, so the memory that a listing or an extraction needs
depends on the data that the volume uses rather than on the sizes that its structures claim.

The parser operates on a single volume that is provided as a `refinery.lib.vhd.fat.VolumeSource`,
i.e. any object exposing a `read(offset, length)` method. It is independent of any container format
and follows the FAT handler from the 7-Zip source code as its reference.
"""
from __future__ import annotations

import datetime
import itertools

from dataclasses import dataclass, field
from typing import Iterable, Iterator, Protocol

from refinery.lib.types import buf

_DIR_ENTRY_SIZE = 32
_SECTOR_SIZES = (512, 1024, 2048, 4096)
_MAX_PATH = 32767
_PATH_SKIPPED = F'entries whose path exceeds {_MAX_PATH} characters were skipped with their contents'
_CHAINS_OVERLAP = 'directory cluster chains loop or overlap, each cluster was listed once'

_ATTR_READ_ONLY = 0x01
_ATTR_VOLUME_ID = 0x08
_ATTR_DIRECTORY = 0x10
_ATTR_LONG_NAME = 0x0F

_LFN_LAST_MASK = 0x40
_LFN_INDEX_MASK = 0x3F

_FLAG_NAME_LOWER = 0x08
_FLAG_EXT_LOWER = 0x10


class VolumeSource(Protocol):
    def read(self, offset: int, length: int) -> buf:
        ...


class FatError(ValueError):
    pass


@dataclass
class FatFile:
    """
    A file or directory entry within a FAT file system. The `cluster` is the first cluster of the
    file data; the `extract` method follows the cluster chain only as far as `size` requires and
    returns the file contents. Entries recovered from deleted directory records are flagged via the
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

    def extract(self) -> buf:
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
    their full paths. Each cluster belongs to at most one directory, and a directory claims its
    clusters up to its end marker before any of its subdirectories is read: when directory chains
    loop or overlap, a directory ends at the first cluster that was already claimed. Entries whose
    path would be longer than 32,767 characters, the maximum on Windows, are skipped together with
    their contents. Both are reported in `warnings`.
    """
    def __init__(self, source: VolumeSource):
        self._source = source
        self.warnings: list[str] = []
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

        if self.bytes_per_sector not in _SECTOR_SIZES:
            raise FatError(F'invalid FAT sector size {self.bytes_per_sector}')
        if not self.sectors_per_cluster or not self.num_fats:
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
        self._fat_offset = reserved_sectors * self.bytes_per_sector
        self._fat_entries = fat_size * self.bytes_per_sector * 8 // self.bits

    @property
    def cluster_size(self) -> int:
        return self.bytes_per_sector * self.sectors_per_cluster

    def _is_eoc(self, cluster: int) -> bool:
        return cluster > self.bad_cluster

    def _cluster_offset(self, cluster: int) -> int:
        sector = self.data_sector + (cluster - 2) * self.sectors_per_cluster
        return sector * self.bytes_per_sector

    def _next(self, cluster: int) -> int:
        if self.bits == 12:
            pair = self._source.read(self._fat_offset + cluster * 3 // 2, 2)
            return (int.from_bytes(pair, 'little') >> ((cluster & 1) << 2)) & 0xFFF
        width = self.bits // 8
        entry = self._source.read(self._fat_offset + cluster * width, width)
        return int.from_bytes(entry, 'little') & 0x0FFFFFFF

    def _chain(self, cluster: int) -> Iterator[int]:
        while 2 <= cluster < self._fat_entries and not self._is_eoc(cluster):
            yield cluster
            cluster = self._next(cluster)

    def _runs(self, cluster: int, size: int) -> Iterator[tuple[int, int]]:
        cluster_size = self.cluster_size
        seen: set[int] = set()
        lower = upper = 0
        for cluster in itertools.islice(self._chain(cluster), -(-size // cluster_size)):
            if cluster in seen:
                break
            seen.add(cluster)
            if cluster != upper:
                if lower < upper:
                    length = (upper - lower) * cluster_size
                    yield self._cluster_offset(lower), length
                    size -= length
                lower = cluster
            upper = cluster + 1
        if lower < upper:
            yield self._cluster_offset(lower), min(size, (upper - lower) * cluster_size)

    def _read_chain(self, cluster: int, size: int) -> buf:
        runs = self._runs(cluster, size)
        first = next(runs, None)
        if first is None:
            return bytearray()
        second = next(runs, None)
        if second is None:
            return self._source.read(*first)
        out = bytearray()
        for offset, length in itertools.chain((first, second), runs):
            out.extend(self._source.read(offset, length))
        return out

    def _read_contiguous(self, cluster: int, size: int) -> buf:
        if cluster < 2 or size <= 0:
            return bytearray()
        return self._source.read(self._cluster_offset(cluster), size)

    def _warn(self, warning: str) -> None:
        if warning not in self.warnings:
            self.warnings.append(warning)

    def _cluster(self, cluster: int) -> buf:
        return self._source.read(self._cluster_offset(cluster), self.cluster_size)

    def _directory(self, cluster: int, seen: set[int]) -> Iterator[buf]:
        clusters: list[int] = []
        for cluster in self._chain(cluster):
            if cluster in seen:
                self._warn(_CHAINS_OVERLAP)
                break
            seen.add(cluster)
            clusters.append(cluster)
            if any(record[0] == 0 for record in self._records((self._cluster(cluster),))):
                break
        return map(self._cluster, clusters)

    def files(self, recover: bool = False) -> Iterator[FatFile]:
        seen: set[int] = set()
        root: Iterable[buf]
        if self.bits == 32:
            root = self._directory(self.root_cluster, seen)
        else:
            root_offset = self.root_dir_sector * self.bytes_per_sector
            root = (self._source.read(root_offset, self.root_entries * _DIR_ENTRY_SIZE),)
        directory = ''
        stack = [(self._entries(root, recover), 0)]
        while stack:
            entries, length = stack[-1]
            directory = directory[:length]
            for file in entries:
                if len(directory) + len(file.path) > _MAX_PATH:
                    self._warn(_PATH_SKIPPED)
                    continue
                file.path = F'{directory}{file.path}'
                yield file
                if file.is_dir and file.cluster >= 2:
                    directory = F'{file.path}/'
                    table = self._directory(file.cluster, seen)
                    stack.append((self._entries(table, recover), len(directory)))
                    break
            else:
                stack.pop()

    @staticmethod
    def _records(pieces: Iterable[buf]) -> Iterator[memoryview]:
        for piece in pieces:
            view = memoryview(piece)
            for pos in range(0, len(view) - _DIR_ENTRY_SIZE + 1, _DIR_ENTRY_SIZE):
                yield view[pos:pos + _DIR_ENTRY_SIZE]

    def _entries(self, pieces: Iterable[buf], recover: bool) -> Iterator[FatFile]:
        lfn_parts: dict[int, memoryview] = {}
        expected = 0
        checksum = -1
        for entry in self._records(pieces):
            first = entry[0]
            if first == 0x00:
                break
            attrib = entry[0x0B]
            if first == 0xE5:
                lfn_parts.clear()
                expected = 0
                if recover:
                    recovered = self._recover_entry(entry)
                    if recovered is not None:
                        yield recovered
                continue
            if (attrib & 0x3F) == _ATTR_LONG_NAME:
                index = first & _LFN_INDEX_MASK
                if first & _LFN_LAST_MASK:
                    lfn_parts.clear()
                    expected = index
                    checksum = entry[0x0D]
                lfn_parts[index] = entry
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
            yield FatFile(
                name, modified, size, is_dir, cluster, self,
                btime=created,
                mtime=modified,
                atime=accessed,
                attributes=attrib,
            )

    def _entry_cluster(self, entry: buf) -> int:
        cluster = int.from_bytes(entry[0x1A:0x1C], 'little')
        if self.bits > 16:
            cluster |= int.from_bytes(entry[0x14:0x16], 'little') << 16
        return cluster

    def _recover_entry(self, entry: buf) -> FatFile | None:
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
            name, modified, size, False, cluster, self,
            btime=created,
            mtime=modified,
            atime=accessed,
            attributes=attrib,
            deleted=True,
        )

    def _assemble_name(
        self,
        entry: buf,
        lfn_parts: dict[int, memoryview],
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
                raw.extend(part[1:11])
                raw.extend(part[14:26])
                raw.extend(part[28:32])
            if raw:
                name = raw.decode('utf-16le', 'replace')
                terminator = name.find('\0')
                if terminator >= 0:
                    name = name[:terminator]
                if name:
                    return name
        return self._short_name(entry)

    @staticmethod
    def _short_checksum(entry: buf) -> int:
        checksum = 0
        for index in range(11):
            checksum = ((checksum >> 1) | ((checksum & 1) << 7)) + entry[index]
            checksum &= 0xFF
        return checksum

    @staticmethod
    def _short_name(entry: buf) -> str:
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


def is_fat(data: buf) -> bool:
    """
    Check whether the start of a volume looks like a FAT boot sector. The check validates the boot
    signature and the presence of a plausible bytes-per-sector value.
    """
    if len(data) < 512:
        return False
    if int.from_bytes(data[0x1FE:0x200], 'little') != 0xAA55:
        return False
    bytes_per_sector = int.from_bytes(data[0x0B:0x0D], 'little')
    return bytes_per_sector in _SECTOR_SIZES and data[0x0D] != 0
