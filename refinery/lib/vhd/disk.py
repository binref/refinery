"""
Parses the partition table of a disk image and yields the byte ranges of the contained volumes.
Both the legacy Master Boot Record (MBR) scheme and the GUID Partition Table (GPT) are supported.
The input is any random access disk source that implements the `refinery.lib.vhd.disk.DiskSource`
protocol, such as `refinery.lib.vhd.VirtualDisk`.

A disk without a recognizable partition table is treated as a single whole disk volume; this
covers superfloppy images that contain a bare file system without any partitioning.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator, Protocol

_SECTOR = 512

_MBR_SIGNATURE = 0xAA55
_MBR_TYPE_GPT_PROTECTIVE = 0xEE
_MBR_TYPE_EMPTY = 0x00

_GPT_SIGNATURE = B'EFI PART'


class DiskSource(Protocol):
    @property
    def size(self) -> int:
        ...

    def read(self, offset: int, length: int) -> bytearray:
        ...


@dataclass
class Partition:
    """
    A single partition discovered on a disk. The `index` is the zero-based position within the
    partition table, `label` is the GPT partition name (empty for MBR partitions), and `offset`
    and `size` describe the byte range of the volume within the disk.
    """
    index: int
    label: str
    offset: int
    size: int
    whole_disk: bool = False


class VolumeView:
    """
    A view into one partition of a disk that exposes the partition contents as a volume with a
    `read(offset, length)` method. Offsets are relative to the start of the partition. This adapts
    a `refinery.lib.vhd.disk.DiskSource` for consumption by a file system parser.
    """
    def __init__(self, disk: DiskSource, partition: Partition):
        self._disk = disk
        self._offset = partition.offset
        self.size = partition.size

    def read(self, offset: int, length: int) -> bytearray:
        return self._disk.read(self._offset + offset, length)


def partitions(disk: DiskSource) -> Iterator[Partition]:
    """
    Yield the partitions of the given disk. The MBR is inspected first; if it contains a GPT
    protective entry, the GPT is parsed instead. When no partition table is found, a single
    `Partition` spanning the whole disk is produced.
    """
    found = False
    mbr = disk.read(0, _SECTOR)
    if len(mbr) >= _SECTOR and int.from_bytes(mbr[0x1FE:0x200], 'little') == _MBR_SIGNATURE:
        entries = [mbr[0x1BE + 16 * k:0x1BE + 16 * (k + 1)] for k in range(4)]
        if any(entry[4] == _MBR_TYPE_GPT_PROTECTIVE for entry in entries):
            for partition in _parse_gpt(disk):
                yield partition
                found = True
        else:
            for index, entry in enumerate(entries):
                kind = entry[4]
                start = int.from_bytes(entry[8:12], 'little')
                count = int.from_bytes(entry[12:16], 'little')
                if kind == _MBR_TYPE_EMPTY or count == 0:
                    continue
                yield Partition(index, '', start * _SECTOR, count * _SECTOR)
                found = True
    if not found:
        yield Partition(0, '', 0, disk.size, whole_disk=True)


def _parse_gpt(disk: DiskSource) -> Iterator[Partition]:
    header = disk.read(_SECTOR, _SECTOR)
    if header[:8] != _GPT_SIGNATURE:
        return
    entry_lba = int.from_bytes(header[0x48:0x50], 'little')
    entry_count = int.from_bytes(header[0x50:0x54], 'little')
    entry_size = int.from_bytes(header[0x54:0x58], 'little')
    table = disk.read(entry_lba * _SECTOR, entry_count * entry_size)
    for index in range(entry_count):
        entry = table[index * entry_size:(index + 1) * entry_size]
        if len(entry) < 0x38 or not any(entry[:16]):
            continue
        first = int.from_bytes(entry[0x20:0x28], 'little')
        last = int.from_bytes(entry[0x28:0x30], 'little')
        if last < first:
            continue
        try:
            raw = bytes(entry[0x38:0x38 + 72]).decode('utf-16le')
            end = raw.find('\0')
            name = raw[:end] if end >= 0 else raw
        except (UnicodeDecodeError, ValueError):
            name = ''
        offset = first * _SECTOR
        size = (last - first + 1) * _SECTOR
        yield Partition(index, name, offset, size)
