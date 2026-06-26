"""
Parsers for the Microsoft Virtual Hard Disk container formats. Two generations are supported:

- The legacy VHD format (file magic `conectix`) in its fixed, dynamic, and differencing variants.
- The newer VHDX format (file magic `vhdxfile`).

The public entry point is `refinery.lib.vhd.VirtualDisk`, which exposes the reconstructed virtual
disk as a random access byte source via its `read` method. This output is independent of the
container format and can be handed to a partition table parser such as `refinery.lib.vhd.disk`.

The implementation follows the VHD and VHDX handlers from the 7-Zip source code as its reference.
"""
from __future__ import annotations

import abc

from refinery.lib.structures import StructReader
from refinery.lib.types import buf
from refinery.lib.vhd.crc import crc32c

_SECTOR = 512

_VHD_COOKIE = B'conectix'
_VHD_DYNAMIC_COOKIE = B'cxsparse'
_VHDX_SIGNATURE = B'vhdxfile'

_VHD_TYPE_FIXED = 2
_VHD_TYPE_DYNAMIC = 3
_VHD_TYPE_DIFFERENCING = 4

_VHD_UNUSED_BLOCK = 0xFFFFFFFF


class VirtualDiskError(ValueError):
    pass


class DiskBackend(abc.ABC):
    """
    Common interface for the virtual disk produced by a container parser. The `size` property is
    the size of the reconstructed virtual disk in bytes; the `read` method provides random access
    to its contents, returning zero bytes for sparse and unallocated regions.
    """
    size: int

    @abc.abstractmethod
    def read(self, offset: int, length: int) -> bytearray:
        ...


class VirtualDisk(DiskBackend):
    """
    Parses a VHD or VHDX virtual hard disk image and exposes the contained virtual disk. The input
    is inspected for the file magic of either format and the matching backend is selected.
    """
    def __init__(self, data: buf):
        view = memoryview(data)
        if is_vhdx(view):
            self._backend: DiskBackend = VhdxImage(view)
        elif is_vhd(view):
            self._backend = VhdImage(view)
        else:
            raise VirtualDiskError('input is not a VHD or VHDX image')

    @property
    def size(self) -> int:
        return self._backend.size

    @property
    def warnings(self) -> list[str]:
        return self._backend.warnings

    def read(self, offset: int, length: int) -> bytearray:
        return self._backend.read(offset, length)


def _phys(view: memoryview, offset: int, length: int) -> bytearray:
    chunk = bytearray(view[offset:offset + length])
    if len(chunk) < length:
        chunk.extend(bytes(length - len(chunk)))
    return chunk


class VhdImage(DiskBackend):
    """
    Reconstructs the virtual disk of a legacy VHD image. Fixed, dynamic, and differencing disks
    are recognized; for differencing disks the parent image is not available from a single input
    stream, so blocks that would be served by the parent are returned as zero bytes.
    """
    def __init__(self, data: buf):
        view = self._view = memoryview(data)
        self.warnings: list[str] = []

        footer = view[:_SECTOR]
        if footer[:len(_VHD_COOKIE)] != _VHD_COOKIE:
            footer = view[-_SECTOR:]
        reader = StructReader(footer, bigendian=True)
        reader.seekset(0x10)
        data_offset = reader.u64()
        reader.seekset(0x30)
        self.size = reader.u64()
        reader.seekset(0x3C)
        self._type = reader.u32()

        if self._type not in (_VHD_TYPE_FIXED, _VHD_TYPE_DYNAMIC, _VHD_TYPE_DIFFERENCING):
            raise VirtualDiskError(F'unsupported VHD disk type {self._type}')

        if self._type == _VHD_TYPE_FIXED:
            return

        if self._type == _VHD_TYPE_DIFFERENCING:
            self.warnings.append(
                'differencing VHD: parent image is not available, missing blocks read as zero')

        dyn = StructReader(view[data_offset:data_offset + 1024], bigendian=True)
        if dyn.read(8) != _VHD_DYNAMIC_COOKIE:
            raise VirtualDiskError('invalid dynamic VHD header')
        dyn.seekset(0x10)
        table_offset = dyn.u64()
        dyn.seekset(0x1C)
        max_entries = dyn.u32()
        self._block_size = dyn.u32()

        if self._block_size & (self._block_size - 1) or self._block_size < _SECTOR:
            raise VirtualDiskError(F'invalid VHD block size {self._block_size}')

        sectors_per_block = self._block_size // _SECTOR
        bitmap_sectors = (sectors_per_block + _SECTOR * 8 - 1) // (_SECTOR * 8)
        self._bitmap_size = bitmap_sectors * _SECTOR

        bat = StructReader(view[table_offset:table_offset + max_entries * 4], bigendian=True)
        self._bat = [bat.u32() for _ in range(max_entries)]

    def read(self, offset: int, length: int) -> bytearray:
        out = bytearray()
        end = min(offset + length, self.size)
        view = self._view
        if self._type == _VHD_TYPE_FIXED:
            return _phys(view, offset, max(0, end - offset))
        block_size = self._block_size
        while offset < end:
            block = offset >> (block_size.bit_length() - 1)
            off_in_block = offset & (block_size - 1)
            count = min(block_size - off_in_block, end - offset)
            sector = self._bat[block] if block < len(self._bat) else _VHD_UNUSED_BLOCK
            if sector == _VHD_UNUSED_BLOCK:
                out.extend(bytes(count))
            else:
                base = sector * _SECTOR
                bitmap = view[base:base + self._bitmap_size]
                data_pos = base + self._bitmap_size + off_in_block
                chunk = _phys(view, data_pos, count)
                self._apply_bitmap(bitmap, chunk, off_in_block)
                out.extend(chunk)
            offset += count
        return out

    def _apply_bitmap(self, bitmap: memoryview, chunk: bytearray, off_in_block: int) -> None:
        position = 0
        while position < len(chunk):
            sector_index = (off_in_block + position) >> 9
            rem = _SECTOR - ((off_in_block + position) & (_SECTOR - 1))
            rem = min(rem, len(chunk) - position)
            present = (bitmap[sector_index >> 3] >> (7 - (sector_index & 7))) & 1
            if not present:
                chunk[position:position + rem] = bytes(rem)
            position += rem


_VHDX_HEADER_OFFSET = 1 << 16
_VHDX_HEADER_SIZE = 1 << 12
_VHDX_REGION_OFFSET = 3 << 16
_VHDX_REGION_SIZE = 1 << 16

_VHDX_GUID_BAT = bytes((
    0x66, 0x77, 0xC2, 0x2D, 0x23, 0xF6, 0x00, 0x42,
    0x9D, 0x64, 0x11, 0x5E, 0x9B, 0xFD, 0x4A, 0x08))
_VHDX_GUID_METADATA = bytes((
    0x06, 0xA2, 0x7C, 0x8B, 0x90, 0x47, 0x9A, 0x4B,
    0xB8, 0xFE, 0x57, 0x5F, 0x05, 0x0F, 0x88, 0x6E))
_VHDX_GUID_FILE_PARAMETERS = bytes((
    0x37, 0x67, 0xA1, 0xCA, 0x36, 0xFA, 0x43, 0x4D,
    0xB3, 0xB6, 0x33, 0xF0, 0xAA, 0x44, 0xE7, 0x6B))
_VHDX_GUID_VIRTUAL_DISK_SIZE = bytes((
    0x24, 0x42, 0xA5, 0x2F, 0x1B, 0xCD, 0x76, 0x48,
    0xB2, 0x11, 0x5D, 0xBE, 0xD8, 0x3B, 0xF4, 0xB8))
_VHDX_GUID_LOGICAL_SECTOR_SIZE = bytes((
    0x1D, 0xBF, 0x41, 0x81, 0x6F, 0xA9, 0x09, 0x47,
    0xBA, 0x47, 0xF2, 0x33, 0xA8, 0xFA, 0xAB, 0x5F))

_VHDX_PAYLOAD_BLOCK_FULLY_PRESENT = 6
_VHDX_PAYLOAD_BLOCK_PARTIALLY_PRESENT = 7

_VHDX_FLAG_HAS_PARENT = 2


class VhdxImage(DiskBackend):
    """
    Reconstructs the virtual disk of a VHDX image. The current header is selected by sequence
    number, the region table is parsed to locate the metadata and block allocation tables, and the
    metadata supplies the block size, logical sector size, and virtual disk size required to
    translate virtual offsets into physical block locations.
    """
    def __init__(self, data: buf):
        view = self._view = memoryview(data)
        self.warnings: list[str] = []

        sequence, log_has_data = self._select_header(view)
        if sequence is None:
            raise VirtualDiskError('no valid VHDX header found')
        if log_has_data:
            self.warnings.append('VHDX contains a non-empty log that was not replayed')

        bat_offset, bat_length, meta_offset, meta_length = self._parse_regions(view)
        self._parse_metadata(view[meta_offset:meta_offset + meta_length])

        if self._flags & _VHDX_FLAG_HAS_PARENT:
            self.warnings.append(
                'differencing VHDX: parent image is not available, missing blocks read as zero')

        self._chunk_ratio_log = 20 + 3 + self._sector_size_log - self._block_size_log
        self._bat = view[bat_offset:bat_offset + bat_length]

    def _select_header(self, view: memoryview) -> tuple[int | None, bool]:
        best_sequence = None
        best_valid = False
        log_has_data = False
        for index in range(2):
            base = _VHDX_HEADER_OFFSET * (1 + index)
            block = bytearray(view[base:base + _VHDX_HEADER_SIZE])
            if len(block) < _VHDX_HEADER_SIZE or block[:4] != B'head':
                continue
            stored_crc = int.from_bytes(block[4:8], 'little')
            block[4:8] = b'\0\0\0\0'
            valid = crc32c(block) == stored_crc
            reader = StructReader(memoryview(block))
            reader.seekset(8)
            sequence = reader.u64()
            reader.seekset(0x44)
            log_length = reader.u32()
            log_guid = bytes(block[0x30:0x40])
            if best_sequence is None or (valid and not best_valid) or (
                valid == best_valid and sequence > best_sequence
            ):
                best_sequence = sequence
                best_valid = valid
                log_has_data = log_length != 0 and any(log_guid)
        return best_sequence, log_has_data

    def _parse_regions(self, view: memoryview) -> tuple[int, int, int, int]:
        bat = None
        meta = None
        for index in range(2):
            base = _VHDX_REGION_OFFSET + index * _VHDX_REGION_SIZE
            block = bytearray(view[base:base + _VHDX_REGION_SIZE])
            if len(block) < _VHDX_REGION_SIZE or block[:4] != B'regi':
                continue
            stored_crc = int.from_bytes(block[4:8], 'little')
            block[4:8] = b'\0\0\0\0'
            if crc32c(block) != stored_crc:
                continue
            count = int.from_bytes(block[8:12], 'little')
            for entry in range(count):
                start = 0x10 + 0x20 * entry
                guid = bytes(block[start:start + 16])
                offset = int.from_bytes(block[start + 0x10:start + 0x18], 'little')
                length = int.from_bytes(block[start + 0x18:start + 0x1C], 'little')
                if guid == _VHDX_GUID_BAT:
                    bat = (offset, length)
                elif guid == _VHDX_GUID_METADATA:
                    meta = (offset, length)
            if bat is not None and meta is not None:
                break
        if bat is None or meta is None:
            raise VirtualDiskError('VHDX region table is missing the BAT or metadata region')
        return bat[0], bat[1], meta[0], meta[1]

    def _parse_metadata(self, table: memoryview) -> None:
        self._block_size_log = 0
        self._sector_size_log = 0
        self._flags = 0
        size = None
        if table[:8] != B'metadata':
            raise VirtualDiskError('invalid VHDX metadata table')
        count = int.from_bytes(table[10:12], 'little')
        for index in range(count):
            start = 32 + 32 * index
            guid = bytes(table[start:start + 16])
            offset = int.from_bytes(table[start + 0x10:start + 0x14], 'little')
            item = table[offset:]
            if guid == _VHDX_GUID_FILE_PARAMETERS:
                block_size = int.from_bytes(item[0:4], 'little')
                self._flags = int.from_bytes(item[4:8], 'little')
                self._block_size_log = block_size.bit_length() - 1
            elif guid == _VHDX_GUID_VIRTUAL_DISK_SIZE:
                size = int.from_bytes(item[0:8], 'little')
            elif guid == _VHDX_GUID_LOGICAL_SECTOR_SIZE:
                sector_size = int.from_bytes(item[0:4], 'little')
                self._sector_size_log = sector_size.bit_length() - 1
        if self._block_size_log <= 0 or self._sector_size_log <= 0 or size is None:
            raise VirtualDiskError('VHDX metadata is missing required entries')
            raise VirtualDiskError('VHDX metadata is missing required entries')
        self.size = size

    def read(self, offset: int, length: int) -> bytearray:
        out = bytearray()
        end = min(offset + length, self.size)
        view = self._view
        block_size = 1 << self._block_size_log
        chunk_ratio = 1 << self._chunk_ratio_log
        while offset < end:
            block = offset >> self._block_size_log
            chunk_index = block >> self._chunk_ratio_log
            entry_index = chunk_index * (chunk_ratio + 1) + (block & (chunk_ratio - 1))
            entry = int.from_bytes(self._bat[entry_index * 8:entry_index * 8 + 8], 'little')
            state = entry & 7
            block_offset = entry & ~0xFFFFF
            off_in_block = offset & (block_size - 1)
            count = min(block_size - off_in_block, end - offset)
            if state == _VHDX_PAYLOAD_BLOCK_FULLY_PRESENT:
                out.extend(_phys(view, block_offset + off_in_block, count))
            else:
                out.extend(bytes(count))
            offset += count
        return out


def is_vhd(data: buf) -> bool:
    """
    Check whether the input looks like a legacy VHD image by testing for the `conectix` cookie at
    the start of the file or in the trailing footer sector.
    """
    view = memoryview(data)
    if len(view) < _SECTOR:
        return False
    if view[:len(_VHD_COOKIE)] == _VHD_COOKIE:
        return True
    return view[-_SECTOR:][:len(_VHD_COOKIE)] == _VHD_COOKIE


def is_vhdx(data: buf) -> bool:
    """
    Check whether the input looks like a VHDX image by testing for the `vhdxfile` signature.
    """
    return memoryview(data)[:len(_VHDX_SIGNATURE)] == _VHDX_SIGNATURE
