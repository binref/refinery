"""
DMG container parser: koly header, blkx tables, chunk decompression, and partition iteration.
"""
from __future__ import annotations

import bz2
import codecs
import plistlib
import struct
import zlib

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Generator, NamedTuple

from refinery.lib.fast.lzfse import lzfse_decompress
from refinery.lib.structures import MemoryFile, Struct, StructReader
from refinery.lib.types import buf


class DiskImageFile(NamedTuple):
    path: str
    date: datetime | None
    data: bytes
    warnings: list[str]
    partition: int | None = None


_KOLY_SIGNATURE = b'koly'
_KOLY_SIZE = 512
_MISH_SIGNATURE = b'mish'
_SECTOR_SIZE = 512

_RSRC_BLKX_TYPE = b'blkx'

_APM_SIGNATURE = b'PM'
_APM_ENTRY_SIZE = 512
_HFS_PLUS_SIGNATURES = (b'H+', b'HX')

_BLK_ZERO = 0x00000000
_BLK_RAW = 0x00000001
_BLK_IGNORE = 0x00000002
_BLK_ADC = 0x80000004
_BLK_ZLIB = 0x80000005
_BLK_BZ2 = 0x80000006
_BLK_LZFSE = 0x80000007
_BLK_XZ = 0x80000008
_BLK_COMMENT = 0x7FFFFFFE
_BLK_END = 0xFFFFFFFF


@dataclass
class BlkxEntry:
    name: str
    entry_id: int | None
    data: memoryview


@dataclass
class PartitionInfo:
    name: str
    entry_id: int | None
    data: buf
    warnings: list[str]


class _ImageType(Enum):
    UDIF = 'udif'
    UDIF_FRONT = 'udif-front'
    APM = 'apm'
    HFS = 'hfs'


@dataclass
class APMEntry:
    map_entries: int
    pblock_start: int
    pblock_count: int
    type: str


class KolyHeader(Struct[memoryview]):
    def __init__(self, reader: StructReader[memoryview]):
        reader.bigendian = True
        self.signature = reader.read_bytes(4)
        if self.signature != _KOLY_SIGNATURE:
            raise ValueError('not a valid DMG koly header')
        self.version = reader.u32()
        self.header_size = reader.u32()
        self.flags = reader.u32()
        self.running_data_fork_offset = reader.u64()
        self.data_fork_offset = reader.u64()
        self.data_fork_length = reader.u64()
        self.rsrc_fork_offset = reader.u64()
        self.rsrc_fork_length = reader.u64()
        self.segment_number = reader.u32()
        self.segment_count = reader.u32()
        self.segment_id = reader.read(16)
        self.data_checksum_type = reader.u32()
        self.data_checksum_size = reader.u32()
        self.data_checksum = reader.read(128)
        self.xml_offset = reader.u64()
        self.xml_length = reader.u64()
        reader.skip(120)
        self.master_checksum_type = reader.u32()
        self.master_checksum_size = reader.u32()
        self.master_checksum = reader.read(128)
        self.image_variant = reader.u32()
        self.sector_count = reader.u64()


class BlkxChunk(Struct[memoryview]):
    __slots__ = (
        'type',
        'comment',
        'sector_number',
        'sector_count',
        'compressed_offset',
        'compressed_length',
    )

    def __init__(self, reader: StructReader[memoryview]):
        self.type = reader.u32()
        self.comment = reader.u32()
        self.sector_number = reader.u64()
        self.sector_count = reader.u64()
        self.compressed_offset = reader.u64()
        self.compressed_length = reader.u64()


class BlkxTable(Struct[memoryview]):
    def __init__(self, reader: StructReader[memoryview]):
        reader.bigendian = True
        signature = reader.read_bytes(4)
        if signature != _MISH_SIGNATURE:
            raise ValueError('not a valid mish block table')
        self.version = reader.u32()
        self.first_sector_number = reader.u64()
        self.sector_count = reader.u64()
        self.data_offset = reader.u64()
        self.buffers_needed = reader.u32()
        self.block_descriptors = reader.u32()
        reader.skip(24)
        self.checksum_type = reader.u32()
        self.checksum_size = reader.u32()
        self.checksum = reader.read(128)
        self.chunk_count = reader.u32()
        self.chunks: list[BlkxChunk] = []
        for _ in range(self.chunk_count):
            self.chunks.append(BlkxChunk(reader))


def _adc_decompress(src: buf) -> bytearray:
    out = bytearray()
    i = 0
    while i < len(src):
        b = src[i]
        i += 1
        if b & 0x80:
            count = (b & 0x7F) + 1
            out.extend(src[i:i + count])
            i += count
        elif b & 0x40:
            count = (b & 0x3F) + 4
            if i + 1 >= len(src):
                break
            offset = struct.unpack_from('>H', src, i)[0]
            i += 2
            for _ in range(count):
                out.append(out[-offset])
        else:
            count = (b >> 2) + 3
            offset = ((b & 0x03) << 8) + src[i]
            i += 1
            for _ in range(count):
                out.append(out[-offset])
    return out


def _parse_rsrc_fork_blkx(
    data: buf,
    rsrc_offset: int,
    rsrc_length: int,
) -> list[BlkxEntry]:
    """
    Parse a classic Mac resource fork to extract blkx entries. This handles old DMGs (pre-10.2)
    that store blkx tables in the resource fork rather than an XML plist.

    The resource fork layout:
    - At offset 0: 4-byte data section offset, 4-byte map section offset, 4-byte data section
      length, 4-byte map section length
    - Data section: each resource is prefixed with a 4-byte big-endian length
    - Map section at +24: 2-byte type list offset, 2-byte name list offset
    - Type list: 2-byte type count (minus 1), then 8-byte entries per type
    - Reference list: 12-byte entries per resource
    """
    if rsrc_length < 16:
        raise ValueError('resource fork too small')
    view = memoryview(data)
    fork = view[rsrc_offset:rsrc_offset + rsrc_length]
    reader = StructReader(fork, bigendian=True)
    data_section_offset = reader.u32()
    map_section_offset = reader.u32()
    if map_section_offset + 30 > rsrc_length:
        raise ValueError('resource fork map section out of bounds')
    map_data = fork[map_section_offset:]
    map_reader = StructReader(map_data, bigendian=True)
    map_reader.seekset(24)
    type_list_offset = map_reader.u16()
    name_list_offset = map_reader.u16()
    type_list = map_data[type_list_offset:]
    tl_reader = StructReader(type_list, bigendian=True)
    type_count_minus_1 = tl_reader.u16()
    type_count = type_count_minus_1 + 1
    blkx_entries: list[BlkxEntry] = []
    for t in range(type_count):
        entry_offset = 2 + t * 8
        if entry_offset + 8 > len(type_list):
            break
        tl_reader.seekset(entry_offset)
        rtype = bytes(tl_reader.read(4))
        res_count_minus_1 = tl_reader.u16()
        ref_list_offset = tl_reader.u16()
        if rtype != _RSRC_BLKX_TYPE:
            continue
        res_count = res_count_minus_1 + 1
        ref_list = type_list[ref_list_offset:]
        for r in range(res_count):
            ref_entry_offset = r * 12
            if ref_entry_offset + 12 > len(ref_list):
                break
            ref_reader = StructReader(ref_list[ref_entry_offset:ref_entry_offset + 12], bigendian=True)
            res_id = ref_reader.u16()
            name_offset_in_list = ref_reader.i16()
            ref_reader.skip(1)  # attributes byte
            data_offset_3b = ref_reader.read(3)
            data_rel_offset = (data_offset_3b[0] << 16) | (data_offset_3b[1] << 8) | data_offset_3b[2]
            abs_data_offset = data_section_offset + data_rel_offset
            if abs_data_offset + 4 > rsrc_length:
                continue
            fork_reader = StructReader(fork[abs_data_offset:], bigendian=True)
            res_data_len = fork_reader.u32()
            res_data = fork_reader.read(res_data_len)
            name = F'partition_{r}'
            if name_offset_in_list >= 0:
                name_data = map_data[name_list_offset:]
                if name_offset_in_list < len(name_data):
                    name_len = name_data[name_offset_in_list]
                    name_bytes = name_data[name_offset_in_list + 1:name_offset_in_list + 1 + name_len]
                    try:
                        name = codecs.decode(name_bytes, 'ascii', errors='replace')
                    except UnicodeDecodeError:
                        pass
            blkx_entries.append(BlkxEntry(
                name=name,
                entry_id=res_id,
                data=res_data,
            ))
    return blkx_entries


def _detect_image_type(data: buf) -> _ImageType | None:
    if len(data) >= _KOLY_SIZE and data[len(data) - _KOLY_SIZE:][:4] == _KOLY_SIGNATURE:
        return _ImageType.UDIF
    if len(data) >= _KOLY_SIZE and data[:4] == _KOLY_SIGNATURE:
        view = memoryview(data)
        reader = StructReader(view[:_KOLY_SIZE], bigendian=True)
        try:
            koly = KolyHeader(reader)
            if koly.version == 4 and koly.header_size == _KOLY_SIZE:
                return _ImageType.UDIF_FRONT
        except Exception:
            pass
    if len(data) >= 1024 and data[512:514] == _APM_SIGNATURE:
        return _ImageType.APM
    if len(data) >= 0x402 and data[0x400:0x402] in _HFS_PLUS_SIGNATURES:
        return _ImageType.HFS
    return None


def _parse_apm_entry(data: memoryview, offset: int) -> APMEntry:
    """
    Parse a single 512-byte Apple Partition Map entry at *offset*.
    """
    reader = StructReader(data[offset:offset + _APM_ENTRY_SIZE], bigendian=True)
    sig = reader.read(2)
    if sig != _APM_SIGNATURE:
        raise ValueError(F'invalid APM entry signature at offset {offset}')
    reader.skip(2)
    map_entries = reader.u32()
    pblock_start = reader.u32()
    pblock_count = reader.u32()
    reader.seekset(48)
    ptype = reader.read_bytes(32)
    ptype = ptype.partition(b'\0')[0].decode('ascii', errors='replace')
    return APMEntry(
        map_entries=map_entries,
        pblock_start=pblock_start,
        pblock_count=pblock_count,
        type=ptype,
    )


def is_dmg(data: buf) -> bool | None:
    """
    Check whether the given data looks like a DMG file. Returns ``True`` for
    UDIF and APM images, ``None`` for bare HFS+ (weak match), and ``False``
    otherwise.
    """
    image_type = _detect_image_type(data)
    if image_type in (_ImageType.UDIF, _ImageType.UDIF_FRONT, _ImageType.APM):
        return True
    if image_type == _ImageType.HFS:
        return None
    return False


class DiskImage:
    """
    Parser for Apple Disk Image (DMG) containers. Handles koly headers, blkx
    partition tables, and chunk decompression (zlib, bz2, LZMA, LZFSE, ADC).
    """

    def __init__(
        self,
        data: bytearray,
    ):
        self._data = data
        self._view = memoryview(data)

    def _decompress_chunk(self, chunk: BlkxChunk, data_offset: int = 0) -> tuple[bytes, str | None]:
        ct = chunk.type
        offset = data_offset + chunk.compressed_offset
        length = chunk.compressed_length
        sector_bytes = chunk.sector_count * _SECTOR_SIZE
        if ct in (_BLK_COMMENT, _BLK_END):
            return b'', None
        if ct in (_BLK_ZERO, _BLK_IGNORE):
            return bytes(sector_bytes), None
        src = self._view[offset:offset + length]
        if ct == _BLK_RAW:
            result = bytes(src)
        elif ct == _BLK_ZLIB:
            result = zlib.decompress(src)
        elif ct == _BLK_BZ2:
            result = bz2.decompress(src)
        elif ct == _BLK_XZ:
            import lzma
            result = lzma.decompress(src)
        elif ct == _BLK_LZFSE:
            result = lzfse_decompress(src)
        elif ct == _BLK_ADC:
            result = _adc_decompress(src)
        else:
            return b'', F'unknown block type 0x{ct:08X}, skipping {length} bytes'
        if len(result) > sector_bytes:
            result = result[:sector_bytes]
        return result, None

    def _read_partition(
        self, table: BlkxTable, name: str, data_offset: int = 0,
    ) -> tuple[bytes, list[str]]:
        warnings: list[str] = []
        output = MemoryFile()
        for chunk in table.chunks:
            if chunk.type in (_BLK_COMMENT, _BLK_END):
                continue
            try:
                block, warning = self._decompress_chunk(chunk, data_offset)
            except Exception as e:
                warnings.append(F'decompression error in {name}: {e}')
                block = bytes(chunk.sector_count * _SECTOR_SIZE)
            else:
                if warning is not None:
                    warnings.append(warning)
            output.write(block)
        return output.getvalue(), warnings

    def partitions(self) -> Generator[PartitionInfo, None, None]:
        """
        Yields (name, entry_id, partition_bytes, warnings) for each partition
        in the disk image. Supports UDIF (koly), Apple Partition Map, and bare
        HFS+ images.
        """
        image_type = _detect_image_type(self._data)
        if image_type in (_ImageType.UDIF, _ImageType.UDIF_FRONT):
            yield from self._partitions_udif(front_koly=image_type is _ImageType.UDIF_FRONT)
        elif image_type is _ImageType.APM:
            yield from self._partitions_apm()
        elif image_type is _ImageType.HFS:
            yield from self._partitions_bare_hfs()
        else:
            raise ValueError('not a recognized DMG or disk image format')

    def _partitions_bare_hfs(self) -> Generator[PartitionInfo, None, None]:
        yield PartitionInfo('HFS+', None, self._data, [])

    def _partitions_apm(self) -> Generator[PartitionInfo, None, None]:
        data = self._data
        view = self._view
        first = _parse_apm_entry(view, _APM_ENTRY_SIZE)
        count = first.map_entries
        for i in range(count):
            offset = _APM_ENTRY_SIZE * (i + 1)
            if offset + _APM_ENTRY_SIZE > len(data):
                break
            entry = _parse_apm_entry(view, offset)
            start = entry.pblock_start * _SECTOR_SIZE
            size = entry.pblock_count * _SECTOR_SIZE
            name = entry.type
            yield PartitionInfo(name, i + 1, view[start:start + size], [])

    def _partitions_udif(self, front_koly: bool = False) -> Generator[PartitionInfo, None, None]:
        view = self._view
        data = self._data
        if len(data) < _KOLY_SIZE:
            raise ValueError('input too small to contain a DMG koly header')
        if front_koly:
            koly_offset = 0
        else:
            koly_offset = len(data) - _KOLY_SIZE
        koly = KolyHeader.Parse(
            view[koly_offset:koly_offset + _KOLY_SIZE])
        data_fork_offset = koly.data_fork_offset
        if front_koly and data_fork_offset == 0:
            data_fork_offset = _KOLY_SIZE
        xml_offset = koly.xml_offset
        xml_length = koly.xml_length
        if xml_length:
            xml_data = view[xml_offset:xml_offset + xml_length]
            try:
                plist = plistlib.loads(xml_data)
            except Exception as e:
                raise ValueError(F'failed to parse DMG XML plist: {e}') from e
            resource_fork = plist.get('resource-fork', plist)
            blkx_list: list[BlkxEntry] = []
            for index, entry in enumerate(resource_fork.get('blkx', [])):
                if isinstance(entry, dict):
                    name = entry.get('CFName') or entry.get('Name') or F'partition_{index}'
                    blkx_list.append(BlkxEntry(name, entry.get('ID'), entry.get('Data', b'')))
                else:
                    blkx_list.append(BlkxEntry(F'partition_{index}', None, entry))
        elif koly.rsrc_fork_length:
            blkx_list = _parse_rsrc_fork_blkx(view, koly.rsrc_fork_offset, koly.rsrc_fork_length)
        else:
            raise ValueError('DMG has no XML plist and no resource fork')
        if not blkx_list:
            raise ValueError('DMG plist contains no blkx entries')
        for entry in blkx_list:
            if not entry.data:
                continue
            try:
                table = BlkxTable.Parse(entry.data)
            except Exception as e:
                yield PartitionInfo(
                    entry.name,
                    entry.entry_id,
                    b'',
                    [F'failed to parse blkx table for {entry.name}: {e}'])
                continue
            if table.sector_count == 0:
                continue
            partition_data, warnings = self._read_partition(
                table, entry.name, data_fork_offset + table.data_offset)
            yield PartitionInfo(entry.name, entry.entry_id, partition_data, warnings)

    def files(self) -> Generator[DiskImageFile, None, None]:
        """
        Yields DiskImageFile named tuples. For partitions containing an HFS+
        filesystem, individual files are extracted. Otherwise the raw partition
        image is emitted. Warnings from decompression or parsing are attached
        to the first file yielded from the corresponding partition.
        """
        from refinery.lib.dmg.hfs import HFSVolume
        volumes: list[tuple[HFSVolume, DiskImageFile, list[str]]] = []
        for part in self.partitions():
            partition = DiskImageFile(
                part.name, None, part.data, part.warnings, part.entry_id)
            try:
                volume = HFSVolume(part.data)
            except Exception:
                yield partition
            else:
                volumes.append((volume, partition, part.warnings))
        for volume, partition, warnings in volumes:
            found_files = False
            for path, file_data, mtime in volume.files():
                yield DiskImageFile(path, mtime, file_data, warnings)
                found_files = True
                warnings = []
            if not found_files:
                yield partition
