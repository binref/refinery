"""
HFS+ filesystem parser for extracting files from Apple Disk Image partitions.
"""
from __future__ import annotations

import codecs
import zlib

from datetime import datetime, timezone
from enum import IntEnum
from typing import Generator

from refinery.lib.types import buf
from refinery.lib.structures import StructReader

_HFS_SIGNATURE_PLUS = b'H+'
_HFS_SIGNATURE_X = b'HX'
_VOLUME_HEADER_OFFSET = 0x400
_MAC_EPOCH_OFFSET = 2082844800
_HFS_ROOT_FOLDER_ID = 2
_EXTENTS_FILE_ID = 3
_ATTRIBUTES_FILE_ID = 8

_DECMPFS_MAGIC = b'fpmc'
_DECMPFS_ATTR_NAME = 'com.apple.decmpfs'

_FORK_DATA = 0x00
_FORK_RSRC = 0xFF


class _RECORD(IntEnum):
    FOLDER = 1
    FILE = 2
    FOLDER_THREAD = 3
    FILE_THREAD = 4


class _NODE(IntEnum):
    LEAF = 0xFF
    INDEX = 0x00
    HEADER = 0x01


def _mac_to_datetime(ts: int) -> datetime | None:
    if ts == 0:
        return None
    try:
        unix_ts = ts - _MAC_EPOCH_OFFSET
        return datetime.fromtimestamp(unix_ts, timezone.utc).replace(tzinfo=None)
    except (OSError, OverflowError, ValueError):
        return None


class HFSFork:
    __slots__ = 'size', 'clump_size', 'num_blocks', 'extents'

    def __init__(self, reader: StructReader):
        self.size = reader.u64()
        self.clump_size = reader.u32()
        self.num_blocks = reader.u32()
        self.extents = []
        for _ in range(8):
            start_block = reader.u32()
            block_count = reader.u32()
            self.extents.append((start_block, block_count))


class HFSVolumeHeader:
    __slots__ = (
        'signature',
        'version',
        'block_size',
        'total_blocks',
        'num_files',
        'num_folders',
        'allocation_fork',
        'extents_fork',
        'catalog_fork',
        'attributes_fork',
        'startup_fork',
    )

    def __init__(self, data: bytes | bytearray | memoryview):
        if len(data) < _VOLUME_HEADER_OFFSET + 0x200:
            raise ValueError('partition data too small for HFS+ volume header')
        reader = StructReader(memoryview(data)[_VOLUME_HEADER_OFFSET:], bigendian=True)
        self.signature = reader.read_bytes(2)
        if self.signature not in (_HFS_SIGNATURE_PLUS, _HFS_SIGNATURE_X):
            raise ValueError(F'invalid HFS+ signature: {self.signature!r}')
        self.version = reader.u16()
        if self.version not in (4, 5):
            raise ValueError(F'unsupported HFS+ version: {self.version}')
        reader.seekset(0x20)
        self.num_files = reader.u32()
        self.num_folders = reader.u32()
        self.block_size = reader.u32()
        self.total_blocks = reader.u32()
        reader.seekset(0x70)
        self.allocation_fork = HFSFork(reader)
        self.extents_fork = HFSFork(reader)
        self.catalog_fork = HFSFork(reader)
        self.attributes_fork = HFSFork(reader)
        self.startup_fork = HFSFork(reader)


class HFSBTreeNode:
    __slots__ = 'flink', 'blink', 'kind', 'height', 'num_records'

    def __init__(self, reader: StructReader):
        self.flink = reader.u32()
        self.blink = reader.u32()
        self.kind = reader.u8()
        self.height = reader.u8()
        self.num_records = reader.u16()


class HFSBTreeHeader:
    __slots__ = (
        'tree_depth',
        'root_node',
        'leaf_records',
        'first_leaf_node',
        'last_leaf_node',
        'node_size',
        'total_nodes',
    )

    def __init__(self, reader: StructReader):
        self.tree_depth = reader.u16()
        self.root_node = reader.u32()
        self.leaf_records = reader.u32()
        self.first_leaf_node = reader.u32()
        self.last_leaf_node = reader.u32()
        self.node_size = reader.u16()
        reader.skip(2)  # max_key_length
        self.total_nodes = reader.u32()


class HFSCatalogItem:
    __slots__ = (
        'record_type',
        'item_id',
        'parent_id',
        'name',
        'create_time',
        'modify_time',
        'data_fork',
        'resource_fork',
    )

    def __init__(self):
        self.record_type: int = 0
        self.item_id: int = 0
        self.parent_id: int = 0
        self.name: str = ''
        self.create_time: int = 0
        self.modify_time: int = 0
        self.data_fork: HFSFork | None = None
        self.resource_fork: HFSFork | None = None


def _iter_node_records(
    node_data: memoryview, num_records: int, node_size: int,
) -> Generator[memoryview, None, None]:
    """
    Yield memoryview slices of each record from a B-tree node, reading the
    offset table at the end of the node.
    """
    reader = StructReader(node_data, bigendian=True)
    for i in range(num_records):
        offset_pos = node_size - 2 * (i + 1)
        if offset_pos < 14:
            break
        reader.seekset(offset_pos)
        rec_offset = reader.u16()
        if rec_offset < 14 or rec_offset >= node_size:
            continue
        next_offset_pos = node_size - 2 * (i + 2)
        if next_offset_pos >= 14:
            reader.seekset(next_offset_pos)
            next_rec_offset = reader.u16()
        else:
            next_rec_offset = node_size - 2 * (num_records + 1)
        yield node_data[rec_offset:next_rec_offset]


class HFSVolume:
    def __init__(self, data: bytes | bytearray | memoryview):
        self.raw = data
        self.header = HFSVolumeHeader(data)
        self.block_size = self.header.block_size
        self._items: list[HFSCatalogItem] = []
        self._id_map: dict[int, HFSCatalogItem] = {}
        self._extent_overflow: dict[tuple[int, int, int], list[tuple[int, int]]] = {}
        self._attributes: dict[tuple[int, str], memoryview] = {}
        self._parse_extents_overflow()
        self._parse_catalog()
        self._parse_attributes()

    def _read_fork_inline(self, fork: HFSFork) -> bytearray:
        """
        Read fork data using only the 8 inline extents (no overflow lookup).
        """
        out = bytearray()
        remaining = fork.size
        for pos, count in fork.extents:
            if count == 0:
                break
            offset = pos * self.block_size
            length = min(count * self.block_size, remaining)
            out.extend(self.raw[offset:offset + length])
            remaining -= length
            if remaining <= 0:
                break
        return out

    def _read_fork(self, fork: HFSFork, file_id: int = 0, fork_type: int = _FORK_DATA) -> bytearray:
        out = bytearray()
        remaining = fork.size
        block_cursor = 0
        for pos, count in fork.extents:
            if count == 0:
                break
            offset = pos * self.block_size
            length = min(count * self.block_size, remaining)
            out.extend(self.raw[offset:offset + length])
            remaining -= length
            block_cursor += count
            if remaining <= 0:
                break
        if remaining > 0 and file_id and self._extent_overflow:
            while remaining > 0:
                key = (file_id, fork_type, block_cursor)
                extra = self._extent_overflow.get(key)
                if not extra:
                    break
                for pos, count in extra:
                    if count == 0:
                        break
                    offset = pos * self.block_size
                    length = min(count * self.block_size, remaining)
                    out.extend(self.raw[offset:offset + length])
                    remaining -= length
                    block_cursor += count
                    if remaining <= 0:
                        break
        return out

    def _read_btree_header(self, tree_data: bytearray):
        """
        Parse the B-tree header node and return (HFSBTreeNode, HFSBTreeHeader).
        """
        reader = StructReader(memoryview(tree_data), bigendian=True)
        node = HFSBTreeNode(reader)
        reader.skip(2)  # 2 reserved bytes before header record
        header = HFSBTreeHeader(reader)
        return node, header

    def _parse_extents_overflow(self):
        if self.header.extents_fork.size == 0:
            return
        extents_data = self._read_fork_inline(self.header.extents_fork)
        if not extents_data:
            return
        try:
            node0, bth = self._read_btree_header(extents_data)
            if node0.kind != _NODE.HEADER:
                return
        except Exception:
            return
        node_size = bth.node_size
        if node_size == 0:
            return
        current = bth.first_leaf_node
        while current != 0:
            node_offset = current * node_size
            if node_offset + node_size > len(extents_data):
                break
            node_data = memoryview(extents_data)[node_offset:node_offset + node_size]
            reader = StructReader(node_data, bigendian=True)
            node = HFSBTreeNode(reader)
            if node.kind != _NODE.LEAF:
                break
            self._parse_extent_leaf_node(node_data, node.num_records, node_size)
            current = node.flink

    def _parse_extent_leaf_node(self, node_data: memoryview, num_records: int, node_size: int):
        for rec in _iter_node_records(node_data, num_records, node_size):
            if len(rec) < 12 + 64:
                continue
            reader = StructReader(rec, bigendian=True)
            key_length = reader.u16()
            if key_length < 10:
                continue
            fork_type = reader.u8()
            reader.skip(1)  # padding
            file_id = reader.u32()
            start_block = reader.u32()
            reader.seekset(2 + key_length)
            reader.byte_align(2)
            extents: list[tuple[int, int]] = []
            for _ in range(8):
                if reader.tell() + 8 > len(rec):
                    break
                sb = reader.u32()
                bc = reader.u32()
                extents.append((sb, bc))
            self._extent_overflow[(file_id, fork_type, start_block)] = extents

    def _parse_attributes(self):
        if self.header.attributes_fork.size == 0:
            return
        attr_data = self._read_fork(self.header.attributes_fork, _ATTRIBUTES_FILE_ID, _FORK_DATA)
        if not attr_data:
            return
        try:
            node0, bth = self._read_btree_header(attr_data)
            if node0.kind != _NODE.HEADER:
                return
        except Exception:
            return
        node_size = bth.node_size
        if node_size == 0:
            return
        current = bth.first_leaf_node
        while current != 0:
            node_offset = current * node_size
            if node_offset + node_size > len(attr_data):
                break
            node_data = memoryview(attr_data)[node_offset:node_offset + node_size]
            reader = StructReader(node_data, bigendian=True)
            node = HFSBTreeNode(reader)
            if node.kind != _NODE.LEAF:
                break
            self._parse_attribute_leaf_node(node_data, node.num_records, node_size)
            current = node.flink

    def _parse_attribute_leaf_node(self, node_data: memoryview, num_records: int, node_size: int):
        for rec in _iter_node_records(node_data, num_records, node_size):
            try:
                self._parse_attribute_record(rec)
            except Exception:
                continue

    def _parse_attribute_record(self, rec: buf):
        if len(rec) < 12:
            return
        reader = StructReader(memoryview(rec), bigendian=True)
        key_length = reader.u16()
        if key_length < 10 or 2 + key_length > len(rec):
            return
        reader.skip(4)  # pad16 + record_type in key
        file_id = reader.u32()
        reader.skip(4)  # start_block
        name_length = reader.u16()
        name_byte_len = name_length * 2
        if 16 + name_byte_len > 2 + key_length:
            return
        try:
            attr_name = codecs.decode(reader.read(name_byte_len), 'utf-16-be')
        except (UnicodeDecodeError, ValueError):
            return
        reader.seekset(2 + key_length)
        reader.byte_align(2)
        if reader.tell() + 8 > len(rec):
            return
        record_type = reader.u32()
        if record_type != 0x10:
            return
        reader.skip(4)  # reserved
        attr_size = reader.u32()
        attr_data = reader.read(attr_size)
        self._attributes[file_id, attr_name] = attr_data

    def _decompress_decmpfs(self, item: HFSCatalogItem) -> bytes | None:
        """
        Attempt to decompress a file using HFS+ transparent compression.
        Returns decompressed bytes, or None if the file is not compressed.
        """
        attr = self._attributes.get((item.item_id, _DECMPFS_ATTR_NAME))
        if attr is None:
            return None
        if len(attr) < 16 or attr[:4] != _DECMPFS_MAGIC:
            return None
        reader = StructReader(attr, bigendian=False)
        reader.skip(4)  # magic already validated
        method = reader.u32()
        uncompressed_size = reader.u64()
        if method in (3, 7, 9):
            payload = attr[16:]
            if not payload:
                return b''
            return self._decmpfs_decompress_inline(payload, method, uncompressed_size)
        if method in (4, 8, 12):
            if item.resource_fork is None or item.resource_fork.size == 0:
                return None
            rsrc_data = self._read_fork(item.resource_fork, item.item_id, _FORK_RSRC)
            if not rsrc_data:
                return None
            return self._decmpfs_decompress_resource(rsrc_data, method, uncompressed_size)
        return None

    def _decmpfs_decompress_inline(self, payload: bytes, method: int, size: int) -> bytes:
        if method == 3:
            if payload[0] == 0x0F:
                return payload[1:1 + size]
            return zlib.decompress(payload, -15)[:size]
        if method == 7:
            return _lzvn_decompress_attr(payload, size)
        if method == 9:
            return payload[:size]
        return payload[:size]

    def _decmpfs_decompress_resource(self, rsrc_data: buf, method: int, size: int) -> bytearray:
        out = bytearray()
        mem = memoryview(rsrc_data)
        if len(rsrc_data) < 260:
            return out
        be_reader = StructReader(mem, bigendian=True)
        data_offset = be_reader.u32()
        if data_offset + 4 > len(rsrc_data):
            return out
        block_data_start = data_offset + 4
        block_table_offset = block_data_start
        if block_table_offset + 8 > len(rsrc_data):
            return out
        le_reader = StructReader(mem[block_table_offset:], bigendian=False)
        le_reader.skip(4)  # skip first field
        num_blocks = le_reader.u32()
        for _ in range(num_blocks):
            if le_reader.tell() + 8 > len(le_reader.getvalue()):
                break
            chunk_offset = le_reader.u32()
            chunk_size = le_reader.u32()
            abs_offset = block_data_start + chunk_offset
            if abs_offset + chunk_size > len(rsrc_data):
                break
            chunk = rsrc_data[abs_offset:abs_offset + chunk_size]
            if not chunk:
                continue
            if method == 4:
                try:
                    out.extend(zlib.decompress(chunk, -15))
                except zlib.error:
                    out.extend(chunk)
            elif method == 8:
                out.extend(_lzvn_decompress_attr(chunk, size - len(out)))
            elif method == 12:
                from refinery.lib.fast.lzfse import lzfse_decompress
                out.extend(lzfse_decompress(chunk))
            else:
                out.extend(chunk)
        del out[size:]
        return out

    def _parse_catalog(self):
        catalog_data = self._read_fork(self.header.catalog_fork, 4, _FORK_DATA)
        if not catalog_data:
            return
        node0, bth = self._read_btree_header(catalog_data)
        if node0.kind != _NODE.HEADER:
            raise ValueError('catalog B-tree node 0 is not a header node')
        node_size = bth.node_size
        if node_size == 0:
            return
        current = bth.first_leaf_node
        while current != 0:
            node_offset = current * node_size
            if node_offset + node_size > len(catalog_data):
                break
            node_data = memoryview(catalog_data)[node_offset:node_offset + node_size]
            reader = StructReader(node_data, bigendian=True)
            node = HFSBTreeNode(reader)
            if node.kind != _NODE.LEAF:
                break
            self._parse_leaf_node(node_data, node.num_records, node_size)
            current = node.flink
        for item in self._items:
            if item.record_type in (_RECORD.FOLDER, _RECORD.FILE):
                self._id_map[item.item_id] = item

    def _parse_leaf_node(self, node_data: memoryview, num_records: int, node_size: int):
        for rec in _iter_node_records(node_data, num_records, node_size):
            if len(rec) < 6:
                continue
            try:
                self._parse_catalog_record(rec)
            except Exception:
                continue

    def _parse_catalog_record(self, rec: buf):
        if len(rec) < 6:
            return
        view = memoryview(rec)
        reader = StructReader(view, bigendian=True)
        key_length = reader.u16()
        if key_length < 6 or 2 + key_length > len(rec):
            return
        parent_id = reader.u32()
        name_length = reader.u16()
        name_byte_len = name_length * 2
        if 8 + name_byte_len > 2 + key_length:
            return
        try:
            name = codecs.decode(reader.read(name_byte_len), 'utf-16-be')
        except (UnicodeDecodeError, ValueError):
            name = ''
        reader.seekset(2 + key_length)
        reader.byte_align(2)
        if reader.tell() + 2 > len(rec):
            return
        val_offset = reader.tell()
        val_length = reader.remaining_bytes
        record_type = reader.u16(peek=True)
        item = HFSCatalogItem()
        item.parent_id = parent_id
        item.name = name
        item.record_type = record_type
        if record_type == _RECORD.FOLDER:
            if val_length < 12:
                return
            reader.seekset(val_offset + 8)
            item.item_id = reader.u32()
            if val_length >= 18:
                item.create_time = reader.u32()
                item.modify_time = reader.u32()
            self._items.append(item)
            return
        if record_type == _RECORD.FILE:
            if val_length < 14:
                return
            reader.seekset(val_offset + 8)
            item.item_id = reader.u32()
            if val_length >= 18:
                item.create_time = reader.u32()
                item.modify_time = reader.u32()
            if val_length >= 0xA8:
                reader.seekset(val_offset + 0x58)
                item.data_fork = HFSFork(reader)
            if val_length >= 0xF8:
                reader.seekset(val_offset + 0xA8)
                item.resource_fork = HFSFork(reader)
            self._items.append(item)

    def _build_path(self, item: HFSCatalogItem) -> str | None:
        parts = [item.name]
        current_id = item.parent_id
        seen = set()
        while current_id not in (0, 1):
            if current_id in seen:
                return None
            seen.add(current_id)
            parent = self._id_map.get(current_id)
            if parent is None:
                return None
            parts.append(parent.name)
            current_id = parent.parent_id
        parts.reverse()
        return '/'.join(parts)

    def files(self) -> Generator[tuple[str, bytes, datetime | None], None, None]:
        for item in self._items:
            if item.record_type != _RECORD.FILE:
                continue
            path = self._build_path(item)
            if path is None:
                continue
            data = B''
            if item.data_fork is not None and item.data_fork.size > 0:
                data = self._read_fork(item.data_fork, item.item_id, _FORK_DATA)
            if not data and self._attributes:
                decompressed = self._decompress_decmpfs(item)
                if decompressed is not None:
                    data = decompressed
            mtime = _mac_to_datetime(item.modify_time)
            yield path, data, mtime


def _lzvn_decompress_attr(payload: bytes, expected_size: int) -> bytearray:
    """
    Decompress LZVN-compressed data from a decmpfs attribute or resource fork.
    """
    from refinery.lib.fast.lzfse import _lzvn_decode
    output = bytearray()
    _lzvn_decode(payload, 0, len(payload), expected_size, output)
    return output
