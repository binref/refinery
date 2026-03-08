"""
 https://github.com/nicoleibrahim/DSStoreParser/tree/master
 https://papers.put.as/papers/macosx/2019/summit_archive_1565288427.pdf
 https://metacpan.org/dist/Mac-Finder-DSStore/view/DSStoreFormat.pod
"""
from __future__ import annotations

import enum
import plistlib
import struct

from collections import defaultdict
from datetime import datetime, timedelta

from refinery.lib.structures import Struct, StructReader, StructReaderBits, struct_to_json
from refinery.lib.types import NamedTuple
from refinery.units.formats import JSONTableUnit

_COCOA_EPOCH = datetime(2001, 1, 1)
_BOOKMARK_HEADER_SIZE = 48
_BOOKMARK_MAGIC = b'book'

_BOOKMARK_KEY_NAMES = {
    0x1004: 'path',
    0x1005: 'cnid_path',
    0x1010: 'file_properties',
    0x1020: 'file_id',
    0x1040: 'file_creation_date',
    0x2000: 'volume_info',
    0x2002: 'volume_path',
    0x2005: 'volume_url',
    0x2010: 'volume_name',
    0x2011: 'volume_uuid',
    0x2012: 'volume_size',
    0x2013: 'volume_creation_date',
    0x2020: 'volume_properties',
    0x2030: 'volume_was_boot',
    0x2040: 'disk_image_info',
    0xC001: 'containing_folder_index',
    0xD010: 'creation_options',
    0xF017: 'display_name',
    0xF020: 'icon_data',
    0xF022: 'icon_flavor',
}


def _parse_bookmark_data_record(raw: bytes, data_rel: int):
    data_abs = data_rel + _BOOKMARK_HEADER_SIZE
    if data_abs + 8 > len(raw):
        return None
    dlen = struct.unpack_from('<I', raw, data_abs)[0]
    dtype = struct.unpack_from('<I', raw, data_abs + 4)[0]
    end = data_abs + 8 + dlen
    payload = raw[data_abs + 8:end] if end <= len(raw) else raw[data_abs + 8:]
    if dtype == 0x0101:
        return payload.decode('utf-8', errors='replace')
    if dtype == 0x0901:
        return payload.decode('utf-8', errors='replace')
    if dtype in (0x0303, 0x0304):
        if dlen == 4:
            return struct.unpack_from('<I', payload)[0]
        if dlen == 8:
            return struct.unpack_from('<Q', payload)[0]
    if dtype == 0x0601:
        items = []
        for j in range(dlen // 4):
            off = struct.unpack_from('<I', payload, j * 4)[0]
            resolved = _parse_bookmark_data_record(raw, off)
            items.append(resolved)
        return items
    if dtype == 0x0400 and dlen == 8:
        try:
            ts = struct.unpack_from('<d', payload)[0]
            return str(_COCOA_EPOCH + timedelta(seconds=ts))
        except (OverflowError, OSError):
            return None
    if dtype == 0x0501 and dlen >= 1:
        return bool(payload[0])
    return None


def _parse_bookmark(raw: bytes) -> dict | None:
    if len(raw) < _BOOKMARK_HEADER_SIZE + 4:
        return None
    if raw[:4] != _BOOKMARK_MAGIC:
        return None
    result = {}
    first_toc_rel = struct.unpack_from('<I', raw, _BOOKMARK_HEADER_SIZE)[0]
    toc_abs = first_toc_rel + _BOOKMARK_HEADER_SIZE
    while toc_abs and toc_abs + 20 <= len(raw):
        toc_magic = struct.unpack_from('<I', raw, toc_abs + 4)[0]
        if toc_magic != 0xFFFFFFFE:
            break
        next_toc_rel = struct.unpack_from('<I', raw, toc_abs + 12)[0]
        entry_count = struct.unpack_from('<I', raw, toc_abs + 16)[0]
        for i in range(entry_count):
            eo = toc_abs + 20 + i * 12
            if eo + 12 > len(raw):
                break
            key = struct.unpack_from('<I', raw, eo)[0]
            data_rel = struct.unpack_from('<I', raw, eo + 4)[0]
            value = _parse_bookmark_data_record(raw, data_rel)
            if value is None:
                continue
            key_name = _BOOKMARK_KEY_NAMES.get(key, F'0x{key:04X}')
            if key_name not in result:
                result[key_name] = value
        toc_abs = (next_toc_rel + _BOOKMARK_HEADER_SIZE) if next_toc_rel else 0
    return result or None


_ALIAS_TAG_NAMES = {
    0: 'parent_directory',
    1: 'parent_cnid',
    2: 'carbon_path',
    14: 'filename',
    15: 'volume_name',
    18: 'posix_path',
    19: 'volume_mount_point',
}


def _parse_alias(raw: bytes) -> dict | None:
    if len(raw) < 150:
        return None
    version = struct.unpack_from('>H', raw, 6)[0]
    if version != 2:
        return None
    result = {}
    kind = struct.unpack_from('>h', raw, 8)[0]
    result['kind'] = 'file' if kind == 0 else 'directory' if kind == 1 else kind
    vol_name_len = min(raw[10], 27)
    result['volume'] = raw[11:11 + vol_name_len].decode('latin-1', errors='replace')
    fn_len = raw[50]
    if fn_len:
        result['target'] = raw[51:51 + fn_len].decode('latin-1', errors='replace')
    pos = 150
    while pos + 4 <= len(raw):
        tag = struct.unpack_from('>h', raw, pos)[0]
        tlen = struct.unpack_from('>H', raw, pos + 2)[0]
        if tag == -1:
            break
        if tlen == 0 and tag == 0:
            break
        tdata = raw[pos + 4:pos + 4 + tlen]
        tag_name = _ALIAS_TAG_NAMES.get(tag)
        if tag_name is not None:
            if tag in (14, 15):
                if len(tdata) >= 2:
                    char_count = struct.unpack_from('>H', tdata, 0)[0]
                    result[tag_name] = tdata[2:2 + char_count * 2].decode('utf-16be', errors='replace')
            elif tag in (18, 19):
                result[tag_name] = tdata.split(b'\x00', 1)[0].decode('utf-8', errors='replace')
            elif tag == 2:
                result[tag_name] = tdata.split(b'\x00', 1)[0].decode('latin-1', errors='replace')
            elif tag == 0:
                result[tag_name] = tdata.split(b'\x00', 1)[0].decode('utf-8', errors='replace')
            elif tag == 1 and len(tdata) >= 4:
                result[tag_name] = struct.unpack_from('>I', tdata)[0]
        pos += 4 + tlen
        if pos % 2:
            pos += 1
    return result or None


def _parse_pBB0(toc_raw: bytes, bookmark_raw: bytes) -> dict | None:
    """
    Parse a pBB0 blob, which is a standalone bookmark TOC (no 'book' header). Its data record
    offsets resolve against the companion pBBk bookmark blob. The blob contains 12-byte triplets
    of (u32 key, u32 data_offset, u32 reserved), optionally preceded by an 8-byte header when
    the first u32 is not a known bookmark key.
    """
    if len(toc_raw) < 12:
        return None
    first = struct.unpack_from('<I', toc_raw, 0)[0]
    offset = 0 if first in _BOOKMARK_KEY_NAMES else 8
    entry_count = (len(toc_raw) - offset) // 12
    if entry_count < 1:
        return None
    result = {}
    for i in range(entry_count):
        eo = offset + i * 12
        if eo + 12 > len(toc_raw):
            break
        key = struct.unpack_from('<I', toc_raw, eo)[0]
        data_rel = struct.unpack_from('<I', toc_raw, eo + 4)[0]
        value = _parse_bookmark_data_record(bookmark_raw, data_rel)
        if value is None:
            continue
        key_name = _BOOKMARK_KEY_NAMES.get(key, F'0x{key:04X}')
        if key_name not in result:
            result[key_name] = value
    return result or None


def _parse_alias_or_bookmark(raw: bytes) -> dict | bytes:
    if raw[:4] == _BOOKMARK_MAGIC:
        parsed = _parse_bookmark(raw)
        if parsed:
            return parsed
    if len(raw) >= 150:
        version = struct.unpack_from('>H', raw, 6)[0]
        if version == 2:
            parsed = _parse_alias(raw)
            if parsed:
                return parsed
    return raw


def _deep_parse_plist(obj):
    """
    Walk a parsed plist structure and sub-parse any bytes values that look like bookmarks or alias
    records.
    """
    if isinstance(obj, dict):
        return {k: _deep_parse_plist(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_deep_parse_plist(v) for v in obj]
    if isinstance(obj, bytes):
        return _parse_alias_or_bookmark(obj)
    return obj


class Fmt(bytes, enum.Enum):
    LongInt = b'long'
    ShortInt = b'shor'
    Bool = b'bool'
    Blob = b'blob'
    Type = b'type'
    UnicodeString = b'ustr'
    Complex = b'comp'
    Date = b'dutc'


class RT(bytes, enum.Enum):
    Iloc = b'Iloc'  # icon location
    bwsp = b'bwsp'  # browser window settings plist
    icvp = b'icvp'  # icon view properties plist
    lsvp = b'lsvp'  # list view properties plist
    lsvP = b'lsvP'  # list view properties plist (alternate)
    lsvC = b'lsvC'  # list view columns plist
    vstl = b'vstl'  # view style (icon/list/column/gallery)
    vSrn = b'vSrn'  # view settings version
    moDD = b'moDD'  # modification date
    phyS = b'phyS'  # physical file size
    logS = b'logS'  # logical file size
    cmmt = b'cmmt'  # Finder comment
    ptbL = b'ptbL'  # Trash put-back location
    ptbN = b'ptbN'  # Trash put-back name
    tagl = b'tagl'  # tags plist
    fwi0 = b'fwi0'  # Finder window info
    fwsw = b'fwsw'  # sidebar width
    dscl = b'dscl'  # disclosure state (folder expanded in list view)
    extn = b'extn'  # cached file extension
    pBBk = b'pBBk'  # Trash put-back bookmark
    pBB0 = b'pBB0'  # Trash put-back bookmark (alternate)
    dilc = b'dilc'  # desktop icon location
    lg1S = b'lg1S'  # logical size (alternate)
    ph1S = b'ph1S'  # physical size (alternate)
    BCLR = b'BCLR'  # background color
    icgo = b'icgo'  # icon goto rect
    icsp = b'icsp'  # icon scroll position
    pict = b'pict'  # background picture
    clip = b'clip'  # text clipping
    fndr = b'fndr'  # Finder info


class BlockLocation(NamedTuple):
    offset: int
    length: int


class Record(Struct):

    name: str
    record_type: str
    format_type: Fmt
    data: int | bool | bytes | datetime | str | dict | list

    def __init__(self, reader: StructReader[memoryview]):
        self.name = reader.read_bytes(2 * reader.u32()).decode('utf-16be')
        self.record_type = reader.read_bytes(4).decode('latin-1')
        self.format_type = Fmt(reader.read_bytes(4))
        self._raw_blob: bytes | None = None
        if self.format_type in (Fmt.LongInt, Fmt.ShortInt):
            self.data = reader.u32()
        elif self.format_type is Fmt.Bool:
            self.data = bool(reader.u8())
        elif self.format_type is Fmt.Blob:
            raw = bytes(reader.read_bytes(reader.u32()))
            if self.record_type == 'pBBk':
                self._raw_blob = raw
            self.data = self._parse_blob(raw)
        elif self.format_type is Fmt.Type:
            self.data = reader.read_bytes(4).decode('latin-1')
        elif self.format_type is Fmt.UnicodeString:
            self.data = reader.read_bytes(2 * reader.u32()).decode('utf-16be')
        elif self.format_type is Fmt.Complex:
            self.data = reader.u64()
        elif self.format_type is Fmt.Date:
            ts = reader.u64() >> 0x10
            ts = datetime(1904, 1, 1) + timedelta(seconds=ts)
            self.data = ts
        else:
            raise RuntimeError(F'Unexpected format type code {self.format_type!r}')

    def _parse_blob(self, raw: bytes):
        rt = self.record_type
        if rt == 'Iloc' and len(raw) >= 16:
            x, y, index = struct.unpack_from('>IIi', raw)
            result = {'x': x, 'y': y}
            if index != -1:
                result['index'] = index
            return result
        if rt == 'dilc' and len(raw) >= 32:
            x, y = struct.unpack_from('>II', raw)
            sx, sy = struct.unpack_from('>ii', raw, 16)
            result = {'x': x, 'y': y}
            if sx != -1 or sy != -1:
                result['screen_x'] = sx
                result['screen_y'] = sy
            return result
        if rt == 'fwi0' and len(raw) >= 8:
            top, left, bottom, right = struct.unpack_from('>HHHH', raw)
            return {'top': top, 'left': left, 'bottom': bottom, 'right': right}
        if rt in ('moDD', 'modD') and len(raw) == 8:
            try:
                ts = struct.unpack_from('<d', raw)[0]
                return str(_COCOA_EPOCH + timedelta(seconds=ts))
            except (OverflowError, OSError, ValueError):
                pass
        parsed = _parse_alias_or_bookmark(raw)
        if parsed is not raw:
            return parsed
        try:
            return _deep_parse_plist(plistlib.loads(raw))
        except Exception:
            return raw

    def __json__(self):
        return self.data


class Node(Struct):

    records: list[Record]
    children: list[Node]

    def __init__(self, reader: StructReader[memoryview], blocks: list[BlockLocation]):
        pnode = reader.u32()
        count = reader.u32()
        self.records = []
        self.children = []
        if not pnode:
            self.records.extend(Record(reader) for _ in range(count))
            return
        for _ in range(count):
            b = blocks[reader.u32()]
            r = Record(reader)
            self.records.append(r)
            with reader.detour(b.offset):
                self.children.append(Node(reader, blocks))

    def _collect(self) -> list[Record]:
        all_records: list[Record] = []
        rc = iter(self.records)
        ch = iter(self.children)
        if self.children:
            for record in rc:
                child = next(ch, None)
                if child is not None:
                    all_records.extend(child._collect())
                all_records.append(record)
            trailing = next(ch, None)
            if trailing is not None:
                all_records.extend(trailing._collect())
        else:
            all_records.extend(rc)
        return all_records

    def __json__(self):
        grouped: dict[str, dict] = defaultdict(dict)
        pBBk_raw: dict[str, bytes] = {}
        pBB0_raw: dict[str, bytes] = {}
        for record in self._collect():
            grouped[record.name][record.record_type] = record.__json__()
            if record.record_type == 'pBBk' and record._raw_blob:
                pBBk_raw[record.name] = record._raw_blob
            elif record.record_type == 'pBB0' and isinstance(record.data, bytes):
                pBB0_raw[record.name] = record.data
        for name, toc_blob in pBB0_raw.items():
            bookmark_blob = pBBk_raw.get(name)
            if bookmark_blob is None:
                continue
            parsed = _parse_pBB0(toc_blob, bookmark_blob)
            if parsed is not None:
                grouped[name]['pBB0'] = parsed
        return dict(grouped)


class DSS(Struct):
    Magic = b'Bud1'

    table: dict[str, Node]

    def __init__(self, reader: StructReaderBits[memoryview]):
        reader.bigendian = True
        if reader.read(4) != self.Magic:
            raise ValueError('Invalid signature.')
        self.root_offset = reader.u32()
        self.root_length = reader.u32()
        if reader.u32() != self.root_offset:
            raise ValueError('Invalid format.')
        reader.seekset(self.root_offset)
        blocks: list[BlockLocation] = []

        toc: dict[str, int] = {}
        free: dict[int, list[int]] = {}

        count = reader.u32()
        reader.skip(4)

        for _ in range(count):
            offset = reader.read_integer(27) << 5
            length = 1 << reader.read_integer(5)
            blocks.append(BlockLocation(offset, length))

        padding = -count % 0x100
        reader.seekrel(padding * 4)

        for _ in range(reader.u32()):
            toc_name_len = reader.u8()
            toc_name_str = reader.read_bytes(toc_name_len).decode('ascii')
            toc[toc_name_str] = reader.u32()

        for k in range(32):
            free[1 << k] = flk = []
            for _ in range(reader.u32()):
                flk.append(reader.u32())

        self.table = {}

        for name, index in toc.items():
            root = blocks[index]
            reader.seekset(root.offset)
            root = blocks[reader.u32()]
            with reader.detour(root.offset):
                self.table[name] = Node(reader, blocks)


class dsstore(JSONTableUnit):
    """
    Extract information from `.DS_Store` files left by MacOS.
    """
    def json(self, data):
        mem = memoryview(data)
        dss = DSS.Parse(mem[4:])
        out = struct_to_json(dss.table, 'latin1')
        assert isinstance(out, dict)
        return out

    @classmethod
    def handles(cls, data):
        return data[:4] == B'\0\0\0\x01' and data[4:8] == DSS.Magic
