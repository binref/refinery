"""
ISO 9660 filesystem parser ported from 7zip's Archive/Iso/ implementation.
"""
from __future__ import annotations

import itertools
import struct

from datetime import datetime, timedelta, timezone

from refinery.lib.id import buffer_offset
from refinery.lib.iso import FileSystemType

BLOCK_SIZE = 2048
START_POS = 0x8000

VD_TYPE_BOOT = 0
VD_TYPE_PRIMARY = 1
VD_TYPE_SUPPLEMENTARY = 2
VD_TYPE_PARTITION = 3
VD_TYPE_TERMINATOR = 255

FILE_FLAG_DIR = 0x02
FILE_FLAG_NON_FINAL_EXTENT = 0x80

SUSP_TAG_SP = b'SP'
SUSP_TAG_CE = b'CE'
SUSP_TAG_NM = b'NM'
SUSP_TAG_PX = b'PX'
SUSP_TAG_SL = b'SL'
SUSP_TAG_RR = b'RR'

MAX_DIR_DEPTH = 256
MAX_DIR_RECORDS = 0x100000


def _read_both_endian_u32(data: bytes | memoryview, offset: int) -> int:
    return struct.unpack_from('<I', data, offset)[0]


def _read_both_endian_u16(data: bytes | memoryview, offset: int) -> int:
    return struct.unpack_from('<H', data, offset)[0]


def _parse_recording_datetime(data: bytes | memoryview) -> datetime | None:
    if len(data) < 7:
        return None
    year = data[0] + 1900
    month = data[1]
    day = data[2]
    hour = data[3]
    minute = data[4]
    second = data[5]
    gmt_offset = struct.unpack_from('b', data, 6)[0]
    if month < 1 or month > 12:
        return None
    if day < 1 or day > 31:
        return None
    try:
        tz = timezone(timedelta(minutes=15 * gmt_offset))
        return datetime(year, month, day, hour, minute, second, tzinfo=tz)
    except (ValueError, OverflowError):
        return None


class DirRecord:
    __slots__ = (
        'extent_location',
        'data_length',
        'datetime',
        'file_flags',
        'file_id',
        'system_use',
    )

    def __init__(self):
        self.extent_location: int = 0
        self.data_length: int = 0
        self.datetime: datetime | None = None
        self.file_flags: int = 0
        self.file_id: bytes | memoryview = b''
        self.system_use: bytes | memoryview = b''

    @property
    def is_dir(self) -> bool:
        return bool(self.file_flags & FILE_FLAG_DIR)

    @property
    def is_non_final_extent(self) -> bool:
        return bool(self.file_flags & FILE_FLAG_NON_FINAL_EXTENT)

    @property
    def is_system_item(self) -> bool:
        return self.file_id == b'\x00' or self.file_id == b'\x01'


class VolumeDescriptor:
    __slots__ = (
        'vd_type',
        'system_id',
        'volume_id',
        'volume_space_size',
        'volume_set_size',
        'volume_sequence_number',
        'logical_block_size',
        'path_table_size',
        'root_dir_record',
        'escape_sequence',
        'is_supplementary',
    )

    def __init__(self):
        self.vd_type: int = 0
        self.system_id: bytes | memoryview = b''
        self.volume_id: bytes | memoryview = b''
        self.volume_space_size: int = 0
        self.volume_set_size: int = 0
        self.volume_sequence_number: int = 0
        self.logical_block_size: int = 0
        self.path_table_size: int = 0
        self.root_dir_record: DirRecord | None = None
        self.escape_sequence: bytes | memoryview = b''
        self.is_supplementary: bool = False

    @property
    def is_joliet(self) -> bool:
        es = self.escape_sequence[:3]
        return es == b'%/@' or es == b'%/C' or es == b'%/E'


class ISORef:
    __slots__ = ('path', 'date', 'extents', 'is_dir', '_inline')

    def __init__(self, path: str, date: datetime | None, is_dir: bool = False):
        self.path = path
        self.date = date
        self.extents: list[tuple[int, int]] = []
        self.is_dir = is_dir
        self._inline: bytes | None = None

    @property
    def total_size(self) -> int:
        if self._inline is not None:
            return len(self._inline)
        return sum(s for _, s in self.extents)


def _find_susp_entry(system_use: bytes | memoryview, tag: bytes, offset: int = 0) -> bytes | memoryview | None:
    pos = offset
    while pos + 4 <= len(system_use):
        entry_tag = system_use[pos:pos + 2]
        entry_len = system_use[pos + 2]
        if entry_len < 4:
            break
        if pos + entry_len > len(system_use):
            break
        if entry_tag == tag:
            return system_use[pos:pos + entry_len]
        pos += entry_len
    return None


def _get_susp_ce(system_use: bytes | memoryview, susp_offset: int = 0) -> tuple[int, int, int] | None:
    entry = _find_susp_entry(system_use, SUSP_TAG_CE, susp_offset)
    if entry is None or len(entry) < 28:
        return None
    block = _read_both_endian_u32(entry, 4)
    offset = _read_both_endian_u32(entry, 12)
    length = _read_both_endian_u32(entry, 20)
    return (block, offset, length)


def _check_susp(root_record: DirRecord) -> int:
    su = root_record.system_use
    for offset in (0, 14):
        sp = _find_susp_entry(su, SUSP_TAG_SP, offset)
        if sp and len(sp) >= 7 and sp[4] == 0xBE and sp[5] == 0xEF:
            skip_len = sp[6]
            return offset + skip_len
    return -1


def _get_name_rr(
    system_use: bytes | memoryview,
    susp_offset: int,
    data: memoryview
) -> str | None:
    parts: list[bytes] = []
    su = system_use
    su_off = susp_offset
    while True:
        nm = _find_susp_entry(su, SUSP_TAG_NM, su_off)
        if nm is None or len(nm) < 5:
            break
        flags = nm[4]
        name_part = nm[5:]
        parts.append(name_part)
        if not (flags & 0x01):
            break
        su_off_next = buffer_offset(su, nm, su_off)
        if su_off_next < 0:
            su_off_next = len(su)
        else:
            su_off_next = len(nm) + su_off_next
        ce = _get_susp_ce(su, su_off)
        if ce:
            block, off, length = ce
            ce_pos = block * BLOCK_SIZE + off
            if ce_pos + length <= len(data):
                su = data[ce_pos:ce_pos + length]
                su_off = 0
                continue
        su_off = su_off_next
    if not parts:
        return None
    return b''.join(parts).decode('utf-8', errors='replace')


def _get_symlink_rr(
    system_use: bytes | memoryview,
    susp_offset: int,
    data: memoryview
) -> str | None:
    entry = _find_susp_entry(system_use, SUSP_TAG_SL, susp_offset)
    if entry is None or len(entry) < 5:
        return None
    return None


def _has_rr(system_use: bytes | memoryview, susp_offset: int) -> bool:
    entry = _find_susp_entry(system_use, SUSP_TAG_RR, susp_offset)
    if entry is not None:
        return True
    entry = _find_susp_entry(system_use, SUSP_TAG_PX, susp_offset)
    return entry is not None


def _parse_fat_image(
    data: memoryview | bytes,
) -> list[tuple[str, datetime | None, bytes]] | None:
    """Parse a FAT12/FAT16 floppy or hard-disk image embedded in an El Torito
    boot entry and return a list of *(path, date, content)* triples.  Returns
    ``None`` when the image does not look like a valid FAT volume.
    """
    if len(data) < 512:
        return None
    bps = struct.unpack_from('<H', data, 11)[0]
    if bps not in (512, 1024, 2048, 4096):
        return None
    spc = data[13]
    if spc == 0 or spc & (spc - 1):
        return None
    reserved = struct.unpack_from('<H', data, 14)[0]
    num_fats = data[16]
    root_entries = struct.unpack_from('<H', data, 17)[0]
    total_sectors = struct.unpack_from('<H', data, 19)[0]
    if total_sectors == 0:
        total_sectors = struct.unpack_from('<I', data, 32)[0]
    spf = struct.unpack_from('<H', data, 22)[0]
    if num_fats == 0 or spf == 0 or root_entries == 0:
        return None

    fat_offset = reserved * bps
    root_dir_offset = fat_offset + num_fats * spf * bps
    root_dir_size = root_entries * 32
    data_offset = root_dir_offset + root_dir_size
    if data_offset > len(data):
        return None

    root_dir_sectors = (root_entries * 32 + bps - 1) // bps
    total_data_sectors = total_sectors - (reserved + num_fats * spf + root_dir_sectors)
    total_clusters = total_data_sectors // spc
    is_fat16 = total_clusters >= 4085
    cluster_bytes = spc * bps

    fat = data[fat_offset:fat_offset + spf * bps]

    def next_cluster(c: int) -> int:
        if is_fat16:
            off = c * 2
            if off + 2 > len(fat):
                return 0xFFFF
            return struct.unpack_from('<H', fat, off)[0]
        off = c * 3 // 2
        if off + 2 > len(fat):
            return 0xFFF
        val = struct.unpack_from('<H', fat, off)[0]
        return val & 0xFFF if c % 2 == 0 else val >> 4

    end_mark = 0xFFF8 if is_fat16 else 0xFF8

    def extract_chain(start: int, size: int) -> bytes:
        result = bytearray()
        remaining = size
        c = start
        while c >= 2 and c < end_mark and remaining > 0:
            cluster_off = data_offset + (c - 2) * cluster_bytes
            chunk = min(cluster_bytes, remaining)
            if cluster_off + chunk > len(data):
                break
            result.extend(data[cluster_off:cluster_off + chunk])
            remaining -= chunk
            c = next_cluster(c)
        return bytes(result[:size])

    def parse_datetime(entry: bytes | memoryview) -> datetime | None:
        time_val = struct.unpack_from('<H', entry, 22)[0]
        date_val = struct.unpack_from('<H', entry, 24)[0]
        if date_val == 0:
            return None
        try:
            return datetime(
                ((date_val >> 9) & 0x7F) + 1980,
                (date_val >> 5) & 0xF,
                date_val & 0x1F,
                (time_val >> 11) & 0x1F,
                (time_val >> 5) & 0x3F,
                (time_val & 0x1F) * 2,
            )
        except (ValueError, OverflowError):
            return None

    files: list[tuple[str, datetime | None, bytes]] = []

    def walk_directory(
        dir_data: bytes | memoryview,
        prefix: str,
        depth: int = 0,
    ) -> None:
        if depth > 16:
            return
        for i in range(0, len(dir_data) - 31, 32):
            entry = dir_data[i:i + 32]
            if entry[0] == 0:
                break
            if entry[0] == 0xE5:
                continue
            attr = entry[11]
            if attr == 0x0F or attr & 0x08:
                continue
            raw_name = bytes(entry[0:8]).rstrip(b' ')
            raw_ext = bytes(entry[8:11]).rstrip(b' ')
            try:
                fname = raw_name.decode('ascii')
                if raw_ext:
                    fname += '.' + raw_ext.decode('ascii')
            except (UnicodeDecodeError, ValueError):
                continue
            fname = fname.lower()
            cluster = struct.unpack_from('<H', entry, 26)[0]
            size = struct.unpack_from('<I', entry, 28)[0]
            dt = parse_datetime(entry)
            full_path = F'{prefix}/{fname}' if prefix else fname
            if attr & 0x10:
                if fname in ('.', '..'):
                    continue
                sub = extract_chain(cluster, cluster_bytes * 256)
                walk_directory(sub, full_path, depth + 1)
            else:
                files.append((full_path, dt, extract_chain(cluster, size)))

    walk_directory(data[root_dir_offset:root_dir_offset + root_dir_size], '')
    return files or None


class ISO9660Archive:
    def __init__(self):
        self.refs: list[ISORef] = []
        self._data: memoryview = memoryview(b'')
        self._block_size: int = BLOCK_SIZE
        self.filesystem_type: FileSystemType = FileSystemType.ISO
        self._has_rr: bool = False
        self._has_joliet: bool = False
        self._primary_vd: VolumeDescriptor | None = None
        self._joliet_vd: VolumeDescriptor | None = None
        self._boot_record_found: bool = False
        self._boot_catalog_location: int = 0

    def open(self, data: bytes | bytearray | memoryview) -> None:
        self._data = memoryview(data) if not isinstance(data, memoryview) else data

        volume_descriptors: list[VolumeDescriptor] = []
        pos = START_POS

        while pos + BLOCK_SIZE <= len(self._data):
            block = self._data[pos:pos + BLOCK_SIZE]
            if len(block) < 7:
                break
            vd_type = block[0]
            magic = block[1:6]
            if magic != b'CD001':
                break

            if vd_type == VD_TYPE_TERMINATOR:
                pos += BLOCK_SIZE
                break
            elif vd_type == VD_TYPE_BOOT:
                self._parse_boot_record(block)
                pos += BLOCK_SIZE
                continue
            elif vd_type == VD_TYPE_PRIMARY or vd_type == VD_TYPE_SUPPLEMENTARY:
                vd = self._parse_volume_descriptor(block, vd_type)
                if vd is not None:
                    volume_descriptors.append(vd)
            pos += BLOCK_SIZE

        primary: VolumeDescriptor | None = None
        joliet: VolumeDescriptor | None = None

        for vd in volume_descriptors:
            if vd.is_supplementary and vd.is_joliet:
                joliet = vd
            elif not vd.is_supplementary:
                if primary is None:
                    primary = vd
                else:
                    primary = vd

        self._primary_vd = primary
        self._joliet_vd = joliet
        self._has_joliet = joliet is not None

        if joliet:
            self._read_directory_tree(joliet, is_joliet=True)
        elif primary:
            self._read_directory_tree(primary, is_joliet=False)

        if self._boot_record_found:
            self._extract_boot_images()

    def _parse_boot_record(self, block: bytes | memoryview) -> None:
        boot_system_id = bytes(block[7:39])
        if boot_system_id.rstrip(b'\x00').rstrip(b'\x20') == b'EL TORITO SPECIFICATION':
            self._boot_record_found = True
            self._boot_catalog_location = struct.unpack_from('<I', block, 71)[0]

    def _parse_volume_descriptor(
        self,
        block: bytes | memoryview,
        vd_type: int
    ) -> VolumeDescriptor | None:
        vd = VolumeDescriptor()
        vd.vd_type = vd_type
        vd.is_supplementary = (vd_type == VD_TYPE_SUPPLEMENTARY)
        vd.system_id = block[8:40]
        vd.volume_id = block[40:72]
        vd.volume_space_size = _read_both_endian_u32(block, 80)
        vd.escape_sequence = block[88:120]
        if not vd.is_supplementary:
            vd.escape_sequence = b''
        vd.volume_set_size = _read_both_endian_u16(block, 120)
        vd.volume_sequence_number = _read_both_endian_u16(block, 124)
        vd.logical_block_size = _read_both_endian_u16(block, 128)
        vd.path_table_size = _read_both_endian_u32(block, 132)

        root_record_data = block[156:190]
        if len(root_record_data) >= 34:
            vd.root_dir_record = self._parse_dir_record(root_record_data)
        return vd

    def _parse_dir_record(self, data: bytes | memoryview) -> DirRecord | None:
        if len(data) < 34:
            return None
        rec = DirRecord()
        record_len = data[0]
        if record_len < 34:
            record_len = 34
        rec.extent_location = _read_both_endian_u32(data, 2)
        rec.data_length = _read_both_endian_u32(data, 10)
        rec.datetime = _parse_recording_datetime(data[18:25])
        rec.file_flags = data[25]
        file_id_len = data[32]
        if 33 + file_id_len > len(data):
            file_id_len = len(data) - 33
        rec.file_id = data[33:33 + file_id_len]
        su_start = 33 + file_id_len
        if file_id_len % 2 == 0:
            su_start += 1
        if su_start < len(data):
            rec.system_use = data[su_start:min(len(data), record_len)]
        return rec

    def _read_directory_tree(
        self,
        vd: VolumeDescriptor,
        is_joliet: bool
    ) -> None:
        root = vd.root_dir_record
        if root is None:
            return

        susp_offset = -1
        has_rr = False

        if not is_joliet:
            actual_root = self._read_root_dot_entry(root)
            susp_root = actual_root or root
            susp_offset = _check_susp(susp_root)
            if susp_offset >= 0:
                has_rr = _has_rr(susp_root.system_use, susp_offset)

        self._has_rr = has_rr

        if is_joliet:
            self.filesystem_type = FileSystemType.JOLIET
        elif has_rr:
            self.filesystem_type = FileSystemType.RR
        else:
            self.filesystem_type = FileSystemType.ISO

        self.refs.clear()
        visited: set[int] = set()
        self._walk_directory(
            root.extent_location,
            root.data_length,
            '',
            is_joliet,
            has_rr,
            susp_offset,
            visited,
            0,
        )

    def _walk_directory(
        self,
        extent_loc: int,
        extent_size: int,
        parent_path: str,
        is_joliet: bool,
        has_rr: bool,
        susp_offset: int,
        visited: set[int],
        depth: int,
    ) -> None:
        if depth > MAX_DIR_DEPTH:
            return
        if extent_loc in visited:
            return
        visited.add(extent_loc)

        dir_pos = extent_loc * self._block_size
        dir_end = dir_pos + extent_size

        if dir_pos >= len(self._data) or dir_end > len(self._data):
            dir_end = min(dir_end, len(self._data))

        pos = dir_pos
        record_count = 0
        pending_ref: ISORef | None = None

        while pos < dir_end and record_count < MAX_DIR_RECORDS:
            if pos >= len(self._data):
                break
            record_len = self._data[pos]
            if record_len == 0:
                next_block = ((pos - dir_pos) // self._block_size + 1) * self._block_size + dir_pos
                if next_block >= dir_end:
                    break
                pos = next_block
                continue
            if record_len < 34:
                pos += 1
                continue
            end = pos + record_len
            if end > len(self._data):
                break

            record_data = self._data[pos:end]
            rec = self._parse_dir_record(record_data)
            pos = end
            record_count += 1

            if rec is None:
                continue
            if rec.is_system_item:
                continue

            name = self._decode_name(rec, is_joliet, has_rr, susp_offset)
            if not name:
                continue

            full_path = F'{parent_path}/{name}' if parent_path else name

            if rec.is_non_final_extent and not rec.is_dir:
                if pending_ref is None or pending_ref.path != full_path:
                    pending_ref = ISORef(full_path, rec.datetime)
                    self.refs.append(pending_ref)
                pending_ref.extents.append((rec.extent_location, rec.data_length))
                continue
            elif pending_ref is not None and pending_ref.path == full_path:
                pending_ref.extents.append((rec.extent_location, rec.data_length))
                pending_ref = None
                continue
            else:
                pending_ref = None

            if rec.is_dir:
                ref = ISORef(full_path, rec.datetime, is_dir=True)
                self.refs.append(ref)
                self._walk_directory(
                    rec.extent_location,
                    rec.data_length,
                    full_path,
                    is_joliet,
                    has_rr,
                    susp_offset,
                    visited,
                    depth + 1,
                )
            else:
                ref = ISORef(full_path, rec.datetime)
                ref.extents.append((rec.extent_location, rec.data_length))
                self.refs.append(ref)

    def _decode_name(
        self,
        rec: DirRecord,
        is_joliet: bool,
        has_rr: bool,
        susp_offset: int,
    ) -> str:
        if has_rr and susp_offset >= 0:
            rr_name = _get_name_rr(rec.system_use, susp_offset, self._data)
            if rr_name:
                return rr_name

        if is_joliet:
            try:
                name = bytes(rec.file_id).decode('utf-16-be')
            except (UnicodeDecodeError, ValueError):
                name = bytes(rec.file_id).decode('latin-1')
        else:
            name = bytes(rec.file_id).decode('latin-1')

        name = self._strip_revision(name)
        if name.endswith('.'):
            name = name[:-1]
        return name

    @staticmethod
    def _strip_revision(name: str) -> str:
        base, sep, revision = name.partition(';')
        if sep and revision.isdigit():
            return base
        return name

    def select_filesystem(self, fs: FileSystemType) -> None:
        if fs is self.filesystem_type:
            return
        if fs is FileSystemType.JOLIET and self._joliet_vd:
            self._read_directory_tree(self._joliet_vd, is_joliet=True)
        elif fs is FileSystemType.RR and self._primary_vd:
            self._read_directory_tree(self._primary_vd, is_joliet=False)
            if not self._has_rr:
                self.filesystem_type = FileSystemType.ISO
        elif fs is FileSystemType.ISO and self._primary_vd:
            self._has_rr = False
            self._read_directory_tree_plain(self._primary_vd)

    def _read_directory_tree_plain(self, vd: VolumeDescriptor) -> None:
        root = vd.root_dir_record
        if root is None:
            return
        self.filesystem_type = FileSystemType.ISO
        self.refs.clear()
        visited: set[int] = set()
        self._walk_directory(
            root.extent_location,
            root.data_length,
            '',
            False,
            False,
            -1,
            visited,
            0,
        )

    def _read_root_dot_entry(self, root: DirRecord) -> DirRecord | None:
        """Read the actual '.' entry from the root directory data on disk.

        The root directory record stored in the Volume Descriptor is a fixed
        34-byte copy that lacks the system use area.  The real first entry in
        the root directory sector may be much larger and contain SUSP/RR data.
        """
        dir_pos = root.extent_location * self._block_size
        if dir_pos >= len(self._data):
            return None
        rec_len = self._data[dir_pos]
        if rec_len < 34:
            return None
        end = dir_pos + rec_len
        if end > len(self._data):
            return None
        return self._parse_dir_record(self._data[dir_pos:end])

    def _extract_boot_images(self) -> None:
        from refinery.lib.iso.eltorito import BootCatalog
        catalog_pos = self._boot_catalog_location * self._block_size
        if catalog_pos + 2048 > len(self._data):
            return
        catalog_data = bytes(self._data[catalog_pos:catalog_pos + 2048])
        catalog = BootCatalog.parse(catalog_data)
        if catalog is None:
            return
        existing_extents: set[int] = set()
        for ref in self.refs:
            for block, _ in ref.extents:
                existing_extents.add(block)
        for entry in catalog.entries:
            if not entry.is_bootable:
                continue
            if entry.load_rba in existing_extents:
                continue
            img_pos = entry.load_rba * self._block_size
            img_size = entry.image_size
            if img_pos >= len(self._data):
                continue
            if img_pos + img_size > len(self._data):
                img_size = len(self._data) - img_pos
            if img_size <= 0:
                continue
            fat_files = _parse_fat_image(self._data[img_pos:img_pos + img_size])
            if fat_files:
                for path, date, file_data in fat_files:
                    ref = ISORef(path, date)
                    ref._inline = file_data
                    self.refs.append(ref)
            else:
                ref = ISORef(entry.name, None)
                ref.extents.append((entry.load_rba, img_size))
                self.refs.append(ref)

    def entries(self):
        for ref in self.refs:
            if not ref.is_dir:
                yield ref

    def extract(self, ref: ISORef) -> bytearray:
        if ref._inline is not None:
            return bytearray(ref._inline)
        if not ref.extents:
            return bytearray()
        result = bytearray()
        for block, size in ref.extents:
            start = block * self._block_size
            end = start + size
            if end > len(self._data):
                end = len(self._data)
            if start >= len(self._data):
                result.extend(itertools.repeat(0, size))
            else:
                result.extend(self._data[start:end])
        return result
