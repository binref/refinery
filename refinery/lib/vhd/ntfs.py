"""
A parser for the NTFS file system. The implementation bootstraps the Master File Table (MFT) from
the boot sector, parses each MFT record (applying the update sequence array fixups), and decodes
the standard information, file name, and data attributes. Non-resident data is reconstructed from
its data runs, including support for sparse runs and LZNT1 compressed runs. File paths are built
by following the parent directory references stored in the file name attributes.

The parser operates on a single volume that is provided as a `refinery.lib.vhd.ntfs.VolumeSource`,
i.e. any object exposing a `read(offset, length)` method. It is independent of any container
format and follows the NTFS handler from the 7-Zip source code as its reference. Only the parts
required to enumerate and extract regular files are implemented; alternate data streams, security
descriptors, and reparse points are not exposed.
"""
from __future__ import annotations

import datetime

from dataclasses import dataclass, field
from typing import Iterator, Protocol

_FILE_MAGIC = B'FILE'

_ATTR_STANDARD_INFO = 0x10
_ATTR_FILE_NAME = 0x30
_ATTR_DATA = 0x80
_ATTR_END = 0xFFFFFFFF

_FILE_NAME_DOS = 2

_SI_CREATED = 0x00
_SI_MODIFIED = 0x08
_SI_CHANGED = 0x10
_SI_ACCESSED = 0x18
_SI_ATTRIBUTES = 0x20

_FN_CREATED = 0x08
_FN_MODIFIED = 0x10
_FN_CHANGED = 0x18
_FN_ACCESSED = 0x20

_FLAG_IN_USE = 0x0001
_FLAG_DIRECTORY = 0x0002

_RECORD_ROOT = 5
_NUM_SYSTEM_RECORDS = 16

_EMPTY_EXTENT = -1


class VolumeSource(Protocol):
    def read(self, offset: int, length: int) -> bytearray:
        ...


class NtfsError(ValueError):
    pass


def _filetime(value: int) -> datetime.datetime | None:
    if value == 0:
        return None
    try:
        epoch = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
        return epoch + datetime.timedelta(microseconds=value // 10)
    except (ValueError, OverflowError):
        return None


@dataclass
class _Attr:
    type: int
    name: str
    non_resident: bool
    data: bytearray
    compression_unit: int = 0
    low_vcn: int = 0
    high_vcn: int = 0
    allocated_size: int = 0
    real_size: int = 0
    initialized_size: int = 0


@dataclass
class _FileName:
    parent: int
    name: str
    name_type: int
    attrib: int
    created: datetime.datetime | None = None
    modified: datetime.datetime | None = None
    changed: datetime.datetime | None = None
    accessed: datetime.datetime | None = None


@dataclass
class _Record:
    index: int
    in_use: bool
    is_dir: bool
    file_names: list[_FileName]
    data_attrs: list[_Attr]
    date: datetime.datetime | None
    created: datetime.datetime | None = None
    changed: datetime.datetime | None = None
    accessed: datetime.datetime | None = None
    attributes: int = 0


@dataclass
class NtfsFile:
    """
    A file or directory entry within an NTFS volume. The `extract` method reconstructs the file
    contents from the unnamed data attribute of the underlying MFT record. The timestamp and
    attribute fields are sourced from the record's `$STANDARD_INFORMATION` and `$FILE_NAME`
    attributes; the latter (`fn_` prefix) are exposed separately because a mismatch between the
    two timestamp sets is a classic indicator of timestamp manipulation (timestomping).
    """
    path: str
    date: datetime.datetime | None
    size: int
    is_dir: bool
    _volume: NtfsVolume = field(repr=False)
    _record: int = 0
    record: int = 0
    allocated: int = 0
    attributes: int = 0
    btime: datetime.datetime | None = None
    mtime: datetime.datetime | None = None
    atime: datetime.datetime | None = None
    ctime: datetime.datetime | None = None
    fn_btime: datetime.datetime | None = None
    fn_mtime: datetime.datetime | None = None
    fn_atime: datetime.datetime | None = None
    fn_ctime: datetime.datetime | None = None
    deleted: bool = False

    def extract(self) -> bytearray:
        return self._volume._extract(self._record)


class NtfsVolume:
    """
    Parses an NTFS volume. The boot sector supplies the cluster geometry and the location of the
    MFT, which is then read as a file in order to enumerate all other records. The `files` method
    yields all non-system file and directory entries with their full paths.
    """
    def __init__(self, source: VolumeSource):
        self._source = source
        boot = source.read(0, 512)
        if boot[3:11] != B'NTFS    ':
            raise NtfsError('missing NTFS boot sector signature')

        bytes_per_sector = int.from_bytes(boot[0x0B:0x0D], 'little')
        sectors_per_cluster = boot[0x0D]
        if not bytes_per_sector or not sectors_per_cluster:
            raise NtfsError('invalid NTFS BIOS parameter block')
        self.sector_size_log = bytes_per_sector.bit_length() - 1
        self.cluster_size_log = self.sector_size_log + (sectors_per_cluster.bit_length() - 1)
        self.num_sectors = int.from_bytes(boot[0x28:0x30], 'little')
        self.num_clusters = self.num_sectors >> (sectors_per_cluster.bit_length() - 1)
        self.mft_cluster = int.from_bytes(boot[0x30:0x38], 'little')

        record_descriptor = int.from_bytes(boot[0x40:0x44], 'little', signed=True)
        if 0 < record_descriptor < 0x80:
            self.record_size_log = (record_descriptor.bit_length() - 1) + self.cluster_size_log
        else:
            self.record_size_log = 0x100 - (record_descriptor & 0xFF)
        self.record_size = 1 << self.record_size_log
        self.cluster_size = 1 << self.cluster_size_log

        self._records: list[_Record | None] = []
        self._load_mft()

    def _read_clusters(self, cluster: int, count: int) -> bytearray:
        return self._source.read(cluster << self.cluster_size_log, count << self.cluster_size_log)

    def _load_mft(self) -> None:
        first = self._read_clusters(self.mft_cluster, max(1, self.record_size >> self.cluster_size_log))
        record = self._parse_record(first[:self.record_size], 0)
        if record is None:
            raise NtfsError('failed to parse the $MFT record')
        data = self._find_unnamed_data(record)
        if data is None:
            raise NtfsError('the $MFT record has no data attribute')
        mft = self._read_attr_data(data)
        count = len(mft) // self.record_size
        self._records = [None] * count
        for index in range(count):
            chunk = mft[index * self.record_size:(index + 1) * self.record_size]
            self._records[index] = self._parse_record(chunk, index)

    def _apply_fixups(self, record: bytearray) -> bool:
        usa_offset = int.from_bytes(record[0x04:0x06], 'little')
        usa_count = int.from_bytes(record[0x06:0x08], 'little')
        if usa_count == 0:
            return False
        usn = record[usa_offset:usa_offset + 2]
        for index in range(1, usa_count):
            tail = (index << self.sector_size_log) - 2
            if tail + 2 > len(record):
                return False
            if record[tail:tail + 2] != usn:
                return False
            source = usa_offset + index * 2
            record[tail:tail + 2] = record[source:source + 2]
        return True

    def _parse_record(self, raw: bytearray, index: int) -> _Record | None:
        record = bytearray(raw)
        if len(record) < self.record_size or record[:4] != _FILE_MAGIC:
            return None
        if not self._apply_fixups(record):
            return None
        flags = int.from_bytes(record[0x16:0x18], 'little')
        attr_offset = int.from_bytes(record[0x14:0x16], 'little')
        bytes_in_use = int.from_bytes(record[0x18:0x1C], 'little')
        limit = min(bytes_in_use, len(record))

        file_names: list[_FileName] = []
        data_attrs: list[_Attr] = []
        date = None
        created = None
        changed = None
        accessed = None
        attributes = 0

        position = attr_offset
        while position + 4 <= limit:
            attr_type = int.from_bytes(record[position:position + 4], 'little')
            if attr_type == _ATTR_END:
                break
            attr, length = self._parse_attr(record, position, limit)
            if attr is None or length == 0:
                break
            position += length
            if attr.type == _ATTR_FILE_NAME:
                name = self._parse_file_name(attr.data)
                if name is not None:
                    file_names.append(name)
            elif attr.type == _ATTR_STANDARD_INFO:
                if len(attr.data) >= 0x24:
                    created = _filetime(int.from_bytes(attr.data[_SI_CREATED:_SI_CREATED + 8], 'little'))
                    date = _filetime(int.from_bytes(attr.data[_SI_MODIFIED:_SI_MODIFIED + 8], 'little'))
                    changed = _filetime(int.from_bytes(attr.data[_SI_CHANGED:_SI_CHANGED + 8], 'little'))
                    accessed = _filetime(int.from_bytes(attr.data[_SI_ACCESSED:_SI_ACCESSED + 8], 'little'))
                    attributes = int.from_bytes(attr.data[_SI_ATTRIBUTES:_SI_ATTRIBUTES + 4], 'little')
                elif len(attr.data) >= 8:
                    date = _filetime(int.from_bytes(attr.data[_SI_MODIFIED:_SI_MODIFIED + 8], 'little'))
            elif attr.type == _ATTR_DATA:
                data_attrs.append(attr)

        return _Record(
            index=index,
            in_use=bool(flags & _FLAG_IN_USE),
            is_dir=bool(flags & _FLAG_DIRECTORY),
            file_names=file_names,
            data_attrs=data_attrs,
            date=date,
            created=created,
            changed=changed,
            accessed=accessed,
            attributes=attributes,
        )

    def _parse_attr(self, record: bytearray, offset: int, limit: int) -> tuple[_Attr | None, int]:
        if offset + 0x18 > limit:
            return None, 0
        attr_type = int.from_bytes(record[offset:offset + 4], 'little')
        length = int.from_bytes(record[offset + 4:offset + 8], 'little')
        if length == 0 or length & 7 or offset + length > limit:
            return None, 0
        non_resident = bool(record[offset + 8])
        name_length = record[offset + 9]
        name_offset = int.from_bytes(record[offset + 0x0A:offset + 0x0C], 'little')
        name = ''
        if name_length:
            start = offset + name_offset
            name = bytes(record[start:start + name_length * 2]).decode('utf-16le', 'replace')

        if non_resident:
            if length < 0x40:
                return None, 0
            low_vcn = int.from_bytes(record[offset + 0x10:offset + 0x18], 'little')
            high_vcn = int.from_bytes(record[offset + 0x18:offset + 0x20], 'little')
            data_offset = int.from_bytes(record[offset + 0x20:offset + 0x22], 'little')
            compression_unit = record[offset + 0x22]
            allocated = int.from_bytes(record[offset + 0x28:offset + 0x30], 'little')
            real_size = int.from_bytes(record[offset + 0x30:offset + 0x38], 'little')
            initialized = int.from_bytes(record[offset + 0x38:offset + 0x40], 'little')
            data = bytearray(record[offset + data_offset:offset + length])
            return _Attr(
                attr_type, name, True, data,
                compression_unit=compression_unit,
                low_vcn=low_vcn,
                high_vcn=high_vcn,
                allocated_size=allocated,
                real_size=real_size,
                initialized_size=initialized,
            ), length
        else:
            data_size = int.from_bytes(record[offset + 0x10:offset + 0x14], 'little')
            data_offset = int.from_bytes(record[offset + 0x14:offset + 0x16], 'little')
            if data_offset + data_size > length:
                return None, 0
            data = bytearray(record[offset + data_offset:offset + data_offset + data_size])
            return _Attr(attr_type, name, False, data), length

    @staticmethod
    def _parse_file_name(data: bytearray) -> _FileName | None:
        if len(data) < 0x42:
            return None
        parent = int.from_bytes(data[0:6], 'little')
        created = _filetime(int.from_bytes(data[_FN_CREATED:_FN_CREATED + 8], 'little'))
        modified = _filetime(int.from_bytes(data[_FN_MODIFIED:_FN_MODIFIED + 8], 'little'))
        changed = _filetime(int.from_bytes(data[_FN_CHANGED:_FN_CHANGED + 8], 'little'))
        accessed = _filetime(int.from_bytes(data[_FN_ACCESSED:_FN_ACCESSED + 8], 'little'))
        attrib = int.from_bytes(data[0x38:0x3C], 'little')
        name_length = data[0x40]
        name_type = data[0x41]
        if 0x42 + name_length * 2 > len(data):
            return None
        name = bytes(data[0x42:0x42 + name_length * 2]).decode('utf-16le', 'replace')
        return _FileName(
            parent, name, name_type, attrib,
            created=created,
            modified=modified,
            changed=changed,
            accessed=accessed,
        )

    @staticmethod
    def _find_unnamed_data(record: _Record) -> _Attr | None:
        for attr in record.data_attrs:
            if not attr.name:
                return attr
        return None

    def _collect_data_attrs(self, record: _Record) -> list[_Attr]:
        return [attr for attr in record.data_attrs if not attr.name]

    def _read_attr_data(self, attr: _Attr, extra: list[_Attr] | None = None) -> bytearray:
        if not attr.non_resident:
            return bytearray(attr.data)
        attrs = [attr]
        if extra:
            attrs = sorted({id(a): a for a in [attr, *extra]}.values(), key=lambda a: a.low_vcn)
        extents = self._parse_extents(attrs)
        return self._read_extents(extents, attr)

    def _parse_extents(self, attrs: list[_Attr]) -> list[tuple[int, int, int]]:
        extents: list[tuple[int, int, int]] = []
        for attr in attrs:
            vcn = attr.low_vcn
            lcn = 0
            data = attr.data
            position = 0
            while position < len(data):
                header = data[position]
                position += 1
                if header == 0:
                    break
                run_len = header & 0x0F
                run_off = header >> 4
                if run_len == 0 or position + run_len > len(data):
                    break
                length = int.from_bytes(data[position:position + run_len], 'little')
                position += run_len
                if run_off == 0:
                    extents.append((vcn, _EMPTY_EXTENT, length))
                    vcn += length
                    continue
                if position + run_off > len(data):
                    break
                delta = int.from_bytes(data[position:position + run_off], 'little', signed=True)
                position += run_off
                lcn += delta
                extents.append((vcn, lcn, length))
                vcn += length
        return extents

    def _read_extents(self, extents: list[tuple[int, int, int]], attr: _Attr) -> bytearray:
        if attr.compression_unit:
            return self._read_compressed(extents, attr)
        out = bytearray()
        for _, lcn, length in extents:
            size = length << self.cluster_size_log
            if lcn == _EMPTY_EXTENT:
                out.extend(bytes(size))
            else:
                out.extend(self._read_clusters(lcn, length))
        del out[attr.real_size:]
        if len(out) < attr.real_size:
            out.extend(bytes(attr.real_size - len(out)))
        if attr.initialized_size < attr.real_size:
            zeros = attr.real_size - attr.initialized_size
            out[attr.initialized_size:] = bytes(zeros)
        return out

    def _read_compressed(self, extents: list[tuple[int, int, int]], attr: _Attr) -> bytearray:
        unit = 1 << attr.compression_unit
        clusters: dict[int, int] = {}
        for vcn, lcn, length in extents:
            if lcn == _EMPTY_EXTENT:
                continue
            for offset in range(length):
                clusters[vcn + offset] = lcn + offset
        out = bytearray()
        total_clusters = (attr.real_size + self.cluster_size - 1) >> self.cluster_size_log
        vcn = 0
        while vcn < total_clusters:
            block = [clusters.get(vcn + k) for k in range(unit)]
            if all(c is None for c in block):
                out.extend(bytes(unit << self.cluster_size_log))
            elif all(c is not None for c in block):
                for cluster in block:
                    if cluster is not None:
                        out.extend(self._read_clusters(cluster, 1))
            else:
                compressed = bytearray()
                for cluster in block:
                    if cluster is None:
                        break
                    compressed.extend(self._read_clusters(cluster, 1))
                out.extend(_lznt1_decompress(compressed, unit << self.cluster_size_log))
            vcn += unit
        del out[attr.real_size:]
        if len(out) < attr.real_size:
            out.extend(bytes(attr.real_size - len(out)))
        if attr.initialized_size < attr.real_size:
            out[attr.initialized_size:] = bytes(attr.real_size - attr.initialized_size)
        return out

    def _extract(self, index: int) -> bytearray:
        record = self._records[index]
        if record is None:
            return bytearray()
        attrs = self._collect_data_attrs(record)
        if not attrs:
            return bytearray()
        primary = next((a for a in attrs if a.low_vcn == 0), attrs[0])
        return self._read_attr_data(primary, attrs)

    def files(self, recover: bool = False) -> Iterator[NtfsFile]:
        names: dict[int, _FileName] = {}
        for record in self._records:
            if record is None or not record.in_use:
                continue
            if record.index < _NUM_SYSTEM_RECORDS:
                continue
            chosen = self._select_name(record)
            if chosen is not None:
                names[record.index] = chosen
        for index, chosen in names.items():
            record = self._records[index]
            if record is None:
                continue
            path = self._build_path(index, names)
            if path is None:
                continue
            yield self._make_file(record, chosen, path, deleted=False)
        if recover:
            yield from self._recover(names)

    def _recover(self, names: dict[int, _FileName]) -> Iterator[NtfsFile]:
        for record in self._records:
            if record is None or record.in_use:
                continue
            if record.index < _NUM_SYSTEM_RECORDS:
                continue
            if self._find_unnamed_data(record) is None:
                continue
            chosen = self._select_name(record)
            if chosen is None:
                continue
            path = self._build_path(record.index, names, chosen)
            if path is None:
                path = F'?/{chosen.name}'
            yield self._make_file(record, chosen, path, deleted=True)

    def _make_file(
        self,
        record: _Record,
        chosen: _FileName,
        path: str,
        deleted: bool,
    ) -> NtfsFile:
        return NtfsFile(
            path=path,
            date=record.date,
            size=self._file_size(record),
            is_dir=record.is_dir,
            _volume=self,
            _record=record.index,
            record=record.index,
            allocated=self._allocated_size(record),
            attributes=record.attributes,
            btime=record.created,
            mtime=record.date,
            ctime=record.changed,
            atime=record.accessed,
            fn_btime=chosen.created,
            fn_mtime=chosen.modified,
            fn_ctime=chosen.changed,
            fn_atime=chosen.accessed,
            deleted=deleted,
        )

    def _select_name(self, record: _Record) -> _FileName | None:
        chosen = None
        for name in record.file_names:
            if name.name_type == _FILE_NAME_DOS:
                continue
            if chosen is None or name.name_type >= chosen.name_type:
                chosen = name
        if chosen is None and record.file_names:
            chosen = record.file_names[0]
        return chosen

    def _build_path(
        self,
        index: int,
        names: dict[int, _FileName],
        start: _FileName | None = None,
    ) -> str | None:
        parts: list[str] = []
        current = index
        seen = set()
        if start is not None:
            parts.append(start.name)
            parent = start.parent
            if parent == _RECORD_ROOT or parent == current:
                return start.name
            if parent < _NUM_SYSTEM_RECORDS:
                return F'?/{start.name}'
            current = parent
        while True:
            if current in seen:
                return None
            seen.add(current)
            name = names.get(current)
            if name is None:
                if parts:
                    return '/'.join(['?', *reversed(parts)])
                return None
            parts.append(name.name)
            parent = name.parent
            if parent == _RECORD_ROOT or parent == current:
                break
            if parent < _NUM_SYSTEM_RECORDS:
                return None
            current = parent
        return '/'.join(reversed(parts))

    def _allocated_size(self, record: _Record) -> int:
        attr = self._find_unnamed_data(record)
        if attr is None or not attr.non_resident:
            return 0
        return attr.allocated_size

    def _file_size(self, record: _Record) -> int:
        attr = self._find_unnamed_data(record)
        if attr is None:
            return 0
        if attr.non_resident:
            return attr.real_size
        return len(attr.data)


def _lznt1_decompress(src: bytearray, out_limit: int) -> bytearray:
    dest = bytearray()
    position = 0
    while position + 2 <= len(src):
        header = int.from_bytes(src[position:position + 2], 'little')
        if header == 0:
            break
        position += 2
        block_size = (header & 0x0FFF) + 1
        if position + block_size > len(src):
            break
        block = src[position:position + block_size]
        position += block_size
        if not header & 0x8000:
            dest.extend(block)
            continue
        dest.extend(_lznt1_block(block, len(dest)))
        if len(dest) >= out_limit:
            break
    return dest


def _lznt1_block(block: bytearray, already: int) -> bytearray:
    out = bytearray()
    position = 0
    base = already
    while position < len(block):
        flags = block[position]
        position += 1
        for bit in range(8):
            if position >= len(block):
                break
            if not (flags >> bit) & 1:
                out.append(block[position])
                position += 1
                continue
            if position + 2 > len(block):
                return out
            token = int.from_bytes(block[position:position + 2], 'little')
            position += 2
            current = len(out)
            if current == 0:
                return out
            distance_bits = 4
            while ((current - 1) >> distance_bits) != 0:
                distance_bits += 1
            length_mask = 0xFFFF >> distance_bits
            length = (token & length_mask) + 3
            distance = (token >> (16 - distance_bits)) + 1
            start = current - distance
            if start < 0:
                return out
            for offset in range(length):
                out.append(out[start + offset])
    del base
    return out


def is_ntfs(data: bytearray) -> bool:
    """
    Check whether the start of a volume looks like an NTFS boot sector by testing for the `NTFS`
    OEM identifier and the boot signature.
    """
    if len(data) < 512:
        return False
    if int.from_bytes(data[0x1FE:0x200], 'little') != 0xAA55:
        return False
    return data[3:11] == B'NTFS    '
