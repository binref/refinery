"""
Low-level 7z format header parsing using StructReader.
"""
from __future__ import annotations

import dataclasses
import enum
import zlib

from datetime import datetime, timedelta, timezone

from refinery.lib.structures import EOF, StructReader

SIGNATURE = B'7z\xBC\xAF\x27\x1C'
SIGNATURE_HEADER_SIZE = 32


class SzException(Exception):
    pass


class SzCannotUnpack(SzException):
    pass


class SzPasswordRequired(SzCannotUnpack):
    pass


class SzInvalidPassword(SzCannotUnpack):
    pass


class SzCorruptArchive(SzCannotUnpack):
    pass


class SzUnsupportedMethod(SzException):
    pass


class PropertyID(int, enum.Enum):
    END = 0x00
    HEADER = 0x01
    ARCHIVE_PROPS = 0x02
    ADDITIONAL_STREAM = 0x03
    MAIN_STREAM = 0x04
    FILES_INFO = 0x05
    PACK_INFO = 0x06
    UNPACK_INFO = 0x07
    SUBSTREAMS_INFO = 0x08
    SIZE = 0x09
    CRC = 0x0A
    FOLDER = 0x0B
    CODER_UNPACK_SIZE = 0x0C
    NUM_UNPACK_STREAM = 0x0D
    EMPTY_STREAM = 0x0E
    EMPTY_FILE = 0x0F
    ANTI = 0x10
    NAME = 0x11
    CTIME = 0x12
    ATIME = 0x13
    MTIME = 0x14
    WIN_ATTRIBUTES = 0x15
    COMMENT = 0x16
    ENCODED_HEADER = 0x17
    START_POS = 0x18
    DUMMY = 0x19


@dataclasses.dataclass
class SignatureHeader:
    major_version: int
    minor_version: int
    start_header_crc: int
    next_header_offset: int
    next_header_size: int
    next_header_crc: int

    @property
    def archive_size(self) -> int:
        return SIGNATURE_HEADER_SIZE + self.next_header_offset + self.next_header_size


@dataclasses.dataclass
class Coder:
    codec_id: bytes
    num_in_streams: int
    num_out_streams: int
    properties: bytes


@dataclasses.dataclass
class BindPair:
    in_index: int
    out_index: int


@dataclasses.dataclass
class Folder:
    coders: list[Coder]
    bind_pairs: list[BindPair]
    packed_indices: list[int]
    unpack_sizes: list[int]
    crc: int | None = None

    @property
    def total_in_streams(self) -> int:
        return sum(c.num_in_streams for c in self.coders)

    @property
    def total_out_streams(self) -> int:
        return sum(c.num_out_streams for c in self.coders)

    @property
    def main_unpack_size(self) -> int:
        main_index = self._find_main_out_stream()
        return self.unpack_sizes[main_index]

    def _find_main_out_stream(self) -> int:
        bound_out = {bp.out_index for bp in self.bind_pairs}
        for i in range(self.total_out_streams):
            if i not in bound_out:
                return i
        return 0


@dataclasses.dataclass
class PackInfo:
    pack_pos: int
    num_pack_streams: int
    sizes: list[int]
    crcs: list[int | None]


@dataclasses.dataclass
class SubstreamsInfo:
    num_unpack_streams: list[int]
    unpack_sizes: list[int]
    crcs: list[int | None]


@dataclasses.dataclass
class FileEntry:
    name: str = ''
    size: int = 0
    crc: int | None = None
    has_stream: bool = True
    is_dir: bool = False
    is_anti: bool = False
    ctime: datetime | None = None
    atime: datetime | None = None
    mtime: datetime | None = None
    attributes: int = 0


@dataclasses.dataclass
class ArchiveHeader:
    pack_info: PackInfo | None = None
    folders: list[Folder] = dataclasses.field(default_factory=list)
    substreams: SubstreamsInfo | None = None
    files: list[FileEntry] = dataclasses.field(default_factory=list)


def read_7z_uint64(reader: StructReader) -> int:
    first = reader.u8()
    mask = 0x80
    value = 0
    for i in range(8):
        if first & mask == 0:
            value |= ((first & (mask - 1)) << (8 * i))
            return value
        value |= reader.u8() << (8 * i)
        mask >>= 1
    return value


def read_booleans(reader: StructReader, count: int, check_all_defined: bool = True) -> list[bool]:
    if check_all_defined:
        all_defined = reader.u8()
        if all_defined:
            return [True] * count
    result = []
    b = 0
    mask = 0
    for _ in range(count):
        if mask == 0:
            b = reader.u8()
            mask = 0x80
        result.append(bool(b & mask))
        mask >>= 1
    return result


def read_crcs(reader: StructReader, count: int) -> list[int | None]:
    defined = read_booleans(reader, count)
    crcs: list[int | None] = []
    for d in defined:
        if d:
            crcs.append(reader.u32())
        else:
            crcs.append(None)
    return crcs


_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _filetime_to_datetime(ft: int) -> datetime | None:
    if ft == 0:
        return None
    try:
        return _FILETIME_EPOCH + timedelta(microseconds=ft // 10)
    except (OverflowError, OSError):
        return None


def parse_signature_header(data: bytes | bytearray | memoryview) -> SignatureHeader:
    view = memoryview(data)
    if view[:6] != SIGNATURE:
        raise SzCorruptArchive('Invalid 7z signature.')
    reader = StructReader(view)
    reader.seekset(6)
    major = reader.u8()
    minor = reader.u8()
    start_crc = reader.u32()
    computed_crc = zlib.crc32(view[12:32]) & 0xFFFFFFFF
    if computed_crc != start_crc:
        raise SzCorruptArchive(
            F'Start header CRC mismatch: expected {start_crc:#010x},'
            F' computed {computed_crc:#010x}.')
    next_header_offset = reader.u64()
    next_header_size = reader.u64()
    next_header_crc = reader.u32()
    return SignatureHeader(
        major_version=major,
        minor_version=minor,
        start_header_crc=start_crc,
        next_header_offset=next_header_offset,
        next_header_size=next_header_size,
        next_header_crc=next_header_crc,
    )


def _parse_pack_info(reader: StructReader) -> PackInfo:
    pack_pos = read_7z_uint64(reader)
    num_pack_streams = read_7z_uint64(reader)
    sizes: list[int] = []
    crcs: list[int | None] = [None] * num_pack_streams
    while True:
        prop_id = reader.u8()
        if prop_id == PropertyID.END:
            break
        if prop_id == PropertyID.SIZE:
            for _ in range(num_pack_streams):
                sizes.append(read_7z_uint64(reader))
        elif prop_id == PropertyID.CRC:
            crcs = read_crcs(reader, num_pack_streams)
        else:
            skip = read_7z_uint64(reader)
            reader.seekrel(skip)
    if not sizes:
        sizes = [0] * num_pack_streams
    return PackInfo(
        pack_pos=pack_pos,
        num_pack_streams=num_pack_streams,
        sizes=sizes,
        crcs=crcs,
    )


def _parse_folder(reader: StructReader) -> Folder:
    num_coders = read_7z_uint64(reader)
    coders: list[Coder] = []
    total_in = 0
    total_out = 0
    for _ in range(num_coders):
        flags = reader.u8()
        codec_size = flags & 0x0F
        is_complex = bool(flags & 0x10)
        has_attrs = bool(flags & 0x20)
        codec_id = bytes(reader.read_exactly(codec_size))
        if is_complex:
            num_in = read_7z_uint64(reader)
            num_out = read_7z_uint64(reader)
        else:
            num_in = 1
            num_out = 1
        props = b''
        if has_attrs:
            props_size = read_7z_uint64(reader)
            props = reader.read_bytes(props_size)
        coders.append(Coder(
            codec_id=codec_id,
            num_in_streams=num_in,
            num_out_streams=num_out,
            properties=props,
        ))
        total_in += num_in
        total_out += num_out
    bind_pairs: list[BindPair] = []
    for _ in range(total_out - 1):
        bind_pairs.append(BindPair(
            in_index=read_7z_uint64(reader),
            out_index=read_7z_uint64(reader),
        ))
    num_packed = total_in - (total_out - 1)
    packed_indices: list[int] = []
    if num_packed == 1:
        bound_in = {bp.in_index for bp in bind_pairs}
        for i in range(total_in):
            if i not in bound_in:
                packed_indices.append(i)
                break
    else:
        for _ in range(num_packed):
            packed_indices.append(read_7z_uint64(reader))
    return Folder(
        coders=coders,
        bind_pairs=bind_pairs,
        packed_indices=packed_indices,
        unpack_sizes=[],
    )


def _parse_unpack_info(reader: StructReader) -> list[Folder]:
    prop_id = reader.u8()
    if prop_id != PropertyID.FOLDER:
        raise SzCorruptArchive(F'Expected FOLDER property, got {prop_id:#x}.')
    num_folders = read_7z_uint64(reader)
    external = reader.u8()
    if external:
        raise SzUnsupportedMethod('External folder references are not supported.')
    folders: list[Folder] = []
    for _ in range(num_folders):
        folders.append(_parse_folder(reader))
    prop_id = reader.u8()
    if prop_id != PropertyID.CODER_UNPACK_SIZE:
        raise SzCorruptArchive(F'Expected CODER_UNPACK_SIZE, got {prop_id:#x}.')
    for folder in folders:
        folder.unpack_sizes = []
        for _ in range(folder.total_out_streams):
            folder.unpack_sizes.append(read_7z_uint64(reader))
    while True:
        prop_id = reader.u8()
        if prop_id == PropertyID.END:
            break
        if prop_id == PropertyID.CRC:
            crcs = read_crcs(reader, num_folders)
            for i, folder in enumerate(folders):
                folder.crc = crcs[i]
        else:
            skip = read_7z_uint64(reader)
            reader.seekrel(skip)
    return folders


def _parse_substreams_info(
    reader: StructReader,
    folders: list[Folder],
) -> SubstreamsInfo:
    num_unpack_streams = [1] * len(folders)
    unpack_sizes: list[int] = []
    crcs: list[int | None] = []
    while True:
        prop_id = reader.u8()
        if prop_id == PropertyID.END:
            break
        if prop_id == PropertyID.NUM_UNPACK_STREAM:
            for i in range(len(folders)):
                num_unpack_streams[i] = read_7z_uint64(reader)
        elif prop_id == PropertyID.SIZE:
            for i, folder in enumerate(folders):
                ns = num_unpack_streams[i]
                subtotal = 0
                for _ in range(ns - 1):
                    s = read_7z_uint64(reader)
                    unpack_sizes.append(s)
                    subtotal += s
                unpack_sizes.append(folder.main_unpack_size - subtotal)
        elif prop_id == PropertyID.CRC:
            num_crc_streams = 0
            for i, folder in enumerate(folders):
                ns = num_unpack_streams[i]
                if ns == 1 and folder.crc is not None:
                    continue
                num_crc_streams += ns
            crcs = read_crcs(reader, num_crc_streams)
        else:
            skip = read_7z_uint64(reader)
            reader.seekrel(skip)
    if not unpack_sizes:
        for i, folder in enumerate(folders):
            ns = num_unpack_streams[i]
            if ns == 1:
                unpack_sizes.append(folder.main_unpack_size)
            else:
                for _ in range(ns):
                    unpack_sizes.append(0)
    return SubstreamsInfo(
        num_unpack_streams=num_unpack_streams,
        unpack_sizes=unpack_sizes,
        crcs=crcs,
    )


def _parse_files_info(reader: StructReader, num_files: int) -> list[FileEntry]:
    files = [FileEntry() for _ in range(num_files)]
    while True:
        try:
            prop_id = reader.u8()
        except EOF:
            break
        if prop_id == PropertyID.END:
            break
        size = read_7z_uint64(reader)
        pos_before = reader.tell()
        if prop_id == PropertyID.NAME:
            external = reader.u8()
            if external:
                reader.seekset(pos_before + size)
                continue
            for f in files:
                name_bytes = bytearray()
                while True:
                    c = reader.read_exactly(2)
                    if c[0] == 0 and c[1] == 0:
                        break
                    name_bytes.extend(c)
                f.name = name_bytes.decode('utf-16-le')
        elif prop_id == PropertyID.EMPTY_STREAM:
            empty_streams = read_booleans(reader, num_files, check_all_defined=False)
            for i, es in enumerate(empty_streams):
                if es:
                    files[i].has_stream = False
        elif prop_id == PropertyID.EMPTY_FILE:
            empty_count = sum(1 for f in files if not f.has_stream)
            empty_file_flags = read_booleans(reader, empty_count, check_all_defined=False)
            idx = 0
            for f in files:
                if not f.has_stream:
                    if idx < len(empty_file_flags) and empty_file_flags[idx]:
                        f.is_dir = False
                    else:
                        f.is_dir = True
                    idx += 1
        elif prop_id == PropertyID.ANTI:
            anti_count = sum(1 for f in files if not f.has_stream)
            anti_flags = read_booleans(reader, anti_count, check_all_defined=False)
            idx = 0
            for f in files:
                if not f.has_stream:
                    if idx < len(anti_flags):
                        f.is_anti = anti_flags[idx]
                    idx += 1
        elif prop_id in (PropertyID.CTIME, PropertyID.ATIME, PropertyID.MTIME):
            defined = read_booleans(reader, num_files)
            external = reader.u8()
            if external:
                reader.seekset(pos_before + size)
                continue
            for i, d in enumerate(defined):
                if d:
                    ft = reader.u64()
                    dt = _filetime_to_datetime(ft)
                    if prop_id == PropertyID.CTIME:
                        files[i].ctime = dt
                    elif prop_id == PropertyID.ATIME:
                        files[i].atime = dt
                    else:
                        files[i].mtime = dt
        elif prop_id == PropertyID.WIN_ATTRIBUTES:
            defined = read_booleans(reader, num_files)
            external = reader.u8()
            if external:
                reader.seekset(pos_before + size)
                continue
            for i, d in enumerate(defined):
                if d:
                    files[i].attributes = reader.u32()
                    if files[i].attributes & 0x10:
                        files[i].is_dir = True
        elif prop_id == PropertyID.DUMMY:
            reader.seekset(pos_before + size)
        else:
            reader.seekset(pos_before + size)
    empty_stream_files = [f for f in files if not f.has_stream]
    for f in empty_stream_files:
        if not f.is_dir and f.name and f.name.endswith('/'):
            f.is_dir = True
    return files


def parse_header(reader: StructReader) -> ArchiveHeader:
    header = ArchiveHeader()
    while True:
        try:
            prop_id = reader.u8()
        except EOF:
            break
        if prop_id == PropertyID.END:
            break
        if prop_id == PropertyID.ARCHIVE_PROPS:
            while True:
                p = reader.u8()
                if p == PropertyID.END:
                    break
                skip = read_7z_uint64(reader)
                reader.seekrel(skip)
        elif prop_id == PropertyID.ADDITIONAL_STREAM:
            skip = read_7z_uint64(reader)
            reader.seekrel(skip)
        elif prop_id == PropertyID.MAIN_STREAM:
            inner = _parse_main_streams_info(reader)
            header.pack_info = inner.pack_info
            header.folders = inner.folders
            header.substreams = inner.substreams
        elif prop_id == PropertyID.FILES_INFO:
            num_files = read_7z_uint64(reader)
            header.files = _parse_files_info(reader, num_files)
        else:
            skip = read_7z_uint64(reader)
            reader.seekrel(skip)
    return header


def _parse_main_streams_info(reader: StructReader) -> ArchiveHeader:
    header = ArchiveHeader()
    while True:
        prop_id = reader.u8()
        if prop_id == PropertyID.END:
            break
        if prop_id == PropertyID.PACK_INFO:
            header.pack_info = _parse_pack_info(reader)
        elif prop_id == PropertyID.UNPACK_INFO:
            header.folders = _parse_unpack_info(reader)
        elif prop_id == PropertyID.SUBSTREAMS_INFO:
            header.substreams = _parse_substreams_info(reader, header.folders)
        else:
            skip = read_7z_uint64(reader)
            reader.seekrel(skip)
    return header


def parse_encoded_header(reader: StructReader) -> ArchiveHeader:
    return _parse_main_streams_info(reader)
