"""
Pure-Python 7z archive parser and extractor.
"""
from __future__ import annotations

import zlib

from datetime import datetime

from refinery.lib.structures import StructReader
from refinery.lib.un7z.coders import (
    CODEC_AES256SHA256,
    decompress_folder,
)
from refinery.lib.un7z.headers import (
    SIGNATURE,
    SIGNATURE_HEADER_SIZE,
    ArchiveHeader,
    FileEntry,
    PropertyID,
    SignatureHeader,
    SzCannotUnpack,
    SzCorruptArchive,
    SzException,
    SzInvalidPassword,
    SzPasswordRequired,
    SzUnsupportedMethod,
    parse_encoded_header,
    parse_header,
    parse_signature_header,
)

__all__ = [
    'SIGNATURE',
    'SIGNATURE_HEADER_SIZE',
    'SzArchive',
    'SzCorruptArchive',
    'SzException',
    'SzFile',
    'SzInvalidPassword',
    'SzPasswordRequired',
    'SzUnsupportedMethod',
    'SzCannotUnpack',
]


class SzFile:
    def __init__(
        self,
        entry: FileEntry,
        archive: SzArchive,
        folder_index: int | None,
        stream_index: int | None,
    ):
        self._entry = entry
        self._archive = archive
        self._folder_index = folder_index
        self._stream_index = stream_index

    @property
    def name(self) -> str:
        return self._entry.name

    @property
    def size(self) -> int:
        return self._entry.size

    @property
    def crc(self) -> int | None:
        return self._entry.crc

    @property
    def is_dir(self) -> bool:
        return self._entry.is_dir

    @property
    def mtime(self) -> datetime | None:
        return self._entry.mtime

    @property
    def ctime(self) -> datetime | None:
        return self._entry.ctime

    @property
    def atime(self) -> datetime | None:
        return self._entry.atime

    @property
    def attributes(self) -> int:
        return self._entry.attributes

    def decompress(self, password: str | bytes | None = None) -> bytes | bytearray | memoryview:
        if self.is_dir:
            return b''
        if self._folder_index is None or self._stream_index is None:
            return b''
        pw = password or self._archive._password
        return self._archive._decompress_file(self._folder_index, self._stream_index, pw)


class SzArchive:
    def __init__(
        self,
        data: bytes | bytearray | memoryview,
        password: str | bytes | None = None,
    ):
        self._view = memoryview(data)
        self._password = password
        self._sig_header: SignatureHeader | None = None
        self._header: ArchiveHeader | None = None
        self._files: list[SzFile] = []
        self._folder_cache: dict[int, list[memoryview]] = {}
        self._parse()

    @property
    def signature_header(self) -> SignatureHeader:
        assert self._sig_header is not None
        return self._sig_header

    @property
    def files(self) -> list[SzFile]:
        return list(self._files)

    def _parse(self):
        self._sig_header = parse_signature_header(self._view)
        sh = self._sig_header
        header_offset = SIGNATURE_HEADER_SIZE + sh.next_header_offset
        header_end = header_offset + sh.next_header_size
        header_view = self._view[header_offset:header_end]
        crc = zlib.crc32(header_view) & 0xFFFFFFFF
        if crc != sh.next_header_crc:
            raise SzCorruptArchive(
                F'Next header CRC mismatch: expected {sh.next_header_crc:#010x},'
                F' computed {crc:#010x}.')
        reader = StructReader(header_view)
        prop_id = reader.u8()
        if prop_id == PropertyID.HEADER:
            self._header = parse_header(reader)
        elif prop_id == PropertyID.ENCODED_HEADER:
            self._header = self._decode_encoded_header(reader)
        else:
            raise SzCorruptArchive(F'Unexpected top-level property: {prop_id:#x}')
        self._build_file_list()

    def _decode_encoded_header(self, reader: StructReader) -> ArchiveHeader:
        enc_header = parse_encoded_header(reader)
        if enc_header.pack_info is None or not enc_header.folders:
            raise SzCorruptArchive('Encoded header has no pack info or folders.')
        pack_offset = SIGNATURE_HEADER_SIZE + enc_header.pack_info.pack_pos
        packed_streams: list[memoryview] = []
        offset = pack_offset
        for size in enc_header.pack_info.sizes:
            packed_streams.append(self._view[offset:offset + size])
            offset += size
        folder = enc_header.folders[0]
        unpack_size = folder.main_unpack_size
        header_data = decompress_folder(folder, packed_streams, unpack_size, self._password)
        inner_reader = StructReader(memoryview(header_data))
        inner_prop = inner_reader.u8()
        if inner_prop == PropertyID.HEADER:
            return parse_header(inner_reader)
        elif inner_prop == PropertyID.ENCODED_HEADER:
            return self._decode_encoded_header(inner_reader)
        else:
            raise SzCorruptArchive(F'Unexpected property in decoded header: {inner_prop:#x}')

    def _build_file_list(self):
        assert self._header is not None
        header = self._header
        files = header.files
        folders = header.folders
        substreams = header.substreams
        num_unpack_per_folder: list[int] = []
        if substreams:
            num_unpack_per_folder = substreams.num_unpack_streams
        else:
            num_unpack_per_folder = [1] * len(folders)
        file_idx = 0
        stream_offset = 0
        for fi, folder in enumerate(folders):
            ns = num_unpack_per_folder[fi] if fi < len(num_unpack_per_folder) else 1
            for si in range(ns):
                while file_idx < len(files) and not files[file_idx].has_stream:
                    entry = files[file_idx]
                    self._files.append(SzFile(entry, self, None, None))
                    file_idx += 1
                if file_idx < len(files):
                    entry = files[file_idx]
                    if substreams and (stream_offset + si) < len(substreams.unpack_sizes):
                        entry.size = substreams.unpack_sizes[stream_offset + si]
                    elif ns == 1:
                        entry.size = folder.main_unpack_size
                    if substreams and substreams.crcs:
                        crc_idx = stream_offset + si
                        if crc_idx < len(substreams.crcs) and substreams.crcs[crc_idx] is not None:
                            entry.crc = substreams.crcs[crc_idx]
                        elif ns == 1 and folder.crc is not None:
                            entry.crc = folder.crc
                    elif ns == 1 and folder.crc is not None:
                        entry.crc = folder.crc
                    self._files.append(SzFile(entry, self, fi, si))
                    file_idx += 1
            stream_offset += ns
        while file_idx < len(files):
            entry = files[file_idx]
            self._files.append(SzFile(entry, self, None, None))
            file_idx += 1

    def _decompress_file(
        self,
        folder_index: int,
        stream_index: int,
        password: str | bytes | None = None,
    ) -> bytes:
        if folder_index in self._folder_cache:
            streams = self._folder_cache[folder_index]
            if stream_index < len(streams):
                return streams[stream_index]
        assert self._header is not None
        header = self._header
        folder = header.folders[folder_index]
        for coder in folder.coders:
            if coder.codec_id == CODEC_AES256SHA256:
                if password is None:
                    raise SzPasswordRequired('Password required for encrypted archive.')
                break
        pack_info = header.pack_info
        if pack_info is None:
            raise SzCorruptArchive('No pack info in header.')
        pack_offset = SIGNATURE_HEADER_SIZE + pack_info.pack_pos
        pack_start = 0
        for fi in range(folder_index):
            f = header.folders[fi]
            for _ in range(len(f.packed_indices)):
                if pack_start < len(pack_info.sizes):
                    pack_start += 1
        packed_streams: list[memoryview] = []
        for pi in range(len(folder.packed_indices)):
            idx = pack_start + pi
            if idx < len(pack_info.sizes):
                sz = pack_info.sizes[idx]
                stream_offset = pack_offset
                for k in range(idx):
                    stream_offset += pack_info.sizes[k]
                packed_streams.append(self._view[stream_offset:stream_offset + sz])
            else:
                packed_streams.append(memoryview(b''))
        unpack_size = folder.main_unpack_size
        try:
            raw = decompress_folder(folder, packed_streams, unpack_size, password)
        except SzPasswordRequired:
            raise
        except SzException:
            raise
        except Exception as e:
            if password is not None:
                raise SzInvalidPassword(str(e)) from e
            raise SzCorruptArchive(str(e)) from e
        substreams = header.substreams
        num_unpack: list[int] = []
        if substreams:
            num_unpack = substreams.num_unpack_streams
        else:
            num_unpack = [1] * len(header.folders)
        ns = num_unpack[folder_index] if folder_index < len(num_unpack) else 1
        if ns <= 1:
            self._folder_cache[folder_index] = [memoryview(raw)]
        else:
            stream_offset_global = sum(
                num_unpack[fi] for fi in range(folder_index)
            )
            raw_view = memoryview(raw)
            streams: list[memoryview] = []
            offset = 0
            for si in range(ns):
                if substreams and (stream_offset_global + si) < len(substreams.unpack_sizes):
                    sz = substreams.unpack_sizes[stream_offset_global + si]
                else:
                    sz = len(raw) - offset
                streams.append(raw_view[offset:offset + sz])
                offset += sz
            self._folder_cache[folder_index] = streams
        result = self._folder_cache[folder_index]
        if stream_index < len(result):
            data = result[stream_index]
            entry_crc = self._get_file_crc(folder_index, stream_index)
            if entry_crc is not None:
                computed = zlib.crc32(data) & 0xFFFFFFFF
                if computed != entry_crc:
                    raise SzCorruptArchive(
                        F'CRC mismatch for stream {stream_index} in folder {folder_index}:'
                        F' expected {entry_crc:#010x}, computed {computed:#010x}.')
            return bytes(data)
        raise SzCorruptArchive(
            F'Stream index {stream_index} out of range for folder {folder_index}.')

    def _get_file_crc(self, folder_index: int, stream_index: int) -> int | None:
        for f in self._files:
            if f._folder_index == folder_index and f._stream_index == stream_index:
                return f.crc
        return None
