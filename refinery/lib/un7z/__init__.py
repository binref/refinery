"""
Pure-Python 7z archive parser and extractor.
"""
from __future__ import annotations

import itertools
import weakref
import zlib

from datetime import datetime
from typing import TYPE_CHECKING, Callable, Iterator

from refinery.lib.solid import SolidStream, SolidStreamTruncated
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
    SzChecksumMismatch,
    SzCorruptArchive,
    SzException,
    SzInvalidPassword,
    SzPasswordRequired,
    SzUnsupportedMethod,
    parse_encoded_header,
    parse_header,
    parse_signature_header,
)

if TYPE_CHECKING:
    from refinery.lib.types import buf

__all__ = [
    'SIGNATURE',
    'SIGNATURE_HEADER_SIZE',
    'SzArchive',
    'SzChecksumMismatch',
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
        offset: int = 0,
    ):
        self._entry = entry
        self._archive = archive
        self._folder_index = folder_index
        self._stream_index = stream_index
        self._offset = offset

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

    @property
    def encrypted(self) -> bool:
        return (fi := self._folder_index) is not None and self._archive._folder_encrypted(fi)

    def extractor(self, password: str | bytes | None = None) -> Callable[[], buf]:
        """
        Return a function that returns the data of this file. The data is decompressed with the
        rest of its folder when the function is first called; the folder keeps the data of other
        files only while a function returned for them is alive.
        """
        if self.is_dir or (fi := self._folder_index) is None:
            return bytes
        archive = self._archive
        pw = password or archive._password
        claim = archive._folder_stream(fi, pw).claim(self._offset, self.size)
        crc = self.crc

        def extract():
            try:
                data = claim()
            except SolidStreamTruncated as truncated:
                data = truncated.partial
            if crc is not None and (computed := zlib.crc32(data) & 0xFFFFFFFF) != crc:
                raise SzChecksumMismatch(
                    F'CRC mismatch for stream {self._stream_index} in folder {fi}:'
                    F' expected {crc:#010x}, computed {computed:#010x}.', data)
            return data

        return extract

    def decompress(self, password: str | bytes | None = None) -> buf:
        return self.extractor(password)()


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
        self._folder_streams: weakref.WeakValueDictionary[tuple[int, str | bytes | None], SolidStream]
        self._folder_streams = weakref.WeakValueDictionary()
        self._packed: list[list[memoryview]] | None = None
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
        header_data = decompress_folder(folder, packed_streams, self._password)
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
            position = 0
            for si in range(ns):
                while file_idx < len(files) and not files[file_idx].has_stream:
                    entry = files[file_idx]
                    self._files.append(SzFile(entry, self, None, None))
                    file_idx += 1
                if file_idx < len(files):
                    entry = files[file_idx]
                    stream = stream_offset + si
                    if substreams and stream < len(substreams.unpack_sizes):
                        entry.size = substreams.unpack_sizes[stream]
                    elif ns == 1:
                        entry.size = folder.main_unpack_size
                    if substreams and stream < len(substreams.crcs):
                        entry.crc = substreams.crcs[stream]
                    elif ns == 1:
                        entry.crc = folder.crc
                    self._files.append(SzFile(entry, self, fi, si, position))
                    position += entry.size
                    file_idx += 1
            stream_offset += ns
        while file_idx < len(files):
            entry = files[file_idx]
            self._files.append(SzFile(entry, self, None, None))
            file_idx += 1

    def _folder_stream(self, folder_index: int, password: str | bytes | None) -> SolidStream:
        key = folder_index, password
        if (stream := self._folder_streams.get(key)) is None:
            def pieces(offset: int) -> Iterator[tuple[int, buf]]:
                yield 0, self._decompress_folder(folder_index, password)
            stream = self._folder_streams[key] = SolidStream(pieces)
        return stream

    def _packed_streams(self, folder_index: int) -> list[memoryview]:
        """
        The packed streams of the given folder. The folders take the packed streams of the archive
        in order, and the table of the streams of every folder is computed once.
        """
        if (table := self._packed) is None:
            assert (header := self._header) is not None
            if (pack_info := header.pack_info) is None:
                raise SzCorruptArchive('No pack info in header.')
            sizes = pack_info.sizes
            offsets = list(itertools.accumulate(sizes, initial=SIGNATURE_HEADER_SIZE + pack_info.pack_pos))
            table = []
            start = 0
            for folder in header.folders:
                streams = []
                for index in range(start, start + len(folder.packed_indices)):
                    if index < len(sizes):
                        streams.append(self._view[offsets[index]:offsets[index] + sizes[index]])
                    else:
                        streams.append(memoryview(b''))
                table.append(streams)
                start = min(start + len(folder.packed_indices), len(sizes))
            self._packed = table
        return table[folder_index]

    def _folder_encrypted(self, folder_index: int) -> bool:
        assert self._header is not None
        return any(coder.codec_id == CODEC_AES256SHA256 for coder in self._header.folders[folder_index].coders)

    def _decompress_folder(
        self,
        folder_index: int,
        password: str | bytes | None = None,
    ) -> buf:
        assert self._header is not None
        header = self._header
        folder = header.folders[folder_index]
        if password is None and self._folder_encrypted(folder_index):
            raise SzPasswordRequired('Password required for encrypted archive.')
        packed_streams = self._packed_streams(folder_index)
        try:
            raw = decompress_folder(folder, packed_streams, password)
        except SzPasswordRequired:
            raise
        except SzException:
            raise
        except Exception as e:
            if password is not None:
                raise SzInvalidPassword(str(e)) from e
            raise SzCorruptArchive(str(e)) from e
        return raw
