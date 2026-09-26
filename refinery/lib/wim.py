"""
Parsing of Windows Imaging Format (WIM) files, including the solid variant that is also known as
the ESD format. A `WimArchive` provides the blobs that a WIM file stores, keyed by their SHA-1 hash,
and the metadata blob of each image. The function `walk_image` parses the directory tree from the
metadata of an image. Each `WimDirectoryEntry` lists the streams of a file, which include its
contents, its NTFS alternate data streams, and its reparse data.
"""
from __future__ import annotations

import codecs
import hashlib
import itertools

from datetime import datetime
from enum import IntEnum, IntFlag
from typing import Iterator, NamedTuple

from refinery.lib.dt import filetime
from refinery.lib.fast.xpress import xpress_huffman_decompress
from refinery.lib.lnk.flags import FileAttributeFlags
from refinery.lib.lzms import lzms_decompress
from refinery.lib.seven.lzx import LzxDecoder
from refinery.lib.structures import Struct, StructReader
from refinery.lib.types import buf


class WimVersion(IntEnum):
    DEFAULT = 0x10D00
    SOLID = 0x00E00


class WimCompression(IntEnum):
    NONE = 0
    XPRESS = 1
    LZX = 2
    LZMS = 3


class WimHeaderFlags(IntFlag):
    RESERVED = 0x00000001
    COMPRESSION = 0x00000002
    READONLY = 0x00000004
    SPANNED = 0x00000008
    RESOURCE_ONLY = 0x00000010
    METADATA_ONLY = 0x00000020
    WRITE_IN_PROGRESS = 0x00000040
    RP_FIX = 0x00000080
    COMPRESS_RESERVED = 0x00010000
    COMPRESS_XPRESS = 0x00020000
    COMPRESS_LZX = 0x00040000
    COMPRESS_LZMS = 0x00080000
    COMPRESS_XPRESS_2 = 0x00200000


class WimResourceFlags(IntFlag):
    FREE = 0x01
    METADATA = 0x02
    COMPRESSED = 0x04
    SPANNED = 0x08
    SOLID = 0x10


class WimStreamKind(IntEnum):
    DATA = 0
    REPARSE = 1
    EFS = 2


class WimHashMismatch(ValueError):
    """
    Raised when the data of a blob does not have the SHA-1 hash under which it is stored. The data
    is available as the attribute `data` of the exception.
    """
    def __init__(self, blob: WimBlob, data: buf):
        self.blob = blob
        self.data = data

    def __str__(self):
        return F'The data of the blob {self.blob.hash.hex()} does not match its SHA-1 hash.'


class WimPartMissing(LookupError):
    """
    Raised when the data of a blob is stored in another part of a split WIM.
    """
    def __init__(self, part: int):
        self.part = part

    def __str__(self):
        return F'The data is stored in part {self.part} of the split WIM.'


_WIM_MAGIC = B'MSWIM\0\0\0'
_WIM_HEADER_SIZE = 208
_WIM_DEFAULT_CHUNK_SIZE = 0x8000
_SOLID_RESOURCE_MAGIC = 0x100000000
_DIRECTORY_ENTRY_SIZE = 0x66
_STREAM_ENTRY_SIZE = 0x26
_TABLE_ENTRY_SIZE = 50

_CHUNK_SIZE_LIMITS = {
    WimCompression.XPRESS : (0x1000, 0x10000),
    WimCompression.LZX    : (0x8000, 0x200000),
    WimCompression.LZMS   : (0x8000, 0x40000000),
}


def _align8(value: int) -> int:
    return (value + 7) & ~7


def _check_chunk_size(method: WimCompression, chunk_size: int) -> int:
    if chunk_size <= 0 or chunk_size & (chunk_size - 1):
        raise ValueError(F'The chunk size {chunk_size:#x} is not a power of two.')
    if (limits := _CHUNK_SIZE_LIMITS.get(method)) is not None:
        lower, upper = limits
        if not lower <= chunk_size <= upper:
            raise ValueError(F'The chunk size {chunk_size:#x} is invalid for {method.name}.')
    return chunk_size


def _utf16(data: buf) -> str:
    return codecs.decode(data, 'utf-16le', errors='replace')


class WimResourceHeader(Struct[memoryview]):
    """
    The location of a resource in the WIM file: its offset, the number of bytes it occupies in the
    file, and the number of bytes it holds when decompressed.
    """
    def __init__(self, reader: StructReader[memoryview]):
        self.stored_size = reader.read_integer(56)
        self.flags = WimResourceFlags(reader.u8())
        self.offset = reader.u64()
        self.size = reader.u64()


class WimHeader(Struct[memoryview]):
    def __init__(self, reader: StructReader[memoryview]):
        if (magic := bytes(reader.read_exactly(8))) != _WIM_MAGIC:
            raise ValueError(F'Invalid WIM signature: {magic.hex()}')
        if (header_size := reader.u32()) != _WIM_HEADER_SIZE:
            raise ValueError(F'Unsupported WIM header size {header_size}.')
        version = reader.u32()
        try:
            self.version = WimVersion(version)
        except ValueError:
            raise ValueError(F'Unsupported WIM format version {version:#x}.') from None
        self.flags = flags = WimHeaderFlags(reader.u32())
        chunk_size = reader.u32() or _WIM_DEFAULT_CHUNK_SIZE
        self.guid = reader.read_guid()
        self.part_number = reader.u16()
        self.total_parts = reader.u16()
        self.image_count = reader.u32()
        self.blob_table = WimResourceHeader(reader)
        self.xml_data = WimResourceHeader(reader)
        self.boot_metadata = WimResourceHeader(reader)
        self.boot_index = reader.u32()
        self.integrity_table = WimResourceHeader(reader)
        reader.read_exactly(_WIM_HEADER_SIZE - reader.tell())
        if not 0 < self.part_number <= self.total_parts:
            raise ValueError(F'Invalid WIM part number {self.part_number} of {self.total_parts}.')
        if not flags & WimHeaderFlags.COMPRESSION:
            self.compression = WimCompression.NONE
        elif flags & WimHeaderFlags.COMPRESS_LZX:
            self.compression = WimCompression.LZX
        elif flags & (WimHeaderFlags.COMPRESS_XPRESS | WimHeaderFlags.COMPRESS_XPRESS_2):
            self.compression = WimCompression.XPRESS
        elif flags & WimHeaderFlags.COMPRESS_LZMS:
            self.compression = WimCompression.LZMS
        else:
            raise ValueError('The WIM header sets the compression flag but names no method.')
        self.chunk_size = _check_chunk_size(self.compression, chunk_size)


class _WimChunkDecoder:
    def __init__(self, method: WimCompression, chunk_size: int):
        self.method = method
        self.chunk_size = chunk_size
        self._lzx: LzxDecoder | None = None

    def decode(self, chunk: memoryview, size: int) -> buf:
        if len(chunk) == size:
            return chunk
        if not 0 < len(chunk) < size:
            raise ValueError(F'A chunk of {size} bytes is stored in {len(chunk)} bytes.')
        method = self.method
        if method == WimCompression.XPRESS:
            output = xpress_huffman_decompress(chunk, size)
        elif method == WimCompression.LZX:
            if (lzx := self._lzx) is None:
                lzx = self._lzx = LzxDecoder(wim_mode=True)
                lzx.keep_history_for_next = False
                lzx.set_params_and_alloc(self.chunk_size.bit_length() - 1)
            output = bytearray(lzx.decompress(chunk, size))
        elif method == WimCompression.LZMS:
            output = lzms_decompress(chunk, size)
        else:
            raise ValueError('A chunk is compressed, but the resource names no compression method.')
        if len(output) != size:
            raise ValueError(F'A chunk of {size} bytes decompressed to {len(output)} bytes.')
        return output


class WimResourceLayout(IntEnum):
    """
    The way in which a resource stores its data. A raw resource stores the data as is. The other
    layouts divide the data into chunks of a fixed size that are compressed independently; a chunk
    that would not become smaller is stored as is. In the chunked layout, a table of chunk offsets
    precedes the chunks. A solid resource holds several blobs and begins with a header that states
    its size, chunk size, and compression method, followed by a table of chunk sizes.
    """
    RAW = 0
    CHUNKED = 1
    SOLID = 2


class WimResource:
    """
    A resource in a WIM file; see `WimResourceLayout` for how it stores its data.
    """
    def __init__(
        self,
        view: memoryview,
        header: WimResourceHeader,
        layout: WimResourceLayout,
        size: int,
        method: WimCompression,
        chunk_size: int,
    ):
        self._view = view
        self.offset = header.offset
        self.stored_size = header.stored_size
        self.layout = layout
        self.size = size
        self.method = method
        self.chunk_size = chunk_size
        self._chunk_bounds: list[tuple[int, int]] | None = None
        self._chunks: dict[int, buf] = {}
        self._decoder: _WimChunkDecoder | None = None

    @classmethod
    def Raw(cls, view: memoryview, header: WimResourceHeader):
        if header.stored_size != header.size:
            raise ValueError(
                F'The uncompressed resource at {header.offset:#x} has size {header.size:#x}, but '
                F'occupies {header.stored_size:#x} bytes.'
            )
        return cls(view, header, WimResourceLayout.RAW, header.size, WimCompression.NONE, 0)

    @classmethod
    def Chunked(
        cls,
        view: memoryview,
        header: WimResourceHeader,
        method: WimCompression,
        chunk_size: int,
    ):
        return cls(view, header, WimResourceLayout.CHUNKED, header.size, method, chunk_size)

    @classmethod
    def Solid(cls, view: memoryview, header: WimResourceHeader):
        reader = StructReader(view[header.offset:header.offset + header.stored_size])
        size = reader.u64()
        chunk_size = reader.u32()
        method = reader.u32()
        try:
            method = WimCompression(method)
        except ValueError:
            raise ValueError(
                F'Unknown compression method {method} in the solid resource at {header.offset:#x}.'
            ) from None
        chunk_size = _check_chunk_size(method, chunk_size)
        return cls(view, header, WimResourceLayout.SOLID, size, method, chunk_size)

    def _compute_chunk_bounds(self) -> list[tuple[int, int]]:
        count = -(-self.size // self.chunk_size)
        stored_size = self.stored_size
        if self.layout == WimResourceLayout.SOLID:
            table_start = 16
            entry_size = 4
            entry_count = count
        else:
            table_start = 0
            entry_size = 8 if self.size > 0xFFFFFFFF else 4
            entry_count = count - 1
        table_end = table_start + entry_count * entry_size
        if table_end > stored_size:
            raise ValueError(F'The chunk table of the resource at {self.offset:#x} exceeds it.')
        reader = StructReader(self._view[self.offset + table_start:self.offset + table_end])
        entries = [reader.read_integer(entry_size * 8) for _ in range(entry_count)]
        if self.layout == WimResourceLayout.SOLID:
            starts = [0]
            for size in entries:
                starts.append(starts[-1] + size)
        else:
            starts = [0, *entries, stored_size - table_end]
        base = self.offset + table_end
        return [(base + starts[k], base + starts[k + 1]) for k in range(count)]

    def _chunk(self, index: int) -> buf:
        if (chunk := self._chunks.get(index)) is not None:
            return chunk
        if (bounds := self._chunk_bounds) is None:
            bounds = self._chunk_bounds = self._compute_chunk_bounds()
        if (decoder := self._decoder) is None:
            decoder = self._decoder = _WimChunkDecoder(self.method, self.chunk_size)
        start, end = bounds[index]
        if not self.offset <= start <= end <= min(self.offset + self.stored_size, len(self._view)):
            raise ValueError(F'Chunk {index} of the resource at {self.offset:#x} exceeds it.')
        size = min(self.chunk_size, self.size - index * self.chunk_size)
        chunk = self._chunks[index] = decoder.decode(self._view[start:end], size)
        return chunk

    def read(self, offset: int, size: int) -> buf:
        """
        Read the given range of the decompressed resource. Chunks are decompressed only when a read
        covers them, and each decompressed chunk is kept for later reads.
        """
        if offset < 0 or size < 0 or offset + size > self.size:
            raise ValueError(
                F'Cannot read {size:#x} bytes at offset {offset:#x} from {self.size:#x} bytes.'
            )
        if self.layout == WimResourceLayout.RAW:
            start = self.offset + offset
            if start + size > len(self._view):
                raise ValueError(F'The resource at offset {self.offset:#x} exceeds the file.')
            return self._view[start:start + size]
        if not size:
            return B''
        chunk_size = self.chunk_size
        first = offset // chunk_size
        last = (offset + size - 1) // chunk_size
        skip = offset - first * chunk_size
        if first == last:
            return memoryview(self._chunk(first))[skip:skip + size]
        output = bytearray()
        for index in range(first, last + 1):
            output.extend(self._chunk(index))
        return memoryview(output)[skip:skip + size]


class WimBlob:
    """
    A blob in a WIM file: data that is identified by its SHA-1 hash. The blob is stored in the
    given resource at the given offset, unless it is stored in another part of a split WIM, in
    which case the resource is `None`.
    """
    def __init__(
        self,
        hash: bytes,
        size: int,
        part: int,
        references: int,
        resource: WimResource | None,
        offset: int = 0,
    ):
        self.hash = hash
        self.size = size
        self.part = part
        self.references = references
        self.resource = resource
        self.offset = offset

    def data(self) -> buf:
        """
        Return the data of the blob. Raises `WimHashMismatch` when the data does not match the hash
        of the blob, and `WimPartMissing` when the blob is stored in another part of a split WIM.
        """
        if (resource := self.resource) is None:
            raise WimPartMissing(self.part)
        data = resource.read(self.offset, self.size)
        if hashlib.sha1(data).digest() != self.hash:
            raise WimHashMismatch(self, data)
        return data


class _WimTableEntry(Struct[memoryview]):
    def __init__(self, reader: StructReader[memoryview]):
        self.header = WimResourceHeader(reader)
        self.part = reader.u16()
        self.references = reader.u32()
        self.hash = bytes(reader.read_exactly(20))


class WimArchive:
    """
    Parses the header and the blob table of a WIM file. The attribute `blobs` maps the SHA-1 hash
    of each blob to a `WimBlob`, and the attribute `images` lists the metadata blob of each image.
    """
    def __init__(self, data: buf):
        view = memoryview(data)
        self._view = view
        self.header = header = WimHeader.Parse(view)
        self.blobs: dict[bytes, WimBlob] = {}
        self.images: list[WimBlob] = []
        table_header = header.blob_table
        table = self._resource(table_header).read(0, table_header.size)
        reader = StructReader(memoryview(table))
        entries = [_WimTableEntry(reader) for _ in range(table_header.size // _TABLE_ENTRY_SIZE)]
        for solid, run in itertools.groupby(entries, self._is_solid):
            if solid:
                self._register_solid_run(list(run))
                continue
            for entry in run:
                resource = None
                if entry.part == header.part_number:
                    resource = self._resource(entry.header)
                self._register(entry, entry.header.size, resource)

    def _is_solid(self, entry: _WimTableEntry) -> bool:
        if self.header.version != WimVersion.SOLID:
            return False
        return bool(entry.header.flags & WimResourceFlags.SOLID)

    def _resource(self, header: WimResourceHeader) -> WimResource:
        if not header.flags & WimResourceFlags.COMPRESSED:
            return WimResource.Raw(self._view, header)
        return WimResource.Chunked(
            self._view, header, self.header.compression, self.header.chunk_size
        )

    def _register_solid_run(self, run: list[_WimTableEntry]):
        resources: list[WimResource] = []
        for entry in run:
            if entry.header.size != _SOLID_RESOURCE_MAGIC:
                continue
            if entry.part != self.header.part_number:
                raise ValueError(F'A solid resource is stored in part {entry.part} of a split WIM.')
            resources.append(WimResource.Solid(self._view, entry.header))
        for entry in run:
            if entry.header.size == _SOLID_RESOURCE_MAGIC:
                continue
            offset = entry.header.offset
            size = entry.header.stored_size
            for resource in resources:
                if offset + size <= resource.size:
                    break
                offset -= resource.size
            else:
                raise ValueError(F'The blob {entry.hash.hex()} lies outside of its solid run.')
            self._register(entry, size, resource, offset)

    def _register(
        self,
        entry: _WimTableEntry,
        size: int,
        resource: WimResource | None,
        offset: int = 0,
    ):
        if not any(entry.hash) or not size:
            return
        blob = WimBlob(entry.hash, size, entry.part, entry.references, resource, offset)
        if not entry.header.flags & WimResourceFlags.METADATA:
            self.blobs.setdefault(blob.hash, blob)
            return
        if (
            entry.references
            and entry.part == self.header.part_number == 1
            and len(self.images) < self.header.image_count
        ):
            self.images.append(blob)


class WimStream(NamedTuple):
    """
    A stream of a file in a WIM image. The name is empty for the unnamed stream, and the hash is
    all zeros for a stream without data.
    """
    name: str
    kind: WimStreamKind
    hash: bytes


def _assign_stream_kinds(
    attributes: FileAttributeFlags,
    streams: list[tuple[str, bytes]],
) -> list[WimStream]:
    if attributes & FileAttributeFlags.Encrypted:
        for name, digest in streams:
            if not name and any(digest):
                return [WimStream(name, WimStreamKind.EFS, digest)]
        return []
    is_reparse_point = bool(attributes & FileAttributeFlags.ReparsePoint)
    assigned: list[WimStream] = []
    found_reparse = found_data = False
    for index, (name, digest) in enumerate(streams):
        if name:
            assigned.append(WimStream(name, WimStreamKind.DATA, digest))
        elif index or any(digest):
            if is_reparse_point and not found_reparse:
                found_reparse = True
                assigned.append(WimStream(name, WimStreamKind.REPARSE, digest))
            elif not found_data:
                found_data = True
                assigned.append(WimStream(name, WimStreamKind.DATA, digest))
    if not found_reparse and not found_data:
        name, digest = streams[0]
        kind = WimStreamKind.REPARSE if is_reparse_point else WimStreamKind.DATA
        assigned.insert(0, WimStream(name, kind, digest))
    return assigned


class _WimStreamEntry(Struct[memoryview]):
    def __init__(self, reader: StructReader[memoryview]):
        start = reader.tell()
        length = _align8(reader.u64())
        if not _STREAM_ENTRY_SIZE <= length <= len(reader.getbuffer()) - start:
            raise ValueError(F'Invalid length {length:#x} of the stream entry at {start:#x}.')
        reader.u64()
        self.hash = bytes(reader.read_exactly(20))
        name_size = reader.u16()
        if name_size & 1 or _STREAM_ENTRY_SIZE + name_size > length:
            raise ValueError(F'Invalid name length {name_size:#x} of the stream entry at {start:#x}.')
        self.name = _utf16(reader.read_exactly(name_size))
        reader.seekset(start + length)


class WimDirectoryEntry(Struct[memoryview]):
    """
    An entry in the directory tree of a WIM image. The attribute `path` holds the names of all
    entries below the root of the image down to this one; the parent path is `None` for the root,
    whose path is empty. The streams of the entry are listed in `streams`.
    """
    def __init__(self, reader: StructReader[memoryview], parent: tuple[str, ...] | None):
        start = reader.tell()
        length = _align8(reader.u64())
        if not _DIRECTORY_ENTRY_SIZE <= length <= len(reader.getbuffer()) - start:
            raise ValueError(F'Invalid length {length:#x} of the directory entry at {start:#x}.')
        self.attributes = attributes = FileAttributeFlags(reader.u32())
        self.security_id = reader.i32()
        self.child_list = reader.u64()
        reader.seekrel(16)
        self.creation_time: datetime | None = filetime(reader.u64())
        self.access_time: datetime | None = filetime(reader.u64())
        self.write_time: datetime | None = filetime(reader.u64())
        main_hash = bytes(reader.read_exactly(20))
        reader.u32()
        self.reparse_tag: int | None = None
        self.hard_link_group = 0
        if attributes & FileAttributeFlags.ReparsePoint:
            self.reparse_tag = reader.u32()
            reader.u32()
        else:
            self.hard_link_group = reader.u64()
        stream_count = reader.u16()
        short_name_size = reader.u16()
        name_size = reader.u16()
        if (short_name_size | name_size) & 1:
            raise ValueError(F'Invalid name length for the directory entry at offset {start:#x}.')
        required = _DIRECTORY_ENTRY_SIZE
        if name_size:
            required += name_size + 2
        if short_name_size:
            required += short_name_size + 2
        if required > length:
            raise ValueError(F'The names of the directory entry at {start:#x} exceed it.')
        self.name = _utf16(reader.read_exactly(name_size))
        if name_size:
            reader.seekrel(2)
        self.short_name = _utf16(reader.read_exactly(short_name_size))
        reader.seekset(start + length)
        extra = [_WimStreamEntry(reader) for _ in range(stream_count)]
        streams = [('', main_hash), *((stream.name, stream.hash) for stream in extra)]
        self.streams = _assign_stream_kinds(attributes, streams)
        self.path: tuple[str, ...] = () if parent is None else (*parent, self.name)

    @property
    def is_directory(self) -> bool:
        return bool(self.attributes & FileAttributeFlags.Directory)

    @property
    def has_valid_name(self) -> bool:
        name = self.name
        return bool(name) and name not in ('.', '..') and '\0' not in name


def _read_entry(
    reader: StructReader[memoryview],
    offset: int,
    parent: tuple[str, ...] | None,
) -> WimDirectoryEntry | None:
    if offset + 8 > len(reader.getbuffer()):
        raise ValueError(F'The directory entry at offset {offset:#x} exceeds the metadata.')
    reader.seekset(offset)
    if _align8(reader.u64(peek=True)) <= 8:
        return None
    return WimDirectoryEntry(reader, parent)


def walk_image(metadata: buf) -> Iterator[WimDirectoryEntry]:
    """
    Parse the directory tree from the metadata of a WIM image and generate its entries in
    depth-first order, starting with the root. Entries that have no name, are named `.` or `..`,
    or whose name contains a null character are skipped with their subtree. The children of an
    entry that is not a directory are ignored. A directory tree in which two directories share
    the same list of children is rejected.
    """
    reader = StructReader(memoryview(metadata))
    security_size = _align8(reader.u32()) or 8
    root = _read_entry(reader, security_size, None)
    if root is None:
        return
    if not root.is_directory:
        raise ValueError('The root of the WIM image is not a directory.')
    yield root
    visited: set[int] = set()
    pending: list[tuple[int, tuple[str, ...]]] = []

    def descend(entry: WimDirectoryEntry):
        if not entry.is_directory or not (offset := entry.child_list):
            return
        if offset in visited:
            raise ValueError(F'The directory tree lists the children at offset {offset:#x} twice.')
        visited.add(offset)
        pending.append((offset, entry.path))

    descend(root)
    while pending:
        offset, parent = pending.pop()
        if (entry := _read_entry(reader, offset, parent)) is None:
            continue
        pending.append((reader.tell(), parent))
        if not entry.has_valid_name:
            continue
        yield entry
        descend(entry)
