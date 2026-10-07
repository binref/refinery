"""
Parsing of CAB archives.
"""
from __future__ import annotations

import weakref
import zlib

from datetime import date, datetime, time
from enum import IntEnum, IntFlag
from typing import TYPE_CHECKING, Callable, Iterable, Iterator, NamedTuple

from refinery.lib.fast.cab import cab_data_checksum
from refinery.lib.seven.lzx import LzxDecoder
from refinery.lib.seven.quantum import QuantumDecoder
from refinery.lib.solid import SolidStream, SolidStreamTruncated
from refinery.lib.structures import Struct, StructReader

if TYPE_CHECKING:
    from refinery.lib.types import buf


class CabVolumeMissing(LookupError):
    def __init__(self, idx: int = -1, ref: CabRef | None = None):
        self.idx = idx
        self.ref = ref

    def __str__(self):
        if self.ref is not None:
            name = str(self.ref)
        else:
            name = F'Disk {self.idx}'
        return F'Missing CAB volume: {name}'


class CabSequenceMismatch(ValueError):
    def __init__(self, index: int, prev: CabRef | None, next: CabRef | None):
        self.index = index
        self.prev = prev
        self.next = next

    def __str__(self):
        k = self.index
        return (
            F'CAB disk sequence mismatch at {k}. Disk {k - 1} expected {self.next!s} as the next '
            F'one, but disk {k + 1} expected {self.prev!s} as its predecessor.')


class CabVolumeCorrupt(ValueError):
    pass


class CabFlags(IntFlag):
    HasPrev = 1
    HasNext = 2
    Reserve = 4


class CabMethod(IntEnum):
    Nothing = 0
    Deflate = 1
    Quantum = 2
    LZX = 3


class CabAttr(IntFlag):
    ReadOnly = 0x01
    Hidden = 0x02
    System = 0x04
    Arch = 0x20
    Exec = 0x40
    NameUTF8 = 0x80


class NFolderIndex(IntFlag):
    HasPrev = 0xFFFD
    HasNext = 0xFFFE
    HasBoth = 0xFFFF


class CabFolder(Struct):

    def __init__(self, reader: StructReader[memoryview], parent: CabDisk, compute_checksums: bool, no_magic: bool):
        start = reader.u32()
        count = reader.u16()
        if no_magic:
            start -= 4
        self.method = (reader.u8(), reader.u8())
        self.compression = CabMethod(self.method[0] & 0xF)
        reader.seekrel(parent.skip_per_fldr)
        with reader.detour(start):
            self.blocks = [CabCompressedBlock(reader, parent) for _ in range(count)]
        self.verify_checksums = compute_checksums
        self._stream: weakref.ref[SolidStream] | None = None

    def __repr__(self):
        return F'<fldr:{self.compression.name}({self.method[1]}):{len(self.blocks)}>'

    def iter_block_data(self):
        """
        Generate the decompressed size and the compressed data of every block, where a block that
        continues on the next disk is merged with its remainder. A block whose data does not match
        its checksum raises `refinery.lib.cab.CabVolumeCorrupt` when it is reached.
        """
        it = enumerate(self.blocks)
        for k, block in it:
            self._verify(k, block)
            if size := block.decompressed_size:
                yield size, block.data
                continue
            merged = bytearray(block.data)
            while not size:
                try:
                    k, tail = next(it)
                except StopIteration as E:
                    raise EOFError from E
                self._verify(k, tail)
                merged.extend(tail.data)
                size = tail.decompressed_size
            yield size, memoryview(merged)

    def _verify(self, index: int, block: CabCompressedBlock):
        if self.verify_checksums and not block.intact:
            raise CabVolumeCorrupt(
                F'Data block {index} of the folder fails its checksum; provided value was '
                F'{block.provided_checksum:08X}, computed value {block.computed_checksum:08X}.')

    def stream(self) -> SolidStream:
        """
        The decompressed folder as a stream from which the files in it are read. The folder keeps
        the stream only while a claim on it is alive.
        """
        if (ref := self._stream) is None or (stream := ref()) is None:
            volatile = self.compression in (CabMethod.LZX, CabMethod.Quantum)
            stream = SolidStream(self._pieces, volatile=volatile)
            self._stream = weakref.ref(stream)
        return stream

    def _pieces(self, origin: int) -> Iterator[tuple[int, buf]]:
        cm = self.compression
        pos = 0
        if cm == CabMethod.Nothing:
            for _, data in self.iter_block_data():
                yield pos, data
                pos += len(data)
            return
        if cm == CabMethod.Deflate:
            zdict = B''

            def decompress(data: memoryview, size: int, k: int) -> buf:
                nonlocal zdict
                if data[:2] != B'CK':
                    raise ValueError('Corrupted MSZip block with invalid header.')
                try:
                    inflate = zlib.decompressobj(-zlib.MAX_WBITS, zdict)
                    zdict = inflate.decompress(data[2:]) + inflate.flush()
                except zlib.error:
                    raise RuntimeError('Failed to inflate CAB data block.')
                return zdict
        elif cm == CabMethod.LZX:
            lzx = LzxDecoder(False)
            lzx.set_params_and_alloc(self.method[1])

            def decompress(data: memoryview, size: int, k: int) -> buf:
                lzx.keep_history = k > 0
                return lzx.decompress(data, size)
        elif cm == CabMethod.Quantum:
            qd = QuantumDecoder(self.method[1] & 0x1F)

            def decompress(data: memoryview, size: int, k: int) -> buf:
                return qd.decompress(data, size, keep_history=k > 0)
        else:
            raise ValueError(F'Unknown decompression method: {cm!r}')
        for k, (size, data) in enumerate(self.iter_block_data()):
            out = decompress(data, size, k)
            if len(out) != size:
                raise RuntimeError(
                    F'Data block {k} of the folder decompressed to {len(out)} bytes, but its header '
                    F'states {size} bytes.'
                )
            yield pos, out
            pos += len(out)


class CabFile(Struct):

    folder: CabFolder | None

    def __init__(self, reader: StructReader[memoryview]):
        self.size = reader.u32()
        self.offset = reader.u32()
        self._index = reader.u16()
        self.folder = None
        self.end = self.offset + self.size
        d = reader.u16()
        t = reader.u16()
        s = (t & 0x1F) << 1

        try:
            self.date = d = date(
                ((d & 0xFE00) >> 0x9) + 1980,
                ((d & 0x01E0) >> 0x5),
                ((d & 0x001F) >> 0x0),
            )
        except Exception:
            self.date = d = None

        try:
            self.time = t = time(
                ((t & 0xF800) >> 0xB),
                ((t & 0x07E0) >> 0x5),
                59 if s == 60 else s,
            )
        except Exception:
            self.time = t = None

        self.timestamp = datetime.combine(d, t) if d and t else None
        self.attributes = CabAttr(reader.u16())
        self.name = reader.read_c_string(self.codec)

    def __repr__(self):
        index = {
            NFolderIndex.HasPrev.value: 'PP',
            NFolderIndex.HasNext.value: 'NN',
            NFolderIndex.HasBoth.value: 'PN',
        }.get(self._index, F'{self._index:02d}')
        d = d.isoformat() if (d := self.date) else '????-??-??'
        t = t.isoformat('seconds') if (t := self.time) else '??:??:??'
        return F'<file:{index}:{d}T{t}:{self.name}>'

    def extractor(self) -> Callable[[], buf]:
        """
        Return a function that returns the data of this file. The folder is decompressed when the
        function is first called; it keeps the data of other files only while the functions returned
        for them are alive.
        """
        if (folder := self.folder) is None:
            return self._missing_folder
        claim = folder.stream().claim(self.offset, self.size)

        def extract() -> buf:
            try:
                return claim()
            except SolidStreamTruncated:
                raise RuntimeError(
                    F'The extracted file does not have the correct size: {self!r}'
                ) from None

        return extract

    def decompress(self) -> buf:
        return self.extractor()()

    def _missing_folder(self) -> buf:
        raise RuntimeError(F'CAB file entry is missing a link to its folder: {self!r}')

    @property
    def codec(self):
        return 'utf8' if self.attributes & CabAttr.NameUTF8 else 'latin1'

    def has_prev(self):
        return self._index in (NFolderIndex.HasPrev, NFolderIndex.HasBoth)

    def has_next(self):
        return self._index in (NFolderIndex.HasNext, NFolderIndex.HasBoth)

    @property
    def index(self):
        if self.has_prev():
            return +0
        if self.has_next():
            return ~0
        else:
            return self._index


class CabCompressedBlock(Struct):

    def __init__(self, reader: StructReader[memoryview], parent: CabDisk):
        self.provided_checksum = reader.u32()
        self._seed = reader.u32(peek=True)
        size = reader.u16()
        self.decompressed_size = reader.u16()
        reader.seekrel(parent.skip_per_data)
        self.data = reader.read_exactly(size)

    @property
    def computed_checksum(self) -> int:
        return cab_data_checksum(self.data, self._seed)

    @property
    def intact(self) -> bool:
        """
        Whether the data matches the checksum of the block; a block with checksum zero has none.
        """
        return not (provided := self.provided_checksum) or provided == self.computed_checksum

    def __repr__(self):
        checksum = 'OK' if self.intact else '!!'
        return F'<block:{len(self.data):04X}->{self.decompressed_size:04X}:{checksum}>'


class CabRef(NamedTuple):
    name: str
    disk: str

    def __str__(self):
        return F'{self.disk} ({self.name})'


class CabDisk(Struct):
    MAGIC = B'MSCF'

    def __init__(self, reader: StructReader[memoryview], compute_checksums: bool, no_magic: bool):
        if no_magic:
            self.signature = self.MAGIC
        else:
            self.signature = reader.read(4)

        self._reserved = []
        self._reserved.append(reader.u32())
        self.size = reader.u32()
        self._reserved.append(reader.u32())
        self.file_offset = reader.u32()
        if no_magic:
            self.file_offset -= 4
        self._reserved.append(reader.u32())

        self.version = (reader.u8(), reader.u8())
        self.nr_of_folders = reader.u16()
        self.nr_of_files = reader.u16()
        self.flags = CabFlags(reader.u16())
        self.id = reader.u16()
        self.index = reader.u16()

        (
            self.skip_per_disk,
            self.skip_per_fldr,
            self.skip_per_data,
        ) = (reader.u16(), reader.u8(), reader.u8()) if (
            self.flags & CabFlags.Reserve
        ) else (0, 0, 0)

        reader.seekrel(self.skip_per_disk)

        self.prev = CabRef(
            reader.read_c_string('ascii'),
            reader.read_c_string('ascii'),
        ) if self.flags & CabFlags.HasPrev else None

        self.next = CabRef(
            reader.read_c_string('ascii'),
            reader.read_c_string('ascii'),
        ) if self.flags & CabFlags.HasNext else None

        self.folders = [
            CabFolder(reader, self, compute_checksums, no_magic) for _ in range(self.nr_of_folders)]

        reader.seekset(self.file_offset)
        self.files = [CabFile(reader) for _ in range(self.nr_of_files)]

        self._reader = reader
        self._arcpos = reader.tell()

    def check(self):
        if self.signature != self.MAGIC:
            raise ValueError(F'Invalid signature: {self.signature.hex()}')
        if self.flags.value > 7:
            raise ValueError(F'Invalid flags: {self.flags.value}.')
        if any(self._reserved):
            raise ValueError('Reserved field was nonzero.')
        if self.size < 36:
            raise ValueError(F'Archive header specifies invalid size of {self.size} bytes.')
        return self


class Cabinet:
    files: dict[int, list[CabFile]]
    disks: dict[int, list[CabDisk]]

    def __init__(self, *disks: memoryview, compute_checksums: bool = True, no_magic: bool = False):
        self.disks = {}
        self.files = {}
        self.compute_checksums = compute_checksums
        self.no_magic = no_magic
        self.extend(disks)

    def get_files(self, id: int | None = None):
        if id is None:
            if len(self.files) != 1:
                raise LookupError
            return next(iter(self.files.values()))
        else:
            return self.files[id]

    def __bool__(self):
        return bool(self.disks)

    def __len__(self):
        return sum(len(disks) for disks in self.disks.values())

    def extend(self, disks: Iterable[memoryview]):
        for d in disks:
            disk = CabDisk.Parse(memoryview(d), self.compute_checksums, self.no_magic)
            byid = self.disks.setdefault(disk.id, [])
            byid.append(disk)
        for byid in self.disks.values():
            byid.sort(key=lambda c: c.index)

    def append(self, *disks: memoryview):
        self.extend(disks)

    def process(self):
        for id, disks in self.disks.items():
            files = self.files[id] = []
            partial: CabFolder | None = None
            folders: list[CabFolder] = []
            for disk in disks:
                folders.clear()
                for folder in disk.folders:
                    if partial is None:
                        folders.append(folder)
                        continue
                    if partial.method != folder.method:
                        raise ValueError('Mismatching methods for continued folder.')
                    if folder.blocks:
                        partial.blocks.extend(folder.blocks)
                        folder.blocks.clear()
                    folders.append(partial)
                    partial = None
                for file in disk.files:
                    file.folder = folders[file.index]
                    if file.has_next():
                        partial = file.folder
                    else:
                        files.append(file)
        return self

    def needs_more_disks(self):
        if not self.disks:
            return True
        try:
            self.check()
        except CabVolumeMissing:
            return True
        else:
            return False

    def check(self):
        """
        Check that every disk of every cabinet is present and that the disks are in sequence. The
        checksums of data blocks are verified when the blocks are decompressed.
        """
        for disks in self.disks.values():
            for k, disk in enumerate(disks):
                if disk.index != k:
                    raise CabVolumeMissing(idx=k)
            prev_list = [disk.prev for disk in disks]
            next_list = [disk.next for disk in disks]
            if prev := prev_list[+0]:
                raise CabVolumeMissing(ref=prev)
            if next := next_list[~0]:
                raise CabVolumeMissing(ref=next)
            for k, (prev, next) in enumerate(zip(prev_list[2:], next_list[:-2]), 2):
                if prev != next:
                    raise CabSequenceMismatch(k, prev, next)
