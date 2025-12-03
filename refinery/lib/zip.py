"""
Structures for parsing ZIP archives.
"""
from __future__ import annotations

from refinery.lib.id import buffer_offset
from refinery.lib.structures import Struct, StructReader
from refinery.lib.intervals import IntIntervalUnion
from refinery.lib.types import buf
from refinery.units.misc.datefix import datefix


class ZipDataDescriptor(Struct):
    Signature = B'PK\x07\x08'

    def __init__(self, reader: StructReader[memoryview], is64bit: bool = False):
        if reader.read(4) != self.Signature:
            raise ValueError
        self.crc32 = reader.u32()
        size = reader.u64 if is64bit else reader.u32
        self.csize = size()
        self.usize = size()
        if self.usize == 0 and self.csize != 0 and not is64bit:
            # This is likely a 64-bit descriptor despite what we thought.
            self.usize = reader.u64()


class ZipFileRecord(Struct):
    Signature = B'PK\x03\x04'

    def __init__(
        self,
        reader: StructReader[memoryview],
        is64bit: bool = False,
        read_data: bool = True,
        streamed: bool = True,
    ):
        if reader.read(4) != self.Signature:
            raise ValueError
        self.version = reader.u16()
        self.flags = reader.u16()
        self.method = reader.u16()
        self.mtime = reader.u16()
        self.mdate = reader.u16()
        self.crc32 = reader.u32()
        self.csize = reader.u32()
        self.usize = reader.u32()
        nl = reader.u16()
        xl = reader.u16()
        self.name = reader.read_exactly(nl)
        self.xtra = ZipExtraField.ParseBuffer(reader.read_exactly(xl))

        for x in self.xtra:
            if x.header_id == ZipExtendedInfo64.HeaderID:
                z64 = ZipExtendedInfo64.Parse(x.data, self.usize, self.csize)
                self.usize = z64.usize
                self.csize = z64.csize
                is64bit = True
                break

        self.data_offset = start = reader.tell()

        if not read_data:
            self.data = None
            return
        else:
            self.data = reader.read_exactly(self.csize)

        if not streamed:
            return

        while not self.csize:
            if (ddpos := buffer_offset(reader.getbuffer(), ZipDataDescriptor.Signature, start)) < 0:
                break
            csize = ddpos - self.data_offset
            self.data = reader.read_exactly(csize)
            info = ZipDataDescriptor(reader, is64bit)
            if info.csize == csize:
                self.crc32 = info.crc32
                self.csize = info.csize
                self.usize = info.usize
            else:
                reader.seekset(self.data_offset)
                start += len(ZipDataDescriptor.Signature)


class ZipEndOfCentralDirectory(Struct):
    Signature = B'PK\x05\x06'

    def __init__(self, reader: StructReader[memoryview]):
        if reader.read(4) != self.Signature:
            raise ValueError
        self.disk_number = reader.u16()
        self.start_disk_number = reader.u16()
        self.entries_on_disk = reader.u16()
        self.entries_in_directory = reader.u16()
        self.directory_size = reader.u32()
        self.directory_offset = reader.u32()
        self.comment_length = reader.u16()


class ZipEocdLocator64(Struct):
    Signature = B'PK\x06\x07'

    def __init__(self, reader: StructReader[memoryview]):
        if reader.read(4) != self.Signature:
            raise ValueError
        self.disk_with_eocd64 = reader.u32()
        self.offset = reader.u64()
        self.total_disks = reader.u32()


class ZipEndOfCentralDirectory64(Struct):
    Signature = B'PK\x06\x06'

    def __init__(self, reader: StructReader[memoryview]):
        if reader.read(4) != self.Signature:
            raise ValueError
        self.eocd64_size = reader.u64()
        self.version_made_by = reader.u16()
        self.version_to_extract = reader.u16()
        self.disk_number = reader.u32()
        self.start_disk_number = reader.u32()
        self.entries_on_disk = reader.u64()
        self.entries_in_directory = reader.u64()
        self.directory_size = reader.u64()
        self.directory_offset = reader.u64()
        self.locator = ZipEocdLocator64(reader)
        self.eocd32 = ZipEndOfCentralDirectory(reader)


class ZipExtraField(Struct):
    def __init__(self, reader: StructReader[memoryview]):
        self.header_id = reader.u16()
        self.data_size = reader.u16()
        self.data = reader.read_exactly(self.data_size)

    @classmethod
    def ParseBuffer(cls, data: buf | None) -> list[ZipExtraField]:
        if data is None:
            return []
        reader = StructReader(memoryview(data))
        extras = []
        while not reader.eof:
            extras.append(cls(reader))
        return extras


class ZipExtendedInfo64(Struct):
    HeaderID = 0x0001

    def __init__(
        self,
        reader: StructReader[memoryview],
        usize: int,
        csize: int,
        header_offset: int = 0,
        disk_nr_start: int = 0,
    ):
        self.usize = usize
        self.csize = csize
        self.header_offset = header_offset
        self.disk_nr_start = disk_nr_start

        if usize == 0xFFFFFFFF:
            self.usize = reader.u64()
        if csize == 0xFFFFFFFF:
            self.csize = reader.u64()
        if header_offset == 0xFFFFFFFF:
            self.header_offset = reader.u64()
        if disk_nr_start == 0xFFFF:
            self.disk_nr_start = reader.u32()


class ZipCentralDirectoryEntry(Struct):
    Signature = B'PK\x01\x02'

    def __init__(self, reader: StructReader[memoryview]):
        if reader.read(4) != self.Signature:
            raise ValueError
        self.version_made_by = reader.u16()
        self.version_to_extract = reader.u16()
        self.flags = reader.u16()
        self.compression = reader.u16()
        try:
            self.date = datefix.dostime(reader.u32(peek=True))
        except Exception:
            self.date = None
        self.mtime = reader.u16()
        self.mdate = reader.u16()
        self.crc32 = reader.u32()
        self.csize = reader.u32()
        self.usize = reader.u32()
        len_filename = reader.u16()
        len_extra = reader.u16()
        len_comment = reader.u16()
        self.disk_nr_start = reader.u16()
        self.internal_attributes = reader.u16()
        self.external_attributes = reader.u32()
        self.header_offset = reader.u32()
        self.filename = len_filename and reader.read(len_filename) or None
        extras = len_extra and reader.read(len_extra) or None
        self.comment = len_comment and reader.read(len_comment) or None
        self.extras = ZipExtraField.ParseBuffer(extras)

        for extra in self.extras:
            if extra.header_id == ZipExtendedInfo64.HeaderID:
                z64 = ZipExtendedInfo64.Parse(
                    extra.data,
                    self.usize,
                    self.csize,
                    self.header_offset,
                    self.disk_nr_start,
                )
                self.usize = z64.usize
                self.csize = z64.csize
                self.header_offset = z64.header_offset
                self.disk_nr_start = z64.disk_nr_start
                break


class Zip:
    def __init__(self, data: buf):
        reader = StructReader(view := memoryview(data))
        self.is64bit = True
        self.coverage = coverage = IntIntervalUnion()

        for EOCD in (
            ZipEndOfCentralDirectory64,
            ZipEndOfCentralDirectory,
        ):
            if (end := buffer_offset(view, EOCD.Signature, back2front=True)) >= 0:
                reader.seekset(end)
                self.offset_eocd = end
                self.eocd = eocd = EOCD(reader)
                coverage.addi(end, len(eocd))
                break
            else:
                self.is64bit = False
        else:
            raise ValueError('No EOCD.')

        start = eocd.directory_offset
        shift = 0 if self.is64bit else (
            end - eocd.directory_size - eocd.directory_offset)
        if shift:
            start = end - eocd.directory_size
        if start < 0:
            raise ValueError('Invalid end of central directory size')
        self.offset_directory = start
        reader.seekset(start)
        records: dict[int, ZipFileRecord] = {}
        unreferenced_records: dict[int, ZipFileRecord] = {}
        self.records = records
        self.unreferenced_records = unreferenced_records
        self.directory = [
            ZipCentralDirectoryEntry(reader) for _ in range(eocd.entries_in_directory)
        ]
        coverage.addi(start, sum(len(d) for d in self.directory))
        streamed = buffer_offset(view, ZipDataDescriptor.Signature) > 0
        for entry in self.directory:
            start = entry.header_offset + shift
            reader.seekset(start)
            records[start] = r = ZipFileRecord(reader, streamed=streamed, is64bit=self.is64bit)
            coverage.addi(start, len(r))

        for start, end in list(coverage.gaps(0, len(view))):
            gap = view[start:end]
            while gap[:4] == ZipFileRecord.Signature:
                reader.seekset(start)
                try:
                    r = ZipFileRecord(reader, read_data=False)
                    n = len(r)
                except Exception:
                    break
                if gap[n:n + 4] != ZipFileRecord.Signature and len(gap) >= n + r.csize:
                    reader.seekset(start)
                    try:
                        r = ZipFileRecord(
                            reader, streamed=streamed, is64bit=self.is64bit)
                    except Exception:
                        pass
                    else:
                        n = len(r)
                gap = gap[n:]
                coverage.addi(start, n)
                start += n
                unreferenced_records[start] = r
