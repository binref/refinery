"""
Structures for parsing ZIP archives.
"""
from __future__ import annotations

from refinery.lib.id import buffer_offset
from refinery.lib.structures import Struct, StructReader
from refinery.lib.types import buf
from refinery.units.misc.datefix import datefix


class ZipDataDescriptor(Struct):
    Signature = B'PK\x07\x08'

    def __init__(self, reader: StructReader[memoryview]):
        if reader.read(4) != self.Signature:
            raise ValueError
        self.crc32 = reader.u32()
        self.csize = reader.u32()
        self.usize = reader.u32()


class ZipFileRecord(Struct):
    Signature = B'PK\x03\x04'

    def __init__(self, reader: StructReader[memoryview]):
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
        self.xtra = reader.read_exactly(xl)
        self.data_offset = start = reader.tell()
        self.data = reader.read_exactly(self.csize)

        while not self.csize:
            if (ddpos := buffer_offset(reader.getbuffer(), ZipDataDescriptor.Signature, start)) < 0:
                break
            csize = ddpos - self.data_offset
            self.data = reader.read_exactly(csize)
            info = ZipDataDescriptor(reader)
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


class ZipCentralDirectory(Struct):
    Signature = B'PK\x01\x02'

    def __init__(self, reader: StructReader[memoryview]):
        if reader.read(4) != self.Signature:
            raise ValueError
        self.version_made_by = reader.u16()
        self.version_to_extract = reader.u16()
        self.flags = reader.u16()
        self.compression = reader.u16()
        self.date = datefix.dostime(reader.u32())
        self.crc32 = reader.u32()
        self.compressed_size = reader.u32()
        self.decompressed_size = reader.u32()
        len_filename = reader.u16()
        len_extra = reader.u16()
        len_comment = reader.u16()
        self.disk_nr_start = reader.u16()
        self.internal_attributes = reader.u16()
        self.external_attributes = reader.u32()
        self.header_offset = reader.u32()
        self.filename = len_filename and reader.read(len_filename) or None
        self.extra = len_extra and reader.read(len_extra) or None
        self.comment = len_comment and reader.read(len_comment) or None


class Zip:
    def __init__(self, data: buf):
        view = memoryview(data)
        end = buffer_offset(view, ZipEndOfCentralDirectory.Signature, back2front=True)
        reader = StructReader(view)
        if end < 0:
            raise ValueError
        reader.seekset(end)
        self.offset_eocd = end
        self.eocd = ZipEndOfCentralDirectory(reader)
        reader.seekset(self.eocd.directory_offset)
        start = end - self.eocd.directory_size
        shift = start - self.eocd.directory_offset
        if start < 0:
            raise ValueError('Invalid end of central directory size')
        self.offset_directory = start
        reader.seekset(start)
        records: dict[int, ZipFileRecord] = {}
        self.directory = [
            ZipCentralDirectory(reader) for _ in range(self.eocd.entries_in_directory)
        ]
        for entry in self.directory:
            start = entry.header_offset + shift
            reader.seekset(start)
            records[start] = ZipFileRecord(reader)
        self.records = records
