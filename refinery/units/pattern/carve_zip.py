#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units import Unit
from refinery.units.misc.datefix import datefix
from refinery.lib.structures import StructReader, Struct


class ZipEndOfCentralDirectory(Struct):
    SIGNATURE = B'PK\x05\x06'

    def __init__(self, reader: StructReader):
        if reader.read(4) != self.SIGNATURE:
            raise ValueError
        self.disk_number = reader.u16()
        self.start_disk_number = reader.u16()
        self.entries_on_disk = reader.u16()
        self.entries_in_directory = reader.u16()
        self.directory_size = reader.u32()
        self.directory_offset = reader.u32()
        self.comment_length = reader.u16()


class ZipCentralDirectory(Struct):
    SIGNATURE = B'PK\x01\x02'

    def __init__(self, reader: StructReader):
        if reader.read(4) != self.SIGNATURE:
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


class carve_zip(Unit):
    """
    Extracts anything from the input data that looks like a zip archive file.
    """

    def process(self, data: bytearray):
        end = len(data)
        mem = memoryview(data)
        rev = []
        while True:
            end = data.rfind(ZipEndOfCentralDirectory.SIGNATURE, 0, end)
            if end < 0:
                break
            try:
                end_marker = ZipEndOfCentralDirectory(mem[end:])
            except ValueError as e:
                self.log_info(F'error parsing end of central directory at 0x{end:X}: {e!s}')
                continue
            else:
                self.log_info(F'successfully parsed end of central directory at 0x{end:X}')
            start = end - end_marker.directory_size
            shift = start - end_marker.directory_offset
            if start < 0:
                self.log_debug('end of central directory size is invalid')
                continue
            try:
                central_directory = ZipCentralDirectory(mem[start:])
            except ValueError:
                self.log_debug('computed location of central directory is invalid')
                end = end - len(ZipEndOfCentralDirectory.SIGNATURE)
                continue
            start = central_directory.header_offset + shift
            rev.append((start, end + len(end_marker)))
            end = start
        for start, end in reversed(rev):
            zip = mem[start:end + len(end_marker)]
            yield self.labelled(zip, offset=start)
