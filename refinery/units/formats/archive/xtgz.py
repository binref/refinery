#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from gzip import GzipFile, FEXTRA, FNAME
from datetime import datetime
from pathlib import Path

from refinery.units.formats.archive import ArchiveUnit
from refinery.lib.structures import Struct, StructReader, StreamDetour
from refinery.lib.meta import metavars


class GzipHeader(Struct):
    MAGIC = B'\x1F\x8B'

    def __init__(self, reader: StructReader):
        unpacker = GzipFile(fileobj=reader)
        with StreamDetour(reader, 0):
            self.magic = reader.read(2)
            self.method, self.flags, self.mtime = reader.read_struct('BBIxx')
            self.extra = None
            self.name = None
            if self.flags & FEXTRA:
                self.extra = reader.read(reader.u16())
            if self.flags & FNAME:
                self.name = reader.read_c_string().decode('latin1')
        self.data = unpacker.read()


class xtgz(ArchiveUnit):
    """
    Extract a file from a GZip archive.
    """
    def unpack(self, data: bytearray):
        archive = GzipHeader(data)
        path = archive.name
        date = archive.mtime
        date = date and datetime.fromtimestamp(date) or None
        if path is None:
            try:
                meta = metavars(data)
                path = Path(meta['path'])
            except KeyError:
                path = 'ungz'
            else:
                self.log_warn(path)
                suffix = path.suffix
                if suffix.lower() == '.gz':
                    path = path.with_suffix('')
                else:
                    path = path.with_suffix(F'{suffix}.ungz')
                path = path.as_posix()
        yield self._pack(path, date, archive.data)

    @classmethod
    def handles(cls, data: bytearray) -> bool:
        return B'\x1F\x8B' in data
