from __future__ import annotations

from datetime import datetime
from gzip import FEXTRA, FNAME, GzipFile
from pathlib import Path

from refinery.lib.meta import metavars
from refinery.lib.structures import StreamDetour, Struct, StructReader
from refinery.units.formats.archive import ArchiveUnit


class GzipHeader(Struct):
    MAGIC = B'\x1F\x8B'

    def __init__(self, reader: StructReader):
        unpacker = GzipFile(fileobj=reader)
        with StreamDetour(reader, 0):
            self.magic = reader.read(2)
            self.method = reader.u8()
            self.flags = reader.u8()
            self.mtime = reader.u32()
            reader.skip(2)
            self.extra = None
            self.name = None
            if self.flags & FEXTRA:
                self.extra = reader.read(reader.u16())
            if self.flags & FNAME:
                self.name = reader.read_c_string('latin1')
        self.data = unpacker.read()


class xtgz(ArchiveUnit):
    """
    Extract a file from a GZip archive.
    """
    CustomJoinBehaviour = '{path}'

    def unpack(self, data: bytearray):
        archive = GzipHeader.Parse(data)
        path = archive.name
        date = archive.mtime
        date = date and datetime.fromtimestamp(date) or None
        if path is None:
            try:
                meta = metavars(data)
                path = Path(meta[self.args.path.decode(self.codec)])
            except KeyError:
                path = ''
            else:
                suffix = path.suffix.lower()
                if suffix == '.tgz':
                    path = path.with_suffix('.tar')
                elif suffix == '.gz':
                    path = path.with_suffix('')
                path = path.as_posix()

        yield self._pack(path, date, archive.data)

    @classmethod
    def handles(cls, data) -> bool:
        return data[:2] == B'\x1F\x8B'
