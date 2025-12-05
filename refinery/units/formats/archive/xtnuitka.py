from __future__ import annotations

from typing import Iterable

from refinery.lib.shared import pyzstd
from refinery.lib.structures import Struct, StructReader
from refinery.lib.types import buf
from refinery.units.formats import PathExtractorUnit, UnpackResult


class xtnuitka(PathExtractorUnit):
    """
    Extracts files packed by Nuitka using the --onefile option.
    """
    _MAGIC = B'KA'

    def unpack(self, data: buf) -> Iterable[UnpackResult]:
        class NuitkaData(Struct):
            unit = self

            def __init__(self, reader: StructReader):
                self.magic = reader.read_exactly(2)
                self.compression_flag = reader.read_exactly(1)
                if self.compressed:
                    zd = pyzstd.ZstdDecompressor()
                    reader = StructReader(zd.decompress(reader.read()))
                self.files = {}
                self.truncated = False
                while not reader.eof:
                    path = reader.read_w_string('utf-16')
                    if not path:
                        break
                    size = reader.u64()
                    data = reader.read(size)
                    if len(data) == size:
                        self.files[path] = data
                    else:
                        self.truncated = True

            @property
            def compressed(self):
                return self.compression_flag == b'Y'

        if data.startswith(b'MZ'):
            arcs = list(self._pe_candidates(data))
        else:
            arcs = [data]

        for arc in arcs:
            archive = NuitkaData.Parse(arc)
            if archive.truncated:
                self.log_warn('the archive is truncated')
            if archive.magic != self._MAGIC:
                self.log_warn('the archive data does not start with the correct magic sequence')
            for path, data in archive.files.items():
                yield UnpackResult(path, data)

    @classmethod
    def handles(cls, data: buf) -> bool | None:
        if data[:2] == b'MZ':
            try:
                next(cls._pe_candidates(data))
            except StopIteration:
                return False
        else:
            return data[:2] == cls._MAGIC

    @classmethod
    def _pe_candidates(cls, data: buf):

        from refinery.units.formats.pe.peoverlay import peoverlay
        blob = data | peoverlay | bytearray
        if blob.startswith(cls._MAGIC):
            yield blob

        from refinery.units.formats.pe.perc import perc
        for blob in data | perc:
            if blob.startswith(cls._MAGIC):
                yield blob
