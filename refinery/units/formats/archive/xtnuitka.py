from __future__ import annotations

from typing import Iterable

from refinery.lib.id import is_likely_pe
from refinery.lib.structures import Struct, StructReader
from refinery.lib.types import buf
from refinery.units.formats import PathExtractorUnit, UnpackResult


class _NuitkaData(Struct):
    """
    The archive that Nuitka appends to an executable built with the onefile option.
    """
    def __init__(self, reader: StructReader):
        from refinery.lib.shared.pyzstd import pyzstd

        self.magic = reader.read_exactly(2)
        self.compression_flag = reader.read_exactly(1)
        if self.compressed:
            zd = pyzstd.ZstdDecompressor()
            reader = StructReader(zd.decompress(reader.read()))
        self.files: list[tuple[str, buf]] = []
        self.truncated = False
        while not reader.eof:
            path = reader.read_w_string('utf-16')
            if not path:
                break
            size = reader.u64()
            data = reader.read(size)
            if len(data) == size:
                self.files.append((path, data))
            else:
                self.truncated = True

    @property
    def compressed(self):
        return self.compression_flag == b'Y'


class xtnuitka(PathExtractorUnit):
    """
    Extract files packed by Nuitka using the --onefile option.
    """
    _MAGIC = B'KA'

    def unpack(self, data: buf) -> Iterable[UnpackResult]:
        if is_likely_pe(data):
            arcs = list(self._pe_candidates(data))
        else:
            arcs = [data]

        for arc in arcs:
            archive = _NuitkaData.Parse(arc)
            if archive.truncated:
                self.log_warn('the archive is truncated')
            if archive.magic != self._MAGIC:
                self.log_warn('the archive data does not start with the correct magic sequence')
            for path, data in archive.files:
                yield UnpackResult(path, data)

    @classmethod
    def handles(cls, data: buf) -> bool:
        if is_likely_pe(data):
            return next(cls._pe_candidates(data), None) is not None
        return data[:2] == cls._MAGIC

    @classmethod
    def _pe_candidates(cls, data: buf):

        from refinery.units.formats.pe.peoverlay import peoverlay
        blob = data | peoverlay | bytearray
        if blob.startswith(cls._MAGIC):
            yield blob

        from refinery.units.formats.pe.perc import perc
        with data | perc as resources:
            for blob in resources:
                if blob.startswith(cls._MAGIC):
                    yield blob
