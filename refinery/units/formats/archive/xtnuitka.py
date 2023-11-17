#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
from typing import Iterable, Optional

from refinery.units.formats import PathExtractorUnit, UnpackResult
from refinery.lib.structures import StructReader, Struct
from refinery.lib.types import ByteStr


class xtnuitka(PathExtractorUnit):
    """
    Extracts files packed by Nuitka using the --onefile option.
    """
    _MAGIC = B'KA'

    @PathExtractorUnit.Requires('pyzstd', 'arc')
    def _pyzstd():
        import pyzstd
        return pyzstd

    def unpack(self, data: ByteStr) -> Iterable[UnpackResult]:
        class NuitkaData(Struct):
            unit = self

            def __init__(self, reader: StructReader):
                self.magic = reader.read_exactly(2)
                self.compression_flag = reader.read_exactly(1)
                if self.compressed:
                    zd = self.unit._pyzstd.ZstdDecompressor()
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
            archive = NuitkaData(arc)
            if archive.truncated:
                self.log_warn('the archive is truncated')
            if archive.magic != self._MAGIC:
                self.log_warn('the archive data does not start with the correct magic sequence')
            for path, data in archive.files.items():
                yield UnpackResult(path, data)

    @classmethod
    def handles(cls, data: ByteStr) -> Optional[bool]:
        if data.startswith(b'MZ'):
            try:
                next(cls._pe_candidates(data))
            except StopIteration:
                return False
        else:
            return data.startswith(cls._MAGIC)

    @classmethod
    def _pe_candidates(cls, data: ByteStr):

        from refinery.units.formats.pe.peoverlay import peoverlay
        blob = data | peoverlay | bytearray
        if blob.startswith(cls._MAGIC):
            yield blob

        from refinery.units.formats.pe.perc import perc
        for blob in data | perc:
            if blob.startswith(cls._MAGIC):
                yield blob
