#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import tarfile
import datetime

from refinery.lib.structures import MemoryFile
from refinery.units.formats.archive import ArchiveUnit


class xttar(ArchiveUnit):
    """
    Extract files from a Tar archive.
    """
    def unpack(self, data: bytearray):
        with MemoryFile(data) as stream:
            try:
                archive = tarfile.open(fileobj=stream)
            except Exception:
                ustar = data.find(B'ustar')
                if ustar < 257:
                    raise
                stream.seek(ustar - 257)
                archive = tarfile.open(fileobj=stream)
        for info in archive.getmembers():
            if not info.isfile():
                continue
            extractor = archive.extractfile(info)
            if extractor is None:
                continue
            date = datetime.datetime.fromtimestamp(info.mtime)
            yield self._pack(info.name, date, lambda e=extractor: e.read())

    @classmethod
    def handles(cls, data: bytearray) -> bool:
        ustar = data.find(B'ustar')
        if ustar >= 0:
            return ustar == 257 or data[ustar:ustar + 3] in (B'\x00\x30\x30', B'\x20\x20\x00')
        return False
