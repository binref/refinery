from __future__ import annotations

import datetime
import tarfile

from refinery.lib.structures import MemoryFile
from refinery.units.formats.archive import ArchiveUnit


class xttar(ArchiveUnit, docs='{0}{s}{PathExtractorUnit}'):
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
    def handles(cls, data) -> bool:
        return data[257:262] == B'ustar'
