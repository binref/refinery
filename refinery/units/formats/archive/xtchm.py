from __future__ import annotations

from refinery.units.formats.archive import ArchiveUnit
from refinery.lib.chm import CHM, ChmHeader


class xtchm(ArchiveUnit, docs='{0}{p}{PathExtractorUnit}'):
    """
    Extract files from CHM (Windows Help) files.
    """
    def unpack(self, data):
        chm = CHM(memoryview(data))
        for path, entry in chm.filesystem.items():
            if entry.length <= 0:
                continue
            if path.startswith('::DataSpace'):
                continue
            def extract(chm=chm, e=entry):
                return chm.read(e)
            yield self._pack(path, None, extract)

    @classmethod
    def handles(cls, data):
        return data[:4] == ChmHeader.Magic
