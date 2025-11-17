from __future__ import annotations

from refinery.lib.chm import CHM, ChmHeader
from refinery.units.formats import PathExtractorUnit, UnpackResult


class xtchm(PathExtractorUnit, docs='{0}{p}{PathExtractorUnit}'):
    """
    Extract files from CHM (Windows Help) files.
    """
    def unpack(self, data):
        chm = CHM.Parse(memoryview(data))

        self.log_info(F'language: {chm.header.language_name}')
        self.log_info(F'codepage: {chm.header.codepage}')

        for path, record in chm.filesystem.items():
            def extract(chm=chm, record=record):
                return chm.read(record)
            if record.length <= 0:
                continue
            if path.startswith('::DataSpace'):
                continue
            yield UnpackResult(path, extract)

    @classmethod
    def handles(cls, data):
        return data[:4] == ChmHeader.Magic
