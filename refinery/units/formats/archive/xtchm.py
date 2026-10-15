from __future__ import annotations

from refinery.lib.chm import CHM, ChmHeader
from refinery.units.formats import PathExtractorUnit, UnpackResult


class xtchm(PathExtractorUnit, docs='{0}{p}{PathExtractorUnit}'):
    """
    Extract files from CHM (Windows Help) files. Compiled HTML Help archives contain HTML, images,
    and scripts used in Microsoft Help.
    """
    def unpack(self, data):
        chm = CHM.Parse(memoryview(data))

        self.log_info(F'language: {chm.header.language_name}')
        self.log_info(F'codepage: {chm.header.codepage}')

        for record in chm.entries():
            if record.length <= 0:
                continue
            if (path := record.name).startswith('::DataSpace'):
                continue
            if path.startswith('/#') or path.startswith('/$'):
                path = F'/$CHM{path}'
            yield UnpackResult(path, chm.extractor(record))

    @classmethod
    def handles(cls, data):
        return data[:4] == ChmHeader.Magic
