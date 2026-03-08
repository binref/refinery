from __future__ import annotations

from refinery.lib.dmg.arc import DiskImage, is_dmg
from refinery.units.formats.archive import ArchiveUnit


class xtdmg(ArchiveUnit, docs='{0}{s}{PathExtractorUnit}'):
    """
    Extract files from an Apple Disk Image (DMG) files with an HFS+ file system.
    """
    def unpack(self, data: bytearray):
        dmg = DiskImage(data)
        for result in dmg.files():
            for w in result.warnings:
                self.log_warn(w)
            if result.partition:
                continue
            yield self._pack(result.path, result.date, result.data)

    @classmethod
    def handles(cls, data) -> bool | None:
        return is_dmg(data)
