from __future__ import annotations

from refinery.lib.inno.ifps import IFPSFile
from refinery.units.formats.ifps import IFPSBase


class ifpsstr(IFPSBase):
    """
    Extract strings from compiled Pascal script files (IFPS format).

    These scripts can be found, for example, when unpacking InnoSetup installers using
    innounp.
    """
    def process(self, data):
        ifps = IFPSFile.Parse(data, self.args.codec)
        for string in ifps.strings:
            yield string.encode(self.codec)

    @classmethod
    def handles(cls, data) -> bool:
        return data[:len(IFPSFile.Magic)] == IFPSFile.Magic
