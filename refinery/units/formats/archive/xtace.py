from __future__ import annotations

from refinery.lib.structures import MemoryFile
from refinery.lib.thirdparty import acefile
from refinery.units.formats.archive import ArchiveUnit


class xtace(ArchiveUnit, docs='{0}{s}{PathExtractorUnit}'):
    """
    Extract files from an ACE archive.
    """
    def unpack(self, data):
        ace = acefile.open(MemoryFile(data, output=bytes))
        for member in ace.getmembers():
            member: acefile.AceMember
            comment = {} if not member.comment else {'comment': member.comment}
            yield self._pack(
                member.filename,
                member.datetime,
                lambda a=ace, m=member: a.read(m, pwd=self.args.pwd),
                **comment
            )

    @classmethod
    def handles(cls, data) -> bool:
        return data[7:14] == b'**ACE**'
