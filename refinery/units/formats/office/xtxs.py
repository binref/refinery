from __future__ import annotations

from datetime import datetime
from uuid import UUID

from refinery.lib.access import AccessDatabase
from refinery.units.formats import PathExtractorUnit, UnpackResult


class xtxs(PathExtractorUnit):
    """
    Extract data from Microsoft Access Databases. Parses .mdb and .accdb files to export tables and
    records as structured data.
    """
    def unpack(self, data):
        db = AccessDatabase(data)
        for name in db.catalog:
            try:
                table = db.parse_table(name)
            except Exception:
                continue
            if not table:
                continue
            length = max(len(cells) for cells in table.values())
            for k in range(length):
                for header, column in table.items():
                    try:
                        entry = column[k]
                    except IndexError:
                        continue
                    if entry is None:
                        continue

                    if isinstance(entry, datetime):
                        entry = entry.isoformat(' ', 'seconds')
                    if isinstance(entry, (int, float, UUID)):
                        entry = str(entry)
                    if isinstance(entry, str):
                        entry = entry.encode(self.codec)
                    if isinstance(entry, bytes):
                        yield UnpackResult(F'{name}/{k}/{header}', entry)

    @classmethod
    def handles(cls, data) -> bool | None:
        if data[:19] == b'\0\01\0\0Standard ACE DB':
            return True
        if data[:19] == b'\0\01\0\0Standard Jet DB':
            return True
