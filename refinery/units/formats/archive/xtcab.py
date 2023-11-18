#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from datetime import datetime

from refinery.units.formats.archive import ArchiveUnit


class xtcab(ArchiveUnit):
    """
    Extract files from CAB (cabinet) archives.
    """
    @ArchiveUnit.Requires('cabarchive', 'arc', 'default', 'extended')
    def _cabarchive():
        import cabarchive
        return cabarchive

    def unpack(self, data: bytearray):
        arc = self._cabarchive.CabArchive(data)
        for item in arc.find_files('*'):
            yield self._pack(item.filename, datetime.combine(item.date, item.time), item.buf)

    @classmethod
    def handles(cls, data: bytearray):
        return data.startswith(B'MSCF')
