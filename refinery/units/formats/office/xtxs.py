#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import Optional

from refinery.units.formats import PathExtractorUnit, UnpackResult
from refinery.lib.vfs import VirtualFileSystem
from refinery.lib.tools import NoLogging


class xtxs(PathExtractorUnit):
    """
    Extract data from Microsoft Access Databases.
    """

    @PathExtractorUnit.Requires('access-parser', 'formats', 'office', 'extended')
    def _access_parser():
        import access_parser
        return access_parser

    def unpack(self, data):

        with VirtualFileSystem() as vfs:
            file = vfs.new(data, 'accdb')
            xsdb = self._access_parser.AccessParser(file.path)

        for name in xsdb.catalog:
            with NoLogging():
                table = xsdb.parse_table(name)
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

                    if isinstance(entry, (int, float)):
                        entry = str(entry)
                    if isinstance(entry, str):
                        entry = entry.encode(self.codec)
                    if isinstance(entry, bytes):
                        yield UnpackResult(F'{name}/{k}/{header}', entry)

    @classmethod
    def handles(self, data: bytearray) -> Optional[bool]:
        view = memoryview(data)
        if b'Standard ACE DB' in view[:20]:
            return True
