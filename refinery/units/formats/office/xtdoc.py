#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units.formats import PathExtractorUnit, UnpackResult
from refinery.units.formats.archive.xtzip import xtzip
from refinery.lib.structures import MemoryFile


class xtdoc(PathExtractorUnit):
    """
    Extract files from an OLE document such as a Microsoft Word DOCX file.
    """

    @PathExtractorUnit.Requires('olefile', optional=False)
    def _olefile():
        import olefile
        return olefile

    def unpack(self, data):
        with MemoryFile(data) as stream:
            try:
                oledoc = self._olefile.OleFileIO(stream)
            except OSError as error:
                self.log_info(F'error, {error}, treating input as zip file')
                yield from xtzip().unpack(data)
                return
            for item in oledoc.listdir():
                if not item or not item[-1]:
                    continue
                path = '/'.join(item)
                olestream = oledoc.openstream(path)
                c0 = ord(item[-1][:1])
                if c0 < 20:
                    item[-1] = F'[{c0:d}]{item[-1][1:]}'
                    path = '/'.join(item)
                self.log_debug('exploring:', path)
                yield UnpackResult(path, olestream.read())
