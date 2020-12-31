#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import olefile

from . import PathExtractorUnit, UnpackResult
from ...lib.structures import MemoryFile


class xtdoc(PathExtractorUnit):
    """
    Extract files from an OLE document such as a Microsoft Word DOCX file.
    """

    def unpack(self, data):
        with MemoryFile(data) as stream:
            oledoc = olefile.OleFileIO(stream)
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
