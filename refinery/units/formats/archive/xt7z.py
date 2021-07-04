#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import py7zr

from ....lib.structures import MemoryFile
from . import ArchiveUnit


class xt7z(ArchiveUnit):
    """
    Extract files from a 7zip archive.
    """
    def unpack(self, data):
        pwd = self.args.pwd
        pwd = pwd and {'password': pwd.decode(self.codec)} or {}
        mv = memoryview(data)
        zp = max(0, data.find(B'7z\xBC\xAF\x27\x1C'))
        archive = py7zr.SevenZipFile(MemoryFile(mv[zp:]), **pwd)
        for info in archive.list():
            def extract(archive: py7zr.SevenZipFile = archive, info: py7zr.FileInfo = info):
                archive.reset()
                return archive.read(info.filename).get(info.filename).read()
            if info.is_directory:
                continue
            yield self._pack(info.filename, info.creationtime, extract)
