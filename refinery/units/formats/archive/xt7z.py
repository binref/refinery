#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
from typing import TYPE_CHECKING

from refinery.lib.structures import MemoryFile
from refinery.units.formats.archive import ArchiveUnit

if TYPE_CHECKING:
    from py7zr import SevenZipFile, FileInfo


class xt7z(ArchiveUnit):
    """
    Extract files from a 7zip archive.
    """
    @ArchiveUnit.Requires('py7zr', optional=False)
    def _py7zr():
        import py7zr
        return py7zr

    def unpack(self, data):

        def mk7z(**keywords):
            return self._py7zr.SevenZipFile(MemoryFile(mv[zp:]), **keywords)

        pwd = self.args.pwd
        mv = memoryview(data)
        zp = max(0, data.find(B'7z\xBC\xAF\x27\x1C'))

        if pwd:
            archive = mk7z(password=pwd.decode(self.codec))
        else:
            archive = mk7z()
            for pwd in self._COMMON_PASSWORDS:
                try:
                    problem = archive.testzip()
                except self._py7zr.PasswordRequired:
                    problem = True
                if not problem:
                    break
                self.log_debug(F'trying password: {pwd}')
                archive = mk7z(password=pwd)

        for info in archive.list():
            def extract(archive: SevenZipFile = archive, info: FileInfo = info):
                archive.reset()
                return archive.read(info.filename).get(info.filename).read()
            if info.is_directory:
                continue
            yield self._pack(info.filename, info.creationtime, extract)
