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

        def mk7z(**keywords):
            return py7zr.SevenZipFile(MemoryFile(mv[zp:]), **keywords)

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
                except py7zr.PasswordRequired:
                    problem = True
                if not problem:
                    break
                self.log_debug(F'trying password: {pwd}')
                archive = mk7z(password=pwd)

        for info in archive.list():
            def extract(archive: py7zr.SevenZipFile = archive, info: py7zr.FileInfo = info):
                archive.reset()
                return archive.read(info.filename).get(info.filename).read()
            if info.is_directory:
                continue
            yield self._pack(info.filename, info.creationtime, extract)
