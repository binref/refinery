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
        with MemoryFile(data) as stream:
            with py7zr.SevenZipFile(stream, **pwd) as archive:
                for info in archive.list():
                    info: py7zr.FileInfo
                    if info.is_directory:
                        continue
                    yield self._pack(
                        info.filename,
                        info.creationtime,
                        lambda a=archive: a.read(info.filename).get(info.filename).read()
                    )
