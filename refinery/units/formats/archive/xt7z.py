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

        if zp > 0:
            self.log_warn(F'found header at offset 0x{zp:X}, extracting from there.')

        if pwd:
            try:
                archive = mk7z(password=pwd.decode(self.codec))
            except self._py7zr.Bad7zFile:
                raise ValueError('corrupt archive; the password is likely invalid.')
        else:
            def passwords():
                yield None
                yield from self._COMMON_PASSWORDS
            for pwd in passwords():
                try:
                    archive = mk7z(password=pwd)
                    problem = archive.testzip()
                except self._py7zr.PasswordRequired:
                    problem = True
                except SystemError:
                    problem = True
                except Exception:
                    if pwd is None:
                        raise
                    problem = True
                if not problem:
                    break
                if pwd is not None:
                    self.log_debug(F'trying password: {pwd}')
            else:
                raise ValueError('a password is required and none of the default passwords worked.')

        for info in archive.list():
            def extract(archive: SevenZipFile = archive, info: FileInfo = info):
                archive.reset()
                return archive.read(info.filename).get(info.filename).read()
            if info.is_directory:
                continue
            yield self._pack(info.filename, info.creationtime, extract, crc32=info.crc32)

    def handles(self, data: bytearray) -> bool:
        return data.startswith(B'7z\xBC\xAF\x27\x1C')
