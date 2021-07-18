#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import Optional

from datetime import datetime
from zipfile import ZipInfo, ZipFile

from . import ArchiveUnit
from ....lib.structures import MemoryFile


class xtzip(ArchiveUnit):
    """
    Extract files from a Zip archive.
    """
    def unpack(self, data):
        password = self.args.pwd.decode(self.codec)
        archive = ZipFile(MemoryFile(data))

        if password:
            archive.setpassword(self.args.pwd)
        else:
            def password_invalid(pwd: Optional[str]):
                if pwd is not None:
                    archive.setpassword(pwd.encode(self.codec))
                try:
                    archive.testzip()
                except RuntimeError as E:
                    if 'password' not in str(E):
                        raise
                    return True
                else:
                    self.log_debug(pwd)
                    return False
            for pwd in [None, *self._COMMON_PASSWORDS]:
                if not password_invalid(pwd):
                    break
            else:
                raise RuntimeError('Archive is password-protected.')

        for info in archive.infolist():
            def xt(archive: ZipFile = archive, info: ZipInfo = info):
                try:
                    return archive.read(info.filename)
                except RuntimeError as E:
                    if 'password' not in str(E):
                        raise
                    if not password:
                        raise RuntimeError('archive is password-protected')
                    else:
                        raise RuntimeError(F'invalid password: {password}') from E
            if info.is_dir():
                continue
            try:
                date = datetime(*info.date_time)
            except Exception:
                date = None
            yield self._pack(info.filename, date, xt)
