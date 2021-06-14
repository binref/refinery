#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import zipfile
import datetime

from . import ArchiveUnit
from ....lib.structures import MemoryFile


class xtzip(ArchiveUnit):
    """
    Extract files from a Zip archive.
    """
    def unpack(self, data):
        archive = zipfile.ZipFile(MemoryFile(data))
        for info in archive.infolist():
            def xt(archive=archive, info=info, pwd=self.args.pwd):
                try:
                    return archive.read(info.filename, pwd=pwd)
                except RuntimeError as E:
                    if 'password' not in str(E):
                        raise
                    pwdstr = pwd.decode(self.codec)
                    raise RuntimeError(F'invalid password: {pwdstr}') from E
            if info.is_dir():
                continue
            try:
                date = datetime.datetime(*info.date_time)
            except Exception:
                date = None
            yield self._pack(info.filename, date, xt)
