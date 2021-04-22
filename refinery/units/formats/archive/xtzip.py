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
        with MemoryFile(data) as stream:
            with zipfile.ZipFile(stream) as archive:
                for info in archive.infolist():
                    def xt(info=info, pwd=self.args.pwd):
                        return archive.read(info.filename, pwd=pwd)
                    if info.is_dir():
                        continue
                    date = datetime.datetime(*info.date_time)
                    yield self._pack(info.filename, date, xt)
