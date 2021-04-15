#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import zipfile

from .. import arg, PathExtractorUnit, UnpackResult
from ....lib.structures import MemoryFile


class xtzip(PathExtractorUnit):
    """
    Extract files from a Zip archive.
    """
    def __init__(
        self, *paths, list=False, join=False, meta=b'path',
        pwd: arg('-p', help='Optionally specify an extraction password.') = B''
    ):
        super().__init__(*paths, list=list, join=join, pwd=pwd)

    def unpack(self, data):
        with MemoryFile(data) as stream:
            with zipfile.ZipFile(stream) as archive:
                for info in archive.infolist():
                    def xt(info=info, pwd=self.args.pwd):
                        return archive.read(info.filename, pwd=pwd)
                    if info.is_dir():
                        continue
                    date = '{:04d}-{:02d}-{:02d} {:02d}:{:02d}:{:02d}'.format(*info.date_time)
                    yield UnpackResult(info.filename, xt, date=date)
