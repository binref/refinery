#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import tarfile
import datetime

from ....lib.structures import MemoryFile
from . import ArchiveUnit


class xttar(ArchiveUnit):
    """
    Extract files from a Tar archive.
    """
    def __init__(self, *paths, list=False, join=False, path=b'path', date=b'date'):
        super().__init__(*paths, list=list, join=join, path=path, date=date)

    def unpack(self, data):
        with MemoryFile(data) as stream:
            with tarfile.open(fileobj=stream) as archive:
                for info in archive.getmembers():
                    if not info.isfile():
                        continue
                    extractor = archive.extractfile(info)
                    if extractor is None:
                        continue
                    date = datetime.datetime.fromtimestamp(info.mtime)
                    yield self._pack(info.name, date, lambda e=extractor: e.read())
