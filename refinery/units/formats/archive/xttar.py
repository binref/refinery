#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import tarfile
import datetime

from ....lib.structures import MemoryFile
from .. import PathExtractorUnit, UnpackResult


class xttar(PathExtractorUnit):
    """
    Extract files from a Tar archive.
    """
    def unpack(self, data):
        with MemoryFile(data) as stream:
            with tarfile.open(fileobj=stream) as archive:
                for info in archive.getmembers():
                    if not info.isfile():
                        continue
                    extractor = archive.extractfile(info)
                    if extractor is None:
                        continue
                    date = datetime.datetime.fromtimestamp(info.mtime).isoformat(' ', 'seconds')
                    yield UnpackResult(info.name, lambda e=extractor: e.read(), date=date)
