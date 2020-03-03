#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import io
import zipfile

from . import PathExtractorUnit


class xtzip(PathExtractorUnit):
    """
    Extract files from a Zip archive.
    """
    def process(self, data):
        with io.BytesIO(data) as stream:
            with zipfile.ZipFile(stream) as archive:
                for info in archive.infolist():
                    if info.is_dir():
                        continue
                    if self._check_path(info.filename):
                        self.log_info(info.filename)
                        yield dict(path=info.filename, data=archive.read(info.filename))
                    else:
                        self.log_debug(info.filename)
