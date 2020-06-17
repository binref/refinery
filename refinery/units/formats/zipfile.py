#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import io
import zipfile

from . import PathExtractorUnit, UnpackResult


class xtzip(PathExtractorUnit):
    """
    Extract files from a Zip archive.
    """
    def unpack(self, data):
        with io.BytesIO(data) as stream:
            with zipfile.ZipFile(stream) as archive:
                for info in archive.infolist():
                    if info.is_dir():
                        continue
                    yield UnpackResult(info.filename, lambda info=info: archive.read(info.filename))
