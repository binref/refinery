#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import io
import zipfile

from . import arg, PathExtractorUnit, UnpackResult


class xtzip(PathExtractorUnit):
    """
    Extract files from a Zip archive.
    """
    def __init__(
        self, *paths, list=False, join=False,
        pwd: arg('-p', help='Optionally specify an extraction password.') = B''
    ):
        super().__init__(*paths, list=list, join=join, pwd=pwd)

    def unpack(self, data):
        with io.BytesIO(data) as stream:
            with zipfile.ZipFile(stream) as archive:
                for info in archive.infolist():
                    if info.is_dir():
                        continue
                    yield UnpackResult(info.filename,
                        lambda info=info, pwd=self.args.pwd: archive.read(info.filename, pwd=pwd))
