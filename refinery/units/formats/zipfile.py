#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import io
import zipfile

from . import ExtractorUnit


class xtzip(ExtractorUnit):
    """
    Extract files from a Zip archive.
    """
    def process(self, data):
        with io.BytesIO(data) as stream:
            with zipfile.ZipFile(stream) as archive:
                for name in archive.namelist():
                    self.log_debug('crawl:', name)
                    if self._check_path(name):
                        self.log_info('match:', name)
                        yield archive.read(name)
