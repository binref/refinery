#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import ByteString, Callable, Union
from datetime import datetime

from .. import arg, PathExtractorUnit, UnpackResult


class ArchiveUnit(PathExtractorUnit, abstract=True):
    def __init__(
        self, *paths, list=False, join=False, path=b'path',
        date: arg('-D', metavar='NAME',
            help='Name of the meta variable to receive the extracted file date. The default value is "{default}".') = b'date',
        pwd: arg('-p', help='Optionally specify an extraction password.') = B''
    ):
        super().__init__(*paths, list=list, join=join, path=path, pwd=pwd, date=date)

    def _pack(self, path: str, date: datetime, data: Union[ByteString, Callable[[], ByteString]], **meta) -> UnpackResult:
        meta[self.args.date.decode(self.codec)] = date.isoformat(' ', 'seconds')
        return UnpackResult(path, data, **meta)
