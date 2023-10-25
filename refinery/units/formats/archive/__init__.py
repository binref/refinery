#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import ByteString, Callable, Optional, Union
from datetime import datetime

from refinery.units.formats import Arg, PathExtractorUnit, UnpackResult


class ArchiveUnit(PathExtractorUnit, abstract=True):
    def __init__(
        self, *paths, list=False, join_path=False, drop_path=False, fuzzy=0, exact=False, regex=False, path=b'path',
        date: Arg('-D', metavar='NAME',
            help='Name of the meta variable to receive the extracted file date. The default value is "{default}".') = b'date',
        pwd: Arg('-p', help='Optionally specify an extraction password.') = B'',
        **kwargs
    ):
        super().__init__(
            *paths,
            list=list,
            join_path=join_path,
            drop_path=drop_path,
            fuzzy=fuzzy,
            exact=exact,
            regex=regex,
            path=path,
            pwd=pwd,
            date=date,
            **kwargs
        )

    _COMMON_PASSWORDS = [
        'infected',
        'virus',
        'malware',
        'dangerous',
        'flare',
        '1234',
        '123',
        'Infected',
        'infected!',
        'INFECTED',
        'notinfected',
        'unzip-me',
        'password',
    ]

    def _pack(
        self,
        path: str,
        date: Optional[Union[datetime, str]],
        data: Union[ByteString, Callable[[], ByteString]],
        **meta
    ) -> UnpackResult:
        if isinstance(date, datetime):
            date = date.isoformat(' ', 'seconds')
        if isinstance(date, str):
            meta[self.args.date.decode(self.codec)] = date
        return UnpackResult(path, data, **meta)
