#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
from typing import TYPE_CHECKING
from functools import wraps
from datetime import datetime

from refinery.units import Executable, Unit, Arg
from refinery.units.formats import PathExtractorUnit, UnpackResult
from refinery.lib.types import ByteStr

if TYPE_CHECKING:
    from typing import ByteString, Callable, Optional, Union, Type, Self


class MultipleArchives(Exception):
    pass


class ArchiveExecutable(Executable):

    def __init__(exe: Union[Self, Type[PathExtractorUnit]], name, bases, nmspc, **kwargs):
        super(ArchiveExecutable, exe).__init__(name, bases, nmspc, **kwargs)

        carver = exe._carver()

        if carver is None:
            return

        unpack = exe.unpack

        @wraps(unpack)
        def __unpack(self: PathExtractorUnit, data: ByteStr):
            carved = data | carver
            try:
                arc1 = next(carved)
            except StopIteration:
                raise ValueError('The input does not contain any archive.')
            try:
                arc2 = next(carved)
            except StopIteration:
                yield from unpack(self, arc1)
                return
            if not self.args.lenient:
                some = 2 + sum(1 for _ in carved)
                text = (
                    F'The input contains {some} archives. Use the {carver.name} unit to extract them individually '
                    R'or set the --lenient/-L option to fuse the archives.')
                raise MultipleArchives(text)
            else:
                archives = [arc1, arc2]
                archives.extend(carved)

            for k, data in enumerate(archives, 1):
                for result in unpack(self, data):
                    result.path = F'archive{k}/{result.path}'
                    yield result

        exe.unpack = __unpack

    def _carver(cls) -> Optional[Unit]:
        return None


class ArchiveUnit(PathExtractorUnit, metaclass=ArchiveExecutable, abstract=True):
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
