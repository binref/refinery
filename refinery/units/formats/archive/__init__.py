from __future__ import annotations

from datetime import datetime
from functools import wraps

from refinery.lib.types import Callable, Param, buf
from refinery.units import Arg, Executable, Unit
from refinery.units.formats import PathExtractorUnit, UnpackResult


class MultipleArchives(Exception):
    pass


class ArchiveExecutable(Executable):

    def __init__(cls, name, bases, nmspc, **kwargs):
        super().__init__(name, bases, nmspc, **kwargs)

        carver = cls._carver()

        if carver is None:
            return

        if not issubclass(cls, PathExtractorUnit):
            raise TypeError

        unpack = cls.unpack

        @wraps(unpack)
        def __unpack(self, data: buf):
            carved = data | carver
            try:
                arc1 = next(carved)
            except StopIteration:
                arc1 = data
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

        setattr(cls, 'unpack', __unpack)

    def _carver(cls) -> Unit | None:
        return None


class ArchiveUnit(PathExtractorUnit, metaclass=ArchiveExecutable, abstract=True):
    def __init__(
        self, *paths, list=False, join_path=False, drop_path=False, fuzzy=0, exact=False, regex=False, path=b'path',
        date: Param[buf, Arg('-D', metavar='NAME',
            help='Name of the meta variable to receive the extracted file date. The default value is "{default}".')] = b'date',
        pwd: Param[buf, Arg('-p', help='Optionally specify an extraction password.')] = B'',
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
        date: datetime | str | None,
        data: buf | Callable[[], buf],
        **meta
    ) -> UnpackResult:
        if isinstance(date, datetime):
            date = date.isoformat(' ', 'seconds')
        if isinstance(date, str):
            meta[self.args.date.decode(self.codec)] = date
        return UnpackResult(path, data, **meta)
