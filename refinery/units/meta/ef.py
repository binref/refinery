from __future__ import annotations

import os
import os.path
import re
import sys

from datetime import datetime
from pathlib import Path
from typing import Iterable

from refinery.lib.meta import metavars
from refinery.lib.structures import MemoryFile
from refinery.lib.tools import bounds, exception_to_string
from refinery.lib.types import Param
from refinery.units import Arg, Unit

_ERROR_IGNORES = {
    'nt': {'system volume information'}
}


class ef(Unit):
    """
    Short for "emit file". The unit reads files from disk and outputs them individually. Has the
    ability to read large files in chunks.
    """

    def __init__(self,
        *filenames: Param[str, Arg.String(metavar='FILEMASK', nargs='+', help=(
            'A list of file masks. Each matching file will be read from disk and emitted. The file '
            'masks can include format string expressions which will be substituted from the current'
            ' meta variables. The masks can use wild-card expressions, but this feature is disabled'
            ' by default on Posix platforms, where it has to be enabled explicitly using the -w '
            'switch. On Windows, the feature is enabled by default and can be disabled using the -t'
            ' switch.'
        ))],
        list: Param[bool, Arg.Switch('-l', help='Only lists files with metadata.')] = False,
        meta: Param[bool, Arg.Switch('-m', help=(
            'Adds the atime, mtime, ctime, and size metadata variables.'
        ))] = False,
        size: Param[slice | None, Arg.Bounds('-s', help=(
            'If specified, only files are read whose size is in the given range.'))] = None,
        read: Param[int, Arg.Number('-r', help=(
            'If specified, files will be read in chunks of size N and each chunk is emitted as one '
            'element in the output list.'
        ))] = 0,
        wild: Param[bool, Arg.Switch('-w', group='W',
            help='Force use of wildcard patterns in file masks.')] = False,
        tame: Param[bool, Arg.Switch('-t', group='W',
            help='Disable wildcard patterns in file masks.')] = False,
        symlinks: Param[bool, Arg.Switch('-y',
            help='Follow symbolic links and junctions, these are ignored by default.')] = False,
        linewise: Param[bool, Arg.Switch('-i', help=(
            'Read the file linewise. By default, one line is read at a time. In line mode, the '
            '--read argument can be used to read the given number of lines in each chunk.'
        ))] = False
    ):
        if wild and tame:
            raise ValueError('Cannot be both wild and tame!')
        super().__init__(
            size=size,
            read=read,
            list=list,
            meta=meta,
            wild=wild,
            tame=tame,
            symlinks=symlinks,
            linewise=linewise,
            filenames=filenames
        )

    def _read_chunks(self, fd):
        while True:
            buffer = fd.read(self.args.read)
            if not buffer:
                break
            yield buffer

    def _read_lines(self, fd):
        count = self.args.read or 1
        if count == 1:
            while True:
                buffer = fd.readline()
                if not buffer:
                    break
                yield buffer
            return
        with MemoryFile() as out:
            while True:
                for _ in range(count):
                    buffer = fd.readline()
                    if not buffer:
                        break
                    out.write(buffer)
                if not out.tell():
                    break
                yield out.getvalue()
                out.seek(0)
                out.truncate()

    def _absolute_path(self, path_string: str):
        path = Path(path_string).resolve().absolute()
        if os.name == 'nt' and not path.parts[0].startswith('\\\\?\\'):
            # The pathlib glob method will simply fail mid-traversal if it attempts to descend into
            # a folder or to a file whose path exceeds MAX_PATH on Windows. As a workaround, we use
            # UNC paths throughout and truncate to relative paths after enumeration.
            path = Path(F'\\\\?\\{path!s}')
        return path

    def _glob(self, pattern: str) -> Iterable[Path]:
        if pattern.endswith('**'):
            pattern += '/*'
        wildcard = re.search(R'[\[\?\*]', pattern)
        if wildcard is None:
            yield self._absolute_path(pattern)
            return
        k = wildcard.start()
        base, pattern = pattern[:k], pattern[k:]
        path = self._absolute_path(base or '.')
        last = path.parts[-1]
        if base.endswith(last):
            # /base/something.*
            pattern = F'{last}{pattern}'
            path = path.parent

        scandir = os.scandir

        class EmptyIterator:
            def __enter__(self):
                return self

            def __exit__(self, *_, **__):
                pass

            def __next__(self):
                raise StopIteration

            def __iter__(self):
                return self

        if sys.version_info >= (3, 12):
            def islink(path):
                return os.path.islink(path) or os.path.isjunction(path)
        else:
            def islink(path):
                try:
                    return bool(os.readlink(path))
                except OSError:
                    return False

        paths_scanned = set()

        def _patched_scandir(path):
            if islink(path):
                if not self.args.symlinks:
                    return EmptyIterator()
                try:
                    rp = os.path.realpath(path, strict=True)
                except OSError:
                    return EmptyIterator()
                if rp in paths_scanned:
                    self.log_warn(F'file system loop at: {path!s}')
                    return EmptyIterator()
                paths_scanned.add(rp)
                path = rp
            try:
                return scandir(path)
            except Exception as e:
                ignore = _ERROR_IGNORES.get(os.name, set())
                if not any(p.lower() in ignore for p in Path(path).parts):
                    self.log_warn(F'error calling scandir, {exception_to_string(e)}: {path}')
                return EmptyIterator()

        try:
            os.scandir = _patched_scandir
            yield from path.glob(pattern)
        finally:
            os.scandir = scandir

    def process(self, data):
        meta = metavars(data)
        size = self.args.size
        size = size and bounds[size]
        meta.ghost = True
        wild = (os.name == 'nt' or self.args.wild) and not self.args.tame
        root = self._absolute_path('.')
        paths = self._glob if wild else lambda mask: [self._absolute_path(mask)]
        do_meta = self.args.meta
        do_stat = size or do_meta

        class SkipErrors:
            unit = self

            def __init__(self):
                self._history: set[type] = set()
                self._message: dict[type, str | None] = {
                    ValueError: (
                        None
                    ), PermissionError: (
                        'access error while scanning: {}'
                    ), OSError: (
                        'system error while scanning: {}'
                    ), FileNotFoundError: (
                        'file unexpectedly not found: {}'
                    ), Exception: (
                        'unknown error while reading: {}'
                    ),
                }
                self.path = None

            def reset(self, path):
                self._history.clear()
                self.path = path
                return self

            def __enter__(self):
                return self

            def __exit__(self, et, ev, trace):
                if et is None:
                    return False
                for t, msg in self._message.items():
                    if issubclass(et, t):
                        if t not in self._history:
                            self._history.add(t)
                            if msg is not None:
                                self.unit.log_info(msg.format(self.path))
                        return True
                else:
                    return False

        for mask in self.args.filenames:
            mask = meta.format_str(mask, self.codec, [data])
            self.log_debug('scanning for mask:', mask)
            kwargs = dict()
            skip_errors = SkipErrors()
            for path in paths(mask):
                skip_errors.reset(path)
                filesize = -1
                with skip_errors:
                    path = path.relative_to(root)
                with skip_errors:
                    if wild and not path.is_file():
                        continue
                with skip_errors:
                    if do_stat:
                        stat = path.stat()
                        filesize = stat.st_size
                        if do_meta:
                            atime = stat.st_atime
                            mtime = stat.st_mtime
                            try:
                                ctime = stat.st_birthtime
                            except AttributeError:
                                ctime = stat.st_ctime
                            kwargs.update(
                                fsize=filesize,
                                atime=datetime.fromtimestamp(atime).isoformat(' ', 'seconds'),
                                ctime=datetime.fromtimestamp(ctime).isoformat(' ', 'seconds'),
                                mtime=datetime.fromtimestamp(mtime).isoformat(' ', 'seconds')
                            )
                if size is not None and filesize not in size:
                    continue
                with skip_errors:
                    if self.args.list:
                        yield self.labelled(str(path).encode(self.codec), **kwargs)
                        continue
                    with path.open('rb') as stream:
                        if self.args.linewise:
                            yield from self._read_lines(stream)
                        elif self.args.read:
                            yield from self._read_chunks(stream)
                        else:
                            contents = stream.read()
                            self.log_info(lambda: F'reading: {path!s} ({len(contents)} bytes)')
                            yield self.labelled(contents, path=path.as_posix(), **kwargs)
