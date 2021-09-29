#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

from pathlib import Path
from datetime import datetime
from typing import Iterable

from ...lib.meta import metavars
from ...lib.structures import MemoryFile
from .. import arg, Unit


class ef(Unit):
    """
    Short for "emit file". The unit reads files from disk and outputs them individually. Has the ability to
    read large files in chunks.
    """

    def __init__(self,
        *filenames: arg(metavar='FILEMASK', nargs='+', type=str, help=(
            'A list of file masks (with wildcard patterns). Each matching '
            'file will be read from disk and emitted. In addition to glob '
            'patterns, the file mask can include format string expressions '
            'which will be substituted from the current meta variables.'
        )),
        list: arg.switch('-l', help='Only lists files with metadata.') = False,
        meta: arg.switch('-m', help=(
            'Adds the atime, mtime, ctime, and size metadata variables.'
        )) = False,
        size: arg.number('-s', help=(
            'If specified, files will be read in chunks of size N and each '
            'chunk is emitted as one element in the output list.'
        )) = 0,
        linewise: arg.switch('-w', help=(
            'Read the file linewise. By default, one line is read at a time. '
            'In line mode, the --size argument can be used to read the given '
            'number of lines in each chunk.'
        )) = False
    ):
        super().__init__(
            size=size,
            list=list,
            meta=meta,
            linewise=linewise,
            filenames=filenames
        )

    def _read_chunks(self, fd):
        while True:
            buffer = fd.read(self.args.size)
            if not buffer:
                break
            yield buffer

    def _read_lines(self, fd):
        count = self.args.size or 1
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

    def glob(self, pattern: str) -> Iterable[Path]:
        if pattern.endswith('**'):
            pattern += '/*'
        root = Path(next(iter(re.split(R'[\?\*\[\]]', pattern, maxsplit=1)))).parent
        glob = str(Path(pattern).relative_to(root))
        for match in root.glob(glob):
            yield match

    def process(self, data):
        meta = metavars(data, ghost=True)
        for mask in self.args.filenames:
            mask = meta.format_str(mask, self.codec, data)
            self.log_debug('scanning for mask:', mask)
            kwargs = dict()
            for path in self.glob(mask):
                if not path.is_file():
                    continue
                if self.args.meta:
                    stat = path.stat()
                    kwargs.update(
                        size=stat.st_size,
                        atime=datetime.fromtimestamp(stat.st_atime).isoformat(' ', 'seconds'),
                        ctime=datetime.fromtimestamp(stat.st_ctime).isoformat(' ', 'seconds'),
                        mtime=datetime.fromtimestamp(stat.st_mtime).isoformat(' ', 'seconds')
                    )
                if self.args.list:
                    try:
                        yield self.labelled(str(path).encode(self.codec), **kwargs)
                    except OSError:
                        self.log_warn(F'os error while scanning: {path!s}')
                    continue
                try:
                    with path.open('rb') as stream:
                        if self.args.linewise:
                            yield from self._read_lines(stream)
                        elif self.args.size:
                            yield from self._read_chunks(stream)
                        else:
                            data = stream.read()
                            self.log_info(lambda: F'reading: {path!s} ({len(data)} bytes)')
                            yield self.labelled(data, path=path.as_posix(), **kwargs)
                except PermissionError:
                    self.log_warn('permission denied:', path)
                except FileNotFoundError:
                    self.log_warn('file is missing:', path)
                except Exception:
                    self.log_warn('unknown error while reading:', path)
