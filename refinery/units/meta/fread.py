#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import arg, Unit

from os.path import isfile
from glob import glob
from io import BytesIO


class fread(Unit):
    """
    Reads files from disk and outputs them individually. Has the ability to
    read large files in chunks.
    """

    def __init__(self,
        *filenames: arg(metavar='FILEMASK', nargs='+', type=str, help=(
            'A list of file masks (with wildcard patterns). Each matching '
            'file will be read from disk and emitted.'
        )),
        size: arg.number('-s', help=(
            'If specified, files will be read in chunks of size N and each '
            'chunk is emitted as one element in the output list.'
        )) = 0,
        line: arg.switch('-l', help=(
            'Read the file linewise. By default, one line is read at a time. '
            'In line mode, the --size argument can be used to read the given '
            'number of lines in each chunk.'
        )) = False
    ):
        super().__init__(size=size, line=line, filenames=filenames)

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
        with BytesIO() as out:
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

    def process(self, data):
        for mask in self.args.filenames:
            self.log_info('scanning for mask:', mask)
            for filename in glob(mask, recursive=True):
                if not isfile(filename):
                    continue
                try:
                    with open(filename, 'rb') as stream:
                        if self.args.line:
                            yield from self._read_lines(stream)
                        elif self.args.size:
                            yield from self._read_chunks(stream)
                        else:
                            self.log_info('reading:', filename)
                            yield dict(data=stream.read(), path=filename)
                except PermissionError:
                    self.log_warn('permission denied:', filename)
                except FileNotFoundError:
                    self.log_warn('file is missing:', filename)
                except Exception:
                    self.log_warn('unknown error while reading:', filename)
