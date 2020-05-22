#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import arg, Unit
from ...lib.tools import isbuffer

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
            'file will be read from disk and emitted. In addition to glob '
            'patterns, the file mask can include format string expressions '
            'which will be substituted from the current meta variables.'
        )),
        size: arg.number('-s', help=(
            'If specified, files will be read in chunks of size N and each '
            'chunk is emitted as one element in the output list.'
        )) = 0,
        linewise: arg.switch('-l', help=(
            'Read the file linewise. By default, one line is read at a time. '
            'In line mode, the --size argument can be used to read the given '
            'number of lines in each chunk.'
        )) = False
    ):
        super().__init__(size=size, linewise=linewise, filenames=filenames)

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
        class metamap(dict):
            def __missing__(_, key): # noqa
                try:
                    value = data[key]
                    if isinstance(value, (str, int, float)):
                        return value
                    if isbuffer(value):
                        return value.decode(self.codec)
                except Exception:
                    pass
                return F'{{{key}}}'

        metamap = metamap()

        for mask in self.args.filenames:
            mask = mask.format_map(metamap)
            self.log_debug('scanning for mask:', mask)
            for filename in glob(mask, recursive=True):
                if not isfile(filename):
                    continue
                try:
                    with open(filename, 'rb') as stream:
                        if self.args.linewise:
                            yield from self._read_lines(stream)
                        elif self.args.size:
                            yield from self._read_chunks(stream)
                        else:
                            data = stream.read()
                            self.log_info(lambda: F'reading: {filename} ({len(data)} bytes)')
                            yield dict(data=data, path=filename)
                except PermissionError:
                    self.log_warn('permission denied:', filename)
                except FileNotFoundError:
                    self.log_warn('file is missing:', filename)
                except Exception:
                    self.log_warn('unknown error while reading:', filename)
