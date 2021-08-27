#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import os.path

from itertools import cycle
from string import Formatter

from .. import arg, Unit, RefineryCriticalException
from ...lib.meta import metavars


class dump(Unit):
    """
    Dump incoming data to files on disk. It is possible to specify filenames with format fields.
    Any metadata field on an incoming chunk is available. Additionally, any field that can be
    populated by the `refinery.cm` unit is also available. These include the following:

        {ext}    : Automatically guessed file extension
        {crc32}  : CRC32 checksum of the data
        {index}  : Index of the data in the input stream, starting at 0
        {size}   : Size of the data in bytes
        {md5}    : MD5 hash of the data
        {sha1}   : SHA1 hash of the data
        {sha256} : SHA-256 hash of the data
        {path}   : Associated path; defaults to {sha256} if none is given.

    When not using formatted file names, the unit ingests as many incoming inputs as filenames were
    specified on the command line. Unless connected to a terminal, the remaining inputs will be
    forwarded on STDOUT. The `-t` or `--tee` switch can be used to forward all inputs, under all
    circumstances, regardless of whether or not they have been processed.

    If no file is specified, the first ingested input is dumped to the clipboard.
    """

    def __init__(
        self, *files: arg(metavar='file', type=str, help='Optionally formatted filename.'),
        tee    : arg.switch('-t', help='Forward all inputs to STDOUT.') = False,
        stream : arg.switch('-s', help='Dump all incoming data to the same file.') = False,
        plain  : arg.switch('-p', help='Never apply any formatting to file names.') = False,
        force  : arg.switch('-f', help='Remove files if necessary to create dump path.') = False,
    ):
        if stream and len(files) != 1:
            raise ValueError('Can only use exactly one file in stream mode.')
        super().__init__(files=files, tee=tee, stream=stream, force=force)
        self.stream = None
        self._formatted = not plain and any(self._has_format(f) for f in files)
        self._reset()

    @staticmethod
    def _has_format(filename):
        if not isinstance(filename, str):
            return False
        formatter = Formatter()
        return any(
            any(t.isalnum() for t in fields)
            for _, fields, *__ in formatter.parse(filename) if fields
        )

    def _reset(self):
        self.exhausted = False
        self.paths = cycle(self.args.files) if self._formatted else iter(self.args.files)
        self._close()

    @property
    def _paste(self):
        return not self.args.files

    def _components(self, path):
        def _reversed_components(path):
            while True:
                path, component = os.path.split(path)
                if not component:
                    break
                yield component
            yield path
        components = list(_reversed_components(path))
        components.reverse()
        return components

    def _open(self, path, unc=False):
        if hasattr(path, 'close'):
            return path
        path = os.path.abspath(path)
        base = os.path.dirname(path)
        if not unc:
            self.log_info('opening:', path)
        try:
            os.makedirs(base, exist_ok=True)
        except FileExistsError:
            self.log_info('existed:', path)
            part, components = '', self._components(path)
            while components:
                component, *components = components
                part = os.path.join(part, component)
                if os.path.exists(part) and os.path.isfile(part):
                    if self.args.force:
                        os.unlink(part)
                        return self._open(path, unc)
                    break
            raise RefineryCriticalException(F'Unable to dump to {path} because {part} is a file.')
        except FileNotFoundError:
            if unc or os.name != 'nt':
                raise
            path = F'\\\\?\\{path}'
            return self._open(path, unc=True)
        except OSError as e:
            if not self.log_info():
                self.log_warn('opening:', path)
            self.log_warn('errored:', e.args[1])
            return open(os.devnull, 'wb')
        else:
            mode = 'ab' if self.args.stream else 'wb'
            return open(path, mode)

    def _close(self, final=False):
        if not self.stream:
            return
        self.stream.flush()
        if self.args.stream and not final:
            return
        self.stream.close()
        self.stream = None

    def process(self, data):
        if not self.exhausted:
            if self._paste:
                import codecs
                import pyperclip
                pyperclip.copy(codecs.decode(
                    data, 'utf-8', errors='backslashreplace'))
            elif not self.stream:
                # This should happen only when the unit is called from Python code
                # rather than via the command line.
                try:
                    path = next(self.paths)
                except StopIteration:
                    raise RefineryCriticalException('the list of filenames was exhausted.')
                else:
                    with self._open(path) as stream:
                        stream.write(data)
            else:
                self.stream.write(data)
                self.log_debug(F'wrote 0x{len(data):08X} bytes')
                self._close()
            forward_input_data = self.args.tee
        else:
            forward_input_data = self.args.tee or not self.isatty
            if not forward_input_data:
                meta = metavars(data)
                size = meta['size']
                self.log_warn(F'discarding unprocessed chunk of size {size!s}.')

        if forward_input_data:
            yield data

    def filter(self, chunks):
        if self.exhausted:
            self._reset()

        if self._paste:
            it = iter(chunks)
            yield next(it)
            self.exhausted = True
            yield from it
            return

        chunkmode = not self.args.stream
        for index, chunk in enumerate(chunks, 0):
            if not chunk.visible:
                continue
            if not self.exhausted and (chunkmode or not self.stream):
                try:
                    path = next(self.paths)
                except StopIteration:
                    self.exhausted = True
                else:
                    if self._has_format(path):
                        meta = metavars(chunk, ghost=True)
                        meta['index'] = index
                        path = meta.format_str(path, self.codec, chunk)
                    self.stream = self._open(path)
            yield chunk

        self._close(final=True)
        self.exhausted = True
