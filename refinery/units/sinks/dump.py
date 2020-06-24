#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import os.path

from itertools import cycle

from .. import arg, Unit, RefineryCriticalException
from ...lib.mime import file_extension_from_data, NoMagicAvailable


class dump(Unit):
    """
    Dump incoming data to files on disk. It is possible to specify filenames with format fields.
    The following format fields are supported. Additionally, any metadata field on an incoming chunk
    can also be used.

        {ext}    : Automatically guessed file extension
        {crc32}  : CRC32 checksum of the data
        {index}  : Index of the data in the input stream, starting at 1
        {length} : Size of the data in bytes
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
        self, *filenames: str,
        tee    : arg.switch('-t', help='Forward all inputs to STDOUT.') = False,
        stream : arg.switch('-s', help='Dump all incoming data to the same file.') = False,
        plain  : arg.switch('-p', help='Never apply any formatting to file names.') = False,
        force  : arg.switch('-f', help='Remove files if necessary to create dump path.') = False,
    ):
        if stream and len(filenames) != 1:
            raise ValueError('Can only use exactly one file in stream mode.')
        super().__init__(filenames=filenames, tee=tee, stream=stream, force=force)
        if plain:
            self.formatted = False
        else:
            from string import Formatter
            nf = Formatter()
            self.formatted = any(any(t.isalnum() for t in fields)
                for f in filenames for _, fields, *__ in nf.parse(f) if fields)
        self._reset()

    def _reset(self):
        self.stream = None
        self.exhausted = False
        if self.formatted:
            self.paths = cycle(self.args.filenames)
        else:
            self.paths = iter(self.args.filenames)

    @property
    def _paste(self):
        return not self.args.filenames

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

    def _open(self, filename, unc=False):
        filename = os.path.abspath(filename)
        base = os.path.dirname(filename)
        if not unc:
            self.log_info('opening:', filename)
        try:
            os.makedirs(base, exist_ok=True)
        except FileExistsError:
            path, components = '', self._components(filename)
            while components:
                component, *components = components
                path = os.path.join(path, component)
                if os.path.exists(path) and os.path.isfile(path):
                    if self.args.force:
                        os.unlink(path)
                        return self._open(filename, unc)
                    break
            raise RefineryCriticalException(F'Unable to dump to {filename} because {path} is a file.')
        except FileNotFoundError:
            if unc or os.name != 'nt':
                raise
            filename = F'\\\\?\\{filename}'
            return self._open(filename, unc=True)
        else:
            return open(filename, 'wb')

    def _close(self):
        if self.stream:
            self.stream.flush()
            self.stream.close()
            self.stream = None

    def _format(self, filename, data, index=0, **meta):
        class DelayedFormatter(dict):
            dmp = self

            def __missing__(self, key):
                if key == 'crc32':
                    from zlib import crc32
                    return F'{crc32(data) & 0xFFFFFFFF:08X}'
                if key == 'ext':
                    try:
                        return file_extension_from_data(data)
                    except NoMagicAvailable:
                        self.dmp.log_warn('no magic library available, using default extension .bin')
                        return 'bin'
                if key == 'path':
                    key = 'sha256'
                if key in ('md5', 'sha1', 'sha256'):
                    import hashlib
                    algorithm = getattr(hashlib, key)
                    return algorithm(data).hexdigest()
                return '{' + key + '}'

        return filename.format_map(
            DelayedFormatter(dict(index=index, length=len(data), **meta))
        )

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
                    filename = next(self.paths)
                except StopIteration:
                    raise RefineryCriticalException('the list of filenames was exhausted.')
                else:
                    with self._open(filename) as stream:
                        stream.write(data)
            else:
                self.stream.write(data)
                self.log_debug(F'wrote 0x{len(data):08X} bytes')
                if not self.args.stream:
                    self._close()
            forward_input_data = self.args.tee
        else:
            forward_input_data = self.args.tee or not self.isatty
            if not forward_input_data:
                self.log_debug(F'discarding unprocessed chunk of size {len(data)}.')

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

        for index, chunk in enumerate(chunks, 1):
            if self.exhausted:
                continue
            if not self.args.stream or not self.stream:
                try:
                    filename = next(self.paths)
                except StopIteration:
                    self.exhausted = True
                else:
                    if self.formatted:
                        filename = self._format(filename, chunk, index, **chunk.meta)
                    self.stream = self._open(filename)
            yield chunk

        self._close()
        self.exhausted = True
