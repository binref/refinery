#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import os.path

from itertools import cycle

from .. import Unit, RefineryCriticalException


class dump(Unit):
    """
    Dump incoming data to files on disk. It is possible to specify filenames with
    format fields using the `-f` or `--format` switch. The following format fields
    are supported:

         {ext} : Automatically guessed file extension
       {crc32} : CRC32 checksum of the data
       {index} : Index of the data in the input stream, starting at 1
      {length} : Size of the data in bytes
         {md5} : MD5 hash of the data
        {sha1} : SHA1 hash of the data
      {sha256} : SHA-256 hash of the data

    When not using formatted file names, the unit ingests as many incoming inputs
    as filenames were specified on the command line. Unless connected to a terminal,
    the remaining inputs will be forwarded on STDOUT. The `-t` or `--tee` switch
    can be used to forward all inputs, under all circumstances, regardless of
    whether or not they have been processed.

    If no file is specified, the first ingested input is dumped to the clipboard.
    """

    @classmethod
    def interface(cls, argp):
        argp.add_argument(
            'filenames',
            type=str,
            default=None,
            nargs='*',
            help='Output file',
            metavar='file'
        )
        argp.add_argument('-t', '--tee', action='store_true',
            help='Forward all inputs to STDOUT.')

        mode = argp.add_mutually_exclusive_group()
        mode.add_argument('-s', '--stream', action='store_true',
            help='Dump all incoming inputs to the same file.')

        mode.add_argument(
            '-m', '--meta', action='store_true', help=(
                'Automatically choose a filename. For multiple inputs, some '
                'units provide a file name in their output; in this case, '
                'this file name is used. Otherwise, the format {sha256} '
                'is used as the file name.'
            )
        )
        mode.add_argument(
            '-f', '--format', action='store_true', help=(
                'Provide format strings instead of a list of filenames. '
                'The format strings will be used cyclically to generate '
                'a file name for each input to be dumped.'
            )
        )

        return super().interface(argp)

    def __init__(self, *args, **kw):
        super().__init__(*args, **kw)
        self._reset()

    def _auto_extension(self, data, default='bin'):
        import re
        from ...lib.magic import magic, magicparse

        if not magic:
            self.log_warn(F'magic library not found, auto extension defaults to {default}')
            return default

        if not isinstance(data, bytes):
            data = bytes(data)

        mime = magicparse(data, mime=True)
        mime = mime.split(';')[0].lower()
        mtype, mext = mime.split('/')

        if mext == 'x-dosexec':
            description = magicparse(data)
            if re.search('executable', description):
                return 'dll' if '(DLL)' in description else 'exe'
        try:
            return {
                'octet-stream'                : 'bin',
                'plain'                       : 'txt',
                'javascript'                  : 'js',
                'java-archive'                : 'jar',
                'svg+xml'                     : 'svg',
                'x-icon'                      : 'ico',
                'wave'                        : 'wav',
                'x-pn-wav'                    : 'wav',
                'x-ms-wim'                    : 'wim',
                'vnd.android.package-archive' : 'apk',
                'vnd.ms-cab-compressed'       : 'cab',
                'x-apple-diskimage'           : 'dmg',
            }[mext]
        except KeyError:
            if 'gzip' in mext:
                import gzip
                ungz = gzip.decompress(data)
                ext1 = self._auto_extension(ungz)
                return ext1 + '.gz'
            xtype_match = re.match(
                r'^x-(\w{2,4})(-compressed)?$',
                mext,
                re.IGNORECASE
            )
            if xtype_match:
                return xtype_match.group(1)
            if len(mext) < 6 and re.match('[a-z]+', mext):
                return mext
            return default

    def _reset(self):
        self.stream = None
        self.exhausted = False
        if self.args.meta:
            self.iter_filenames = iter(())
        elif self.args.format:
            self.iter_filenames = cycle(self.args.filenames)
        else:
            self.iter_filenames = iter(self.args.filenames)
        if self.args.stream and len(self.args.filenames) > 1:
            raise ValueError('can only use one file in stream mode.')

    @property
    def _paste(self):
        return not bool(self.args.filenames) and not bool(self.args.format) and not self.args.meta

    def _open(self, filename, unc=False):
        filename = os.path.abspath(filename)
        base = os.path.dirname(filename)
        if not unc:
            self.log_info('opening:', filename)
        try:
            os.makedirs(base, exist_ok=True)
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

    def _format(self, filename, data, index=0):
        class DelayedFormatter(dict):
            def __missing__(_, key):  # noqa: W291
                if key == 'crc32':
                    from zlib import crc32
                    return F'{crc32(data) & 0xFFFFFFFF:08X}'
                if key == 'ext':
                    return self._auto_extension(data)
                if key in ('md5', 'sha1', 'sha256'):
                    import hashlib
                    algorithm = getattr(hashlib, key)
                    return algorithm(data).hexdigest()
                return '{' + key + '}'
        return filename.format_map(
            DelayedFormatter(dict(index=index, length=len(data)))
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
                    filename = next(self.iter_filenames)
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

        for index, chunk in enumerate(chunks):
            if self.exhausted:
                continue
            if not self.args.stream or not self.stream:
                try:
                    if not self.args.meta:
                        filename = next(self.iter_filenames)
                    else:
                        filename = chunk['path']
                        if not filename:
                            import hashlib
                            filename = hashlib.sha256(chunk).hexdigest()
                except StopIteration:
                    self.exhausted = True
                else:
                    if self.args.format:
                        filename = self._format(filename, chunk, index + 1)
                    self.stream = self._open(filename)
            yield chunk

        self._close()
        self.exhausted = True
