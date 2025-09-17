from __future__ import annotations

import io
import os
import os.path

from itertools import cycle
from string import Formatter

from refinery.lib.meta import metavars
from refinery.lib.types import Param
from refinery.units import Arg, RefineryCriticalException, Unit


def _is_path_obstruction(p: str):
    try:
        return os.path.exists(p) and not os.path.isdir(p)
    except Exception:
        return False


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

    If the data cannot be written to the specified path because a file already exists in place of a
    directory that would have to be created, the unit renames the directory until dumping is possible.

    If no file is specified, all ingested inputs are concatenated and written to the clipboard. This
    will only succeed when the data can successfully be encoded.
    """

    def __init__(
        self, *files: Param[str, Arg.String(metavar='file', help='Optionally formatted filename.')],
        tee: Param[bool, Arg.Switch('-t', help='Forward all inputs to STDOUT.')] = False,
        stream: Param[bool, Arg.Switch('-s', help='Dump all incoming data to the same file.')] = False,
        plain: Param[bool, Arg.Switch('-p', help='Never apply any formatting to file names.')] = False,
        force: Param[bool, Arg.Switch('-f', help='Remove files if necessary to create dump path.')] = False,
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
    def _clipcopy(self):
        return not self.args.files

    def _components(self, path: str):
        def _reversed_components(path: str):
            while True:
                path, component = os.path.split(path)
                if not component:
                    break
                yield component
            yield path
        components = list(_reversed_components(path))
        components.reverse()
        return components

    def _fix_path(self, path) -> str:
        base = ''
        *parts, name = self._components(path)
        while parts:
            segment, *parts = parts
            base = os.path.join(base, segment)
            if not _is_path_obstruction(base):
                continue
            elif self.args.force:
                try:
                    os.unlink(base)
                except Exception:
                    raise RefineryCriticalException(F'Unable to dump to {path} because {base} is not a directory.')
                else:
                    self.log_info(F'removing path obstruction: {base}')
                    continue
            else:
                stem, _, ex = base.rpartition('.')
                base = stem = stem or ex
                counter = 1
                while _is_path_obstruction(base):
                    base = F'{stem}.{counter}'
                    counter += 1
        return os.path.join(base, name)

    def _open(self, path, unc=False):
        if hasattr(path, 'close'):
            return path
        for is_second_attempt in (False, True):
            path = os.path.abspath(path)
            base = os.path.dirname(path)
            try:
                os.makedirs(base, exist_ok=True)
            except FileNotFoundError:
                if is_second_attempt:
                    raise
                elif unc or os.name != 'nt':
                    path = self._fix_path(path)
                else:
                    return self._open(F'\\\\?\\{path}', unc=True)
            except FileExistsError:
                if is_second_attempt:
                    raise RefineryCriticalException(F'Unknown error while attempting to create directory: {base}')
                path = self._fix_path(path)
            except OSError as e:
                if not self.log_info():
                    self.log_warn('opening:', path)
                self.log_warn('errored:', e.args[1])
                return open(os.devnull, 'wb')
            else:
                self.log_info('opening:', path[4:] if unc else path)
                mode = 'ab' if self.args.stream else 'wb'
                return open(path, mode)

    def _close(self, final=False):
        if not self.stream:
            return
        self.stream.flush()
        if self.args.stream and not final:
            return
        if self._clipcopy:
            if os.name == 'nt':
                from refinery.lib.winclip import CF, ClipBoard
                try:
                    img = self._image.open(self.stream)
                    with io.BytesIO() as out:
                        img.save(out, 'BMP')
                except Exception:
                    with ClipBoard(CF.TEXT) as cpb:
                        cpb.copy(self.stream.getvalue())
                else:
                    with ClipBoard(CF.DIB) as cpb:
                        out.seek(14, io.SEEK_SET)
                        cpb.copy(out.read())
            else:
                data = self.stream.getvalue()
                data = data.decode(self.codec, errors='backslashreplace')
                self._pyperclip.copy(data)
        self.stream.close()
        self.stream = None

    @Unit.Requires('pyperclip')
    def _pyperclip():
        import pyperclip
        return pyperclip

    @Unit.Requires('Pillow', ['formats'])
    def _image():
        from PIL import Image
        return Image

    def process(self, data: bytearray):
        forward_input_data = self.args.tee
        if self._clipcopy:
            if stream := self.stream:
                stream.write(data)
        elif not self.exhausted:
            if not self.stream:
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
        else:
            forward_input_data = forward_input_data or not self.isatty()
            if not forward_input_data:
                size = metavars(data).size
                self.log_warn(F'discarding unprocessed chunk of size {size!s}.')
        if forward_input_data:
            yield data

    def filter(self, chunks):
        if self.exhausted:
            self._reset()

        nostream = not self.args.stream
        clipcopy = self._clipcopy

        if clipcopy:
            self.stream = io.BytesIO()

        for index, chunk in enumerate(chunks, 0):
            if not chunk.visible:
                continue
            if not clipcopy and not self.exhausted and (nostream or not self.stream):
                try:
                    path = next(self.paths)
                except StopIteration:
                    self.exhausted = True
                else:
                    if self._has_format(path):
                        meta = metavars(chunk)
                        meta.ghost = True
                        meta.index = index
                        path = meta.format_str(path, self.codec, [chunk])
                    self.stream = self._open(path)
            yield chunk

        self._close(final=True)
        self.exhausted = True
