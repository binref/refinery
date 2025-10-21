from __future__ import annotations

import io
import os
import os.path

from functools import lru_cache
from itertools import cycle
from pathlib import Path
from string import Formatter

from refinery.lib.meta import metavars
from refinery.lib.types import Param
from refinery.units import Arg, RefineryCriticalException, Unit


def _is_path_obstruction(p: Path):
    try:
        return p.exists() and not p.is_dir()
    except Exception:
        return False


def _format_fields(filename):
    if not isinstance(filename, str):
        return False
    formatter = Formatter()
    try:
        for _, fields, *__ in formatter.parse(filename):
            if fields:
                yield from fields
    except Exception:
        return


def _has_format(check):
    if isinstance(check, str):
        fields = _format_fields(check)
    elif isinstance(check, (list, tuple, set)):
        fields = check
    else:
        return False
    return any(field.isalnum() for field in fields)


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
        self._formatted = not plain and any(_has_format(f) for f in files)
        self._reset()

    def _reset(self):
        self.exhausted = False
        self.paths = cycle(self.args.files) if self._formatted else iter(self.args.files)
        self._close()

    @property
    def _clipcopy(self):
        return not self.args.files

    @lru_cache(maxsize=None)
    def _fix_path_part(self, base: Path) -> Path:
        if not _is_path_obstruction(base):
            return base
        if self.args.force:
            try:
                os.unlink(base)
            except Exception:
                raise RefineryCriticalException(F'Unable to remove path obstruction: {base}.')
            else:
                self.log_info(F'removed path obstruction: {base}')
                return base
        else:
            stem = base = base.with_suffix('')
            counter = 0
            while _is_path_obstruction(base):
                base = stem.with_suffix(F'.{counter}')
                counter += 1
            return base

    def _fix_path(self, path: Path) -> Path:
        fixed = Path()
        for p in path.parent.parts:
            fixed = self._fix_path_part(fixed / p)
        return fixed / path.name

    def _open(self, path, unc=False):
        if hasattr(path, 'close'):
            return path
        path = self._fix_path(Path(path).absolute())
        base = path.parent
        try:
            os.makedirs(base, exist_ok=True)
        except FileNotFoundError:
            if unc or os.name != 'nt':
                raise
            return self._open(F'\\\\?\\{path}', unc=True)
        except FileExistsError:
            raise RefineryCriticalException(
                F'Unknown error while attempting to create parent directory: {base}')
        except OSError as e:
            if not self.log_info():
                self.log_warn('opening:', path)
            self.log_warn('errored:', e.args[1])
            return open(os.devnull, 'wb')
        else:
            info = str(path)
            self.log_info('opening:', info[4:] if unc else info)
            mode = 'ab' if self.args.stream else 'wb'
            return path.open(mode)

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
                    if _has_format(path):
                        meta = metavars(chunk)
                        meta.ghost = True
                        meta.index = index
                        new_path = meta.format_str(path, self.codec, [chunk])
                        if new_path != path:
                            path = new_path
                        elif self.leniency < 1:
                            raise ValueError(
                                F'Could not resolve formatting in path "{path}"; '
                                R'increase leniency to ignore this.')
                    self.stream = self._open(path)
            yield chunk

        self._close(final=True)
        self.exhausted = True


class d2p(dump):
    """
    Stands for "dump to path"; this is a shortcut for the `refinery.dump` unit which is equivalent
    to running:

        dump {path}

    This will dump all chunk in the current frame to the path given by the `path` meta variable,
    which is cmmonly set by units like `refinery.xt`.
    """
    def __init__(self, tee=False, stream=False, plain=False, force=False):
        super().__init__('{path}', tee=tee, stream=stream, plain=plain, force=force)
