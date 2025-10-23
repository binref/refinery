from __future__ import annotations

import re

from typing import TYPE_CHECKING

from refinery.lib.id import buffer_offset, is_likely_pe
from refinery.lib.structures import MemoryFile
from refinery.units.formats.archive import ArchiveUnit
from refinery.units.formats.pe import get_pe_size

if TYPE_CHECKING:
    from py7zr import SevenZipFile


_SIGNATURE = B'7z\xBC\xAF\x27\x1C'


class _IOFactory:
    def __init__(self):
        self.buffer = None

    def create(self, _):
        if self.buffer is not None:
            raise RuntimeError('IO factory was unexpectedly called twice.')
        self.buffer = MemoryFile()
        return self.buffer


class xt7z(ArchiveUnit, docs='{0}{s}{PathExtractorUnit}'):
    """
    Extract files from a 7zip archive.
    """
    @ArchiveUnit.Requires('py7zr', ['arc', 'default', 'extended'])
    def _py7zr():
        import py7zr
        import py7zr.exceptions
        return py7zr

    def unpack(self, data: bytearray):
        for match in re.finditer(re.escape(_SIGNATURE), data):
            start = match.start()
            if start != 0:
                self.log_info(F'found a header at offset 0x{start:X}, trying to extract from there.')
            try:
                yield from self._unpack_from(data, start)
            except self._py7zr.Bad7zFile:
                continue
            else:
                break

    def _unpack_from(self, data: bytearray, zp: int = 0):
        def mk7z(**keywords):
            return self._py7zr.SevenZipFile(MemoryFile(mv[zp:]), **keywords)

        pwd = self.args.pwd
        mv = memoryview(data)
        archive = None

        def test(archive: SevenZipFile):
            if self.args.list:
                archive.list()
                return False
            return archive.testzip()

        if pwd:
            try:
                archive = mk7z(password=pwd.decode(self.codec))
            except self._py7zr.Bad7zFile:
                raise ValueError('corrupt archive; the password is likely invalid.')
        else:
            def passwords():
                yield None
                yield from self._COMMON_PASSWORDS
            for pwd in passwords():
                if pwd is None:
                    self.log_debug('trying empty password')
                else:
                    self.log_debug(F'trying password: {pwd}')
                try:
                    archive = mk7z(password=pwd)
                    problem = test(archive)
                except self._py7zr.PasswordRequired:
                    problem = True
                except self._py7zr.UnsupportedCompressionMethodError as E:
                    raise ValueError(E.message)
                except self._py7zr.exceptions.InternalError:
                    # ignore internal errors during testzip
                    break
                except SystemError:
                    problem = True
                except Exception:
                    if pwd is None:
                        raise
                    problem = True
                if not problem:
                    break
            else:
                raise ValueError('a password is required and none of the default passwords worked.')

        assert archive is not None
        has_read_method = hasattr(archive, 'read')

        for info in archive.list():
            if has_read_method:
                def extract(archive: SevenZipFile = archive, name: str = info.filename):
                    archive.reset()
                    io = archive.read([name])
                    io = io[name]
                    io.seek(0)
                    return io.read()
            else:
                def extract(archive: SevenZipFile = archive, name: str = info.filename):
                    io = _IOFactory()
                    archive.reset()
                    archive.extract(None, [name], factory=io)
                    return io.buffer.getvalue()

            if info.is_directory:
                continue

            yield self._pack(
                info.filename,
                info.creationtime,
                extract,
                crc32=info.crc32,
                uncompressed=info.uncompressed
            )

    @classmethod
    def handles(cls, data) -> bool | None:
        if data[:6] == _SIGNATURE:
            return True
        if not is_likely_pe(data):
            return None
        offset = get_pe_size(data)
        memory = memoryview(data)
        memory = memory[offset:]
        if memory[:10] == B';!@Install' and buffer_offset(memory, _SIGNATURE, 0, 0x1000) > 0:
            return True
