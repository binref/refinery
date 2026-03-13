from __future__ import annotations

import re

from refinery.lib.id import buffer_offset, is_likely_pe
from refinery.lib.un7z import (
    SIGNATURE,
    SzArchive,
    SzCorruptArchive,
    SzInvalidPassword,
    SzPasswordRequired,
    SzUnsupportedMethod,
)
from refinery.units.formats.archive import ArchiveUnit
from refinery.units.formats.pe import get_pe_size


class xt7z(ArchiveUnit, docs='{0}{s}{PathExtractorUnit}'):
    """
    Extract files from a 7zip archive.
    """

    def unpack(self, data: bytearray):
        for match in re.finditer(re.escape(SIGNATURE), data):
            start = match.start()
            if start != 0:
                self.log_info(F'found a header at offset 0x{start:X}, trying to extract from there.')
            try:
                yield from self._unpack_from(data, start)
            except SzCorruptArchive:
                continue
            else:
                break

    def _unpack_from(self, data: bytearray, zp: int = 0):
        mv = memoryview(data)
        chunk = mv[zp:]
        pwd = self.args.pwd

        def try_open(password: str | bytes | None) -> SzArchive:
            return SzArchive(chunk, password=password)

        archive: SzArchive | None = None

        if pwd:
            try:
                archive = try_open(pwd.decode(self.codec))
            except SzCorruptArchive:
                raise ValueError('corrupt archive; the password is likely invalid.')
        else:
            def passwords():
                yield None
                yield from self.CommonPasswords
            for pwd in passwords():
                if pwd is None:
                    self.log_debug('trying empty password')
                else:
                    self.log_debug(F'trying password: {pwd}')
                try:
                    archive = try_open(pwd)
                    for f in archive.files:
                        if not f.is_dir:
                            f.decompress(password=pwd)
                            break
                    problem = False
                except SzPasswordRequired:
                    problem = True
                except SzUnsupportedMethod as E:
                    raise ValueError(str(E))
                except SzInvalidPassword:
                    problem = True
                except SzCorruptArchive:
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

        for info in archive.files:
            if info.is_dir:
                continue

            def extract(f=info, p=pwd):
                return f.decompress(password=p)

            yield self._pack(
                info.name,
                info.mtime or info.ctime,
                extract,
                crc32=info.crc,
                uncompressed=info.size,
            )

    @classmethod
    def handles(cls, data) -> bool | None:
        if data[:6] == SIGNATURE:
            return True
        if not is_likely_pe(data):
            return None
        offset = get_pe_size(data)
        memory = memoryview(data)
        memory = memory[offset:]
        if memory[:10] == B';!@Install' and buffer_offset(memory, SIGNATURE, 0, 0x1000) > 0:
            return True
