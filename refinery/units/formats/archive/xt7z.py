from __future__ import annotations

import re

from refinery.lib.id import buffer_offset, is_likely_pe
from refinery.lib.un7z import (
    SIGNATURE,
    SzArchive,
    SzCannotUnpack,
    SzChecksumMismatch,
    SzCorruptArchive,
    SzUnsupportedMethod,
)
from refinery.units import RefineryPartialResult
from refinery.units.formats.archive import ArchiveUnit
from refinery.units.formats.pe import get_pe_size


class xt7z(ArchiveUnit, docs='{0}{p}{PathExtractorUnit}'):
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
        extractors: list = []
        probed = None

        def prepare(archive: SzArchive, password):
            return [(info, info.extractor(password)) for info in archive.files if not info.is_dir]

        def checked(read):
            try:
                return read()
            except SzChecksumMismatch as mismatch:
                raise RefineryPartialResult(str(mismatch), mismatch.data) from mismatch

        if pwd:
            pwd = pwd.decode(self.codec)
            try:
                archive = try_open(pwd)
            except SzCorruptArchive:
                raise ValueError('corrupt archive; the password is likely invalid.')
            extractors = prepare(archive, pwd)
        else:
            def passwords():
                yield None
                yield from self.CommonPasswords
            unlocked = None
            for pwd in passwords():
                if pwd is None:
                    self.log_debug('trying empty password')
                else:
                    self.log_debug(F'trying password: {pwd}')
                trial = None
                try:
                    trial = try_open(pwd)
                    extractors = prepare(trial, pwd)
                    if pwd is None:
                        unlocked = trial, extractors
                    probed = next(((k, read()) for k, (info, read) in enumerate(extractors) if info.encrypted), None)
                    problem = False
                except SzUnsupportedMethod as E:
                    raise ValueError(str(E))
                except SzCannotUnpack:
                    problem = True
                except Exception:
                    if pwd is None:
                        raise
                    problem = True
                if not problem:
                    archive = trial
                    break
            else:
                if unlocked is None:
                    raise ValueError('a password is required and none of the default passwords worked.')
                self.log_info('none of the default passwords worked; extracting the files that are not encrypted')
                archive, extractors = unlocked
                probed = None

        assert archive is not None

        for k, (info, extract) in enumerate(extractors):
            yield self._pack(
                info.name,
                info.mtime or info.ctime,
                probed[1] if probed is not None and probed[0] == k else lambda read=extract: checked(read),
                checksum=info.crc,
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
