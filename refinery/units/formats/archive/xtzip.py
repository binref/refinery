from __future__ import annotations

import codecs

from refinery.lib import lief
from refinery.lib.id import buffer_offset, is_likely_pe
from refinery.lib.types import buf
from refinery.lib.zip import InvalidChecksum, InvalidPassword, PasswordRequired, Zip, ZipDirEntry
from refinery.units import RefineryPartialResult
from refinery.units.formats.archive import ArchiveUnit, MultipleArchives
from refinery.units.formats.pe import get_pe_size


class xtzip(ArchiveUnit, docs='{0}{s}{PathExtractorUnit}'):
    """
    Extract files from a Zip archive.
    """
    def unpack(self, data: buf):
        def trypwd(password: str | None):
            try:
                zipf = Zip(view, password)
            except (PasswordRequired, InvalidPassword):
                return None
            for file in zipf.records.values():
                if file.is_dir():
                    continue
                if file.is_password_ok(password):
                    break
                return False
            return zipf

        view = memoryview(data)
        password = self.args.pwd
        if not password:
            password = None
        elif not isinstance(password, str):
            password = codecs.decode(password, self.codec)
        passwords = [password]
        if not password:
            passwords.extend(self._COMMON_PASSWORDS)
        for p in passwords:
            if zipf := trypwd(p):
                break
        else:
            zipf = Zip(view, password)

        if some := zipf.sub_archive_count() and not self.args.lenient:
            text = (
                F'The input contains {some + 1} archives. Use the xtzip unit to extract '
                R'them individually or set the --lenient/-L option to fuse the archives.')
            raise MultipleArchives(text)

        if zipf.password:
            self.log_debug('Using password:', zipf.password)

        if boundary := zipf.coverage.boundary():
            w = len(hex(boundary[1]))
            for start, end in zipf.coverage.gaps():
                self.log_info(F'data cave detected at range {start:#0{w}x}:{end:#0{w}x}')
                yield self._pack(F'.{start:#0{w}x}.cave', None, view[start:end])

        for entry in zipf.directory:
            def xt(entry=entry):
                record = zipf.read(entry)
                try:
                    return record.unpack(zipf.password)
                except InvalidChecksum as ck:
                    raise RefineryPartialResult('invalid checksum', ck.data) from ck
                except InvalidPassword:
                    if not record.data:
                        raise
                    msg = 'invalid password; use -L to extract raw encrypted data'
                    raise RefineryPartialResult(msg, record.data)
            if entry.is_dir():
                continue
            yield self._pack(entry.name, entry.date, xt)

    @classmethod
    def handles(cls, data):
        if data[:4] in (
            B'PK\x03\x04',
            B'PK\x07\x08',
        ):
            return True
        if not is_likely_pe(data):
            return False
        memory = memoryview(data)
        if 0 <= buffer_offset(memory[-0x400:], ZipDirEntry.Signature):
            return True
        pe = lief.load_pe_fast(data)
        offset = get_pe_size(pe)
        if 0 <= buffer_offset(memory[offset:], B'PK\x03\x04') < 0x1000:
            return True
        if not pe.has_debug:
            return False
        for entry in pe.debug:
            if not isinstance(entry, lief.PE.CodeViewPDB):
                continue
            path = entry.filename
            if not isinstance(path, str):
                path = codecs.decode(path, 'latin1')
            if 'sfxzip32' in path and 'WinRAR' in path:
                return True
