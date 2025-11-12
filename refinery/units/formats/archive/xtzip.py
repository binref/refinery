from __future__ import annotations

import codecs

from datetime import datetime

from refinery.lib import lief
from refinery.lib.id import buffer_offset, is_likely_pe
from refinery.lib.structures import MemoryFile, Struct, StructReader
from refinery.lib.types import buf
from refinery.units import RefineryPartialResult
from refinery.units.formats.archive import ArchiveUnit
from refinery.units.formats.pe import get_pe_size
from refinery.units.pattern.carve_zip import ZipEndOfCentralDirectory, carve_zip

ZIP_FILENAME_UTF8_FLAG = 0x800


class _FileRecord(Struct):
    def __init__(self, reader: StructReader[memoryview]):
        if reader.u32() != 0x04034B50:
            raise ValueError
        self.version = reader.u16()
        self.flags = reader.u16()
        self.method = reader.u16()
        self.mtime = reader.u16()
        self.mdate = reader.u16()
        self.crc32 = reader.u32()
        self.csize = reader.u32()
        self.usize = reader.u32()
        nl = reader.u16()
        xl = reader.u16()
        self.name = reader.read_exactly(nl)
        self.xtra = reader.read_exactly(xl)
        self.data = reader.read_exactly(self.csize)


class xtzip(ArchiveUnit, docs='{0}{s}{PathExtractorUnit}'):
    """
    Extract files from a Zip archive.
    """
    @ArchiveUnit.Requires('chardet', ['default', 'extended'])
    def _chardet():
        import chardet
        return chardet

    @ArchiveUnit.Requires('pyzipper', ['arc', 'default', 'extended'])
    def _pyzipper():
        import pyzipper
        return pyzipper

    @classmethod
    def _carver(cls):
        return carve_zip

    def unpack(self, data: buf):
        from zipfile import BadZipFile, ZipFile, ZipInfo

        def password_invalid(password: bytes | None):
            nonlocal archive, fallback
            if password:
                archive.setpassword(password)
            try:
                archive.testzip()
                files = (t for t in archive.infolist() if t.filename and not t.is_dir())
                files = sorted(files, key=lambda info: info.file_size)
                for info in files:
                    self.log_debug('testing password against:', info.filename)
                    try:
                        with archive.open(info.filename, "r") as test:
                            while test.read(1024):
                                pass
                    except BadZipFile:
                        continue
                    else:
                        break
            except NotImplementedError:
                if fallback:
                    raise
                self.log_debug('compression method unsupported, switching to pyzipper')
                archive = self._pyzipper.AESZipFile(MemoryFile(data))
                fallback = True
                return password_invalid(password)
            except RuntimeError as E:
                if 'password' not in str(E):
                    raise
                return True
            else:
                if password:
                    self.log_debug('using password:', password)
                return False

        password = bytes(self.args.pwd)
        fallback = False
        archive = ZipFile(MemoryFile(data))
        passwords = [password]

        if not password:
            passwords.extend(p.encode(self.codec) for p in self._COMMON_PASSWORDS)
        for p in passwords:
            if not password_invalid(p):
                break

        for info in archive.infolist():
            def xt(archive: ZipFile = archive, info: ZipInfo = info, view=memoryview(data)):
                try:
                    return archive.read(info.filename)
                except RuntimeError as E:
                    if 'password' not in str(E):
                        raise
                    msg = 'invalid password; use -L to extract raw encrypted data'
                    rec = _FileRecord.Parse(view[info.header_offset:])
                    raise RefineryPartialResult(msg, rec.data) from E

            if info.filename:
                if info.is_dir():
                    continue

            # courtesy of https://stackoverflow.com/a/37773438/9130824
            filename = info.filename
            if info.flag_bits & ZIP_FILENAME_UTF8_FLAG == 0:
                filename_bytes = filename.encode('437')
                try:
                    guessed_encoding = self._chardet.detect(filename_bytes)['encoding']
                except ImportError:
                    guessed_encoding = None
                guessed_encoding = guessed_encoding or 'cp1252'
                filename = filename_bytes.decode(guessed_encoding, 'replace')

            try:
                date = datetime(*info.date_time)
            except Exception as e:
                self.log_info(F'{e!s} - unable to determine date from tuple {info.date_time} for: {filename}')
                date = None

            yield self._pack(filename, date, xt)

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
        if 0 <= buffer_offset(memory[-0x400:], ZipEndOfCentralDirectory.SIGNATURE):
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
