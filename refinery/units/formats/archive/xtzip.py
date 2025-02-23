#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import Optional

from datetime import datetime

from refinery.units.formats.archive import ArchiveUnit
from refinery.lib.structures import MemoryFile
from refinery.units.pattern.carve_zip import ZipEndOfCentralDirectory, carve_zip

ZIP_FILENAME_UTF8_FLAG = 0x800


class xtzip(ArchiveUnit):
    """
    Extract files from a Zip archive.
    """
    @ArchiveUnit.Requires('chardet', 'default', 'extended')
    def _chardet():
        import chardet
        return chardet

    @ArchiveUnit.Requires('pyzipper', 'arc', 'default', 'extended')
    def _pyzipper():
        import pyzipper
        return pyzipper

    @classmethod
    def _carver(cls):
        return carve_zip

    def unpack(self, data: bytearray):
        from zipfile import ZipInfo, ZipFile, BadZipFile

        def password_invalid(password: Optional[bytes]):
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
        else:
            raise RuntimeError('Archive is password-protected.')

        for info in archive.infolist():
            def xt(archive: ZipFile = archive, info: ZipInfo = info):
                try:
                    return archive.read(info.filename)
                except RuntimeError as E:
                    if 'password' not in str(E):
                        raise
                    if not password:
                        raise RuntimeError('archive is password-protected')
                    else:
                        raise RuntimeError(F'invalid password: {password.decode(self.codec)}') from E
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
    def handles(cls, data: bytearray) -> Optional[bool]:
        return data.rfind(ZipEndOfCentralDirectory.SIGNATURE) > 0
