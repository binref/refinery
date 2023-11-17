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
    @ArchiveUnit.Requires('chardet', 'default')
    def _chardet():
        import chardet
        return chardet

    @ArchiveUnit.Requires('pyzipper', 'arc', 'default')
    def _pyzipper():
        import pyzipper
        return pyzipper

    def unpack(self, data: bytearray):
        if not data.startswith(B'PK'):
            self.log_info('input file is not a zip file, attempting to carve one')
            data = next(data | carve_zip)
            offset = data['offset']
            self.log_debug(F'carved a zip file from 0x{offset:X}')

        from zipfile import ZipFile, ZipInfo

        password = bytes(self.args.pwd)
        archive = ZipFile(MemoryFile(data))

        if password:
            archive.setpassword(password)
        else:
            def password_invalid(pwd: Optional[str], pyzipper=False):
                nonlocal archive
                if pwd is not None:
                    archive.setpassword(pwd.encode(self.codec))
                try:
                    archive.testzip()
                except NotImplementedError:
                    if pyzipper:
                        raise
                    self.log_debug('compression method unsupported, switching to pyzipper')
                    archive = self._pyzipper.AESZipFile(MemoryFile(data))
                    return password_invalid(pwd, True)
                except RuntimeError as E:
                    if 'password' not in str(E):
                        raise
                    return True
                else:
                    if pwd:
                        self.log_debug('using password:', pwd)
                    return False
            for pwd in [None, *self._COMMON_PASSWORDS]:
                if not password_invalid(pwd):
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
