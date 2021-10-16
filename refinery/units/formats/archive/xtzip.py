#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import Optional

from datetime import datetime
from zipfile import ZipInfo, ZipFile

from refinery.units.formats.archive import ArchiveUnit
from refinery.lib.structures import MemoryFile

ZIP_FILENAME_UTF8_FLAG = 0x800


class xtzip(ArchiveUnit):
    """
    Extract files from a Zip archive.
    """
    @ArchiveUnit.Requires('chardet', optional=True)
    def _chardet():
        import chardet
        return chardet

    def unpack(self, data):
        password = self.args.pwd.decode(self.codec)
        archive = ZipFile(MemoryFile(data))

        if password:
            archive.setpassword(self.args.pwd)
        else:
            def password_invalid(pwd: Optional[str]):
                if pwd is not None:
                    archive.setpassword(pwd.encode(self.codec))
                try:
                    archive.testzip()
                except RuntimeError as E:
                    if 'password' not in str(E):
                        raise
                    return True
                else:
                    self.log_debug(pwd)
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
                        raise RuntimeError(F'invalid password: {password}') from E
            if info.is_dir():
                continue
            try:
                date = datetime(*info.date_time)
            except Exception:
                date = None

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

            yield self._pack(filename, date, xt)
