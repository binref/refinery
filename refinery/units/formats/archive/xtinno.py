#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import re

from refinery.units.formats.archive import ArchiveUnit

from refinery.lib.mime import FileMagicInfo as magic
from refinery.lib.json import BytesAsArrayEncoder
from refinery.lib.inno.archive import InnoArchive, InvalidPassword, SetupFileFlags


class xtinno(ArchiveUnit):
    """
    Extract files from InnoSetup archives.
    """
    _STREAM_NAMES = 'meta/TSetup', 'meta/TData', 'embedded/uninstaller.exe'
    _ISCRIPT_NAME = 'embedded/script'
    _LICENSE_NAME = 'embedded/license.rtf'

    def unpack(self, data: bytearray):
        inno = InnoArchive(data, self)

        password: bytes = self.args.pwd
        password = password.decode(self.codec) if password else ''

        if any(file.encrypted for file in inno.files) and password is None:
            self.log_info('some files are password-protected and no password was given')

        yield self._pack(self._STREAM_NAMES[0], None, inno.streams.TSetup.data)
        with BytesAsArrayEncoder as encoder:
            yield self._pack(F'{self._STREAM_NAMES[0]}.json', None,
                encoder.dumps(inno.setup_info.json()).encode(self.codec))

        yield self._pack(self._STREAM_NAMES[1], None, inno.streams.TData.data)
        with BytesAsArrayEncoder as encoder:
            yield self._pack(F'{self._STREAM_NAMES[1]}.json', None,
                encoder.dumps(inno.setup_data.json()).encode(self.codec))

        def _uninstaller(i=inno):
            return i.read_stream(i.streams.Uninstaller)
        yield self._pack(self._STREAM_NAMES[2], None, _uninstaller)

        if license := inno.setup_info.Header.get_license():
            yield self._pack(self._LICENSE_NAME, None, license.encode(self.codec))

        if script := inno.setup_info.Header.get_script():
            yield self._pack(F'{self._ISCRIPT_NAME}.bin', None, script)
            yield self._pack(F'{self._ISCRIPT_NAME}.ps', None,
                lambda i=inno: i.ifps.disassembly().encode(self.codec))

        if dll := inno.setup_info.get_decompress_dll():
            yield self._pack(F'embedded/decompress.{magic(dll).extension}', None, dll)

        if dll := inno.setup_info.get_decryption_dll():
            yield self._pack(F'embedded/decryption.{magic(dll).extension}', None, dll)

        for size, images in (
            ('small', inno.setup_info.get_wizard_images_small()),
            ('large', inno.setup_info.get_wizard_images_large()),
        ):
            _formatting = len(str(len(images) + 1))
            for k, img in enumerate(images, 1):
                yield self._pack(F'embedded/images/{size}{k:0{_formatting}d}.{magic(img).extension}', None, img)

        for file in inno.files:
            if file.dupe:
                continue

            def _read(i=inno, f=file, p=password):
                if self.leniency > 0:
                    return i.read_file(f, p)
                try:
                    return i.read_file_and_check(f, p)
                except InvalidPassword:
                    raise
                except Exception as E:
                    raise ValueError(F'{E!s} [ignore this check with -L]') from E

            yield self._pack(file.path, file.date, _read,
                tags=[t.name for t in SetupFileFlags if t & file.tags])

    @classmethod
    def handles(self, data):
        if data[:2] != B'MZ':
            return False
        if re.search(re.escape(InnoArchive.ChunkPrefix), data) is None:
            return False
        return bool(
            re.search(BR'Inno Setup Setup Data \(\d+\.\d+\.', data))
