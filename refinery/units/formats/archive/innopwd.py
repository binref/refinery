#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

from refinery.units import Unit

from refinery.lib.inno.archive import InnoArchive, InvalidPassword
from refinery.lib.inno.emulator import InnoSetupEmulator
from refinery.lib.inno.ifps import IFPSFile


class innopwd(Unit):
    """
    This unit emulates an InnoSetup installer in an attempt to determine the installer password.
    This works only when the password is contained within the script, but several malware samples
    are known to use this technique.
    """
    def process(self, data: bytearray):
        if data.startswith(IFPSFile.Magic):
            inno = IFPSFile(data)
            self.log_info('running in script-only mode; cannot check passwords')
            can_check = False
        else:
            inno = InnoArchive(data, self)
            file = min(inno.files, key=lambda f: (not f.encrypted, f.size))
            if not file.encrypted:
                self.log_info('the archive is not password-protected, password is empty')
                return None
            self.log_info('password type:', file.password_type.name)
            self.log_info('password hash:', file.password_hash)
            self.log_info('password salt:', file.password_salt)
            can_check = True

        iemu = InnoSetupEmulator(inno)
        iemu.emulate_installation()

        for password in iemu.passwords:
            if can_check:
                try:
                    inno.read_chunk(file, password, check_only=True)
                except InvalidPassword:
                    self.log_info('discarding password:', password)
                    continue
            yield password.encode(self.codec)
            if can_check:
                break

    @classmethod
    def handles(self, data):
        import re
        if data[:2] != B'MZ':
            return False
        if re.search(re.escape(InnoArchive.ChunkPrefix), data) is None:
            return False
        return bool(
            re.search(BR'Inno Setup Setup Data \(\d+\.\d+\.', data))
