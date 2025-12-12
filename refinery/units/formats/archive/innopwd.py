from __future__ import annotations

from refinery.lib.inno.archive import InnoArchive, is_inno_setup
from refinery.lib.inno.emulator import (
    IFPSEmulatorConfig,
    InnoSetupEmulator,
    NewFunctionCall,
    NewInstruction,
    NewMutex,
    NewPassword,
)
from refinery.lib.inno.ifps import IFPSFile
from refinery.units import Unit


class innopwd(Unit):
    """
    This unit emulates an InnoSetup installer in an attempt to determine the installer password.
    This works only when the password is contained within the script, but several malware samples
    are known to use this technique.
    """
    def process(self, data: bytearray):
        if data.startswith(IFPSFile.Magic):
            inno = IFPSFile.Parse(data)
            self.log_info('running in script-only mode; cannot check passwords')
            file = None
        else:
            inno = InnoArchive(data, self)
            file = inno.get_encrypted_sample()
            if file is None:
                self.log_info('the archive is not password-protected, password is empty')
                return None
            assert file.crypto
            self.log_info('password type:', file.crypto.PasswordType.name)
            self.log_info('password test:', file.crypto.PasswordTest)
            self.log_info('password seed:', file.crypto.PasswordSeed)

        info = self.log_info()
        dbug = self.log_debug()
        emulator = InnoSetupEmulator(inno, IFPSEmulatorConfig(
            log_mutexes=info,
            log_passwords=True,
            log_calls=info,
            log_opcodes=dbug,
        ))
        function = None

        for event in emulator.emulate_installation():
            if isinstance(event, NewInstruction):
                if not function or function.name != event.function.name:
                    function = event.function
                    self.log_debug(repr(function))
                self.log_debug(F'\x20\x20{event.offset:#08x} {event.instruction!s}')
                continue
            if isinstance(event, NewFunctionCall):
                self.log_info(F'calling {event.name!s}{event.args!r}')
                continue
            if isinstance(event, NewMutex):
                self.log_info(F'mutex registered: {event!s}')
                continue
            if isinstance(event, NewPassword):
                if isinstance(inno, InnoArchive) and file and not inno.check_password(file, event):
                    self.log_info('discarding password:', event)
                    continue
                yield event.encode(self.codec)
                if file is not None:
                    self.log_info('aborting emulation after validating password')
                    return

    @classmethod
    def handles(cls, data):
        return is_inno_setup(data)
