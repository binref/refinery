from __future__ import annotations

import codecs

from refinery.lib.id import buffer_offset
from refinery.lib.types import buf
from refinery.lib.unrar import (
    RAR_HEADER_V14,
    RAR_HEADER_V15,
    RAR_HEADER_V50,
    RarFile,
    RarInvalidChecksum,
    RarInvalidPassword,
    RarMissingPassword,
    detect_format,
)
from refinery.units import RefineryPartialResult
from refinery.units.formats.archive import ArchiveUnit


class xtrar(ArchiveUnit, docs='{0}{p}{PathExtractorUnit}'):
    """
    Extract files from a RAR archive.
    """
    @staticmethod
    def _find_rar_file(data: buf):
        view = memoryview(data)
        if detect_format(view) is not None:
            return view
        from refinery.lib.id import get_pe_type
        if get_pe_type(data):
            from refinery.units.formats.pe import get_pe_size
            offset = get_pe_size(data)
            overlay = view[offset:]
            if detect_format(overlay) is not None:
                return overlay
        for signature in (
            RAR_HEADER_V50,
            RAR_HEADER_V15,
            RAR_HEADER_V14,
        ):
            offset = buffer_offset(view, signature)
            if offset >= 0:
                return view[offset:]

    def unpack(self, data):
        if (view := self._find_rar_file(data)) is None:
            raise ValueError('Input does not appear to be a RAR file.')
        password = self.args.pwd
        if not password:
            password = None
        elif not isinstance(password, str):
            password = codecs.decode(password, self.codec)
        rar = RarFile(view, password=password)
        if rar.is_encrypted and not password and not rar.entries:
            raise RarMissingPassword
        if not self.args.list:
            has_encrypted = any(e.is_encrypted for e in rar.entries)
            if has_encrypted and not password:
                first_encrypted = next(
                    (e for e in rar.entries if e.is_encrypted and not e.is_dir), None)
                if first_encrypted is not None:
                    for pwd in self.CommonPasswords:
                        try:
                            rar.read(first_encrypted, pwd)
                        except (
                            RarMissingPassword,
                            RarInvalidPassword,
                            RarInvalidChecksum,
                        ):
                            continue
                        except Exception:
                            break
                        else:
                            password = pwd
                            self.log_info(F'using password: {pwd}')
                            break
        for entry in rar.entries:
            def extract(r=rar, e=entry, p=password):
                try:
                    return r.read(e, p)
                except RarInvalidChecksum as check:
                    raise RefineryPartialResult(str(check), check.data) from check
                except RarInvalidPassword as E:
                    raise ValueError(F'invalid password: {entry.name}') from E
                except RarMissingPassword as E:
                    raise ValueError(F'missing password: {entry.name}') from E
            if entry.is_dir:
                continue
            yield self._pack(entry.name, entry.date, extract)

    @classmethod
    def handles(cls, data) -> bool:
        return cls._find_rar_file(data) is not None
