from __future__ import annotations

import codecs

from refinery.lib.id import buffer_offset
from refinery.lib.types import buf
from refinery.lib.unrar import (
    RAR_HEADER_V14,
    RAR_HEADER_V15,
    RAR_HEADER_V50,
    RarCorruptArchive,
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
        files = [entry for entry in rar.entries if not entry.is_dir]
        extractors = [rar.extractor(entry, password) for entry in files]
        probed = None
        if not self.args.list and not password:
            encrypted = next((k for k, entry in enumerate(files) if entry.is_encrypted and entry.size != 0), None)
            if encrypted is not None:
                for pwd in self.CommonPasswords:
                    trial = [rar.extractor(entry, pwd) for entry in files]
                    try:
                        data = trial[encrypted]()
                    except (
                        RarMissingPassword,
                        RarInvalidPassword,
                        RarInvalidChecksum,
                        RarCorruptArchive,
                    ):
                        continue
                    except Exception:
                        break
                    else:
                        self.log_info(F'using password: {pwd}')
                        extractors = trial
                        probed = encrypted, data
                        break
        for k, (entry, read) in enumerate(zip(files, extractors)):
            if probed is not None and probed[0] == k:
                yield self._pack(entry.name, entry.date, probed[1])
                continue

            def extract(read=read, entry=entry):
                try:
                    return read()
                except RarInvalidChecksum as check:
                    raise RefineryPartialResult(str(check), check.data) from check
                except RarCorruptArchive as exc:
                    if exc.partial is None:
                        raise
                    raise RefineryPartialResult(str(exc), exc.partial) from exc
                except RarInvalidPassword as E:
                    raise ValueError(F'invalid password: {entry.name}') from E
                except RarMissingPassword as E:
                    raise ValueError(F'missing password: {entry.name}') from E
            yield self._pack(entry.name, entry.date, extract)

    @classmethod
    def handles(cls, data) -> bool:
        return cls._find_rar_file(data) is not None
