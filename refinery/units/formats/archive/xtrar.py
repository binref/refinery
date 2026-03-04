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
from refinery.lib.unrar.headers import CryptMethod, RarCryptHeader, RarFileEntry
from refinery.units import RefineryPartialResult
from refinery.units.formats.archive import ArchiveUnit


def _format_hashcat_hash(entry: RarFileEntry, data: buf | None = None, headers: bool = False) -> str | None:
    cm = entry.crypt_method
    h = int(not headers)
    if cm == CryptMethod.CRYPT_RAR50:
        if entry.use_psw_check and entry.psw_check and entry.init_v:
            salt = entry.salt.hex()
            iv = entry.init_v.hex()
            check = entry.psw_check.hex()
            return F'$rar5$16${salt}${entry.lg2_count}${iv}$8${check}'
        return None
    if cm == CryptMethod.CRYPT_RAR30:
        salt = entry.salt.hex()
        crc = entry.crc32
        csize = entry.packed_size
        usize = entry.size
        if data is not None and len(data) >= 16:
            d = bytes(data).hex()
            m = entry.method + 0x30
            return F'$RAR3$*{h}*{salt}*{crc:08x}*{csize}*{usize}*1*{d}*{m:x}'
        return None
    if cm == CryptMethod.CRYPT_RAR20:
        return F'$RAR2${entry.salt.hex()}'
    if cm in (CryptMethod.CRYPT_RAR15, CryptMethod.CRYPT_RAR13):
        return F'$RAR2${cm.name}'
    return None


def _format_hashcat_hash_header(crypt_header: RarCryptHeader) -> str | None:
    if crypt_header.use_psw_check and crypt_header.psw_check and crypt_header.header_iv:
        salt = crypt_header.salt.hex()
        iv = crypt_header.header_iv.hex()
        check = crypt_header.psw_check.hex()
        return F'$rar5$16${salt}${crypt_header.lg2_count}${iv}$8${check}'
    return None


class xtrar(ArchiveUnit, docs='{0}{s}{PathExtractorUnit}'):
    """
    Extract files from a RAR archive. This unit supports all RAR format versions
    including RAR4 and RAR5, with support for all compression algorithms, encryption,
    and multi-volume archives.
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
            hash_str = _format_hashcat_hash_header(rar._crypt_header) if rar._crypt_header else None
            exc = RarMissingPassword('(header-encrypted archive)')
            if hash_str:
                exc.args = (F'{exc.args[0]} hashcat-compatible hash: {hash_str}',)
            raise exc
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
                    target = _format_hashcat_hash(e, r._get_compressed_data(e))
                    raise ValueError(F'invalid password; {target} {e.name}') from E
                except RarMissingPassword as E:
                    target = _format_hashcat_hash(e, r._get_compressed_data(e))
                    raise ValueError(F'missing password; {target} {e.name}') from E
            if entry.is_dir:
                continue
            yield self._pack(entry.name, entry.date, extract)

    @classmethod
    def handles(cls, data) -> bool:
        return detect_format(data) is not None
