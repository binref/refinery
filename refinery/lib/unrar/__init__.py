"""
Pure-Python RAR archive parser and extractor.

Supports all RAR format versions (1.4, 1.5-4.x, 5.0) with:
- Full header parsing and file listing
- All decompression algorithms (Store, v1.5, v2.0, v3.0 LZ+PPMd, v5.0)
- All encryption versions (RAR 1.3 through RAR 5.0)
- CRC32 and BLAKE2sp hash verification
- Multi-volume archives
- Solid archives
- Unicode filenames
"""
from __future__ import annotations

import dataclasses
import zlib

from refinery.lib.types import buf
from refinery.lib.unrar.headers import (
    RAR_HEADER_V14,
    RAR_HEADER_V15,
    RAR_HEADER_V50,
    CryptMethod,
    HashType,
    RarCryptHeader,
    RarEndArchiveHeader,
    RarFileEntry,
    RarFormat,
    RarMainHeader,
    parse_headers,
)


class RarException(Exception):
    """
    Base exception for RAR operations.
    """


class RarMissingPassword(RarException):
    """
    Raised when a password is required but not provided.
    """
    def __init__(self, name: str):
        super().__init__('Password required for extraction.')


class RarInvalidPassword(RarException):
    """
    Raised when the provided password is incorrect.
    """
    def __init__(self):
        super().__init__('The provided password is incorrect.')


class RarInvalidChecksum(RarException):
    """
    Raised when data integrity check fails.
    """
    def __init__(self, hash_type: str, name: str, data: buf, expected_hash: bytes, computed_hash: bytes):
        self.name = name
        self.data = data
        self.expected_hash = expected_hash
        self.computed_hash = computed_hash
        self.hash_type = hash_type

    def __str__(self):
        return (
            F'Invalid {self.hash_type} for {self.name};'
            F' computed {self.computed_hash.hex()},'
            F' expected {self.expected_hash.hex()}.')


class RarCorruptArchive(RarException):
    """
    Raised when the archive structure is corrupted.
    """


class RarVolumeMissing(RarException):
    """
    Raised when a required volume is missing.
    """
    def __init__(self, index: int):
        self.index = index

    def __str__(self):
        return F'Missing RAR volume {self.index}'


def detect_format(data: bytes | memoryview) -> RarFormat | None:
    """
    Detect the RAR format version from the archive signature.
    """
    if len(data) >= 8 and data[:8] == RAR_HEADER_V50:
        return RarFormat.RARFMT50
    if len(data) >= 7 and data[:7] == RAR_HEADER_V15:
        return RarFormat.RARFMT15
    if len(data) >= 4 and data[:4] == RAR_HEADER_V14:
        return RarFormat.RARFMT14
    return None


def get_data_slice(volume: memoryview, entry: RarFileEntry) -> memoryview:
    """
    Extract the compressed data for an entry from its volume.
    """
    start = entry._data_offset
    end = start + entry._data_size
    if end > len(volume):
        end = len(volume)
    return volume[start:end]


class RarFile:
    """
    RAR archive reader. Supports all format versions and compression methods.

    Usage:
        rar = RarFile(data)
        for entry in rar.entries:
            print(entry.name, entry.size)
        content = rar.read(rar.entries[0])

    Multi-volume:
        rar = RarFile(vol1_data, vol2_data, vol3_data)
    """

    def __init__(self, *volumes: bytes | memoryview, password: str | None = None):
        if not volumes:
            raise RarCorruptArchive('No archive data provided')

        self._volumes: list[memoryview] = []
        for v in volumes:
            if isinstance(v, memoryview):
                self._volumes.append(v)
            else:
                self._volumes.append(memoryview(v))

        self._password = password
        self._format: RarFormat | None = None
        self._main_header: RarMainHeader | None = None
        self._end_header: RarEndArchiveHeader | None = None
        self._crypt_header: RarCryptHeader | None = None
        self._raw_entries: list[RarFileEntry] = []
        self._file_entries: list[RarFileEntry] = []
        self._solid_engine = None
        self._solid_index: int = -1

        self._parse()

    def _parse(self):
        """
        Parse all volumes and build the entry list.
        """
        for vol_idx, vol_data in enumerate(self._volumes):
            fmt = detect_format(vol_data)
            if fmt is None:
                if vol_idx == 0:
                    raise RarCorruptArchive('Unrecognized archive signature')
                continue

            if vol_idx == 0:
                self._format = fmt
            elif fmt != self._format:
                raise RarCorruptArchive(
                    F'Volume {vol_idx} format mismatch: expected {self._format}, got {fmt}')

            main_hdr, entries, end_hdr, crypt_hdr = parse_headers(
                vol_data, fmt, password=self._password)

            if vol_idx == 0:
                self._main_header = main_hdr
                self._crypt_header = crypt_hdr
                if main_hdr and main_hdr.is_encrypted and crypt_hdr is None:
                    pass

            for entry in entries:
                entry._volume_index = vol_idx

            self._raw_entries.extend(entries)
            if end_hdr is not None:
                self._end_header = end_hdr

        self._merge_entries()

    def _merge_entries(self):
        """
        Merge split entries across volumes and build the public entry list.
        Filters out service entries from the public list.
        """
        merged: list[RarFileEntry] = []
        pending_split: RarFileEntry | None = None

        for entry in self._raw_entries:
            if entry.is_service:
                continue

            if pending_split is not None:
                if entry.split_before and entry.name == pending_split.name:
                    pending_split.packed_size += entry.packed_size
                    if not entry.split_after:
                        merged.append(pending_split)
                        pending_split = None
                    continue
                else:
                    merged.append(pending_split)
                    pending_split = None

            if entry.split_after and not entry.split_before:
                pending_split = dataclasses.replace(entry)
                continue

            if not entry.split_before:
                merged.append(entry)

        if pending_split is not None:
            merged.append(pending_split)

        self._file_entries = merged

    @property
    def entries(self) -> list[RarFileEntry]:
        """
        List of all file entries in the archive.
        """
        return list(self._file_entries)

    @property
    def format(self) -> RarFormat | None:
        """
        The detected RAR format version.
        """
        return self._format

    @property
    def is_solid(self) -> bool:
        """
        Whether the archive uses solid compression.
        """
        return bool(self._main_header and self._main_header.is_solid)

    @property
    def is_volume(self) -> bool:
        """
        Whether this is a multi-volume archive.
        """
        return bool(self._main_header and self._main_header.is_volume)

    @property
    def is_encrypted(self) -> bool:
        """
        Whether the archive headers are encrypted.
        """
        return bool(self._main_header and self._main_header.is_encrypted)

    def namelist(self) -> list[str]:
        """
        Return a list of archive member names.
        """
        return [e.name for e in self._file_entries]

    def infolist(self) -> list[RarFileEntry]:
        """
        Return a list of RarFileEntry objects for all archive members.
        """
        return list(self._file_entries)

    def read(self, entry: str | int | RarFileEntry, password: str | None = None) -> buf:
        """
        Extract and return the contents of an archive member.

        Args:
            entry: File name, index, or RarFileEntry object
            password: Optional password override for encrypted entries
        """
        fe = self._resolve_entry(entry)
        if fe.is_dir:
            return b''

        pw = password or self._password

        if fe.is_encrypted and not pw:
            raise RarMissingPassword(fe.name)

        entry_index = self._file_entries.index(fe)

        if fe.solid and entry_index > 0:
            for i in range(self._solid_index + 1, entry_index):
                prev = self._file_entries[i]
                if prev.is_dir:
                    continue
                prev_data = self._get_compressed_data(prev)
                if prev.is_encrypted:
                    if pw is None:
                        raise RarMissingPassword(prev.name)
                    prev_data = self._decrypt(prev_data, prev, pw)
                self._decompress(prev_data, prev)

        data = self._get_compressed_data(fe)

        if fe.is_encrypted:
            assert pw is not None
            data = self._decrypt(data, fe, pw)

        result = self._decompress(data, fe)
        self._solid_index = entry_index

        self._verify(result, fe, pw)

        return result

    def _resolve_entry(self, entry: str | int | RarFileEntry) -> RarFileEntry:
        """
        Resolve a user-provided entry reference to a RarFileEntry.
        """
        if isinstance(entry, RarFileEntry):
            return entry
        if isinstance(entry, int):
            if 0 <= entry < len(self._file_entries):
                return self._file_entries[entry]
            raise IndexError(F'Entry index {entry} out of range')
        if isinstance(entry, str):
            normalized = entry.replace('\\', '/')
            for fe in self._file_entries:
                if fe.name.replace('\\', '/') == normalized:
                    return fe
            raise KeyError(F'Entry not found: {entry}')
        raise TypeError(F'Expected str, int, or RarFileEntry, got {type(entry).__name__}')

    def _get_compressed_data(self, entry: RarFileEntry) -> bytes | memoryview:
        """
        Gather all compressed data for an entry, potentially across volumes.
        """
        vol_idx = entry._volume_index
        if vol_idx >= len(self._volumes):
            raise RarVolumeMissing(vol_idx)

        if not entry.split_after:
            vol = self._volumes[vol_idx]
            return get_data_slice(vol, entry)

        result = bytearray()

        for raw_entry in self._raw_entries:
            if raw_entry.name == entry.name and not raw_entry.is_service:
                vi = raw_entry._volume_index
                if vi >= len(self._volumes):
                    raise RarVolumeMissing(vi)
                vol = self._volumes[vi]
                chunk = get_data_slice(vol, raw_entry)
                result.extend(chunk)

        return memoryview(result)

    def _decrypt(self, data: buf, entry: RarFileEntry, password: str) -> buf:
        """
        Decrypt compressed data.
        """
        from refinery.lib.unrar.crypt import make_decryptor
        decryptor = make_decryptor(
            entry.crypt_method,
            password,
            salt=entry.salt,
            iv=entry.init_v,
            lg2_count=entry.lg2_count,
            use_psw_check=entry.use_psw_check,
            psw_check=entry.psw_check,
        )
        if decryptor is None:
            return data
        result: buf = decryptor.decrypt(data)
        return result

    def _decompress(self, data: bytes | memoryview, entry: RarFileEntry) -> buf:
        """
        Decompress data based on the compression method and format version.
        """
        if entry.method == 0:
            return data[:entry.size] if len(data) > entry.size else data

        engine = self._solid_engine

        if entry.solid and engine is not None:
            engine.init_solid(data, entry.size)
            return engine.decompress()

        unp_ver = entry.unp_ver

        if self._format == RarFormat.RARFMT50 or unp_ver >= 50:
            from refinery.lib.unrar.unpack50 import Unpack50
            win_size = entry.win_size if entry.win_size > 0 else 0x400000
            engine = Unpack50(data, entry.size, win_size, entry.solid)
        elif unp_ver >= 29:
            from refinery.lib.unrar.unpack30 import Unpack30
            win_size = entry.win_size if entry.win_size > 0 else 0x400000
            engine = Unpack30(data, entry.size, win_size, entry.solid)
        elif unp_ver >= 20:
            from refinery.lib.unrar.unpack20 import Unpack20
            engine = Unpack20(data, entry.size, entry.solid)
        elif unp_ver >= 15:
            from refinery.lib.unrar.unpack15 import Unpack15
            engine = Unpack15(data, entry.size, entry.solid)
        else:
            raise RarCorruptArchive(
                F'Unsupported compression version {unp_ver} for {entry.name}')

        self._solid_engine = engine
        return engine.decompress()

    def _verify(self, data: buf, entry: RarFileEntry, password: str | None = None):
        """
        Verify the integrity of decompressed data.
        """
        if entry.hash_type == HashType.HASH_CRC32:
            computed = zlib.crc32(data) & 0xFFFFFFFF
            expected = entry.crc32
            if entry.use_hash_key and password:
                from refinery.lib.unrar.crc import convert_hash_to_mac
                from refinery.lib.unrar.crypt import CryptRar50, make_decryptor
                decryptor = make_decryptor(
                    CryptMethod.CRYPT_RAR50,
                    password,
                    salt=entry.salt,
                    iv=entry.init_v,
                    lg2_count=entry.lg2_count,
                )
                if isinstance(decryptor, CryptRar50):
                    mac_crc, _ = convert_hash_to_mac(
                        HashType.HASH_CRC32, decryptor.hash_key, crc_value=computed)
                    if mac_crc != expected:
                        raise RarInvalidChecksum('CRC32-HMAC', entry.name, data,
                            expected.to_bytes(4, 'little'), mac_crc.to_bytes(4, 'little'))
                    return
            if computed != expected:
                raise RarInvalidChecksum('CRC32', entry.name, data, expected.to_bytes(4), computed.to_bytes(4))

        elif entry.hash_type == HashType.HASH_RAR14:
            from refinery.lib.unrar.crc import checksum14
            computed = checksum14(data)
            expected = entry.crc32
            if computed != expected:
                raise RarInvalidChecksum('CRC14', entry.name, data, expected.to_bytes(2), computed.to_bytes(2))

        elif entry.hash_type == HashType.HASH_BLAKE2:
            from refinery.lib.unrar.crc import blake2sp_hash
            computed_hash = blake2sp_hash(data)

            if entry.use_hash_key and password:
                from refinery.lib.unrar.crc import convert_hash_to_mac
                from refinery.lib.unrar.crypt import CryptRar50, make_decryptor
                decryptor = make_decryptor(
                    CryptMethod.CRYPT_RAR50,
                    password,
                    salt=entry.salt,
                    iv=entry.init_v,
                    lg2_count=entry.lg2_count,
                )
                if isinstance(decryptor, CryptRar50):
                    _, mac_digest = convert_hash_to_mac(
                        HashType.HASH_BLAKE2, decryptor.hash_key, digest=computed_hash)
                    if mac_digest != entry.hash_digest:
                        raise RarInvalidChecksum(
                            'BLAKE2sp-HMAC', entry.name, data, entry.hash_digest, mac_digest)
                    return

            if computed_hash != entry.hash_digest:
                raise RarInvalidChecksum('BLAKE2sp', entry.name, data, entry.hash_digest, computed_hash)
