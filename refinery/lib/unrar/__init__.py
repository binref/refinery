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
import weakref
import zlib

from bisect import bisect_right
from functools import partial
from typing import Callable, Iterator

from refinery.lib.solid import SolidStream, SolidStreamTruncated
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

_MAX_DICTIONARY = 0x1000000000
"""
The largest dictionary that the reference decoder accepts, 64 GB.
"""

_UNKNOWN_SIZE_ROOM = 1 << 64
"""
The room that a member of unknown size takes in the decompressed stream of its archive: more than
any member can decompress to.
"""


class RarException(Exception):
    """
    Base exception for RAR operations.
    """


class RarMissingPassword(RarException):
    """
    Raised when a password is required but not provided.
    """
    def __init__(self, name: str | None = None):
        super().__init__('Password required for extraction.')
        self.name = name


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
    Raised when the archive structure is corrupted. When the corruption is detected while
    decompressing an entry, the `entry` attribute is that entry, and the `partial` attribute carries
    the output decoded for it up to that point.
    """
    def __init__(
        self,
        message: str = 'The archive structure is corrupted.',
        partial: bytes | None = None,
        entry: RarFileEntry | None = None,
    ):
        super().__init__(message)
        self.partial = partial
        self.entry = entry


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
        self._streams: weakref.WeakValueDictionary[str | None, SolidStream]
        self._streams = weakref.WeakValueDictionary()

        self._parse()
        self._layout()

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
                    pending_split.crc32 = entry.crc32
                    pending_split.use_hash_key = entry.use_hash_key
                    pending_split.hash_type = entry.hash_type
                    pending_split.hash_digest = entry.hash_digest
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

    def _layout(self):
        """
        Place the members in one decompressed stream and find the members where decompression can
        start, which are all members that do not continue the decompression of a previous one. An
        empty member that no later member continues is never decompressed, because nothing depends
        on it; it shares its position with the next member, whose decompression it must not fail.
        A member of unknown size takes more room than any member can fill and ends where its
        stream ends.
        """
        self._index: dict[int, int] = {}
        self._positions: list[int] = []
        self._starts: list[int] = []
        self._start_positions: list[int] = []
        self._idle: set[int] = set()
        position = 0
        for k, entry in enumerate(self._file_entries):
            self._index[id(entry)] = k
            self._positions.append(position)
            if entry.is_dir:
                continue
            if not entry.solid or not self._starts:
                self._starts.append(k)
                self._start_positions.append(position)
            position += self._room(entry)
        continued = False
        for k in reversed(range(len(self._file_entries))):
            if (entry := self._file_entries[k]).is_dir:
                continue
            if entry.size == 0 and not continued:
                self._idle.add(k)
            continued = entry.solid

    @staticmethod
    def _room(entry: RarFileEntry) -> int:
        """
        The room that the given member takes in the decompressed stream of the archive.
        """
        if (size := entry.size) is None:
            return _UNKNOWN_SIZE_ROOM
        return size

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
        return self.extractor(entry, password)()

    def extractor(
        self,
        entry: str | int | RarFileEntry,
        password: str | None = None,
    ) -> Callable[[], buf]:
        """
        Return a function that returns the contents of an archive member. Members of a solid archive
        are decompressed in order; the archive keeps the contents of a member that was decompressed
        before its turn only while the function returned for it is alive.
        """
        fe = self._resolve_entry(entry)
        if fe.is_dir:
            return bytes
        pw = password or self._password
        if fe.is_encrypted and not pw:
            def missing() -> buf:
                raise RarMissingPassword(fe.name)
            return missing
        if (stream := self._streams.get(pw)) is None:
            stream = self._streams[pw] = SolidStream(partial(self._decode, pw), self._restart)
        claim = stream.claim(self._positions[self._index[id(fe)]], self._room(fe))

        def extract() -> buf:
            try:
                data = claim()
            except SolidStreamTruncated as truncated:
                data = truncated.partial
            except RarCorruptArchive as error:
                if (corrupt := error.entry) is None or corrupt is fe:
                    raise
                raise RarCorruptArchive(
                    F'The member {corrupt.name} that this one continues is corrupt: {error}', entry=corrupt
                ) from error
            self._verify(data, fe, pw)
            return data

        return extract

    def _chain(self, offset: int) -> int:
        return self._starts[bisect_right(self._start_positions, offset) - 1]

    def _restart(self, offset: int) -> int:
        return self._positions[self._chain(offset)]

    def _decode(self, password: str | None, origin: int) -> Iterator[tuple[int, buf]]:
        """
        Decompress the members from the start of the chain that holds the given origin onward. An
        empty piece announces the position of each member before it is decompressed, so that a
        member which decompressed to fewer bytes than its size ends there and does not fail with
        the member after it.
        """
        entries = self._file_entries
        engine = None
        for k in range(self._chain(origin), len(entries)):
            entry = entries[k]
            if entry.is_dir or k in self._idle:
                continue
            position = self._positions[k]
            yield position, B''
            try:
                data = self._get_compressed_data(entry)
                if entry.is_encrypted:
                    if password is None:
                        raise RarMissingPassword(entry.name)
                    data = self._decrypt(data, entry, password)
                output, engine = self._decompress(data, entry, engine)
            except RarCorruptArchive as error:
                raise RarCorruptArchive(str(error), error.partial, entry) from error
            yield position, output

    def _resolve_entry(self, entry: str | int | RarFileEntry) -> RarFileEntry:
        """
        Resolve a user-provided entry reference to a RarFileEntry.
        """
        if isinstance(entry, RarFileEntry):
            if id(entry) in self._index:
                return entry
            try:
                return self._file_entries[self._file_entries.index(entry)]
            except ValueError:
                raise KeyError(F'Entry not found: {entry.name}') from None
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

    def _decompress(self, data: bytes | memoryview, entry: RarFileEntry, engine=None):
        """
        Decompress data based on the compression method and format version. A member that continues
        a solid chain is decompressed by the engine of the chain, with its own algorithm.
        """
        if entry.method == 0:
            if (size := entry.size) is not None and len(data) > size:
                data = data[:size]
            return data, engine

        unp_ver = entry.unp_ver
        win_size = entry.win_size or 0x400000

        if self._format == RarFormat.RARFMT50 or unp_ver >= 50:
            if unp_ver > 51:
                raise self._unsupported(entry)
            if entry.win_size > _MAX_DICTIONARY:
                raise RarCorruptArchive(
                    F'The dictionary of {entry.name} exceeds the 64 GB limit of RAR.'
                )
            from refinery.lib.unrar.unpack50 import Unpack50
            engine = self._engine(engine, Unpack50, data, entry, win_size, extended=unp_ver == 51)
        elif unp_ver >= 29:
            from refinery.lib.unrar.unpack30 import Unpack30
            engine = self._engine(engine, Unpack30, data, entry, win_size)
        elif unp_ver >= 20:
            from refinery.lib.unrar.unpack20 import Unpack20
            engine = self._engine(engine, Unpack20, data, entry)
        elif unp_ver >= 15:
            from refinery.lib.unrar.unpack15 import Unpack15
            engine = self._engine(engine, Unpack15, data, entry)
        else:
            raise self._unsupported(entry)

        return engine.decompress(), engine

    def _engine(
        self,
        engine,
        algorithm: type,
        data: bytes | memoryview,
        entry: RarFileEntry,
        *arguments,
        **options,
    ):
        """
        Continue the solid chain of the given engine with the entry, or start a new engine of the
        given algorithm. Positional arguments only configure a new engine; keyword options also
        apply to every member that continues its chain.
        """
        if not entry.solid or engine is None:
            return algorithm(data, entry.size, *arguments, entry.solid, **options)
        if type(engine) is not algorithm:
            raise self._algorithm_changed(entry)
        engine.init_solid(data, entry.size, **options)
        return engine

    @staticmethod
    def _unsupported(entry: RarFileEntry) -> RarCorruptArchive:
        return RarCorruptArchive(
            F'Unsupported compression version {entry.unp_ver} for {entry.name}'
        )

    @staticmethod
    def _algorithm_changed(entry: RarFileEntry) -> RarCorruptArchive:
        return RarCorruptArchive(
            F'The solid member {entry.name} uses another compression algorithm than its chain.'
        )

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
                raise RarInvalidChecksum('CRC32', entry.name, data,
                    expected.to_bytes(4, 'little'), computed.to_bytes(4, 'little'))

        elif entry.hash_type == HashType.HASH_RAR14:
            from refinery.lib.unrar.crc import checksum14
            computed = checksum14(data)
            expected = entry.crc32
            if computed != expected:
                raise RarInvalidChecksum('CRC14', entry.name, data,
                    expected.to_bytes(2, 'little'), computed.to_bytes(2, 'little'))

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
