"""
Header structures, enums, and constants for RAR archive formats.
"""
from __future__ import annotations

import enum
import itertools
import struct
import zlib

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import NamedTuple

from refinery.lib.types import buf

RAR_HEADER_V15 = b'Rar!\x1a\a\00'   # 52 61 72 21 1A 07 00
RAR_HEADER_V50 = b'Rar!\x1a\a\01\0' # 52 61 72 21 1A 07 01 00
RAR_HEADER_V14 = b'RE~^'            # 52 45 7E 5E


class RarFormat(enum.IntEnum):
    RARFMT14 = 14
    RARFMT15 = 15
    RARFMT50 = 50


SIZEOF_MARKHEAD3 = 7
SIZEOF_MARKHEAD5 = 8
SIZEOF_MAINHEAD14 = 7
SIZEOF_MAINHEAD3 = 13
SIZEOF_FILEHEAD14 = 21
SIZEOF_FILEHEAD3 = 32
SIZEOF_SHORTBLOCKHEAD = 7
SIZEOF_SHORTBLOCKHEAD5 = 7
SIZEOF_LONGBLOCKHEAD = 11
SIZEOF_SUBBLOCKHEAD = 14
SIZEOF_COMMHEAD = 13
SIZEOF_PROTECTHEAD = 26


class HeaderType(enum.IntEnum):
    HEAD_MARK = 0x00
    HEAD_MAIN = 0x01
    HEAD_FILE = 0x02
    HEAD_SERVICE = 0x03
    HEAD_CRYPT = 0x04
    HEAD_ENDARC = 0x05
    HEAD_UNKNOWN = 0xFF
    HEAD3_MARK = 0x72
    HEAD3_MAIN = 0x73
    HEAD3_FILE = 0x74
    HEAD3_CMT = 0x75
    HEAD3_AV = 0x76
    HEAD3_OLDSERVICE = 0x77
    HEAD3_PROTECT = 0x78
    HEAD3_SIGN = 0x79
    HEAD3_SERVICE = 0x7A
    HEAD3_ENDARC = 0x7B


_HEAD3_TO_5 = {
    HeaderType.HEAD3_MAIN: HeaderType.HEAD_MAIN,
    HeaderType.HEAD3_FILE: HeaderType.HEAD_FILE,
    HeaderType.HEAD3_SERVICE: HeaderType.HEAD_SERVICE,
    HeaderType.HEAD3_ENDARC: HeaderType.HEAD_ENDARC,
}


class MHD(enum.IntEnum):
    VOLUME = 0x0001
    COMMENT = 0x0002
    LOCK = 0x0004
    SOLID = 0x0008
    PACK_COMMENT = 0x0010
    NEWNUMBERING = 0x0010
    AV = 0x0020
    PROTECT = 0x0040
    PASSWORD = 0x0080
    FIRSTVOLUME = 0x0100


class LHD(enum.IntEnum):
    SPLIT_BEFORE = 0x0001
    SPLIT_AFTER = 0x0002
    PASSWORD = 0x0004
    COMMENT = 0x0008
    SOLID = 0x0010
    WINDOWMASK = 0x00E0
    WINDOW64 = 0x0000
    WINDOW128 = 0x0020
    WINDOW256 = 0x0040
    WINDOW512 = 0x0060
    WINDOW1024 = 0x0080
    WINDOW2048 = 0x00A0
    WINDOW4096 = 0x00C0
    DIRECTORY = 0x00E0
    LARGE = 0x0100
    UNICODE = 0x0200
    SALT = 0x0400
    VERSION = 0x0800
    EXTTIME = 0x1000
    SKIP_IF_UNKNOWN = 0x4000
    LONG_BLOCK = 0x8000


class EARC(enum.IntEnum):
    NEXT_VOLUME = 0x0001
    DATACRC = 0x0002
    REVSPACE = 0x0004
    VOLNUMBER = 0x0008


class HFL(enum.IntEnum):
    EXTRA = 0x0001
    DATA = 0x0002
    SKIPIFUNKNOWN = 0x0004
    SPLITBEFORE = 0x0008
    SPLITAFTER = 0x0010
    CHILD = 0x0020
    INHERITED = 0x0040


class MHFL(enum.IntEnum):
    VOLUME = 0x0001
    VOLNUMBER = 0x0002
    SOLID = 0x0004
    PROTECT = 0x0008
    LOCK = 0x0010


class FHFL(enum.IntEnum):
    DIRECTORY = 0x0001
    UTIME = 0x0002
    CRC32 = 0x0004
    UNPUNKNOWN = 0x0008


class EHFL(enum.IntEnum):
    NEXTVOLUME = 0x0001


class CHFL(enum.IntEnum):
    CRYPT_PSWCHECK = 0x0001


class FCI(enum.IntEnum):
    ALGO_MASK = 0x003F
    SOLID = 0x0040
    METHOD_SHIFT = 7
    METHOD_MASK = 0x0380
    DICT_SHIFT = 10
    DICT_MASK = 0x3C00


MHEXTRA_LOCATOR = 0x01
MHEXTRA_LOCATOR_QLIST = 0x01
MHEXTRA_LOCATOR_RR = 0x02

FHEXTRA_CRYPT = 0x01
FHEXTRA_HASH = 0x02
FHEXTRA_HTIME = 0x03
FHEXTRA_VERSION = 0x04
FHEXTRA_REDIR = 0x05
FHEXTRA_UOWNER = 0x06
FHEXTRA_SUBDATA = 0x07

FHEXTRA_HASH_BLAKE2 = 0x00

FHEXTRA_HTIME_UNIXTIME = 0x01
FHEXTRA_HTIME_MTIME = 0x02
FHEXTRA_HTIME_CTIME = 0x04
FHEXTRA_HTIME_ATIME = 0x08
FHEXTRA_HTIME_UNIX_NS = 0x10

FHEXTRA_CRYPT_PSWCHECK = 0x01
FHEXTRA_CRYPT_HASHMAC = 0x02

FHEXTRA_REDIR_DIR = 0x01

FHEXTRA_UOWNER_UNAME = 0x01
FHEXTRA_UOWNER_GNAME = 0x02
FHEXTRA_UOWNER_NUMUID = 0x04
FHEXTRA_UOWNER_NUMGID = 0x08


SIZE_SALT50 = 16
SIZE_SALT30 = 8
SIZE_INITV = 16
SIZE_PSWCHECK = 8
SIZE_PSWCHECK_CSUM = 4
CRYPT_BLOCK_SIZE = 16
CRYPT5_KDF_LG2_COUNT_MAX = 24


class CryptMethod(enum.IntEnum):
    CRYPT_NONE = 0
    CRYPT_RAR13 = 1
    CRYPT_RAR15 = 2
    CRYPT_RAR20 = 3
    CRYPT_RAR30 = 4
    CRYPT_RAR50 = 5


class HostSystem(enum.IntEnum):
    HOST5_WINDOWS = 0
    HOST5_UNIX = 1
    HOST_MSDOS = 0
    HOST_OS2 = 1
    HOST_WIN32 = 2
    HOST_UNIX = 3
    HOST_MACOS = 4
    HOST_BEOS = 5


class HostSystemType(enum.IntEnum):
    HSYS_WINDOWS = 0
    HSYS_UNIX = 1
    HSYS_UNKNOWN = 2


class FileSystemRedirect(enum.IntEnum):
    FSREDIR_NONE = 0
    FSREDIR_UNIXSYMLINK = 1
    FSREDIR_WINSYMLINK = 2
    FSREDIR_JUNCTION = 3
    FSREDIR_HARDLINK = 4
    FSREDIR_FILECOPY = 5


class HashType(enum.IntEnum):
    HASH_NONE = 0
    HASH_RAR14 = 1
    HASH_CRC32 = 2
    HASH_BLAKE2 = 3


BLAKE2_DIGEST_SIZE = 32


def read_vint(data: bytes | memoryview, pos: int = 0) -> tuple[int, int]:
    """
    Decode a RAR5 variable-length integer from data starting at pos.
    Returns (value, new_pos).
    """
    result = 0
    shift = 0
    while pos < len(data) and shift < 64:
        b = data[pos]
        pos += 1
        result += (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7
    return 0, pos


def vint_size(data: bytes | memoryview, pos: int = 0) -> int:
    """
    Return the number of bytes a vint occupies at the given position.
    """
    for i in range(pos, len(data)):
        if not (data[i] & 0x80):
            return i - pos + 1
    return 0


def dos_datetime(dostime: int) -> datetime | None:
    """
    Convert a DOS-format date/time to a Python datetime.
    """
    try:
        date_part = (dostime >> 16) & 0xFFFF
        time_part = dostime & 0xFFFF
        year = ((date_part >> 9) & 0x7F) + 1980
        month = (date_part >> 5) & 0x0F
        day = date_part & 0x1F
        hour = (time_part >> 11) & 0x1F
        minute = (time_part >> 5) & 0x3F
        second = (time_part & 0x1F) * 2
        return datetime(year, month or 1, day or 1, hour, minute, min(second, 59))
    except (ValueError, OverflowError):
        return None


def decode_rar4_filename(name_bytes: bytes, enc_data: bytes) -> str:
    """
    Decode a RAR 4.x Unicode filename from the encoded representation.
    The name_bytes is the ASCII portion; enc_data contains the encoding flags
    and high bytes. Returns the decoded Unicode filename.
    """
    if not enc_data:
        return name_bytes.decode('latin-1')

    enc_pos = 0
    dec_pos = 0
    name_size = len(name_bytes)
    result = []

    high_byte = enc_data[enc_pos] if enc_pos < len(enc_data) else 0
    enc_pos += 1
    flags = 0
    flag_bits = 0

    while enc_pos < len(enc_data):
        if flag_bits == 0:
            if enc_pos >= len(enc_data):
                break
            flags = enc_data[enc_pos]
            enc_pos += 1
            flag_bits = 8

        switch = flags >> 6
        if switch == 0:
            if enc_pos >= len(enc_data):
                break
            result.append(chr(enc_data[enc_pos]))
            enc_pos += 1
            dec_pos += 1
        elif switch == 1:
            if enc_pos >= len(enc_data):
                break
            result.append(chr(enc_data[enc_pos] + (high_byte << 8)))
            enc_pos += 1
            dec_pos += 1
        elif switch == 2:
            if enc_pos + 1 >= len(enc_data):
                break
            result.append(chr(enc_data[enc_pos] + (enc_data[enc_pos + 1] << 8)))
            enc_pos += 2
            dec_pos += 1
        elif switch == 3:
            if enc_pos >= len(enc_data):
                break
            length = enc_data[enc_pos]
            enc_pos += 1
            if length & 0x80:
                if enc_pos >= len(enc_data):
                    break
                correction = enc_data[enc_pos]
                enc_pos += 1
                for _ in range((length & 0x7F) + 2):
                    if dec_pos >= name_size:
                        break
                    result.append(chr(((name_bytes[dec_pos] + correction) & 0xFF) + (high_byte << 8)))
                    dec_pos += 1
            else:
                for _ in range(length + 2):
                    if dec_pos >= name_size:
                        break
                    result.append(chr(name_bytes[dec_pos]))
                    dec_pos += 1

        flags = (flags << 2) & 0xFF
        flag_bits -= 2

    return ''.join(result)


class RarMainHeader(NamedTuple):
    flags: int
    is_volume: bool
    is_solid: bool
    is_locked: bool
    is_protected: bool
    is_encrypted: bool
    first_volume: bool
    new_numbering: bool
    comment_in_header: bool
    vol_number: int


class RarEndArchiveHeader(NamedTuple):
    next_volume: bool
    data_crc: int | None
    vol_number: int | None


@dataclass(repr=False)
class RarFileEntry:
    """
    Metadata for a single file or service entry in a RAR archive.
    """
    name: str = ''
    size: int = 0
    packed_size: int = 0
    date: datetime | None = None
    ctime: datetime | None = None
    atime: datetime | None = None
    method: int = 0
    is_dir: bool = False
    is_encrypted: bool = False
    crc32: int = 0
    hash_type: int = HashType.HASH_NONE
    hash_digest: buf = b''
    host_os: int = 0
    hs_type: int = HostSystemType.HSYS_UNKNOWN
    unp_ver: int = 0
    win_size: int = 0
    solid: bool = False
    split_before: bool = False
    split_after: bool = False
    crypt_method: int = CryptMethod.CRYPT_NONE
    salt: buf = b''
    init_v: buf = b''
    lg2_count: int = 0
    psw_check: buf = b''
    use_psw_check: bool = False
    hash_key: buf = b''
    use_hash_key: bool = False
    redir_type: int = FileSystemRedirect.FSREDIR_NONE
    redir_name: str = ''
    is_service: bool = False
    header_type: int = HeaderType.HEAD_FILE
    header_flags: int = 0
    file_flags: int = 0
    _volume_index: int = 0
    _data_offset: int = 0
    _data_size: int = 0
    unknown_unp_size: bool = False

    def __repr__(self):
        kind = 'dir' if self.is_dir else 'file'
        enc = ' [encrypted]' if self.is_encrypted else ''
        return F'<RarFileEntry:{kind}:{self.name}{enc}>'


class RarCryptHeader(NamedTuple):
    lg2_count: int
    salt: buf
    use_psw_check: bool
    psw_check: buf
    header_iv: buf = b''


class RawHeaderReader:
    """
    Simple binary reader for header data.
    """

    def __init__(self, data: bytes | bytearray | memoryview):
        self.data = memoryview(data)
        self.pos = 0

    def get1(self) -> int:
        if self.pos < len(self.data):
            v = self.data[self.pos]
            self.pos += 1
            return v
        return 0

    def get2(self) -> int:
        if self.pos + 1 < len(self.data):
            v = self.data[self.pos] | (self.data[self.pos + 1] << 8)
            self.pos += 2
            return v
        return 0

    def get4(self) -> int:
        if self.pos + 3 < len(self.data):
            v, = struct.unpack_from('<I', self.data, self.pos)
            self.pos += 4
            return v
        return 0

    def get8(self) -> int:
        if self.pos + 7 < len(self.data):
            v, = struct.unpack_from('<Q', self.data, self.pos)
            self.pos += 8
            return v
        return 0

    def getv(self) -> int:
        """
        Read a RAR5 variable-length integer.
        """
        result = 0
        shift = 0
        while self.pos < len(self.data) and shift < 64:
            b = self.data[self.pos]
            self.pos += 1
            result += (b & 0x7F) << shift
            if not (b & 0x80):
                return result
            shift += 7
        return 0

    def getv_size(self, pos: int | None = None) -> int:
        """
        Return byte count of vint at given position.
        """
        p = pos if pos is not None else self.pos
        for i in range(p, len(self.data)):
            if not (self.data[i] & 0x80):
                return i - p + 1
        return 0

    def getb(self, size: int) -> memoryview:
        end = min(self.pos + size, len(self.data))
        result = self.data[self.pos:end]
        self.pos = end
        return result

    def remaining(self) -> int:
        return max(0, len(self.data) - self.pos)

    def set_pos(self, pos: int):
        self.pos = pos

    def get_pos(self) -> int:
        return self.pos

    def size(self) -> int:
        return len(self.data)

    def crc15(self, processed_only: bool = False) -> int:
        """
        Compute RAR 1.5 header CRC (16-bit).
        """
        if len(self.data) <= 2:
            return 0
        end = self.pos if processed_only else len(self.data)
        crc = zlib.crc32(self.data[2:end], 0xFFFFFFFF)
        return (~crc) & 0xFFFF

    def crc50(self) -> int:
        """
        Compute RAR 5.0 header CRC32.
        """
        if len(self.data) <= 4:
            return 0xFFFFFFFF
        return zlib.crc32(self.data[4:]) & 0xFFFFFFFF


def _detect_crypt_method_15(unp_ver: int) -> int:
    if unp_ver == 13:
        return CryptMethod.CRYPT_RAR13
    elif unp_ver == 15:
        return CryptMethod.CRYPT_RAR15
    elif unp_ver in (20, 26):
        return CryptMethod.CRYPT_RAR20
    else:
        return CryptMethod.CRYPT_RAR30


def parse_header15(raw: RawHeaderReader) -> tuple:
    """
    Parse a RAR 1.5-4.x header block from the given RawHeaderReader.
    Returns (header_type, header_size, flags, parsed_object, next_block_delta).
    parsed_object is RarMainHeader, RarFileEntry, RarEndArchiveHeader, or None.
    """
    raw.get2()
    header_type_raw = raw.get1()
    flags = raw.get2()
    head_size = raw.get2()

    if head_size < SIZEOF_SHORTBLOCKHEAD:
        return HeaderType.HEAD_UNKNOWN, head_size, flags, None, head_size

    header_type = HeaderType(header_type_raw)
    header_type = _HEAD3_TO_5.get(header_type, header_type)

    if header_type == HeaderType.HEAD_MAIN:
        raw.get2()
        raw.get4()
        is_volume = bool(flags & MHD.VOLUME)
        is_solid = bool(flags & MHD.SOLID)
        is_locked = bool(flags & MHD.LOCK)
        is_protected = bool(flags & MHD.PROTECT)
        is_encrypted = bool(flags & MHD.PASSWORD)
        first_volume = bool(flags & MHD.FIRSTVOLUME)
        new_numbering = bool(flags & MHD.NEWNUMBERING)
        comment_in_header = bool(flags & MHD.COMMENT)

        mh = RarMainHeader(
            flags=flags,
            is_volume=is_volume,
            is_solid=is_solid,
            is_locked=is_locked,
            is_protected=is_protected,
            is_encrypted=is_encrypted,
            first_volume=first_volume,
            new_numbering=new_numbering,
            comment_in_header=comment_in_header,
            vol_number=0,
        )
        return header_type, head_size, flags, mh, head_size

    elif header_type in (HeaderType.HEAD_FILE, HeaderType.HEAD_SERVICE):
        hd = RarFileEntry()
        hd.header_type = header_type
        hd.header_flags = flags
        hd.is_service = (header_type == HeaderType.HEAD_SERVICE)

        hd.split_before = bool(flags & LHD.SPLIT_BEFORE)
        hd.split_after = bool(flags & LHD.SPLIT_AFTER)
        hd.is_encrypted = bool(flags & LHD.PASSWORD)
        hd.solid = (not hd.is_service) and bool(flags & LHD.SOLID)
        hd.is_dir = (flags & LHD.WINDOWMASK) == LHD.DIRECTORY
        hd.win_size = 0 if hd.is_dir else 0x10000 << ((flags & LHD.WINDOWMASK) >> 5)

        data_size = raw.get4()
        low_unp_size = raw.get4()
        hd.host_os = raw.get1()
        hd.hash_type = HashType.HASH_CRC32
        hd.crc32 = raw.get4()
        file_time = raw.get4()
        hd.unp_ver = raw.get1()
        hd.method = raw.get1() - 0x30

        if hd.unp_ver < 20 and (raw.data[raw.pos - 1] if raw.pos > 0 else 0):
            pass  # handled below

        name_size = raw.get2()
        hd.file_flags = raw.get4()

        if hd.is_encrypted:
            hd.crypt_method = _detect_crypt_method_15(hd.unp_ver)

        if hd.host_os in (HostSystem.HOST_UNIX, HostSystem.HOST_BEOS):
            hd.hs_type = HostSystemType.HSYS_UNIX
        elif hd.host_os <= HostSystem.HOST_BEOS:
            hd.hs_type = HostSystemType.HSYS_WINDOWS

        if hd.host_os == HostSystem.HOST_UNIX and (hd.file_flags & 0xF000) == 0xA000:
            hd.redir_type = FileSystemRedirect.FSREDIR_UNIXSYMLINK

        if hd.unp_ver < 20 and (hd.file_flags & 0x10):
            hd.is_dir = True

        large_file = bool(flags & LHD.LARGE)
        if large_file:
            high_pack = raw.get4()
            high_unp = raw.get4()
            hd.unknown_unp_size = (low_unp_size == 0xFFFFFFFF and high_unp == 0xFFFFFFFF)
        else:
            high_pack = 0
            high_unp = 0
            hd.unknown_unp_size = (low_unp_size == 0xFFFFFFFF)

        hd.packed_size = (high_pack << 32) | data_size
        hd.size = (high_unp << 32) | low_unp_size

        read_name_size = min(name_size, raw.remaining())
        name_bytes = bytes(raw.getb(read_name_size))

        if not hd.is_service:
            if flags & LHD.UNICODE:
                null_pos = name_bytes.find(b'\x00')
                if null_pos >= 0 and null_pos + 1 < len(name_bytes):
                    ascii_part = name_bytes[:null_pos]
                    enc_part = name_bytes[null_pos + 1:]
                    hd.name = decode_rar4_filename(ascii_part, enc_part)
                else:
                    hd.name = name_bytes.split(b'\x00', 1)[0].decode('latin-1')
            else:
                hd.name = name_bytes.rstrip(b'\x00').decode('latin-1')
        else:
            hd.name = name_bytes.rstrip(b'\x00').decode('latin-1', errors='replace')

        if flags & LHD.SALT:
            hd.salt = raw.getb(SIZE_SALT30)

        hd.date = dos_datetime(file_time)

        if flags & LHD.EXTTIME:
            _parse_ext_time(raw, hd, file_time)

        next_delta = head_size + hd.packed_size
        return header_type, head_size, flags, hd, next_delta

    elif header_type == HeaderType.HEAD_ENDARC:
        next_vol = bool(flags & EARC.NEXT_VOLUME)
        data_crc_present = bool(flags & EARC.DATACRC)
        vol_number_present = bool(flags & EARC.VOLNUMBER)
        data_crc = raw.get4() if data_crc_present else None
        vol_number = raw.get2() if vol_number_present else None
        eh = RarEndArchiveHeader(
            next_volume=next_vol,
            data_crc=data_crc,
            vol_number=vol_number,
        )
        return header_type, head_size, flags, eh, head_size

    else:
        next_delta = head_size
        if flags & LHD.LONG_BLOCK:
            next_delta += raw.get4()
        return header_type, head_size, flags, None, next_delta


def _parse_ext_time(raw: RawHeaderReader, hd: RarFileEntry, file_time: int):
    """
    Parse RAR 1.5-4.x extended time fields.
    """
    if raw.remaining() < 2:
        return
    ext_flags = raw.get2()
    for i in range(4):
        rmode = (ext_flags >> ((3 - i) * 4)) & 0xF
        if not (rmode & 8):
            continue
        if i == 0:
            base_time = file_time
        else:
            base_time = raw.get4() if raw.remaining() >= 4 else 0
        dt = dos_datetime(base_time)
        if dt is None:
            continue
        count = rmode & 3
        reminder = 0
        for j in range(count):
            b = raw.get1()
            reminder |= b << ((j + 3 - count) * 8)

        if i == 0:
            hd.date = dt
        elif i == 1:
            hd.ctime = dt
        elif i == 2:
            hd.atime = dt


def parse_header50(data: bytes | memoryview, offset: int = 0) -> tuple:
    """
    Parse a RAR 5.0 header block.
    Returns (header_type, header_total_size, parsed_object, next_block_delta).
    """
    raw = RawHeaderReader(data)

    raw.get4()
    size_bytes = raw.getv_size(4)
    block_size = raw.getv()

    if block_size == 0 or size_bytes == 0:
        return HeaderType.HEAD_UNKNOWN, 0, None, 0

    header_size = 4 + size_bytes + block_size

    header_type = HeaderType(raw.getv())
    block_flags = raw.getv()

    extra_size = 0
    if block_flags & HFL.EXTRA:
        extra_size = raw.getv()

    data_size = 0
    if block_flags & HFL.DATA:
        data_size = raw.getv()

    next_delta = header_size + data_size

    if header_type == HeaderType.HEAD_CRYPT:
        raw.getv()
        enc_flags = raw.getv()
        use_psw_check = bool(enc_flags & CHFL.CRYPT_PSWCHECK)
        lg2_count = raw.get1()
        salt = raw.getb(SIZE_SALT50)
        psw_check = b''
        if use_psw_check:
            psw_check = raw.getb(SIZE_PSWCHECK)
            csum = raw.getb(SIZE_PSWCHECK_CSUM)
            import hashlib
            digest = hashlib.sha256(psw_check).digest()
            if csum != digest[:SIZE_PSWCHECK_CSUM]:
                use_psw_check = False
        ch = RarCryptHeader(
            lg2_count=lg2_count,
            salt=salt,
            use_psw_check=use_psw_check,
            psw_check=psw_check,
        )
        return header_type, header_size, ch, next_delta

    elif header_type == HeaderType.HEAD_MAIN:
        arc_flags = raw.getv()
        is_volume = bool(arc_flags & MHFL.VOLUME)
        is_solid = bool(arc_flags & MHFL.SOLID)
        is_locked = bool(arc_flags & MHFL.LOCK)
        is_protected = bool(arc_flags & MHFL.PROTECT)
        vol_number = 0
        if arc_flags & MHFL.VOLNUMBER:
            vol_number = raw.getv()
        first_volume = is_volume and vol_number == 0

        mh = RarMainHeader(
            flags=arc_flags,
            is_volume=is_volume,
            is_solid=is_solid,
            is_locked=is_locked,
            is_protected=is_protected,
            is_encrypted=False,
            first_volume=first_volume,
            new_numbering=True,
            comment_in_header=False,
            vol_number=vol_number,
        )
        return header_type, header_size, mh, next_delta

    elif header_type in (HeaderType.HEAD_FILE, HeaderType.HEAD_SERVICE):
        hd = RarFileEntry()
        hd.header_type = header_type
        hd.header_flags = block_flags
        hd.is_service = (header_type == HeaderType.HEAD_SERVICE)

        hd.packed_size = data_size
        hd.file_flags = raw.getv()
        hd.size = raw.getv()
        hd.unknown_unp_size = bool(hd.file_flags & FHFL.UNPUNKNOWN)

        raw.getv()
        hd.is_dir = bool(hd.file_flags & FHFL.DIRECTORY)

        if hd.file_flags & FHFL.UTIME:
            unix_time = raw.get4()
            try:
                hd.date = datetime.fromtimestamp(unix_time, tz=timezone.utc)
            except (OSError, OverflowError, ValueError):
                pass

        if hd.file_flags & FHFL.CRC32:
            hd.hash_type = HashType.HASH_CRC32
            hd.crc32 = raw.get4()

        comp_info = raw.getv()
        hd.method = (comp_info >> FCI.METHOD_SHIFT) & 7
        hd.unp_ver = (comp_info & FCI.ALGO_MASK) + 50
        hd.solid = bool(comp_info & FCI.SOLID)
        hd.win_size = 0 if hd.is_dir else 0x20000 << ((comp_info >> FCI.DICT_SHIFT) & 0xF)

        hd.host_os = raw.getv()
        if hd.host_os == HostSystem.HOST5_UNIX:
            hd.hs_type = HostSystemType.HSYS_UNIX
        elif hd.host_os == HostSystem.HOST5_WINDOWS:
            hd.hs_type = HostSystemType.HSYS_WINDOWS

        name_size = raw.getv()
        name_bytes = bytes(raw.getb(name_size))
        hd.name = name_bytes.rstrip(b'\x00').decode('utf-8', errors='replace')

        hd.split_before = bool(block_flags & HFL.SPLITBEFORE)
        hd.split_after = bool(block_flags & HFL.SPLITAFTER)

        if extra_size > 0:
            _parse_extra50(raw, hd, extra_size, header_size)

        return hd.header_type, header_size, hd, next_delta

    elif header_type == HeaderType.HEAD_ENDARC:
        arc_flags = raw.getv()
        eh = RarEndArchiveHeader(
            next_volume=bool(arc_flags & EHFL.NEXTVOLUME),
            data_crc=None,
            vol_number=None,
        )
        return header_type, header_size, eh, next_delta

    return header_type, header_size, None, next_delta


def _parse_extra50(
    raw: RawHeaderReader,
    hd: RarFileEntry,
    extra_size: int,
    header_size: int,
):
    """
    Parse RAR5 extra fields for a file/service header.
    """
    extra_start = header_size - extra_size
    if extra_start < raw.get_pos():
        return
    raw.set_pos(extra_start)

    while raw.remaining() >= 2:
        field_size = raw.getv()
        if field_size <= 0 or raw.remaining() == 0 or field_size > raw.remaining():
            break
        next_pos = raw.get_pos() + field_size
        field_type = raw.getv()

        if field_type == FHEXTRA_CRYPT:
            enc_version = raw.getv()
            if enc_version <= 0:  # CRYPT_VERSION = 0
                enc_flags = raw.getv()
                hd.use_psw_check = bool(enc_flags & FHEXTRA_CRYPT_PSWCHECK)
                hd.use_hash_key = bool(enc_flags & FHEXTRA_CRYPT_HASHMAC)
                hd.lg2_count = raw.get1()
                hd.salt = raw.getb(SIZE_SALT50)
                hd.init_v = raw.getb(SIZE_INITV)
                if hd.use_psw_check:
                    hd.psw_check = raw.getb(SIZE_PSWCHECK)
                    csum = raw.getb(SIZE_PSWCHECK_CSUM)
                    import hashlib
                    digest = hashlib.sha256(hd.psw_check).digest()
                    hd.use_psw_check = (csum == digest[:SIZE_PSWCHECK_CSUM])
                    if hd.is_service and hd.psw_check == b'\x00' * SIZE_PSWCHECK:
                        hd.use_psw_check = False
                hd.crypt_method = CryptMethod.CRYPT_RAR50
                hd.is_encrypted = True

        elif field_type == FHEXTRA_HASH:
            hash_type = raw.getv()
            if hash_type == FHEXTRA_HASH_BLAKE2:
                hd.hash_type = HashType.HASH_BLAKE2
                hd.hash_digest = raw.getb(BLAKE2_DIGEST_SIZE)

        elif field_type == FHEXTRA_HTIME:
            time_flags = raw.getv()
            is_unix = bool(time_flags & FHEXTRA_HTIME_UNIXTIME)
            if time_flags & FHEXTRA_HTIME_MTIME:
                if is_unix:
                    ts = raw.get4()
                    try:
                        hd.date = datetime.fromtimestamp(ts, tz=timezone.utc)
                    except (OSError, OverflowError, ValueError):
                        pass
                else:
                    raw.get8()
            if time_flags & FHEXTRA_HTIME_CTIME:
                if is_unix:
                    ts = raw.get4()
                    try:
                        hd.ctime = datetime.fromtimestamp(ts, tz=timezone.utc)
                    except (OSError, OverflowError, ValueError):
                        pass
                else:
                    raw.get8()
            if time_flags & FHEXTRA_HTIME_ATIME:
                if is_unix:
                    ts = raw.get4()
                    try:
                        hd.atime = datetime.fromtimestamp(ts, tz=timezone.utc)
                    except (OSError, OverflowError, ValueError):
                        pass
                else:
                    raw.get8()

        elif field_type == FHEXTRA_REDIR:
            hd.redir_type = raw.getv()
            raw.getv()
            redir_name_size = raw.getv()
            redir_name = bytes(raw.getb(redir_name_size))
            hd.redir_name = redir_name.decode('utf-8', errors='replace')

        raw.set_pos(next_pos)


def parse_headers(
    data: bytes | memoryview,
    fmt: RarFormat,
    password: str | None = None,
) -> tuple[
    RarMainHeader | None,
    list[RarFileEntry],
    RarEndArchiveHeader | None,
    RarCryptHeader | None,
]:
    """
    Parse all headers from a RAR volume.
    Returns (main_header, file_entries, end_header, crypt_header).
    """
    pos = 0
    main_header = None
    entries: list[RarFileEntry] = []
    end_header = None
    crypt_header = None
    encrypted = False
    _hdr_key = None

    view = memoryview(data) if not isinstance(data, memoryview) else data

    if fmt == RarFormat.RARFMT50:
        pos = SIZEOF_MARKHEAD5
    elif fmt == RarFormat.RARFMT15:
        pos = SIZEOF_MARKHEAD3
    elif fmt == RarFormat.RARFMT14:
        pos = 4

    while pos < len(data):
        remaining = view[pos:]
        if len(remaining) < SIZEOF_SHORTBLOCKHEAD:
            break

        if encrypted:
            if crypt_header is not None:
                if password is None or fmt != RarFormat.RARFMT50:
                    break
                if _hdr_key is None:
                    from refinery.lib.unrar.crypt import rar5_pbkdf2, rar5_psw_check
                    _hdr_key, _, psw_check_value = rar5_pbkdf2(
                        password, crypt_header.salt, crypt_header.lg2_count)
                    if crypt_header.use_psw_check:
                        computed = rar5_psw_check(psw_check_value)
                        if computed != crypt_header.psw_check:
                            from refinery.lib.unrar import RarInvalidPassword
                            raise RarInvalidPassword
                if len(remaining) < SIZE_INITV:
                    break
                iv = remaining[:SIZE_INITV]
                enc_data = remaining[SIZE_INITV:]
                if not enc_data:
                    break
                if pad := -len(enc_data) % CRYPT_BLOCK_SIZE:
                    enc_data = bytearray(enc_data)
                    enc_data.extend(itertools.repeat(0, pad))
                from Cryptodome.Cipher import AES
                cipher = AES.new(_hdr_key, AES.MODE_CBC, iv=iv)
                dec_data = cipher.decrypt(enc_data)
                header_type, header_size, parsed, next_delta = parse_header50(dec_data)
                if header_size == 0:
                    break
                data_size = next_delta - header_size
                enc_header_size = header_size
                if enc_header_size % CRYPT_BLOCK_SIZE:
                    enc_header_size += CRYPT_BLOCK_SIZE - enc_header_size % CRYPT_BLOCK_SIZE
                abs_data_offset = pos + SIZE_INITV + enc_header_size

                if header_type in (HeaderType.HEAD_FILE, HeaderType.HEAD_SERVICE):
                    if isinstance(parsed, RarFileEntry):
                        parsed._volume_index = 0
                        parsed._data_offset = abs_data_offset
                        parsed._data_size = data_size
                        entries.append(parsed)
                elif header_type == HeaderType.HEAD_MAIN:
                    if isinstance(parsed, RarMainHeader):
                        main_header = parsed
                elif header_type == HeaderType.HEAD_ENDARC:
                    if isinstance(parsed, RarEndArchiveHeader):
                        end_header = parsed
                    break

                pos = abs_data_offset + data_size
                continue
            elif fmt in (RarFormat.RARFMT15, RarFormat.RARFMT14):
                if password is None:
                    break
                if len(remaining) < SIZE_SALT30 + CRYPT_BLOCK_SIZE:
                    break
                salt = remaining[:SIZE_SALT30]
                from refinery.lib.unrar.crypt import rar3_kdf
                key, iv = rar3_kdf(password, salt)
                enc_data = remaining[SIZE_SALT30:]
                if pad := -len(enc_data) % CRYPT_BLOCK_SIZE:
                    enc_data = bytearray(enc_data)
                    enc_data.extend(itertools.repeat(0, pad))
                from Cryptodome.Cipher import AES
                cipher = AES.new(key, AES.MODE_CBC, iv=iv)
                dec_data = cipher.decrypt(enc_data)
                raw = RawHeaderReader(dec_data)
                header_type, header_size, flags, parsed, next_delta = parse_header15(raw)
                if header_size == 0:
                    break
                enc_header_size = header_size
                if enc_header_size % CRYPT_BLOCK_SIZE:
                    enc_header_size += CRYPT_BLOCK_SIZE - enc_header_size % CRYPT_BLOCK_SIZE
                abs_data_offset = pos + SIZE_SALT30 + enc_header_size
                data_size = next_delta - header_size

                if header_type in (HeaderType.HEAD_FILE, HeaderType.HEAD_SERVICE):
                    if isinstance(parsed, RarFileEntry):
                        parsed._volume_index = 0
                        parsed._data_offset = abs_data_offset
                        parsed._data_size = data_size
                        entries.append(parsed)
                elif header_type == HeaderType.HEAD_MAIN:
                    if isinstance(parsed, RarMainHeader):
                        main_header = parsed
                elif header_type == HeaderType.HEAD_ENDARC:
                    if isinstance(parsed, RarEndArchiveHeader):
                        end_header = parsed
                    break

                pos = abs_data_offset + data_size
                continue
            else:
                break

        if fmt == RarFormat.RARFMT50:
            header_type, header_size, parsed, next_delta = parse_header50(remaining)
        elif fmt in (RarFormat.RARFMT15, RarFormat.RARFMT14):
            raw = RawHeaderReader(remaining)
            header_type, header_size, flags, parsed, next_delta = parse_header15(raw)
        else:
            break

        if header_size == 0:
            break

        if header_type == HeaderType.HEAD_CRYPT:
            if isinstance(parsed, RarCryptHeader):
                iv_start = pos + next_delta
                iv_end = iv_start + SIZE_INITV
                header_iv = view[iv_start:iv_end] if iv_end <= len(view) else b''
                crypt_header = parsed._replace(header_iv=header_iv)
                encrypted = True

        elif header_type == HeaderType.HEAD_MAIN:
            if isinstance(parsed, RarMainHeader):
                main_header = parsed
                if main_header.is_encrypted:
                    encrypted = True

        elif header_type in (HeaderType.HEAD_FILE, HeaderType.HEAD_SERVICE):
            if isinstance(parsed, RarFileEntry):
                parsed._volume_index = 0
                parsed._data_offset = pos + header_size
                parsed._data_size = parsed.packed_size
                entries.append(parsed)

        elif header_type == HeaderType.HEAD_ENDARC:
            if isinstance(parsed, RarEndArchiveHeader):
                end_header = parsed
            break

        if next_delta <= 0:
            break
        pos += next_delta

    return main_header, entries, end_header, crypt_header
