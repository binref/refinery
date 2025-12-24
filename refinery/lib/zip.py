"""
Structures for unpacking ZIP archives. This can cover a lot more than the built-in zipfile module,
but it is incapable of creating ZIP archives.
"""
from __future__ import annotations

import bisect
import codecs
import enum
import re
import zlib

from datetime import datetime
from typing import TYPE_CHECKING, NamedTuple

from Cryptodome.Cipher import AES, ARC2, ARC4, DES, DES3, Blowfish
from Cryptodome.Hash import HMAC, SHA1
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Util import Counter

from refinery.lib.decompression import parse_lzma_properties
from refinery.lib.id import buffer_offset
from refinery.lib.intervals import IntIntervalUnion
from refinery.lib.shared import pyppmd, pyzstd
from refinery.lib.structures import FlagAccessMixin, Struct, StructReader, StructReaderBits
from refinery.lib.types import buf
from refinery.units.misc.datefix import datefix

if TYPE_CHECKING:
    from typing import Iterable, Self


class PasswordRequired(Exception):
    pass


class InvalidPassword(ValueError):
    pass


class InvalidChecksum(ValueError):
    def __init__(self, record: ZipFileRecord, data: buf, expected: int, computed: int) -> None:
        self.record = record
        self.data = data
        self.expected = expected
        self.computed = computed

    def __str__(self):
        return (
            F'Invalid checksum for {self.record.name};'
            F' computed {self.computed:08X},'
            F' expected {self.expected:08X}.')


class DataIntegrityError(ValueError):
    pass


class ZipAnomalies(enum.IntFlag):
    Normal = 0
    DataDescriptorWithoutHeader = 1


class ZipFlags(FlagAccessMixin, enum.IntFlag):
    Encrypted           = 0x0001 # noqa
    CompressOption1     = 0x0002 # noqa
    CompressOption2     = 0x0004 # noqa
    DataDescriptor      = 0x0008 # noqa
    EnhancedDeflate     = 0x0010 # noqa
    CompressedPatched   = 0x0020 # noqa
    StrongEncryption    = 0x0040 # noqa
    UseUTF8             = 0x0800 # noqa
    EncryptedCD         = 0x2000 # noqa


class ZipEncryptionAlgorithm(enum.IntEnum):
    DES             = 0x6601 # noqa
    BuggyRC2        = 0x6602 # noqa (version needed to extract < 5.2)
    TrippleDES168   = 0x6603 # noqa
    TrippleDES112   = 0x6609 # noqa
    AES128          = 0x660E # noqa
    AES192          = 0x660F # noqa
    AES256          = 0x6610 # noqa
    RC2             = 0x6702 # noqa (version needed to extract >= 5.2)
    Blowfish        = 0x6720 # noqa
    Twofish         = 0x6721 # noqa
    RC4             = 0x6801 # noqa
    Unknown         = 0xFFFF # noqa


class ZipEncryptionFlags(FlagAccessMixin, enum.IntFlag):
    DecryptWithPassword = 1
    DecryptWithCertificate = 2


class ZipCompressionMethod(enum.IntEnum):
    STORE           = 0x00 # noqa
    SHRINK          = 0x01 # noqa
    REDUCED1        = 0x02 # noqa
    REDUCED2        = 0x03 # noqa
    REDUCED3        = 0x04 # noqa
    REDUCED4        = 0x05 # noqa
    IMPLODE         = 0x06 # noqa
    TOKENIZE        = 0x07 # noqa
    DEFLATE         = 0x08 # noqa
    DEFLATE64       = 0x09 # noqa
    PKWARE_IMPLODE  = 0x0A # noqa
    BZIP2           = 0x0C # noqa
    LZMA            = 0x0E # noqa
    IBM_CMPSC       = 0x10 # noqa
    IBM_TERSE       = 0x12 # noqa
    IBM_LZ77        = 0x13 # noqa
    ZSTD_DEPRECATED = 0x14 # noqa
    ZSTD            = 0x5D # noqa
    MP3             = 0x5E # noqa
    XZ              = 0x5F # noqa
    JPEG            = 0x60 # noqa
    WAVPACK         = 0x61 # noqa
    PPMD            = 0x62 # noqa
    AExENCRYPTION   = 0x63 # noqa
    RESERVED11      = 0x0B # noqa
    RESERVED13      = 0x0D # noqa
    RESERVED15      = 0x0F # noqa
    RESERVED17      = 0x11 # noqa


class ZipCrypto(Struct):
    CRC32Table: list[int] = []

    def __init__(self, reader: StructReader, crc: int):
        if not (ct := self.CRC32Table):
            for c in range(256):
                for _ in range(8):
                    c, x = divmod(c, 2)
                    c ^= x * 0xEDB88320
                ct.append(c)
        self.header = reader.read(12)
        self.crc = crc
        self._restart()

    def _restart(self):
        self.state = (0x12345678, 0x23456789, 0x34567890)

    def _decrypt(self, password: Iterable[int], data: buf):
        key0, key1, key2 = self.state
        crc32table = self.CRC32Table

        def update_keys(char: int):
            nonlocal key0, key1, key2
            key0 = (key0 >> 8) ^ crc32table[(key0 ^ char) & 0xFF]
            key1 = (key1 + (key0 & 0xFF)) & 0xFFFFFFFF
            key1 = (key1 * 134775813 + 1) & 0xFFFFFFFF
            char = (key1 >> 24)
            key2 = (key2 >> 8) ^ crc32table[(key2 ^ char) & 0xFF]

        for c in password:
            update_keys(c)

        for c in data:
            k = key2 | 2
            c ^= ((k * (k ^ 1)) >> 8) & 0xFF
            update_keys(c)
            yield c

        self.state = key0, key1, key2

    def checkpwd(self, password: str | None):
        if password is None:
            return False
        self._restart()
        head = bytes(self._decrypt(password.encode('latin1'), self.header))
        return head[11] == (self.crc >> 24) & 0xFF

    def decrypt(self, password: str, data: buf):
        if not self.checkpwd(password):
            raise InvalidPassword
        return bytearray(self._decrypt((), data))


class ZipInternalFileAttributes(FlagAccessMixin, enum.IntFlag):
    ApparentText = 0x0001
    RecordLengthControl = 0x0002


class SigningBlock42Entry(Struct):
    def __init__(self, reader: StructReader[memoryview]):
        length = reader.u64()
        self.id = reader.u32()
        self.value = reader.read_exactly(length - 4)


class PkgSigningBlock(Struct):
    Signature = None
    SeekDelta = 0

    @classmethod
    def FromCentralDir(cls, reader: StructReader[memoryview]) -> Self | None:
        cd = reader.tell()
        sd = cls.SeekDelta
        sb = cls.Signature
        if sb is None:
            raise NotImplementedError
        if (seek := cd - len(sb) - 8) >= 0:
            reader.seekset(seek)
            size = reader.u64()
            if reader.read(len(sb)) != sb:
                return None
            if (seek := reader.tell() - size - sd) >= 0:
                reader.seekset(seek)
                try:
                    apksig = cls(reader, size)
                except (ValueError, EOFError):
                    reader.seekset(cd)
                    return None
                if (m := len(apksig)) != (n := size + sd):
                    raise ValueError(F'Size mismatch: {m} != {n}.')
                return apksig


class ApkSigningBlock42(PkgSigningBlock):
    """
    The standard APK signing block.
    """
    Signature = B'APK Sig Block 42'
    SeekDelta = 8

    def __init__(self, reader: StructReader[memoryview], size: int):
        self.offset = reader.tell()
        n = reader.u64()
        if n != size or n < 0x18:
            raise ValueError(F'Invalid length {n} for {self.__class__.__name__}.')
        self.data = reader.read_exactly(n - 0x18)
        body = StructReader(self.data)
        if (m := reader.u64()) != n:
            raise ValueError(F'Size mismatch: {m} != {n}.')
        if reader.read(0x10) != self.Signature:
            raise ValueError('Invalid signature.')
        fields: list[SigningBlock42Entry] = []
        try:
            while not body.eof:
                fields.append(SigningBlock42Entry(body))
        except (ValueError, EOFError):
            self.fields = None
        else:
            self.fields = fields


class RpkSigningBlock42(ApkSigningBlock42):
    """
    Rapid Package variant of the signing block. Also known as MiniApp.
    """
    Signature = B'RPK Sig Block 42'


class ApkSigningBlock42_VariantWithAt(ApkSigningBlock42):
    """
    An unknown variant of the APK signing block with an @ symbol instead of A. Seen in:
    e85f49b2234cc84d222e57a24c905cd37ceaf460a55e38956389e759f2ffd0a8
    """
    Signature = B'@PK Sig Block 42'


class UnknownSigningBlockPK57(PkgSigningBlock):
    """
    Unknown block of what appears to be a custom signature, seen in:
    fc5a13755bc0a744ea2c0807eee83823a03cdb28bf99c5d40419719a2b159cb4
    """
    Signature = B'PK\x05\x07'
    SeekDelta = 12

    def __init__(self, reader: StructReader[memoryview], size: int):
        self.offset = reader.tell()
        self.unknown = reader.u32()
        self.signature = reader.read(size - 4)
        self.size = reader.u64()
        if self.size != size:
            raise ValueError
        if reader.read(4) != self.Signature:
            raise ValueError


class ZipEncryptionHeader(Struct):
    def __init__(self, reader: StructReader[memoryview]):
        self.iv = bytes(reader.read_exactly(reader.u16()))
        self.header_size = reader.u32()
        self.format = reader.u16()
        if self.format != 3:
            raise ValueError(F'Invalid format {self.format:#x} in {self.__class__.__name__}.')
        self.algorithm = ZipEncryptionAlgorithm(reader.u16())
        self.bitlen = reader.u16()
        self.flags = ZipEncryptionFlags(reader.u16())
        self.erd = reader.read_exactly(reader.u16())
        self.reserved1 = r1 = reader.u32()
        self.reserved2 = reader.read_exactly(reader.u16()) if r1 else None
        if (vn := reader.u16()) <= 4:
            raise ValueError(F'Invalid size {vn} for validation data in {self.__class__.__name__}.')
        self.validation = reader.read_exactly(vn - 4)
        self.crc32 = reader.u32()
        self._derivations = {}

    def derive_key(self, password: str):
        def _cipher(key):
            if block_cipher is None:
                return ARC4.new(key)
            iv = self.iv[:block_cipher.block_size]
            return block_cipher.new(key, getattr(block_cipher, 'MODE_CBC'), iv=iv)
        try:
            derived = self._derivations[password]
        except KeyError:
            algorithm = self.algorithm
            key_size = 16

            if algorithm == ZipEncryptionAlgorithm.AES128:
                block_cipher = AES
            elif algorithm == ZipEncryptionAlgorithm.AES192:
                key_size = 24
                block_cipher = AES
            elif algorithm == ZipEncryptionAlgorithm.AES256:
                key_size = 32
                block_cipher = AES
            elif algorithm == ZipEncryptionAlgorithm.DES:
                key_size = 8
                block_cipher = DES
            elif algorithm == ZipEncryptionAlgorithm.TrippleDES168:
                key_size = 24
                block_cipher = DES3
            elif algorithm == ZipEncryptionAlgorithm.TrippleDES112:
                block_cipher = DES3
            elif algorithm == ZipEncryptionAlgorithm.RC2:
                block_cipher = ARC2
            elif algorithm == ZipEncryptionAlgorithm.RC4:
                block_cipher = None
            elif algorithm == ZipEncryptionAlgorithm.Blowfish:
                block_cipher = Blowfish
            elif algorithm == ZipEncryptionAlgorithm.BuggyRC2:
                raise NotImplementedError(
                    F'This ZIP uses a buggy and unsupported RC2 implementation, indicated by the legacy identifier {algorithm:#x}.')
            elif algorithm == ZipEncryptionAlgorithm.Twofish:
                raise NotImplementedError(
                    'This ZIP uses the unsupported Twofish encryption mode.')
            else:
                raise ValueError(
                    F'Unsupported encryption algorithm {algorithm:#x}.')

            password_hash = SHA1.new(password.encode('utf-8')).digest()
            master_key_material = PBKDF2(
                password_hash.decode('latin1'),
                password_hash,
                dkLen=key_size * 2 + 2,
                count=1000,
                hmac_hash_module=SHA1
            )
            master_key = master_key_material[:key_size]

            rd = _cipher(master_key).decrypt(self.erd)
            iv = SHA1.new(self.iv + rd).digest()
            key_material = PBKDF2(
                iv.decode('latin1'),
                iv,
                dkLen=key_size * 2 + 2,
                count=1000,
                hmac_hash_module=SHA1
            )

            data_key = key_material[:key_size]
            auth_key = key_material[key_size:key_size * 2]
            password_verify = key_material[key_size * 2:key_size * 2 + 2]

            if password_verify != self.validation[:2]:
                self._derivations[password] = None
                raise InvalidPassword
            else:
                self._derivations[password] = block_cipher, data_key, auth_key
        else:
            if derived is None:
                raise InvalidPassword
            block_cipher, data_key, auth_key = derived

        return _cipher(data_key), auth_key

    def checkpwd(self, password: str | None):
        if password is None:
            return False
        try:
            self.derive_key(password)
        except InvalidPassword:
            return False
        else:
            return True

    def decrypt(self, password: str, data: bytes):
        cipher, hmk = self.derive_key(password)

        if len(self.validation) > 2:
            computed_hmac = HMAC.new(hmk, data, SHA1).digest()
            expected_hmac = self.validation[2:12] if len(self.validation) >= 12 else self.validation[2:]
            if computed_hmac[:len(expected_hmac)] != expected_hmac:
                raise DataIntegrityError

        return cipher.decrypt(data)


class ZipArchiveExtraDataRecord(Struct):
    Signature = B'PK\x06\x08'

    def __init__(self, reader: StructReader[memoryview]):
        if reader.read(4) != self.Signature:
            raise ValueError
        self.extra_field_data = reader.read_exactly(reader.u32())
        self.extra_fields = ZipExtraField.ParseBuffer(self.extra_field_data)


class ZipDigitalSignature(Struct):
    Signature = B'PK\x05\x05'

    def __init__(self, reader: StructReader[memoryview]):
        if reader.read(4) != self.Signature:
            raise ValueError
        self.size_of_data = reader.u16()
        self.signature_data = reader.read_exactly(self.size_of_data)


class ZipDataDescriptorRaw(NamedTuple):
    crc32: int
    csize: int
    usize: int


class ZipDataDescriptor(Struct):
    Signature = B'PK\x07\x08'

    def __init__(
        self,
        reader: StructReader[memoryview],
        is64bit: bool = False,
        expected_size: int = -1,
    ):
        if reader.read(4) != self.Signature:
            raise ValueError
        self.crc32 = reader.u32()
        if expected_size >= 0:
            u64value = reader.u64(peek=True)
            u32value = reader.u32(peek=True)
            if expected_size == u32value:
                if expected_size != u64value:
                    is64bit = False
            elif expected_size == u64value:
                if expected_size != u32value:
                    is64bit = True
        size = reader.u64 if is64bit else reader.u32
        self.csize = size()
        self.usize = size()
        if not is64bit and self.usize == 0 and self.csize > 0x100:
            # This is likely a 64-bit descriptor despite what we thought.
            self.usize = reader.u64()
            is64bit = True
        self.is64bit = is64bit


class ZipFileRecord(Struct):
    Signature = B'PK\x03\x04'

    def __init__(
        self,
        reader: StructReader[memoryview],
        is64bit: bool = False,
        ddirs: list[int] | None = None,
        read_data: bool = True,
        dir: ZipDirEntry | None = None,
    ):
        self._unpacked = None
        self._decrypted = None
        self.offset = reader.tell()
        self.dir = dir

        self.anomalies = ZipAnomalies.Normal

        if reader.read(4) != self.Signature:
            raise ValueError
        self.version = reader.u16()
        self.flags = ZipFlags(reader.u16())
        self.method = ZipCompressionMethod(reader.u16())
        try:
            self.date = datefix.dostime(reader.u32(peek=True))
        except Exception:
            self.date = None
        self.mtime = reader.u16()
        self.mdate = reader.u16()

        descriptor = reader.peek(12)
        self.crc32 = reader.u32()
        self.csize = reader.u32()
        self.usize = reader.u32()

        nl = reader.u16()
        xl = reader.u16()
        self.name_bytes = reader.read_exactly(nl)
        self.xtra_data = reader.read_exactly(xl)
        self.xtra = ZipExtraField.ParseBuffer(self.xtra_data)

        self.ae = None
        self.ux = None
        self.up = None
        self.ts = None

        codec = 'utf8' if self.flags.UseUTF8 else 'latin1'
        self.name = codecs.decode(self.name_bytes, codec)

        for x in self.xtra:
            if z64 := ZipExtInfo64.TryParse(x, self.usize, self.csize):
                self.usize = z64.usize
                self.csize = z64.csize
                is64bit = True
            elif ae := ZipExtAES.TryParse(x):
                if self.method != ZipCompressionMethod.AExENCRYPTION:
                    raise ValueError(F'AES extension found, but compression method was {self.method.name}.')
                self.ae = ae
                self.method = ae.method
            elif up := ZipExtUnicodePath.TryParse(x):
                self.up = up
                if up.crc == zlib.crc32(self.name_bytes) & 0xFFFFFFFF:
                    self.name = up.name
            elif ux := ZipExtUnixIDs.TryParse(x):
                self.ux = ux
            elif ts := ZipExtTimestamp.TryParse(x):
                self.ts = ts

        self.data_offset = start = reader.tell()
        self.data_descriptor = None

        if not self.flags.Encrypted:
            self.encryption = NoCrypto()
        elif self.flags.StrongEncryption:
            self.encryption = ZipEncryptionHeader(reader)
        else:
            if ae := (dir.ae if dir else None) or self.ae:
                self.encryption = AExCrypto(reader, ae)
            else:
                self.encryption = ZipCrypto(reader, self.crc32)

        skipped = len(self.encryption)

        if not read_data:
            self.data = None
            return

        if 0 < self.csize:
            rest = self.csize - skipped
            if rest < 0:
                raise DataIntegrityError
            self.data = reader.read_exactly(rest)
        else:
            self.data = B''

        if ddirs and not self.csize:
            k = bisect.bisect_left(ddirs, start)
            for k in range(k, len(ddirs)):
                ddpos = ddirs[k]
                csize = ddpos - self.data_offset
                self.data = reader.read_exactly(csize - skipped)
                self.data_descriptor = info = ZipDataDescriptor(reader, is64bit, csize)
                if info.csize == csize:
                    self.crc32 = info.crc32
                    self.csize = info.csize
                    self.usize = info.usize
                    is64bit = info.is64bit
                    break
                try:
                    u = self.unpack()
                except Exception:
                    pass
                else:
                    self.csize = csize
                    self.usize = len(u)
                    break
                reader.seekset(self.data_offset)
                start += 4
        elif self.flags.DataDescriptor or reader.peek(4) == ZipDataDescriptor.Signature:
            self.data_descriptor = info = ZipDataDescriptor(reader, is64bit)
            is64bit = info.is64bit
            self.crc32 = self.crc32 or info.crc32
            self.csize = self.csize or info.csize
            self.usize = self.usize or info.usize
        elif reader.peek(12) == descriptor:
            self.data_descriptor = ZipDataDescriptorRaw(reader.u32(), reader.u32(), reader.u32())
            self.anomalies |= ZipAnomalies.DataDescriptorWithoutHeader

        self.is64bit = is64bit

    def get_mtime(self):
        ts = None
        if dir := self.dir:
            if (ts := dir.ts) is None and (dt := dir.date):
                return dt
        if ts and (t := ts.mtime) or self.ts and (t := self.ts.mtime):
            return datetime.fromtimestamp(t)
        return self.date

    def get_ctime(self):
        if self.dir and (ts := self.dir.ts) and (t := ts.ctime) or (ts := self.ts) and (t := ts.ctime):
            return datetime.fromtimestamp(t)

    def get_atime(self):
        if self.dir and (ts := self.dir.ts) and (t := ts.atime) or (ts := self.ts) and (t := ts.atime):
            return datetime.fromtimestamp(t)

    def get_name(self):
        if (dir := self.dir) and (name := dir.name):
            return name
        return self.name

    def get_gid(self):
        if ux := (d.ux if (d := self.dir) else None) or self.ux:
            return ux.gid

    def get_uid(self):
        if ux := (d.ux if (d := self.dir) else None) or self.ux:
            return ux.uid

    def is_dir(self):
        return self.get_name().endswith(('/', '\\'))

    def is_password_ok(self, password: str | None = None):
        return self.encryption.checkpwd(password)

    def unpack(self, password: str | None = None, check: bool = True):
        if not check:
            def _nocheck(x):
                return x
            _checked = _nocheck
        else:
            def _checker(unpacked: buf):
                crc32loc = self.crc32
                crc32dir = 0 if (dir := self.dir) is None else dir.crc32
                if crc32loc == 0 and crc32dir == 0:
                    return unpacked
                crc32 = zlib.crc32(unpacked)
                if crc32 == crc32loc or crc32 == crc32dir:
                    return unpacked
                raise InvalidChecksum(self, unpacked, crc32dir or crc32loc, crc32)
            _checked = _checker

        if (d := self.data) is None:
            raise ValueError(F'The data for this {self.__class__.__name__} was not read.')
        if (u := self._unpacked) is not None:
            return _checked(u)

        if e := self.encryption:
            if not password:
                raise PasswordRequired
            compressed = e.decrypt(password, d)
        else:
            compressed = d

        if (m := self.method) == ZipCompressionMethod.STORE:
            u = compressed
        elif m == ZipCompressionMethod.DEFLATE:
            u = zlib.decompress(compressed, -15)
        elif m == ZipCompressionMethod.DEFLATE64:
            from refinery.lib.seven.deflate import Deflate
            u = bytearray()
            deflate = Deflate(u, StructReader(memoryview(compressed)), df64=True)
            deflate.decode()
        elif m == ZipCompressionMethod.BZIP2:
            import bz2
            u = bz2.decompress(compressed)
        elif m == ZipCompressionMethod.LZMA:
            import lzma
            cv = memoryview(compressed)
            cr = StructReader(cv)
            _ = cr.u8() # major version
            _ = cr.u8() # minor version
            n = cr.u16()
            properties_data = cr.read_exactly(n)
            compressed_data = cr.read()
            decompressor = lzma.LZMADecompressor(
                lzma.FORMAT_RAW, filters=[parse_lzma_properties(properties_data, 1)])
            u = decompressor.decompress(compressed_data)
        elif m == ZipCompressionMethod.PPMD:
            cv = memoryview(compressed)
            cr = StructReaderBits(cv)
            order = 1 + cr.read_nibble()
            msize = 1 + cr.read_byte() << 20
            rm = cr.read_nibble()
            ppmd = pyppmd.PpmdDecompressor(order, msize, restore_method=rm)
            u = ppmd.decompress(bytes(cr.read()))
        elif m == ZipCompressionMethod.ZSTD:
            dctx = pyzstd.ZstdDecompressor()
            u = dctx.decompress(compressed)
        elif m == ZipCompressionMethod.XZ:
            import lzma
            u = lzma.decompress(compressed, format=lzma.FORMAT_XZ)
        else:
            raise NotImplementedError(F'Compression method {m.name} is not implemented.')

        self._unpacked = u
        return _checked(u)


class ZipEndOfCentralDirectory(Struct):
    Signature = B'PK\x05\x06'

    def __init__(self, reader: StructReader[memoryview]):
        self.offset = reader.tell()
        if reader.read(4) != self.Signature:
            raise ValueError
        self.disk_number = reader.u16()
        self.start_disk_number = reader.u16()
        self.entries_on_disk = reader.u16()
        self.entries_in_directory = reader.u16()
        self.directory_size = reader.u32()
        self.directory_offset = reader.u32()
        self.comment_length = reader.u16()


class ZipEocdLocator64(Struct):
    Signature = B'PK\x06\x07'

    def __init__(self, reader: StructReader[memoryview]):
        if reader.read(4) != self.Signature:
            raise ValueError
        self.disk_with_eocd64 = reader.u32()
        self.offset = reader.u64()
        self.total_disks = reader.u32()


class ZipEndOfCentralDirectory64(Struct):
    Signature = B'PK\x06\x06'

    def __init__(self, reader: StructReader[memoryview]):
        self.offset = reader.tell()
        if reader.read(4) != self.Signature:
            raise ValueError
        self.eocd64_size = reader.u64()
        self.version_made_by = reader.u16()
        self.version_to_extract = reader.u16()
        self.disk_number = reader.u32()
        self.start_disk_number = reader.u32()
        self.entries_on_disk = reader.u64()
        self.entries_in_directory = reader.u64()
        self.directory_size = reader.u64()
        self.directory_offset = reader.u64()
        self.locator = ZipEocdLocator64(reader)
        self.eocd32 = ZipEndOfCentralDirectory(reader)


class ZipExtraField(Struct):
    def __init__(self, reader: StructReader[memoryview]):
        self.header_id = reader.u16()
        self.data_size = reader.u16()
        self.data = reader.read_exactly(self.data_size)

    @classmethod
    def ParseBuffer(cls, data: buf | None) -> list[ZipExtraField]:
        if data is None:
            return []
        reader = StructReader(memoryview(data))
        extras = []
        while not reader.eof:
            try:
                extras.append(cls(reader))
            except EOFError:
                break
        return extras


class ZipExt(Struct):
    HeaderID: int

    @classmethod
    def TryParse(cls, extra: ZipExtraField, *args, **kwargs):
        if extra.header_id != cls.HeaderID:
            return None
        return cls.Parse(extra.data, *args, **kwargs)


class NoCrypto:
    def __len__(self):
        return 0

    def decrypt(self, password: str, data: buf):
        return data

    def checkpwd(self, password: str | None):
        return not password


class AExCrypto(Struct):
    def __init__(self, cr: StructReader[memoryview], ae: ZipExtAES):
        self.version = ae.version
        self.strength = ae.strength

        self.salt = cr.read((ae.strength + 1) << 2)
        self.pvv = cr.read(2)
        if ae.version == 3:
            self.nonce = cr.read(12)
            self.auth_size = 16
        else:
            self.nonce = None
            self.auth_size = 10
        self.keylen = (ae.strength + 1) << 3

    def _derive(self, password: str, salt: buf):
        ks = self.keylen
        dk = ks + 2
        if self.version < 3:
            dk += ks
        derived = PBKDF2(password, salt, dkLen=dk, count=1000, hmac_hash_module=SHA1)
        cr = StructReader(derived)
        key = cr.read(ks)
        mac = cr.read(ks) if self.version < 3 else B''
        pvv = cr.read()
        return key, mac, pvv

    def checkpwd(self, password: str | None):
        if password is None:
            return False
        _, _, dp = self._derive(password, self.salt)
        return dp == self.pvv

    def decrypt(self, password: str, data: buf):
        dk, dm, dp = self._derive(password, self.salt)
        if dp != self.pvv:
            raise InvalidPassword
        view = memoryview(data)
        ciphertext = view[:-self.auth_size]
        auth = view[-self.auth_size:]
        if self.version < 3:
            hmac = HMAC.new(dm, ciphertext, SHA1).digest()
            if hmac[:10] != auth:
                raise DataIntegrityError
            ctr = Counter.new(128, initial_value=1, little_endian=True)
            cipher = AES.new(dk, AES.MODE_CTR, counter=ctr)
            result = cipher.decrypt(ciphertext)
        else:
            cipher = AES.new(dk, AES.MODE_GCM, nonce=self.nonce)
            result = cipher.decrypt(ciphertext)
            try:
                cipher.verify(auth)
            except ValueError as V:
                raise DataIntegrityError from V
        return result


class ZipExtAES(ZipExt):
    HeaderID = 0x9901

    def __init__(self, reader: StructReader[memoryview]):
        self.version = reader.u16()
        self.vendor = reader.u16()
        self.strength = reader.u8()
        if not 1 <= self.strength <= 3:
            raise ValueError(F'Invalid AES strength {self.strength}.')
        self.method = ZipCompressionMethod(reader.u16())


class ZipExtInfo64(ZipExt):
    HeaderID = 0x0001

    def __init__(
        self,
        reader: StructReader[memoryview],
        usize: int,
        csize: int,
        header_offset: int = 0,
        disk_nr_start: int = 0,
    ):
        self.usize = usize
        self.csize = csize
        self.header_offset = header_offset
        self.disk_nr_start = disk_nr_start

        if usize == 0xFFFFFFFF:
            self.usize = reader.u64()
        if csize == 0xFFFFFFFF:
            self.csize = reader.u64()
        if header_offset == 0xFFFFFFFF:
            self.header_offset = reader.u64()
        if disk_nr_start == 0xFFFF:
            self.disk_nr_start = reader.u32()


class ZipExtUnixIDs(ZipExt):
    HeaderID = 0x7875

    def __init__(self, reader: StructReader[memoryview]):
        self.version = reader.u8()
        self.uid = reader.read_integer(reader.u8() * 8)
        self.gid = reader.read_integer(reader.u8() * 8)


class ZipExtTimestampFlags(FlagAccessMixin, enum.IntFlag):
    Modification = 1
    Access = 2
    Creation = 4


class ZipExtTimestamp(ZipExt):
    HeaderID = 0x5455

    def __init__(self, reader: StructReader[memoryview]):
        self.flags = ZipExtTimestampFlags(reader.u8())
        self.mtime = None
        self.atime = None
        self.ctime = None
        if reader.remaining_bytes >= 4 and self.flags.Modification:
            self.mtime = reader.u32()
        if reader.remaining_bytes >= 4 and self.flags.Access:
            self.atime = reader.u32()
        if reader.remaining_bytes >= 4 and self.flags.Creation:
            self.ctime = reader.u32()


class ZipExtUnicodePath(ZipExt):
    HeaderID = 0x7075

    def __init__(self, reader: StructReader[memoryview]):
        self.version = reader.u8()
        self.crc = reader.u32()
        self.name = codecs.decode(reader.read(), 'utf8')


class ZipDirEntry(Struct):
    Signature = B'PK\x01\x02'

    def is_dir(self):
        return self.name.endswith(('/', '\\'))

    def __init__(self, reader: StructReader[memoryview]):
        if reader.read(4) != self.Signature:
            raise ValueError
        self.version_made_by = reader.u16()
        self.version_to_extract = reader.u16()
        self.flags = ZipFlags(reader.u16())
        self.compression = ZipCompressionMethod(reader.u16())
        try:
            self.date = datefix.dostime(reader.u32(peek=True))
        except Exception:
            self.date = None
        self.mtime = reader.u16()
        self.mdate = reader.u16()
        self.crc32 = reader.u32()
        self.csize = reader.u32()
        self.usize = reader.u32()
        nl = reader.u16()
        xl = reader.u16()
        cl = reader.u16()
        self.disk_nr_start = reader.u16()
        self.internal_attributes = ZipInternalFileAttributes(reader.u16())
        self.external_attributes = reader.u32()
        self.header_offset = reader.u32()
        self.name_bytes = reader.read_exactly(nl)
        extras = reader.read_exactly(xl)
        self.comment = reader.read_exactly(cl)
        self.xtra = ZipExtraField.ParseBuffer(extras)

        codec = 'utf8' if self.flags.UseUTF8 else 'latin1'
        self.name = codecs.decode(self.name_bytes, codec)

        self.ae = None
        self.up = None
        self.ux = None
        self.ts = None

        for x in self.xtra:
            if z64 := ZipExtInfo64.TryParse(x, self.usize, self.csize, self.header_offset, self.disk_nr_start):
                self.usize = z64.usize
                self.csize = z64.csize
                self.header_offset = z64.header_offset
                self.disk_nr_start = z64.disk_nr_start
            elif ae := ZipExtAES.TryParse(x):
                self.ae = ae
            elif up := ZipExtUnicodePath.TryParse(x):
                self.up = up
                if up.crc == zlib.crc32(self.name_bytes) & 0xFFFFFFFF:
                    self.name = up.name
            elif ux := ZipExtUnixIDs.TryParse(x):
                self.ux = ux
            elif ts := ZipExtTimestamp.TryParse(x):
                self.ts = ts


class Zip:

    def parse_record(self, offset: int | None = None, read_data: bool = True, dir: ZipDirEntry | None = None):
        if offset is not None:
            self.reader.seekset(offset)
        return ZipFileRecord(
            self.reader,
            is64bit=self.is64bit,
            ddirs=self.ddirs,
            read_data=read_data,
            dir=dir,
        )

    def read(self, entry: str | int | ZipDirEntry):
        if isinstance(entry, str):
            entries = self.by_name[entry]
            if (c := len(entries)) > 1:
                raise RuntimeError(F'There are {c} central directory entries for: {entry}')
            entry = entries[0]
        if isinstance(entry, ZipDirEntry):
            start = entry.header_offset + self.shift
            dir = entry
        else:
            start = entry
            dir = None
        if start < 0:
            raise EOFError(F'Record referenced at {-start} bytes before start of file.')
        if (x := start - len(self.reader)) >= 0:
            raise EOFError(F'Record referenced at offset {x} from EOF.')
        try:
            return self.records[start]
        except KeyError:
            pass
        self.reader.seekset(start)
        self.records[start] = r = self.parse_record(dir=dir)
        self.coverage.addi(start, len(r))
        self.unreferenced_records.pop(start, None)
        return r

    def sub_archive_count(self):
        return sum(sub.sub_archive_count() + 1 for sub in self.sub_archives.values())

    def __init__(
        self,
        data: buf,
        password: str | None = None,
        read_records: bool = True,
        read_unreferenced_records: bool = True,
        sub_archives_covered: bool = True,
    ):
        self.reader = reader = StructReader(view := memoryview(data))
        self.is64bit = True
        self.coverage = coverage = IntIntervalUnion()
        self.password = password

        self.has_pk00_header = (data[:4] == B'PK00')
        if self.has_pk00_header:
            self.coverage.addi(0, 4)

        for EOCD in (
            ZipEndOfCentralDirectory64,
            ZipEndOfCentralDirectory,
        ):
            if (end := buffer_offset(view, EOCD.Signature, back2front=True)) >= 0:
                reader.seekset(end)
                self.offset_eocd = end
                self.eocd = eocd = EOCD(reader)
                coverage.addi(end, len(eocd))
                break
            else:
                self.is64bit = False
        else:
            raise ValueError('No EOCD.')

        start = eocd.directory_offset
        self.shift = end - eocd.directory_size - start
        if self.shift:
            start = end - eocd.directory_size
        if start < 0:
            raise ValueError('Invalid end of central directory size')
        self.offset_directory = start
        reader.seekset(start)
        apksig = None

        for sb in (
            ApkSigningBlock42,
            RpkSigningBlock42,
            ApkSigningBlock42_VariantWithAt,
            UnknownSigningBlockPK57,
        ):
            self.apksig = sb.FromCentralDir(reader)
            if (apksig := self.apksig):
                coverage.addi(apksig.offset, len(apksig))
                break

        if reader.peek(4) == ZipArchiveExtraDataRecord.Signature:
            self.archive_extra_data = ZipArchiveExtraDataRecord(reader)
            coverage.addi(start, len(self.archive_extra_data))
            start = reader.tell()
        else:
            self.archive_extra_data = None

        if reader.peek(4) != ZipDirEntry.Signature:
            self.encryption = ZipEncryptionHeader(reader)
            coverage.addi(start, len(self.encryption))
            start = reader.tell()
            size = eocd.directory_size - (start - self.offset_directory)
            self.encrypted_directory = reader.read_exactly(size)
            coverage.addi(start, size)
            if password is None:
                raise PasswordRequired
            decrypted_cd = self.encryption.decrypt(password, self.encrypted_directory)
            cd = StructReader(memoryview(decrypted_cd))
            self.directory = [
                ZipDirEntry(cd) for _ in range(eocd.entries_in_directory)
            ]
        else:
            self.encryption = None
            self.encrypted_directory = None
            self.directory = [
                ZipDirEntry(reader) for _ in range(eocd.entries_in_directory)
            ]
            coverage.addi(start, sum(len(d) for d in self.directory))

        by_name: dict[str, list[ZipDirEntry]] = {}
        self.by_name = by_name

        for entry in self.directory:
            by_name.setdefault(entry.name, []).append(entry)

        records: dict[int, ZipFileRecord] = {}
        unreferenced_records: dict[int, ZipFileRecord] = {}
        unreferenced_dirents: dict[int, ZipDirEntry] = {}
        self.records = records
        self.unreferenced_records = unreferenced_records
        self.unreferenced_dirents = unreferenced_dirents
        start = reader.tell()

        if reader.peek(4) == ZipDigitalSignature.Signature:
            self.digital_signature = ZipDigitalSignature(reader)
            coverage.addi(start, len(self.digital_signature))
            start = reader.tell()
        else:
            self.digital_signature = None

        self.ddirs = [match.start()
            for match in re.finditer(re.escape(ZipDataDescriptor.Signature), view)]

        if not read_records:
            return

        verdicts64bit = {self.is64bit}

        for entry in self.directory:
            try:
                record = self.read(entry)
            except Exception:
                pass
            else:
                verdicts64bit.add(record.is64bit)

        if len(verdicts64bit) == 2:
            # For at least one record, a data descriptor indicated that our 64-bit assumption
            # was incorrect. We try to re-parse with the opposite assumption and use whatever
            # produces more correctly parsed records.
            backup_records = self.records
            self.records.clear()
            self.is64bit = not self.is64bit
            for entry in self.directory:
                try:
                    record = self.read(entry)
                except Exception:
                    pass
            self.is64bit = not self.is64bit
            if len(self.records) < len(backup_records):
                self.records = backup_records

        sub_archives: dict[int, Zip] = {}
        end = self.eocd.offset

        while True:
            try:
                sub = Zip(view[:end], read_unreferenced_records=False)
            except Exception:
                break
            if (sub_eocd := sub.eocd.offset) in self.coverage:
                end = sub_eocd
                continue
            sub_archives[sub_eocd] = sub
            if sub_archives_covered:
                for i in sub.coverage:
                    self.coverage.addi(*i)
            end = sub.eocd.offset

        self.sub_archives = sub_archives

        if not read_unreferenced_records:
            return

        for start, end in list(coverage.gaps(0, len(view))):
            gap = view[start:end]
            if apksig and end == apksig.offset and not any(gap):
                coverage.addi(start, len(gap))
                continue
            while gap[:2] == B'PK':
                reader.seekset(start)
                if gap[:4] == ZipDirEntry.Signature:
                    try:
                        r = ZipDirEntry(reader)
                        n = len(r)
                    except Exception:
                        break
                    unreferenced_dirents[start] = r
                elif gap[:4] == ZipFileRecord.Signature:
                    try:
                        r = self.parse_record(read_data=False)
                        n = len(r)
                    except Exception:
                        break
                    if gap[n:n + 4] != ZipFileRecord.Signature and len(gap) >= n + r.csize:
                        reader.seekset(start)
                        try:
                            r = self.parse_record()
                        except Exception:
                            pass
                        else:
                            n = len(r)
                    unreferenced_records[start] = r
                else:
                    break
                gap = gap[n:]
                coverage.addi(start, n)
                start += n
