"""
Decryption support for encrypted Microsoft Office documents.

Supports ECMA-376 Agile (OOXML), ECMA-376 Standard, RC4, RC4 CryptoAPI, and XOR obfuscation
methods across DOC, XLS, PPT, and OOXML container formats.

Ported from the msoffcrypto-tool project; uses Cryptodome instead of the cryptography package.
"""
from __future__ import annotations

import base64
import codecs
import enum
import functools
import io
import logging
import zipfile

from hashlib import md5, sha1, sha256, sha384, sha512
from struct import pack, unpack, unpack_from
from typing import NamedTuple
from xml.dom.minidom import parseString

from Cryptodome.Cipher import AES, ARC4

from refinery.lib.ole.file import (
    OleFile,
    is_ole_file,
)
from refinery.lib.structures import MemoryFile

logger = logging.getLogger(__name__)


class FileFormatError(Exception):
    pass


class DecryptionError(Exception):
    pass


class InvalidKeyError(DecryptionError):
    pass


class EncryptionType(enum.Enum):
    PLAIN         = 'plain'          # noqa: E221
    AGILE         = 'agile'          # noqa: E221
    STANDARD      = 'standard'       # noqa: E221
    RC4           = 'rc4'            # noqa: E221
    RC4_CRYPTOAPI = 'rc4_cryptoapi'
    XOR           = 'xor'            # noqa: E221


class EncryptionHeader(NamedTuple):
    flags: int
    size_extra: int
    alg_id: int
    alg_id_hash: int
    key_size: int
    provider_type: int
    csp_name: str


class EncryptionVerifier(NamedTuple):
    salt_size: int
    salt: bytes
    encrypted_verifier: bytes
    verifier_hash_size: int
    encrypted_verifier_hash: bytes


class RC4CryptoAPIInfo(NamedTuple):
    salt: bytes
    key_size: int
    encrypted_verifier: bytes
    encrypted_verifier_hash: bytes


class RC4Info(NamedTuple):
    salt: bytes
    encrypted_verifier: bytes
    encrypted_verifier_hash: bytes


class StandardEncryptionInfo(NamedTuple):
    header: EncryptionHeader
    verifier: EncryptionVerifier


class AgileEncryptionInfo(NamedTuple):
    key_data_salt: bytes
    key_data_hash_algorithm: str
    key_data_block_size: int
    encrypted_hmac_key: bytes
    encrypted_hmac_value: bytes
    encrypted_verifier_hash_input: bytes
    encrypted_verifier_hash_value: bytes
    encrypted_key_value: bytes
    spin_value: int
    password_salt: bytes
    password_hash_algorithm: str
    password_key_bits: int


class FibBase(NamedTuple):
    w_ident: int
    n_fib: int
    f_encrypted: int
    f_which_tbl_stm: int
    f_obfuscation: int
    i_key: int


class RecordHeader(NamedTuple):
    rec_ver: int
    rec_instance: int
    rec_type: int
    rec_len: int


class CurrentUserAtom(NamedTuple):
    rh: RecordHeader
    size: int
    header_token: int
    offset_to_current_edit: int
    len_user_name: int
    doc_file_version: int
    major_version: int
    minor_version: int
    unused: bytes
    ansi_user_name: bytes
    rel_version: int
    unicode_user_name: bytes


class UserEditAtom(NamedTuple):
    rh: RecordHeader
    last_slide_id_ref: int
    version: int
    minor_version: int
    major_version: int
    offset_last_edit: int
    offset_persist_directory: int
    doc_persist_id_ref: int
    persist_id_seed: int
    last_view: int
    unused: bytes
    encrypt_session_persist_id_ref: int | None


class PersistDirectoryEntry(NamedTuple):
    persist_id: int
    c_persist: int
    rg_persist_offset: list[int]


class PersistDirectoryAtom(NamedTuple):
    rh: RecordHeader
    rg_persist_dir_entry: list[PersistDirectoryEntry]


def _rc4_makekey(password: str, salt: bytes, block: int) -> bytes:
    pw = password.encode('UTF-16LE')
    h0 = md5(pw).digest()[:5]
    h1 = md5((h0 + salt) * 16).digest()[:5]
    return md5(h1 + pack('<I', block)).digest()[:16]


class DocumentRC4:

    @staticmethod
    def verifypw(
        password: str,
        salt: bytes,
        encrypted_verifier: bytes,
        encrypted_verifier_hash: bytes,
    ) -> bool:
        key = _rc4_makekey(password, salt, 0)
        dec = ARC4.new(key)
        verifier = dec.decrypt(encrypted_verifier)
        verifier_hash = dec.decrypt(encrypted_verifier_hash)
        return md5(verifier).digest() == verifier_hash

    @staticmethod
    def decrypt(
        password: str,
        salt: bytes,
        ibuf: io.IOBase,
        blocksize: int = 0x200,
    ) -> MemoryFile[bytearray]:
        obuf = MemoryFile()
        block = 0
        key = _rc4_makekey(password, salt, block)
        for buf in iter(functools.partial(ibuf.read, blocksize), b''):
            obuf.write(ARC4.new(key).decrypt(buf))
            block += 1
            key = _rc4_makekey(password, salt, block)
        obuf.seek(0)
        return obuf


def _rc4api_makekey(
    password: str,
    salt: bytes,
    key_length: int,
    block: int,
) -> bytes:
    pw = password.encode('UTF-16LE')
    hfinal = sha1(sha1(salt + pw).digest() + pack('<I', block)).digest()
    if key_length == 40:
        return hfinal[:5] + b'\x00' * 11
    return hfinal[:key_length // 8]


class DocumentRC4CryptoAPI:

    @staticmethod
    def verifypw(
        password: str,
        salt: bytes,
        key_size: int,
        encrypted_verifier: bytes,
        encrypted_verifier_hash: bytes,
    ) -> bool:
        key = _rc4api_makekey(password, salt, key_size, 0)
        dec = ARC4.new(key)
        verifier = dec.decrypt(encrypted_verifier)
        verifier_hash = dec.decrypt(encrypted_verifier_hash)
        return sha1(verifier).digest() == verifier_hash

    @staticmethod
    def decrypt(
        password: str,
        salt: bytes,
        key_size: int,
        ibuf: io.IOBase,
        blocksize: int = 0x200,
        block: int = 0,
    ) -> MemoryFile[bytearray]:
        obuf = MemoryFile()
        key = _rc4api_makekey(password, salt, key_size, block)
        for buf in iter(functools.partial(ibuf.read, blocksize), b''):
            obuf.write(ARC4.new(key).decrypt(buf))
            block += 1
            key = _rc4api_makekey(password, salt, key_size, block)
        obuf.seek(0)
        return obuf


class DocumentXOR:

    _PAD = [
        0xBB, 0xFF, 0xFF, 0xBA, 0xFF, 0xFF, 0xB9, 0x80,
        0x00, 0xBE, 0x0F, 0x00, 0xBF, 0x0F, 0x00,
    ]
    _INITIAL_CODE = [
        0xE1F0, 0x1D0F, 0xCC9C, 0x84C0, 0x110C, 0x0E10, 0xF1CE, 0x313E,
        0x1872, 0xE139, 0xD40F, 0x84F9, 0x280C, 0xA96A, 0x4EC3,
    ]
    _XOR_MATRIX = [
        0xAEFC, 0x4DD9, 0x9BB2, 0x2745, 0x4E8A, 0x9D14, 0x2A09,
        0x7B61, 0xF6C2, 0xFDA5, 0xEB6B, 0xC6F7, 0x9DCF, 0x2BBF,
        0x4563, 0x8AC6, 0x05AD, 0x0B5A, 0x16B4, 0x2D68, 0x5AD0,
        0x0375, 0x06EA, 0x0DD4, 0x1BA8, 0x3750, 0x6EA0, 0xDD40,
        0xD849, 0xA0B3, 0x5147, 0xA28E, 0x553D, 0xAA7A, 0x44D5,
        0x6F45, 0xDE8A, 0xAD35, 0x4A4B, 0x9496, 0x390D, 0x721A,
        0xEB23, 0xC667, 0x9CEF, 0x29FF, 0x53FE, 0xA7FC, 0x5FD9,
        0x47D3, 0x8FA6, 0x0F6D, 0x1EDA, 0x3DB4, 0x7B68, 0xF6D0,
        0xB861, 0x60E3, 0xC1C6, 0x93AD, 0x377B, 0x6EF6, 0xDDEC,
        0x45A0, 0x8B40, 0x06A1, 0x0D42, 0x1A84, 0x3508, 0x6A10,
        0xAA51, 0x4483, 0x8906, 0x022D, 0x045A, 0x08B4, 0x1168,
        0x76B4, 0xED68, 0xCAF1, 0x85C3, 0x1BA7, 0x374E, 0x6E9C,
        0x3730, 0x6E60, 0xDCC0, 0xA9A1, 0x4363, 0x86C6, 0x1DAD,
        0x3331, 0x6662, 0xCCC4, 0x89A9, 0x0373, 0x06E6, 0x0DCC,
        0x1021, 0x2042, 0x4084, 0x8108, 0x1231, 0x2462, 0x48C4,
    ]

    @staticmethod
    def _ror(n: int, rotations: int, width: int) -> int:
        return (2 ** width - 1) & (n >> rotations | n << (width - rotations))

    @staticmethod
    def _xor_ror(byte1: int, byte2: int) -> int:
        return DocumentXOR._ror(byte1 ^ byte2, 1, 8)

    @staticmethod
    def verifypw(password: str, verification_bytes: int) -> bool:
        verifier = 0
        pw_arr = [len(password)] + [ord(ch) for ch in password]
        pw_arr.reverse()
        for b in pw_arr:
            if verifier & 0x4000:
                intermediate = 1
            else:
                intermediate = 0
            verifier = (intermediate ^ ((verifier * 2) & 0x7FFF)) ^ b
        return (verifier ^ 0xCE4B) == verification_bytes

    @staticmethod
    def _create_xor_key(password: str) -> int:
        xor_key = DocumentXOR._INITIAL_CODE[len(password) - 1]
        element = 0x68
        for ch in reversed(password):
            c = ord(ch)
            for _ in range(7):
                if c & 0x40:
                    xor_key = (xor_key ^ DocumentXOR._XOR_MATRIX[element]) % 65536
                c = (c << 1) % 256
                element -= 1
        return xor_key

    @staticmethod
    def _create_xor_array(password: str) -> list[int]:
        xor_key = DocumentXOR._create_xor_key(password)
        index = len(password)
        obfuscation = [0] * 16

        if index % 2 == 1:
            temp = (xor_key & 0xFF00) >> 8
            obfuscation[index] = DocumentXOR._xor_ror(DocumentXOR._PAD[0], temp)
            index -= 1
            temp = xor_key & 0x00FF
            obfuscation[index] = DocumentXOR._xor_ror(ord(password[-1]), temp)

        while index > 0:
            index -= 1
            temp = (xor_key & 0xFF00) >> 8
            obfuscation[index] = DocumentXOR._xor_ror(ord(password[index]), temp)
            index -= 1
            temp = xor_key & 0x00FF
            obfuscation[index] = DocumentXOR._xor_ror(ord(password[index]), temp)

        idx = 15
        pad_idx = 15 - len(password)
        while pad_idx > 0:
            temp = (xor_key & 0xFF00) >> 8
            obfuscation[idx] = DocumentXOR._xor_ror(DocumentXOR._PAD[pad_idx], temp)
            idx -= 1
            pad_idx -= 1
            temp = xor_key & 0x00FF
            obfuscation[idx] = DocumentXOR._xor_ror(DocumentXOR._PAD[pad_idx], temp)
            idx -= 1
            pad_idx -= 1

        return obfuscation

    @staticmethod
    def decrypt(
        password: str,
        ibuf: io.IOBase,
        plaintext: list[int],
        records: list,
        base: int,
    ) -> MemoryFile[bytearray]:
        obuf = MemoryFile()
        xor_array = DocumentXOR._create_xor_array(password)
        data_index = 0
        while data_index < len(plaintext):
            count = 1
            if plaintext[data_index] in (-1, -2):
                for j in range(data_index + 1, len(plaintext)):
                    if plaintext[j] >= 0:
                        break
                    count += 1
                if plaintext[data_index] == -2:
                    xor_idx = (data_index + count + 4) % 16
                else:
                    xor_idx = (data_index + count) % 16
                for _ in range(count):
                    b = ibuf.read(1)
                    dec = DocumentXOR._ror(b[0] ^ xor_array[xor_idx], 5, 8)
                    obuf.write_byte(dec)
                    xor_idx = (xor_idx + 1) % 16
            else:
                obuf.write(ibuf.read(1))
            data_index += count
        obuf.seek(0)
        return obuf


_ALGORITHM_HASH = {
    'SHA1'  : sha1,
    'SHA256': sha256,
    'SHA384': sha384,
    'SHA512': sha512,
}

_BLK_KEY_ENCRYPTED_KEY_VALUE = bytearray(
    [0x14, 0x6E, 0x0B, 0xE7, 0xAB, 0xAC, 0xD0, 0xD6])


def _get_hash_func(algorithm: str):
    return _ALGORITHM_HASH.get(algorithm, sha1)


def _normalize_key(key: bytes, n: int) -> bytes:
    if len(key) >= n:
        return key[:n]
    return key + b'\x36' * (n - len(key))


def _decrypt_aes_cbc(data: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv[:16])
    return cipher.decrypt(data)


class ECMA376Agile:

    @staticmethod
    def _derive_iterated_hash(
        password: str,
        salt: bytes,
        algorithm: str,
        spin: int,
    ):
        h = _get_hash_func(algorithm)
        hobj = h(salt + password.encode('UTF-16LE'))
        for i in range(spin):
            hobj = h(pack('<I', i) + hobj.digest())
        return hobj

    @staticmethod
    def _derive_encryption_key(
        h: bytes,
        block_key: bytes | bytearray,
        algorithm: str,
        key_bits: int,
    ) -> bytes:
        hfinal = _get_hash_func(algorithm)(h + block_key)
        return hfinal.digest()[:key_bits // 8]

    @staticmethod
    def decrypt(
        key: bytes,
        key_data_salt: bytes,
        hash_algorithm: str,
        ibuf: io.IOBase,
    ) -> bytearray:
        SEGMENT_LENGTH = 4096
        hashCalc = _get_hash_func(hash_algorithm)
        obuf = MemoryFile()
        ibuf.seek(0)
        total_size = unpack('<Q', ibuf.read(8))[0]
        remaining = total_size
        for i, buf in enumerate(
            iter(functools.partial(ibuf.read, SEGMENT_LENGTH), b'')
        ):
            iv = hashCalc(key_data_salt + pack('<I', i)).digest()[:16]
            dec = _decrypt_aes_cbc(buf, key, iv)
            if remaining < len(dec):
                dec = dec[:remaining]
            obuf.write(dec)
            remaining -= len(dec)
            if remaining <= 0:
                break
        return obuf.getvalue()

    @staticmethod
    def makekey_from_password(
        password: str,
        salt: bytes,
        hash_algorithm: str,
        encrypted_key_value: bytes,
        spin_value: int,
        key_bits: int,
    ) -> bytes:
        h = ECMA376Agile._derive_iterated_hash(password, salt, hash_algorithm, spin_value)
        enc_key = ECMA376Agile._derive_encryption_key(
            h.digest(), _BLK_KEY_ENCRYPTED_KEY_VALUE, hash_algorithm, key_bits)
        return _decrypt_aes_cbc(encrypted_key_value, enc_key, salt)


class ECMA376Standard:

    @staticmethod
    def decrypt(key: bytes, ibuf: io.IOBase) -> bytearray:
        obuf = MemoryFile()
        total_size = unpack('<I', ibuf.read(4))[0]
        ibuf.seek(8)
        data = ibuf.read()
        pad = (AES.block_size - len(data) % AES.block_size) % AES.block_size
        if pad:
            data = data + b'\x00' * pad
        cipher = AES.new(key, AES.MODE_ECB)
        dec = cipher.decrypt(data)
        obuf.write(dec[:total_size])
        return obuf.getvalue()

    @staticmethod
    def verifykey(
        key: bytes,
        encrypted_verifier: bytes,
        encrypted_verifier_hash: bytes,
    ) -> bool:
        cipher = AES.new(key, AES.MODE_ECB)
        verifier = cipher.decrypt(encrypted_verifier)
        expected = sha1(verifier).digest()
        cipher = AES.new(key, AES.MODE_ECB)
        verifier_hash = cipher.decrypt(encrypted_verifier_hash)[:sha1().digest_size]
        return expected == verifier_hash

    @staticmethod
    def makekey_from_password(
        password: str,
        alg_id: int,
        alg_id_hash: int,
        provider_type: int,
        key_size: int,
        salt_size: int,
        salt: bytes,
    ) -> bytes:
        ITER_COUNT = 50000
        cb_hash = sha1().digest_size
        cb_key = key_size // 8

        pw = password.encode('UTF-16LE')
        h = sha1(salt + pw).digest()
        for i in range(ITER_COUNT):
            h = sha1(pack('<I', i) + h).digest()
        hfinal = sha1(h + pack('<I', 0)).digest()

        buf1 = bytearray(b'\x36' * 64)
        for i in range(cb_hash):
            buf1[i] ^= hfinal[i]
        x1 = sha1(buf1).digest()
        buf2 = bytearray(b'\x5c' * 64)
        for i in range(cb_hash):
            buf2[i] ^= hfinal[i]
        x2 = sha1(buf2).digest()
        x3 = x1 + x2
        return x3[:cb_key]


def _parse_encryption_header(blob: io.IOBase) -> EncryptionHeader:
    flags = unpack('<I', blob.read(4))[0]
    size_extra = unpack('<I', blob.read(4))[0]
    alg_id = unpack('<I', blob.read(4))[0]
    alg_id_hash = unpack('<I', blob.read(4))[0]
    key_size = unpack('<I', blob.read(4))[0]
    provider_type = unpack('<I', blob.read(4))[0]
    blob.read(4)
    blob.read(4)
    csp_name = codecs.decode(blob.read(), 'utf-16le')
    return EncryptionHeader(
        flags=flags,
        size_extra=size_extra,
        alg_id=alg_id,
        alg_id_hash=alg_id_hash,
        key_size=key_size,
        provider_type=provider_type,
        csp_name=csp_name,
    )


def _parse_encryption_verifier(blob: io.IOBase, algorithm: str) -> EncryptionVerifier:
    salt_size = unpack('<I', blob.read(4))[0]
    salt = bytes(blob.read(16))
    encrypted_verifier = bytes(blob.read(16))
    verifier_hash_size = unpack('<I', blob.read(4))[0]
    if algorithm == 'RC4':
        encrypted_verifier_hash = bytes(blob.read(20))
    elif algorithm == 'AES':
        encrypted_verifier_hash = bytes(blob.read(32))
    else:
        raise ValueError(F'Invalid algorithm: {algorithm}')
    return EncryptionVerifier(
        salt_size=salt_size,
        salt=salt,
        encrypted_verifier=encrypted_verifier,
        verifier_hash_size=verifier_hash_size,
        encrypted_verifier_hash=encrypted_verifier_hash,
    )


def _parse_header_rc4_cryptoapi(stream: io.IOBase) -> RC4CryptoAPIInfo:
    stream.read(4)
    header_size = unpack('<I', stream.read(4))[0]
    blob = MemoryFile(stream.read(header_size))
    header = _parse_encryption_header(blob)
    key_size = 0x28 if header.key_size == 0 else header.key_size
    blob = MemoryFile(stream.read())
    verifier = _parse_encryption_verifier(blob, 'RC4')
    return RC4CryptoAPIInfo(
        salt=verifier.salt,
        key_size=key_size,
        encrypted_verifier=verifier.encrypted_verifier,
        encrypted_verifier_hash=verifier.encrypted_verifier_hash,
    )


def _parse_header_rc4(stream: io.IOBase) -> RC4Info:
    return RC4Info(
        salt=bytes(stream.read(16)),
        encrypted_verifier=bytes(stream.read(16)),
        encrypted_verifier_hash=bytes(stream.read(16)),
    )


def _parseinfo_standard(ole_stream: io.IOBase) -> StandardEncryptionInfo:
    ole_stream.read(4)
    enc_header_size = unpack('<I', ole_stream.read(4))[0]
    block = ole_stream.read(enc_header_size)
    header = _parse_encryption_header(MemoryFile(block))
    block = ole_stream.read()
    algo = 'AES' if header.alg_id & 0xFF00 == 0x6600 else 'RC4'
    verifier = _parse_encryption_verifier(MemoryFile(block), algo)
    return StandardEncryptionInfo(header=header, verifier=verifier)


def _parseinfo_agile(ole_stream: io.IOBase) -> AgileEncryptionInfo:
    ole_stream.seek(8)
    xml = parseString(ole_stream.read())
    kd = xml.getElementsByTagName('keyData')[0]
    di = xml.getElementsByTagName('dataIntegrity')[0]
    pw = xml.getElementsByTagNameNS(
        'http://schemas.microsoft.com/office/2006/keyEncryptor/password',
        'encryptedKey')[0]
    return AgileEncryptionInfo(
        key_data_salt=base64.b64decode(kd.getAttribute('saltValue')),
        key_data_hash_algorithm=kd.getAttribute('hashAlgorithm'),
        key_data_block_size=int(kd.getAttribute('blockSize')),
        encrypted_hmac_key=base64.b64decode(di.getAttribute('encryptedHmacKey')),
        encrypted_hmac_value=base64.b64decode(di.getAttribute('encryptedHmacValue')),
        encrypted_verifier_hash_input=base64.b64decode(
            pw.getAttribute('encryptedVerifierHashInput')),
        encrypted_verifier_hash_value=base64.b64decode(
            pw.getAttribute('encryptedVerifierHashValue')),
        encrypted_key_value=base64.b64decode(pw.getAttribute('encryptedKeyValue')),
        spin_value=int(pw.getAttribute('spinCount')),
        password_salt=base64.b64decode(pw.getAttribute('saltValue')),
        password_hash_algorithm=pw.getAttribute('hashAlgorithm'),
        password_key_bits=int(pw.getAttribute('keyBits')),
    )


def _parseinfo(
    ole_stream: io.IOBase,
) -> tuple[EncryptionType, StandardEncryptionInfo | AgileEncryptionInfo]:
    v_major, v_minor = unpack('<HH', ole_stream.read(4))
    if v_major == 4 and v_minor == 4:
        return EncryptionType.AGILE, _parseinfo_agile(ole_stream)
    elif v_major in (2, 3, 4) and v_minor == 2:
        return EncryptionType.STANDARD, _parseinfo_standard(ole_stream)
    elif v_major in (3, 4) and v_minor == 3:
        raise DecryptionError('Unsupported EncryptionInfo version (Extensible Encryption)')
    raise DecryptionError(F'Unsupported EncryptionInfo version ({v_major}:{v_minor})')


class OOXMLFile:

    def __init__(self, file: io.IOBase):
        file.seek(0)
        data = file.read()
        file.seek(0)
        self._data = data
        self._type = EncryptionType.PLAIN
        self._info: StandardEncryptionInfo | AgileEncryptionInfo | None = None
        self._key: bytes | None = None

        if is_ole_file(data):
            ole = OleFile(data)
            self._ole = ole
            if not ole.exists('EncryptionInfo'):
                raise FileFormatError('No EncryptionInfo stream found')
            with ole.openstream('EncryptionInfo') as stream:
                self._type, self._info = _parseinfo(stream)
        elif zipfile.is_zipfile(file):
            self._type = EncryptionType.PLAIN
        else:
            raise FileFormatError('Unsupported file format')

    def _require_key(self) -> bytes:
        if self._key is None:
            raise DecryptionError('load_key() must be called before decrypt()')
        return self._key

    def load_key(self, password: str | None = None):
        if not password:
            raise DecryptionError('No password specified')
        if self._type == EncryptionType.AGILE:
            if not isinstance(self._info, AgileEncryptionInfo):
                raise DecryptionError('Encryption info mismatch')
            self._key = ECMA376Agile.makekey_from_password(
                password,
                self._info.password_salt,
                self._info.password_hash_algorithm,
                self._info.encrypted_key_value,
                self._info.spin_value,
                self._info.password_key_bits,
            )
        elif self._type == EncryptionType.STANDARD:
            if not isinstance(self._info, StandardEncryptionInfo):
                raise DecryptionError('Encryption info mismatch')
            self._key = ECMA376Standard.makekey_from_password(
                password,
                self._info.header.alg_id,
                self._info.header.alg_id_hash,
                self._info.header.provider_type,
                self._info.header.key_size,
                self._info.verifier.salt_size,
                self._info.verifier.salt,
            )

    def _decrypt_package(self) -> bytearray:
        key = self._require_key()
        if self._type == EncryptionType.AGILE:
            if not isinstance(self._info, AgileEncryptionInfo):
                raise DecryptionError('Encryption info mismatch')
            with self._ole.openstream('EncryptedPackage') as stream:
                return ECMA376Agile.decrypt(
                    key,
                    self._info.key_data_salt,
                    self._info.key_data_hash_algorithm,
                    stream,
                )
        if self._type == EncryptionType.STANDARD:
            with self._ole.openstream('EncryptedPackage') as stream:
                return ECMA376Standard.decrypt(key, stream)
        raise DecryptionError(F'Unsupported encryption type: {self._type}')

    def decrypt(self, outfile: io.IOBase):
        if self._type == EncryptionType.PLAIN:
            raise DecryptionError('Document is not encrypted')
        obuf = self._decrypt_package()
        outfile.write(obuf)
        if not zipfile.is_zipfile(io.BytesIO(obuf)):
            raise InvalidKeyError('The file could not be decrypted with this password')

    def is_encrypted(self) -> bool:
        return self._type != EncryptionType.PLAIN


def _parse_fib_base(data: bytes | bytearray | memoryview) -> FibBase:
    mv = memoryview(data)
    w_ident = unpack_from('<H', mv, 0)[0]
    n_fib = unpack_from('<H', mv, 2)[0]
    bits = unpack_from('<H', mv, 10)[0]
    f_encrypted = (bits >> 8) & 1
    f_which_tbl = (bits >> 9) & 1
    f_obfuscation = (bits >> 15) & 1
    i_key = unpack_from('<I', mv, 14)[0]
    return FibBase(
        w_ident=w_ident,
        n_fib=n_fib,
        f_encrypted=f_encrypted,
        f_which_tbl_stm=f_which_tbl,
        f_obfuscation=f_obfuscation,
        i_key=i_key,
    )


def _patch_fib_encryption(data: bytearray) -> bytearray:
    """
    Return a copy of the first 32 bytes of the FIB with encryption cleared.
    """
    patched = bytearray(data[:32])
    bits = unpack_from('<H', patched, 10)[0]
    bits &= ~(1 << 8)
    bits &= ~(1 << 15)
    patched[10:12] = pack('<H', bits)
    patched[14:18] = pack('<I', 0)
    return patched


class Doc97File:

    def __init__(self, file: io.IOBase):
        file.seek(0)
        self._data = file.read()
        self._ole = OleFile(self._data)
        self._key: str | None = None
        self._salt: bytes | None = None
        self._key_size: int = 0
        self._type: EncryptionType | None = None

        with self._ole.openstream('wordDocument') as stream:
            fib_raw = stream.read(32)
            self._fib = _parse_fib_base(fib_raw)
        self._tablename = '1Table' if self._fib.f_which_tbl_stm else '0Table'

    def load_key(self, password: str | None = None):
        if not password:
            raise DecryptionError('No password specified')
        fib = self._fib
        if not fib.f_encrypted:
            raise DecryptionError('File is not encrypted')
        if fib.f_obfuscation:
            raise DecryptionError('XOR obfuscation in DOC is not supported')

        with self._ole.openstream(self._tablename) as table:
            v_major, v_minor = unpack('<HH', table.read(4))
            if v_major == 1 and v_minor == 1:
                rc4_info = _parse_header_rc4(table)
                if DocumentRC4.verifypw(
                    password, rc4_info.salt,
                    rc4_info.encrypted_verifier,
                    rc4_info.encrypted_verifier_hash,
                ):
                    self._type = EncryptionType.RC4
                    self._key = password
                    self._salt = rc4_info.salt
                else:
                    raise InvalidKeyError('Failed to verify password')
            elif v_major in (2, 3, 4) and v_minor == 2:
                cryptoapi_info = _parse_header_rc4_cryptoapi(table)
                if DocumentRC4CryptoAPI.verifypw(
                    password, cryptoapi_info.salt, cryptoapi_info.key_size,
                    cryptoapi_info.encrypted_verifier,
                    cryptoapi_info.encrypted_verifier_hash,
                ):
                    self._type = EncryptionType.RC4_CRYPTOAPI
                    self._key = password
                    self._salt = cryptoapi_info.salt
                    self._key_size = cryptoapi_info.key_size
                else:
                    raise InvalidKeyError('Failed to verify password')
            else:
                raise DecryptionError('Unsupported encryption method')

    def _require_key(self) -> tuple[str, bytes]:
        if self._key is None or self._salt is None:
            raise DecryptionError('load_key() must be called before decrypt()')
        return self._key, self._salt

    def _decrypt_stream(self, name: str) -> MemoryFile[bytearray]:
        key, salt = self._require_key()
        stream = self._ole.openstream(name)
        if self._type == EncryptionType.RC4:
            return DocumentRC4.decrypt(key, salt, stream)
        return DocumentRC4CryptoAPI.decrypt(key, salt, self._key_size, stream)

    def decrypt(self, outfile: io.IOBase):
        FIB_LENGTH = 0x44
        fib_raw = bytearray(self._ole.openstream('wordDocument').read(FIB_LENGTH))
        patched_header = _patch_fib_encryption(fib_raw)
        fib_prefix = bytearray(patched_header)
        fib_prefix.extend(fib_raw[len(patched_header):FIB_LENGTH])

        dec_wd = self._decrypt_stream('wordDocument')
        dec_wd.seek(FIB_LENGTH)
        fib_prefix += dec_wd.read()
        word_doc_buf = fib_prefix

        table_buf = self._decrypt_stream(self._tablename).read()

        data_buf: bytes | bytearray | None = None
        if self._ole.exists('Data'):
            data_buf = self._decrypt_stream('Data').read()

        out = bytearray(self._data)
        ole = OleFile(out)
        ole.write_stream('wordDocument', word_doc_buf)
        ole.write_stream(self._tablename, table_buf)
        if data_buf is not None:
            ole.write_stream('Data', data_buf)
        outfile.write(out)

    def is_encrypted(self) -> bool:
        return self._fib.f_encrypted == 1


_BIFF_BOF         = 2057  # noqa
_BIFF_FILEPASS    = 47    # noqa
_BIFF_USREXCL     = 404   # noqa
_BIFF_FILELOCK     = 405   # noqa
_BIFF_INTERFACEHDR = 225   # noqa
_BIFF_RRDINFO      = 406   # noqa
_BIFF_RRDHEAD      = 312   # noqa
_BIFF_BOUNDSHEET8  = 133   # noqa


class _BIFFStream:

    def __init__(self, data: io.IOBase):
        self._data = data

    def has_record(self, target: int) -> bool:
        pos = self._data.tell()
        while True:
            h = self._data.read(4)
            if not h or len(h) < 4:
                self._data.seek(pos)
                return False
            num, size = unpack('<HH', h)
            if num == target:
                self._data.seek(pos)
                return True
            self._data.read(size)

    def skip_to(self, target: int) -> tuple[int, int]:
        while True:
            h = self._data.read(4)
            if not h or len(h) < 4:
                raise DecryptionError('Record not found')
            num, size = unpack('<HH', h)
            if num == target:
                return num, size
            self._data.read(size)

    def iter_record(self):
        while True:
            h = self._data.read(4)
            if not h or len(h) < 4:
                break
            num, size = unpack('<HH', h)
            record = MemoryFile(self._data.read(size))
            yield num, size, record


_NOT_OBFUSCATED = frozenset((
    _BIFF_BOF,
    _BIFF_FILEPASS,
    _BIFF_USREXCL,
    _BIFF_FILELOCK,
    _BIFF_INTERFACEHDR,
    _BIFF_RRDINFO,
    _BIFF_RRDHEAD,
))


class Xls97File:

    def __init__(self, file: io.IOBase):
        file.seek(0)
        self._data = file.read()
        self._ole = OleFile(self._data)
        self._key: str | None = None
        self._salt: bytes | None = None
        self._key_size: int = 0
        self._type: EncryptionType | None = None

    def load_key(self, password: str | None = None):
        if not password:
            raise DecryptionError('No password specified')
        with self._ole.openstream('Workbook') as wb:
            workbook = _BIFFStream(wb)
            num = unpack('<H', workbook._data.read(2))[0]
            if num != _BIFF_BOF:
                raise FileFormatError('Invalid Workbook stream')
            size = unpack('<H', workbook._data.read(2))[0]
            workbook._data.read(size)
            _num, size = workbook.skip_to(_BIFF_FILEPASS)

            enc_type = unpack('<H', workbook._data.read(2))[0]
            enc_info = MemoryFile(workbook._data.read(size - 2))

            if enc_type == 0x0000:
                key, verification_bytes = unpack('<HH', enc_info.read(4))
                if DocumentXOR.verifypw(password, verification_bytes):
                    self._type = EncryptionType.XOR
                    self._key = password
                else:
                    raise InvalidKeyError('Failed to verify password')
            elif enc_type == 0x0001:
                v_major, v_minor = unpack('<HH', enc_info.read(4))
                if v_major == 1 and v_minor == 1:
                    rc4_info = _parse_header_rc4(enc_info)
                    if DocumentRC4.verifypw(
                        password, rc4_info.salt,
                        rc4_info.encrypted_verifier,
                        rc4_info.encrypted_verifier_hash,
                    ):
                        self._type = EncryptionType.RC4
                        self._key = password
                        self._salt = rc4_info.salt
                    else:
                        raise InvalidKeyError('Failed to verify password')
                elif v_major in (2, 3, 4) and v_minor == 2:
                    cryptoapi_info = _parse_header_rc4_cryptoapi(enc_info)
                    if DocumentRC4CryptoAPI.verifypw(
                        password, cryptoapi_info.salt, cryptoapi_info.key_size,
                        cryptoapi_info.encrypted_verifier,
                        cryptoapi_info.encrypted_verifier_hash,
                    ):
                        self._type = EncryptionType.RC4_CRYPTOAPI
                        self._key = password
                        self._salt = cryptoapi_info.salt
                        self._key_size = cryptoapi_info.key_size
                    else:
                        raise InvalidKeyError('Failed to verify password')
                else:
                    raise DecryptionError('Unsupported encryption method')

    def _read_workbook_records(self) -> tuple[list[int], MemoryFile]:
        plain_buf: list[int] = []
        encrypted_buf = MemoryFile()
        with self._ole.openstream('Workbook') as wb:
            workbook = _BIFFStream(wb)
            for num, size, record in workbook.iter_record():
                if num == _BIFF_FILEPASS:
                    plain_buf.extend((0, 0))
                    plain_buf.extend(pack('<H', size))
                    plain_buf.extend(0 for _ in range(size))
                    encrypted_buf.write(b'\x00' * (4 + size))
                elif num in _NOT_OBFUSCATED:
                    header = pack('<HH', num, size)
                    plain_buf.extend(header)
                    plain_buf.extend(record.read())
                    encrypted_buf.write(b'\x00' * (4 + size))
                elif num == _BIFF_BOUNDSHEET8:
                    header = pack('<HH', num, size)
                    plain_buf.extend(header)
                    plain_buf.extend(record.read(4))
                    plain_buf.extend(-2 for _ in range(size - 4))
                    encrypted_buf.write(b'\x00' * 4 + b'\x00' * 4 + record.read())
                else:
                    header = pack('<HH', num, size)
                    plain_buf.extend(header)
                    plain_buf.extend(-1 for _ in range(size))
                    encrypted_buf.write(b'\x00' * 4 + record.read())
        encrypted_buf.seek(0)
        return plain_buf, encrypted_buf

    def decrypt(self, outfile: io.IOBase):
        if self._key is None:
            raise DecryptionError('load_key() must be called before decrypt()')
        plain_buf, encrypted_buf = self._read_workbook_records()

        if self._type == EncryptionType.RC4:
            if self._salt is None:
                raise DecryptionError('load_key() must be called before decrypt()')
            dec = DocumentRC4.decrypt(self._key, self._salt, encrypted_buf, blocksize=1024)
        elif self._type == EncryptionType.RC4_CRYPTOAPI:
            if self._salt is None:
                raise DecryptionError('load_key() must be called before decrypt()')
            dec = DocumentRC4CryptoAPI.decrypt(
                self._key, self._salt, self._key_size, encrypted_buf, blocksize=1024)
        elif self._type == EncryptionType.XOR:
            dec = DocumentXOR.decrypt(self._key, encrypted_buf, plain_buf, [], 10)
        else:
            raise DecryptionError(F'Unsupported encryption type: {self._type}')

        for c in plain_buf:
            if c in (-1, -2):
                dec.seek(1, 1)
            else:
                dec.write_byte(c)
        dec.seek(0)

        out = bytearray(self._data)
        ole = OleFile(out)
        ole.write_stream('Workbook', dec.read())
        outfile.write(out)

    def is_encrypted(self) -> bool:
        stream = _BIFFStream(self._ole.openstream('Workbook'))
        num = unpack('<H', stream._data.read(2))[0]
        if num != _BIFF_BOF:
            return False
        size = unpack('<H', stream._data.read(2))[0]
        stream._data.read(size)
        return stream.has_record(_BIFF_FILEPASS)


def _parse_record_header(data: bytes | bytearray | memoryview) -> RecordHeader:
    buf = unpack_from('<H', data, 0)[0]
    return RecordHeader(
        rec_ver=buf & 0xF,
        rec_instance=(buf >> 4) & 0xFFF,
        rec_type=unpack_from('<H', data, 2)[0],
        rec_len=unpack_from('<I', data, 4)[0],
    )


def _pack_record_header(rh: RecordHeader) -> bytearray:
    buf = (rh.rec_ver & 0xF) | ((rh.rec_instance & 0xFFF) << 4)
    return bytearray(pack('<HHI', buf, rh.rec_type, rh.rec_len))


def _parse_current_user_atom(blob: io.IOBase) -> CurrentUserAtom:
    rh = _parse_record_header(blob.read(8))
    size = unpack('<I', blob.read(4))[0]
    header_token = unpack('<I', blob.read(4))[0]
    offset_to_current_edit = unpack('<I', blob.read(4))[0]
    len_user_name = unpack('<H', blob.read(2))[0]
    doc_file_version = unpack('<H', blob.read(2))[0]
    major_version, minor_version = unpack('<BB', blob.read(2))
    unused = blob.read(2)
    ansi_user_name = blob.read(len_user_name)
    rel_version_raw = blob.read(4)
    rel_version = unpack('<I', rel_version_raw)[0] if len(rel_version_raw) == 4 else 0
    unicode_user_name = blob.read(2 * len_user_name)
    return CurrentUserAtom(
        rh=rh,
        size=size,
        header_token=header_token,
        offset_to_current_edit=offset_to_current_edit,
        len_user_name=len_user_name,
        doc_file_version=doc_file_version,
        major_version=major_version,
        minor_version=minor_version,
        unused=unused,
        ansi_user_name=ansi_user_name,
        rel_version=rel_version,
        unicode_user_name=unicode_user_name,
    )


def _pack_current_user_atom(cu: CurrentUserAtom) -> bytearray:
    out = bytearray()
    out += _pack_record_header(cu.rh)
    out += pack('<I', cu.size)
    out += pack('<I', cu.header_token)
    out += pack('<I', cu.offset_to_current_edit)
    out += pack('<H', cu.len_user_name)
    out += pack('<H', cu.doc_file_version)
    out += pack('<BB', cu.major_version, cu.minor_version)
    out += cu.unused
    out += cu.ansi_user_name
    out += pack('<I', cu.rel_version)
    out += cu.unicode_user_name
    return out


def _parse_user_edit_atom(blob: io.IOBase) -> UserEditAtom:
    rh = _parse_record_header(blob.read(8))
    last_slide_id = unpack('<I', blob.read(4))[0]
    version = unpack('<H', blob.read(2))[0]
    minor_ver, major_ver = unpack('<BB', blob.read(2))
    offset_last_edit = unpack('<I', blob.read(4))[0]
    offset_persist_dir = unpack('<I', blob.read(4))[0]
    doc_persist_id = unpack('<I', blob.read(4))[0]
    persist_id_seed = unpack('<I', blob.read(4))[0]
    last_view = unpack('<H', blob.read(2))[0]
    unused = blob.read(2)
    buf = blob.read(4)
    encrypt_session_ref = unpack('<I', buf)[0] if len(buf) == 4 else None
    return UserEditAtom(
        rh=rh,
        last_slide_id_ref=last_slide_id,
        version=version,
        minor_version=minor_ver,
        major_version=major_ver,
        offset_last_edit=offset_last_edit,
        offset_persist_directory=offset_persist_dir,
        doc_persist_id_ref=doc_persist_id,
        persist_id_seed=persist_id_seed,
        last_view=last_view,
        unused=unused,
        encrypt_session_persist_id_ref=encrypt_session_ref,
    )


def _pack_user_edit_atom(uea: UserEditAtom) -> bytearray:
    out = bytearray()
    out += _pack_record_header(uea.rh)
    out += pack('<I', uea.last_slide_id_ref)
    out += pack('<H', uea.version)
    out += pack('<BB', uea.minor_version, uea.major_version)
    out += pack('<I', uea.offset_last_edit)
    out += pack('<I', uea.offset_persist_directory)
    out += pack('<I', uea.doc_persist_id_ref)
    out += pack('<I', uea.persist_id_seed)
    out += pack('<H', uea.last_view)
    out += uea.unused
    if uea.encrypt_session_persist_id_ref is not None:
        out += pack('<I', uea.encrypt_session_persist_id_ref)
    return out


def _parse_persist_directory_entry(blob: io.IOBase) -> PersistDirectoryEntry:
    buf = unpack('<I', blob.read(4))[0]
    persist_id = buf & 0xFFFFF
    c_persist = (buf >> 20) & 0xFFF
    offsets = [unpack('<I', blob.read(4))[0] for _ in range(c_persist)]
    return PersistDirectoryEntry(
        persist_id=persist_id, c_persist=c_persist, rg_persist_offset=offsets)


def _pack_persist_directory_entry(entry: PersistDirectoryEntry) -> bytearray:
    buf = (entry.persist_id & 0xFFFFF) | ((entry.c_persist & 0xFFF) << 20)
    out = bytearray(pack('<I', buf))
    for v in entry.rg_persist_offset:
        out += pack('<I', v)
    return out


def _parse_persist_directory_atom(blob: io.IOBase) -> PersistDirectoryAtom:
    rh = _parse_record_header(blob.read(8))
    raw = MemoryFile(blob.read(rh.rec_len))
    entries = []
    pos = 0
    while pos < rh.rec_len:
        entry = _parse_persist_directory_entry(raw)
        entry_size = 4 + 4 * len(entry.rg_persist_offset)
        entries.append(entry)
        pos += entry_size
    return PersistDirectoryAtom(rh=rh, rg_persist_dir_entry=entries)


def _pack_persist_directory_atom(pda: PersistDirectoryAtom) -> bytearray:
    out = bytearray(_pack_record_header(pda.rh))
    for entry in pda.rg_persist_dir_entry:
        out += _pack_persist_directory_entry(entry)
    return out


def _construct_persist_object_directory(
    cu_stream: io.IOBase, ppt_stream: io.IOBase
) -> dict[int, int]:
    cu_stream.seek(0)
    cu = _parse_current_user_atom(cu_stream)
    ppt_stream.seek(cu.offset_to_current_edit)

    pda_stack = []
    for _ in range(1):
        uea = _parse_user_edit_atom(ppt_stream)
        ppt_stream.seek(uea.offset_persist_directory)
        pda = _parse_persist_directory_atom(ppt_stream)
        pda_stack.append(pda)
        if uea.offset_last_edit == 0:
            break
        ppt_stream.seek(uea.offset_last_edit)

    directory: dict[int, int] = {}
    while pda_stack:
        pda = pda_stack.pop()
        for entry in pda.rg_persist_dir_entry:
            for i, offset in enumerate(entry.rg_persist_offset):
                directory[entry.persist_id + i] = offset
    return directory


class Ppt97File:

    def __init__(self, file: io.IOBase):
        file.seek(0)
        self._data = file.read()
        self._ole = OleFile(self._data)
        self._key: str | None = None
        self._salt: bytes | None = None
        self._key_size: int = 0
        self._type: EncryptionType | None = None

    def load_key(self, password: str | None = None):
        if not password:
            raise DecryptionError('No password specified')
        cu_stream = self._ole.openstream('Current User')
        ppt_stream = self._ole.openstream('PowerPoint Document')

        pod = _construct_persist_object_directory(cu_stream, ppt_stream)

        cu_stream.seek(0)
        cu = _parse_current_user_atom(cu_stream)
        ppt_stream.seek(cu.offset_to_current_edit)
        uea = _parse_user_edit_atom(ppt_stream)

        if uea.encrypt_session_persist_id_ref is None:
            raise DecryptionError('PowerPoint file has no encryption session reference')
        crypt_offset = pod[uea.encrypt_session_persist_id_ref]
        ppt_stream.seek(crypt_offset)
        rh = _parse_record_header(ppt_stream.read(8))
        crypt_data = ppt_stream.read(rh.rec_len)

        enc_info = MemoryFile(crypt_data)
        v_major, v_minor = unpack('<HH', enc_info.read(4))
        if not (v_major in (2, 3, 4) and v_minor == 2):
            raise DecryptionError('Unsupported PPT encryption version')

        info = _parse_header_rc4_cryptoapi(enc_info)
        if DocumentRC4CryptoAPI.verifypw(
            password, info.salt, info.key_size,
            info.encrypted_verifier, info.encrypted_verifier_hash,
        ):
            self._type = EncryptionType.RC4_CRYPTOAPI
            self._key = password
            self._salt = info.salt
            self._key_size = info.key_size
        else:
            raise InvalidKeyError('Failed to verify password')

    def _require_key(self) -> tuple[str, bytes]:
        if self._key is None or self._salt is None:
            raise DecryptionError('load_key() must be called before decrypt()')
        return self._key, self._salt

    def decrypt(self, outfile: io.IOBase):
        key, salt = self._require_key()
        cu_stream = self._ole.openstream('Current User')
        ppt_stream = self._ole.openstream('PowerPoint Document')

        cu_stream.seek(0)
        cu_atom = _parse_current_user_atom(cu_stream)
        cu_atom_new = cu_atom._replace(header_token=0xE391C05F)
        cu_buf = _pack_current_user_atom(cu_atom_new)

        ppt_stream.seek(0)
        dec_ba = bytearray(ppt_stream.read())

        ppt_stream.seek(cu_atom.offset_to_current_edit)
        uea = _parse_user_edit_atom(ppt_stream)

        rh_new = uea.rh._replace(rec_len=uea.rh.rec_len - 4)
        uea_new = uea._replace(rh=rh_new, encrypt_session_persist_id_ref=0x00000000)
        uea_bytes = bytearray(_pack_user_edit_atom(uea_new))
        offset = cu_atom.offset_to_current_edit
        dec_ba[offset:offset + len(uea_bytes)] = uea_bytes

        ppt_stream.seek(cu_atom.offset_to_current_edit)
        uea = _parse_user_edit_atom(ppt_stream)
        ppt_stream.seek(uea.offset_persist_directory)
        pda = _parse_persist_directory_atom(ppt_stream)

        first = pda.rg_persist_dir_entry[0]._replace(
            c_persist=pda.rg_persist_dir_entry[0].c_persist - 1)
        pda_new = pda._replace(rg_persist_dir_entry=[first])
        pda_bytes = bytearray(_pack_persist_directory_atom(pda_new))
        offset = uea.offset_persist_directory
        dec_ba[offset:offset + len(pda_bytes)] = pda_bytes

        ppt_stream.seek(0)
        pod = _construct_persist_object_directory(
            MemoryFile(cu_buf), MemoryFile(bytearray(ppt_stream.read())))
        directory_items = list(pod.items())

        for i, (persist_id, offset) in enumerate(directory_items):
            mv = memoryview(dec_ba)
            rh = _parse_record_header(mv[offset:offset + 8])
            if rh.rec_type == 0x2F14:
                dec_ba[offset:offset + 8 + rh.rec_len] = b'\x00' * (8 + rh.rec_len)
                continue
            if rh.rec_type in (0x0FF5, 0x1772):
                continue
            rec_len = directory_items[i + 1][1] - offset - 8
            enc_buf = MemoryFile(mv[offset:offset + 8 + rec_len])
            blocksize = self._key_size * ((8 + rec_len) // self._key_size + 1)
            dec = DocumentRC4CryptoAPI.decrypt(
                key, salt, self._key_size,
                enc_buf, blocksize=blocksize, block=persist_id)
            dec_bytes = bytearray(dec.read())
            dec_ba[offset:offset + len(dec_bytes)] = dec_bytes

        out = bytearray(self._data)
        ole = OleFile(out)
        cu_stream_size = ole.get_size('Current User')
        cu_padded = bytearray(cu_buf)
        if len(cu_padded) < cu_stream_size:
            cu_padded += b'\x00' * (cu_stream_size - len(cu_padded))
        ole.write_stream('Current User', cu_padded)
        ole.write_stream('PowerPoint Document', bytes(dec_ba))
        outfile.write(out)

    def is_encrypted(self) -> bool:
        cu_stream = self._ole.openstream('Current User')
        cu_stream.seek(0)
        cu = _parse_current_user_atom(cu_stream)
        ppt_stream = self._ole.openstream('PowerPoint Document')
        ppt_stream.seek(cu.offset_to_current_edit)
        uea = _parse_user_edit_atom(ppt_stream)
        return uea.rh.rec_len == 0x20


def OfficeFile(file: io.IOBase):
    """
    Detect the format of an Office file and return the appropriate handler.
    """
    file.seek(0)
    data = file.read()
    file.seek(0)

    if is_ole_file(data):
        ole = OleFile(data)
        if ole.exists('EncryptionInfo'):
            return OOXMLFile(file)
        if ole.exists('wordDocument'):
            return Doc97File(file)
        if ole.exists('Workbook'):
            return Xls97File(file)
        if ole.exists('PowerPoint Document'):
            return Ppt97File(file)
        raise FileFormatError('Unrecognized OLE file format')
    elif zipfile.is_zipfile(file):
        return OOXMLFile(file)
    else:
        raise FileFormatError('Unsupported file format')
