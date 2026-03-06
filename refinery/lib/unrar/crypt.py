"""
Encryption and decryption for all RAR format versions.
"""
from __future__ import annotations

import hashlib
import hmac
import struct

from refinery.lib.types import buf
from refinery.lib.unrar.crc import crc_table as _get_crc_table
from refinery.lib.unrar.headers import (
    CRYPT5_KDF_LG2_COUNT_MAX,
    CRYPT_BLOCK_SIZE,
    SIZE_PSWCHECK,
    CryptMethod,
)


class CryptRar13:
    """
    RAR 1.3 trivial XOR encryption.
    """

    def __init__(self, password: str):
        key = [0, 0, 0]
        for ch in password:
            b = ord(ch) & 0xFF
            key[0] = (key[0] + b) & 0xFF
            key[1] = (key[1] ^ b) & 0xFF
            key[2] = (key[2] + b) & 0xFF
            key[2] = ((key[2] << 1) | (key[2] >> 7)) & 0xFF  # rotls(Key13[2], 1, 8)
        self._key = list(key)

    def decrypt(self, data: buf) -> bytearray:
        key = list(self._key)
        out = bytearray(len(data))
        for i, b in enumerate(data):
            key[1] = (key[1] + key[2]) & 0xFF
            key[0] = (key[0] + key[1]) & 0xFF
            out[i] = (b - key[0]) & 0xFF
        return out


class CryptRar15:
    """
    RAR 1.5 CRC-based XOR stream cipher.
    """

    def __init__(self, password: str):
        crc_tab = _get_crc_table()
        pw_bytes = password.encode('latin-1', errors='replace')
        # CRC32 of the full password
        psw_crc = 0xFFFFFFFF
        for b in pw_bytes:
            psw_crc = (psw_crc >> 8) ^ crc_tab[(psw_crc ^ b) & 0xFF]
        self._crc_tab = crc_tab
        self._key = [
            (psw_crc >> 0x00) & 0xFFFF,    # Key15[0]
            (psw_crc >> 0x10) & 0xFFFF,    # Key15[1]
            0,                             # Key15[2]
            0,                             # Key15[3]
        ]
        for b in pw_bytes:
            self._key[2] = (self._key[2] ^ (b ^ crc_tab[b])) & 0xFFFF
            self._key[3] = (self._key[3] + b + (crc_tab[b] >> 16)) & 0xFFFF

    def decrypt(self, data: buf) -> bytearray:
        crc_tab = self._crc_tab
        key = list(self._key)
        out = bytearray(data)
        for i in range(len(out)):
            key[0] = (key[0] + 0x1234) & 0xFFFF
            idx = (key[0] & 0x1FE) >> 1
            crc_val = crc_tab[idx]
            key[1] = (key[1] ^ crc_val) & 0xFFFF
            key[2] = (key[2] - (crc_val >> 16)) & 0xFFFF
            key[0] = (key[0] ^ key[2]) & 0xFFFF
            key[3] = (((key[3] >> 1) | (key[3] << 15)) & 0xFFFF) ^ key[1]
            key[3] = ((key[3] >> 1) | (key[3] << 15)) & 0xFFFF
            key[0] = (key[0] ^ key[3]) & 0xFFFF
            out[i] ^= (key[0] >> 8) & 0xFF
        return out


_INIT_SUBST_TABLE_20 = bytes((
    215, 19, 149, 35, 73, 197, 192, 205, 249, 28, 16, 119, 48, 221, 2, 42,
    232, 1, 177, 233, 14, 88, 219, 25, 223, 195, 244, 90, 87, 239, 153, 137,
    255, 199, 147, 70, 92, 66, 246, 13, 216, 40, 62, 29, 217, 230, 86, 6,
    71, 24, 171, 196, 101, 113, 218, 123, 93, 91, 163, 178, 202, 67, 44, 235,
    107, 250, 75, 234, 49, 167, 125, 211, 83, 114, 157, 144, 32, 193, 143, 36,
    158, 124, 247, 187, 89, 214, 141, 47, 121, 228, 61, 130, 213, 194, 174, 251,
    97, 110, 54, 229, 115, 57, 152, 94, 105, 243, 212, 55, 209, 245, 63, 11,
    164, 200, 31, 156, 81, 176, 227, 21, 76, 99, 139, 188, 127, 17, 248, 51,
    207, 120, 189, 210, 8, 226, 41, 72, 183, 203, 135, 165, 166, 60, 98, 7,
    122, 38, 155, 170, 69, 172, 252, 238, 39, 134, 59, 128, 236, 27, 240, 80,
    131, 3, 85, 206, 145, 79, 154, 142, 159, 220, 201, 133, 74, 64, 20, 129,
    224, 185, 138, 103, 173, 182, 43, 34, 254, 82, 198, 151, 231, 180, 58, 10,
    118, 26, 102, 12, 50, 132, 22, 191, 136, 111, 162, 179, 45, 4, 148, 108,
    161, 56, 78, 126, 242, 222, 15, 175, 146, 23, 33, 241, 181, 190, 77, 225,
    0, 46, 169, 186, 68, 95, 237, 65, 53, 208, 253, 168, 9, 18, 100, 52,
    116, 184, 160, 96, 109, 37, 30, 106, 140, 104, 150, 5, 204, 117, 112, 84,
))

_M32 = 0xFFFFFFFF
_NROUNDS = 32


def _rotl32(v: int, n: int) -> int:
    return ((v << n) | (v >> (32 - n))) & _M32


class CryptRar20:
    """
    RAR 2.0 substitution table + Feistel block cipher.
    """

    def __init__(self, password: str, salt: bytes = b''):
        self._subst = bytearray(_INIT_SUBST_TABLE_20)
        self._key = [0xD3A3B879, 0x3F6D12F7, 0x7515A235, 0xA4E7F123]
        self._set_key(password)

    def _set_key(self, password: str):
        crc_tab = _get_crc_table()
        pw_bytes = password.encode('latin-1', errors='replace')
        pw_len = len(pw_bytes)

        for j in range(256):
            for i in range(0, pw_len, 2):
                n1 = crc_tab[(pw_bytes[i] - j) & 0xFF] & 0xFF
                i1 = i + 1 if i + 1 < pw_len else i
                n2 = crc_tab[(pw_bytes[i1] + j) & 0xFF] & 0xFF
                k = 1
                while n1 != n2:
                    self._subst[n1], self._subst[(n1 + i + k) & 0xFF] = (
                        self._subst[(n1 + i + k) & 0xFF], self._subst[n1])
                    n1 = (n1 + 1) & 0xFF
                    k += 1

        psw = bytearray(pw_bytes)
        if pw_len & (CRYPT_BLOCK_SIZE - 1):
            padded = (pw_len | (CRYPT_BLOCK_SIZE - 1)) + 1
            psw.extend(b'\x00' * (padded - pw_len))

        for i in range(0, len(psw), CRYPT_BLOCK_SIZE):
            self._encrypt_block(psw, i)

    def _subst_long(self, val: int) -> int:
        t = self._subst
        b0 = t[(val) & 0xFF]
        b1 = t[(val >> 8) & 0xFF]
        b2 = t[(val >> 16) & 0xFF]
        b3 = t[(val >> 24) & 0xFF]
        return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)

    def _encrypt_block(self, data: bytearray, offset: int = 0):
        key = self._key
        A = struct.unpack_from('<I', data, offset + 0)[0] ^ key[0]
        B = struct.unpack_from('<I', data, offset + 4)[0] ^ key[1]
        C = struct.unpack_from('<I', data, offset + 8)[0] ^ key[2]
        D = struct.unpack_from('<I', data, offset + 12)[0] ^ key[3]
        for i in range(_NROUNDS):
            T = ((C + _rotl32(D, 11)) ^ key[i & 3]) & _M32
            TA = A ^ self._subst_long(T)
            T = (((D ^ _rotl32(C, 17)) + key[i & 3]) & _M32)
            TB = B ^ self._subst_long(T)
            A = C
            B = D
            C = TA
            D = TB
        struct.pack_into('<4I', data, offset, C ^ key[0], D ^ key[1], A ^ key[2], B ^ key[3])
        self._upd_keys(data[offset:offset + 16])

    def _decrypt_block(self, data: bytearray, offset: int = 0):
        key = self._key
        in_buf = data[offset:offset + 16]
        A = struct.unpack_from('<I', data, offset + 0)[0] ^ key[0]
        B = struct.unpack_from('<I', data, offset + 4)[0] ^ key[1]
        C = struct.unpack_from('<I', data, offset + 8)[0] ^ key[2]
        D = struct.unpack_from('<I', data, offset + 12)[0] ^ key[3]
        for i in range(_NROUNDS - 1, -1, -1):
            T = ((C + _rotl32(D, 11)) ^ key[i & 3]) & _M32
            TA = A ^ self._subst_long(T)
            T = (((D ^ _rotl32(C, 17)) + key[i & 3]) & _M32)
            TB = B ^ self._subst_long(T)
            A = C
            B = D
            C = TA
            D = TB
        struct.pack_into('<4I', data, offset, C ^ key[0], D ^ key[1], A ^ key[2], B ^ key[3])
        self._upd_keys(in_buf)

    def decrypt(self, data: buf) -> bytearray:
        out = bytearray(data)
        for i in range(0, len(out) - 15, 16):
            self._decrypt_block(out, i)
        return out

    def _upd_keys(self, block: bytes | bytearray):
        crc_tab = _get_crc_table()
        for i in range(0, 16, 4):
            self._key[0] ^= crc_tab[block[i] & 0xFF]
            self._key[1] ^= crc_tab[block[i + 1] & 0xFF]
            self._key[2] ^= crc_tab[block[i + 2] & 0xFF]
            self._key[3] ^= crc_tab[block[i + 3] & 0xFF]


def rar3_kdf(password: str, salt: buf) -> tuple[bytes, bytes]:
    """
    RAR 3.0 key derivation function.
    SHA-1 based, 0x40000 iterations.
    Returns (key_16_bytes, iv_16_bytes).
    """
    ROUNDS = 0x40000

    pw_utf16 = password.encode('utf-16-le')

    raw_data = pw_utf16 + bytes(salt)

    iv = bytearray(16)
    sha1 = hashlib.sha1()

    for i in range(ROUNDS):
        sha1.update(raw_data)
        sha1.update(struct.pack('<I', i)[:3])

        if i % (ROUNDS // 16) == 0:
            iv_idx = i // (ROUNDS // 16)
            if iv_idx < 16:
                iv_digest = sha1.copy().digest()
                iv[iv_idx] = iv_digest[19]

    key_digest = sha1.digest()
    key = bytearray(16)
    for i in range(4):
        for j in range(4):
            key[i * 4 + j] = key_digest[i * 4 + 3 - j]

    return bytes(key), bytes(iv)


class CryptRar30:
    """
    RAR 3.0 AES-128-CBC encryption.
    """

    def __init__(self, password: str, salt: buf):
        key, iv = rar3_kdf(password, salt)
        self._key = key
        self._iv = iv

    def decrypt(self, data: buf) -> bytes:
        from Cryptodome.Cipher import AES
        pad_len = (CRYPT_BLOCK_SIZE - (len(data) % CRYPT_BLOCK_SIZE)) % CRYPT_BLOCK_SIZE
        if pad_len:
            data = bytearray(data)
            data.extend(b'\x00' * pad_len)
        cipher = AES.new(self._key, AES.MODE_CBC, iv=self._iv)
        return cipher.decrypt(data)


def rar5_pbkdf2(password: str, salt: buf, lg2_count: int) -> tuple[bytes, bytes, bytes]:
    """
    RAR 5.0 key derivation. Custom PBKDF2 producing:
        32 Bytes Key
        32 Bytes HashKeyValue
        32 Bytes PswCheckValue
    Returns (key, hash_key_value, psw_check_value). This is a single PBKDF2 block with intermediate
    value extraction.
    """
    lg2_count = min(lg2_count, CRYPT5_KDF_LG2_COUNT_MAX)
    pw_bytes = password.encode('utf-8')
    count = 1 << lg2_count
    salt_data = bytes(salt) + b'\0\0\0\01'
    u = hmac.new(pw_bytes, salt_data, hashlib.sha256).digest()
    fn = bytearray(u)
    cur_counts = (count - 1, 16, 16)
    results = []
    for phase in range(3):
        for _ in range(cur_counts[phase]):
            u = hmac.new(pw_bytes, u, hashlib.sha256).digest()
            for k in range(32):
                fn[k] ^= u[k]
        results.append(bytes(fn))
    return tuple(results)


def rar5_psw_check(psw_check_value: bytes) -> bytes:
    """
    XOR-fold 32-byte PswCheckValue down to 8 bytes.
    """
    result = bytearray(SIZE_PSWCHECK)
    for i in range(len(psw_check_value)):
        result[i % SIZE_PSWCHECK] ^= psw_check_value[i]
    return bytes(result)


class CryptRar50:
    """
    RAR 5.0 AES-256-CBC encryption.
    """

    def __init__(
        self,
        password: str,
        salt: buf,
        lg2_count: int,
        iv: buf,
        use_psw_check: bool = False,
        expected_psw_check: buf = b'',
    ):
        key, hash_key_value, psw_check_value = rar5_pbkdf2(password, salt, lg2_count)
        self._key = key
        self._iv = iv
        self._hash_key = hash_key_value

        if use_psw_check and expected_psw_check:
            computed = rar5_psw_check(psw_check_value)
            if computed != expected_psw_check:
                from refinery.lib.unrar import RarInvalidPassword
                raise RarInvalidPassword

    @property
    def hash_key(self) -> bytes:
        return self._hash_key

    def decrypt(self, data: buf) -> bytes:
        from Cryptodome.Cipher import AES
        pad_len = (CRYPT_BLOCK_SIZE - (len(data) % CRYPT_BLOCK_SIZE)) % CRYPT_BLOCK_SIZE
        if pad_len:
            data = bytearray(data)
            data.extend(b'\x00' * pad_len)
        cipher = AES.new(self._key, AES.MODE_CBC, iv=self._iv)
        return cipher.decrypt(data)


def make_decryptor(
    crypt_method: int,
    password: str,
    salt: buf = b'',
    iv: buf = b'',
    lg2_count: int = 0,
    use_psw_check: bool = False,
    psw_check: buf = b'',
):
    """
    Create the appropriate decryptor for the given encryption method.
    """
    if crypt_method == CryptMethod.CRYPT_NONE:
        return None
    elif crypt_method == CryptMethod.CRYPT_RAR13:
        return CryptRar13(password)
    elif crypt_method == CryptMethod.CRYPT_RAR15:
        return CryptRar15(password)
    elif crypt_method == CryptMethod.CRYPT_RAR20:
        return CryptRar20(password, salt)
    elif crypt_method == CryptMethod.CRYPT_RAR30:
        return CryptRar30(password, salt)
    elif crypt_method == CryptMethod.CRYPT_RAR50:
        return CryptRar50(password, salt, lg2_count, iv, use_psw_check, psw_check)
    else:
        raise ValueError(F'Unknown encryption method: {crypt_method}')
