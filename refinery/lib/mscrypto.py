#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Microsoft Crypto API structures
"""
import enum

from Crypto.PublicKey import RSA
from Crypto.Math.Numbers import Integer

from .structures import Struct, StructReader


class _ENUM(enum.IntEnum):
    def __str__(self): return self.name
    def __repr__(self): return self.name


class TYPES(_ENUM):
    KEYSTATEBLOB               = 0xC # noqa
    OPAQUEKEYBLOB              = 0x9 # noqa
    PLAINTEXTKEYBLOB           = 0x8 # noqa
    PRIVATEKEYBLOB             = 0x7 # noqa
    PUBLICKEYBLOB              = 0x6 # noqa
    PUBLICKEYBLOBEX            = 0xA # noqa
    SIMPLEBLOB                 = 0x1 # noqa
    SYMMETRICWRAPKEYBLOB       = 0xB # noqa


class ALGORITHMS(_ENUM):
    CALG_3DES                  = 0x00006603 # noqa
    CALG_3DES_112              = 0x00006609 # noqa
    CALG_AES                   = 0x00006611 # noqa
    CALG_AES_128               = 0x0000660e # noqa
    CALG_AES_192               = 0x0000660f # noqa
    CALG_AES_256               = 0x00006610 # noqa
    CALG_AGREEDKEY_ANY         = 0x0000aa03 # noqa
    CALG_CYLINK_MEK            = 0x0000660c # noqa
    CALG_DES                   = 0x00006601 # noqa
    CALG_DESX                  = 0x00006604 # noqa
    CALG_DH_EPHEM              = 0x0000aa02 # noqa
    CALG_DH_SF                 = 0x0000aa01 # noqa
    CALG_DSS_SIGN              = 0x00002200 # noqa
    CALG_ECDH                  = 0x0000aa05 # noqa
    CALG_ECDH_EPHEM            = 0x0000ae06 # noqa
    CALG_ECDSA                 = 0x00002203 # noqa
    CALG_ECMQV                 = 0x0000a001 # noqa
    CALG_HASH_REPLACE_OWF      = 0x0000800b # noqa
    CALG_HUGHES_MD5            = 0x0000a003 # noqa
    CALG_HMAC                  = 0x00008009 # noqa
    CALG_KEA_KEYX              = 0x0000aa04 # noqa
    CALG_MAC                   = 0x00008005 # noqa
    CALG_MD2                   = 0x00008001 # noqa
    CALG_MD4                   = 0x00008002 # noqa
    CALG_MD5                   = 0x00008003 # noqa
    CALG_NO_SIGN               = 0x00002000 # noqa
    CALG_OID_INFO_CNG_ONLY     = 0xffffffff # noqa
    CALG_OID_INFO_PARAMETERS   = 0xfffffffe # noqa
    CALG_PCT1_MASTER           = 0x00004c04 # noqa
    CALG_RC2                   = 0x00006602 # noqa
    CALG_RC4                   = 0x00006801 # noqa
    CALG_RC5                   = 0x0000660d # noqa
    CALG_RSA_KEYX              = 0x0000a400 # noqa
    CALG_RSA_SIGN              = 0x00002400 # noqa
    CALG_SCHANNEL_ENC_KEY      = 0x00004c07 # noqa
    CALG_SCHANNEL_MAC_KEY      = 0x00004c03 # noqa
    CALG_SCHANNEL_MASTER_HASH  = 0x00004c02 # noqa
    CALG_SEAL                  = 0x00006802 # noqa
    CALG_SHA1                  = 0x00008004 # noqa
    CALG_SHA_256               = 0x0000800c # noqa
    CALG_SHA_384               = 0x0000800d # noqa
    CALG_SHA_512               = 0x0000800e # noqa
    CALG_SKIPJACK              = 0x0000660a # noqa
    CALG_SSL2_MASTER           = 0x00004c05 # noqa
    CALG_SSL3_MASTER           = 0x00004c01 # noqa
    CALG_SSL3_SHAMD5           = 0x00008008 # noqa
    CALG_TEK                   = 0x0000660b # noqa
    CALG_TLS1_MASTER           = 0x00004c06 # noqa
    CALG_TLS1PRF               = 0x0000800a # noqa


class BCRYPT_MAGIC(_ENUM):
    BCRYPT_RSAPUBLIC_MAGIC      = 0x31415352 # noqa
    BCRYPT_RSAPRIVATE_MAGIC     = 0x32415352 # noqa
    BCRYPT_RSAFULLPRIVATE_MAGIC = 0x33415352 # noqa


class BLOBHEADER(Struct):
    def __init__(self, reader: StructReader):
        t, self.version, self.reserved, a = reader.read_struct('BBHI')
        self.type = TYPES(t)
        self.algorithm = ALGORITHMS(a)


class PLAINTEXTKEYBLOB(Struct):
    def __bytes__(self): return bytes(self.data)

    def __init__(self, reader: StructReader):
        self.size = reader.u32()
        self.data = reader.read(self.size)


class SIMPLEBLOB(Struct):
    def __bytes__(self): return bytes(self.data)

    def __init__(self, reader: StructReader):
        self.magic = reader.read(4)
        if self.magic != B'\0\0\xA4\0':
            raise ValueError(F'Invalid magic bytes: {self.magic.hex(":").upper()}')
        self.data = reader.read(0x100)


class BCRYPT_RSAKEY_BLOB(Struct):
    def __init__(self, reader: StructReader):
        magic, bits, e_size, n_size, p_size, q_size = reader.read_struct('<6L')
        e_size *= 8
        n_size *= 8
        self.magic = BCRYPT_MAGIC(magic)
        reader.bigendian = True
        self.exponent = reader.read_integer(e_size)
        self.modulus = reader.read_integer(n_size)
        self.bit_size = bits
        if self.has_private_key:
            p_size *= 8
            q_size *= 8
            self.prime1 = reader.read_integer(p_size)
            self.prime2 = reader.read_integer(q_size)
            if self.magic is BCRYPT_MAGIC.BCRYPT_RSAFULLPRIVATE_MAGIC:
                self.exp1 = reader.read_integer(p_size)
                self.exp2 = reader.read_integer(q_size)
                self.coefficient = reader.read_integer(p_size)
                self.exp_private = reader.read_integer(n_size)
            else:
                self.exp1 = None
                self.exp2 = None
                self.coefficient = None
                self.exp_private = None
        else:
            self.prime1 = None
            self.prime2 = None

    @property
    def has_private_key(self):
        return self.magic in (
            BCRYPT_MAGIC.BCRYPT_RSAPRIVATE_MAGIC,
            BCRYPT_MAGIC.BCRYPT_RSAFULLPRIVATE_MAGIC
        )

    def convert(self):
        components = self.modulus, self.exponent
        if self.has_private_key:
            components += self.exp_private, self.prime1, self.prime2
        return RSA.construct(components)


class RSAPUBKEY(Struct):
    def __init__(self, reader: StructReader):
        self.magic = reader.read(4)
        if self.magic not in (B'RSA2', B'RSA1'):
            raise ValueError(F'Invalid signature: {self.magic.hex()}')
        self.size, self.exponent = reader.read_struct('II')
        if self.size % 8 != 0:
            raise ValueError(F'The bitlength {self.size} is not a multiple of 8.')
        self.modulus = reader.read_integer(self.size)

    def convert(self):
        return RSA.construct((self.modulus, self.exponent))

    def __str__(self):
        return self.key().export_key(format='PEM')

    def __bytes__(self):
        return str(self).encode('ascii')


class PRIVATEKEYBLOB(Struct):
    def __init__(self, reader: StructReader):
        self.pub = RSAPUBKEY(reader)
        halfsize = self.pub.size // 2
        self.prime1 = reader.read_integer(halfsize)
        self.prime2 = reader.read_integer(halfsize)
        self.exp1 = reader.read_integer(halfsize)
        self.exp2 = reader.read_integer(halfsize)
        self.coefficient = reader.read_integer(halfsize)
        self.exponent = reader.read_integer(halfsize)
        self._check()

    def _check(self):
        if self.pub.modulus // self.prime1 != self.prime2:
            raise ValueError('Product of primes does not equal the modulus.')
        from math import gcd
        a = self.prime1 - 1
        b = self.prime2 - 1
        totient = (a * b) // gcd(a, b)
        if self.pub.exponent * self.exponent % totient != 1:
            raise ValueError('Public exponent is not a modular inverse of private exponent.')

    def convert(self):
        parameters = (
            self.pub.modulus,
            self.pub.exponent,
            self.exponent,
            self.prime1,
            self.prime2,
            self.coefficient
        )
        try:
            return RSA.construct(parameters, consistency_check=True)
        except ValueError as V:
            try:
                return RSA.RsaKey(
                    n=Integer(self.pub.modulus),
                    e=Integer(self.pub.exponent),
                    d=Integer(self.exponent),
                    p=Integer(self.prime1),
                    q=Integer(self.prime2),
                    u=Integer(self.coefficient),
                )
            except Exception as E:
                raise E from V

    def __str__(self):
        return self.key().export_key(format='PEM')

    def __bytes__(self):
        return str(self).encode('ascii')


class DHPUBKEY(Struct):
    def __init__(self, reader: StructReader):
        self.magic, self.size = reader.read_struct('4sI')
        if self.magic not in (B'\0DH1', B'\0DH2'):
            raise ValueError(F'Invalid magic bytes: {self.magic.hex(":").upper()}')
        if self.size % 8 != 0:
            raise ValueError('Bit length is not a multiple of 8.')
        self.public = reader.read_integer(self.size)
        self.prime = reader.read_integer(self.size)
        self.generator = reader.read_integer(self.size)

    def __bytes__(self):
        raise NotImplementedError


class CRYPTOKEY(Struct):
    def __init__(self, reader: StructReader):
        self.header = BLOBHEADER(reader)
        if self.header.type in {
            TYPES.KEYSTATEBLOB,
            TYPES.OPAQUEKEYBLOB,
            TYPES.SYMMETRICWRAPKEYBLOB
        }:
            raise ValueError(F'Unsupported type: {self.header.type}')
        elif self.header.type == TYPES.PLAINTEXTKEYBLOB:
            self.key = PLAINTEXTKEYBLOB(reader)
        elif self.header.type == TYPES.SIMPLEBLOB:
            self.key = SIMPLEBLOB(reader)
        else:
            if self.header.algorithm not in {
                ALGORITHMS.CALG_RSA_KEYX,
                ALGORITHMS.CALG_RSA_SIGN
            }:
                raise ValueError(F'Unknown algorithm for {self.header.type}: {self.header.algorithm}')
            elif self.header.type == TYPES.PRIVATEKEYBLOB:
                self.key = PRIVATEKEYBLOB(reader)
            elif self.header.type == TYPES.PUBLICKEYBLOB:
                self.key = RSAPUBKEY(reader)
            elif self.header.type == TYPES.PUBLICKEYBLOBEX:
                self.key = DHPUBKEY(reader)
