"""
Validation routines for the wallet address patterns in `refinery.lib.patterns.wallets`. The regular
expressions in that module are often too permissive; they recognize the shape of an address but
cannot tell apart a genuine address from an arbitrary string that happens to use the same
alphabet and length. The functions here add a second stage that verifies the integrity check built
into each address format:

- Base58Check addresses (most legacy coins) carry a four byte `SHA256` double hash checksum.
- Bech32 and Bech32m addresses (SegWit, Cosmos, and related) carry a `BCH` code checksum.
- CashAddr addresses (Bitcoin Cash) carry a wider 40 bit `BCH` code checksum.
- EVM addresses optionally carry an `EIP55` mixed case checksum derived from `Keccak256`.
- Stellar addresses are Base32 encoded with a trailing `CRC16` (XMODEM) checksum.
- TON addresses are Base64 encoded with a trailing `CRC16` (XMODEM) checksum.
- NEM addresses are Base32 encoded with a trailing `Keccak256` checksum.
- Monero addresses use a block based Base58 encoding with a trailing `Keccak256` checksum.
- Substrate addresses (Polkadot) carry a `Blake2b` checksum over an `SS58PRE` prefixed payload.
- Cardano Shelley addresses are Bech32; Byron addresses are `CBOR` with a `CRC32` checksum.
- Solana addresses are a raw 32 byte public key and are validated by their decoded length.
- WIF private keys are Base58Check encoded with a `0x80` version byte; `xtw` surfaces them as a
  leaked secret rather than as a destination address.

The `validate` function is the entry point used by `refinery.units.pattern.xtw`. Address kinds
for which no validator is registered always pass, so enabling validation never discards a coin
that we do not yet know how to check.
"""
from __future__ import annotations

import hashlib

from typing import Callable

from refinery.lib.types import buf

_BASE58 = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
_BASE58_INVERSE = {character: value for value, character in enumerate(_BASE58)}

_RIPPLE = b'rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz'

_BECH32 = b'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
_BECH32_INVERSE = {character: value for value, character in enumerate(_BECH32)}
_BECH32_CONST = 1
_BECH32M_CONST = 0x2BC830A3


def _base58_decode(data: buf, alphabet: bytes = _BASE58) -> bytes | None:
    inverse = _BASE58_INVERSE if alphabet is _BASE58 else {
        character: value for value, character in enumerate(alphabet)}
    zero = alphabet[0]
    number = 0
    leading_zeros = 0
    counting = True
    for character in bytes(data):
        value = inverse.get(character)
        if value is None:
            return None
        number = number * 58 + value
        if counting and character == zero:
            leading_zeros += 1
        else:
            counting = False
    body = number.to_bytes((number.bit_length() + 7) // 8, 'big') if number else B''
    return B'\0' * leading_zeros + body


def base58check(data: buf, alphabet: bytes = _BASE58) -> bytes | None:
    """
    Decode a Base58Check string and verify its trailing four byte double-`SHA256` checksum. The
    decoded payload, including its version prefix, is returned when the checksum is valid, and
    `None` is returned otherwise. The optional `alphabet` selects the Base58 dialect; it defaults
    to the Bitcoin alphabet but can be set to the Ripple alphabet for XRP addresses.
    """
    raw = _base58_decode(data, alphabet)
    if raw is None or len(raw) < 5:
        return None
    payload, checksum = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != checksum:
        return None
    return payload


_MONERO_BLOCK_SIZES = {2: 1, 3: 2, 5: 3, 6: 4, 7: 5, 9: 6, 10: 7, 11: 8}


def _monero_base58_decode(data: buf) -> bytes | None:
    """
    Decode a Monero style Base58 string. Unlike Base58Check, Monero encodes the payload in eight
    byte blocks that each map to eleven characters; the final, shorter block uses a fixed lookup
    from encoded length to decoded length. Returns `None` for any malformed block.
    """
    body = bytes(data)
    out = bytearray()
    for index in range(0, len(body), 11):
        block = body[index:index + 11]
        size = _MONERO_BLOCK_SIZES.get(len(block))
        if size is None:
            return None
        number = 0
        for character in block:
            value = _BASE58_INVERSE.get(character)
            if value is None:
                return None
            number = number * 58 + value
        if number >> (8 * size):
            return None
        out += number.to_bytes(size, 'big')
    return bytes(out)



def _bech32_polymod(values: list[int]) -> int:
    generator = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = (checksum & 0x1FFFFFF) << 5 ^ value
        for bit, term in enumerate(generator):
            if (top >> bit) & 1:
                checksum ^= term
    return checksum


def bech32_valid(data: buf, hrp: bytes) -> bool:
    """
    Verify that the input is a valid Bech32 or Bech32m string with the given human readable part.
    The distinction between the two checksum variants is irrelevant for address validation, so
    either constant is accepted.
    """
    address = bytes(data).lower()
    if not address.startswith(hrp + B'1'):
        return False
    values = []
    for character in address[len(hrp) + 1:]:
        value = _BECH32_INVERSE.get(character)
        if value is None:
            return False
        values.append(value)
    expanded = [c >> 5 for c in hrp] + [0] + [c & 31 for c in hrp]
    checksum = _bech32_polymod(expanded + values)
    return checksum == _BECH32_CONST or checksum == _BECH32M_CONST


def _cashaddr_polymod(values: list[int]) -> int:
    generator = (
        0x98F2BC8E61,
        0x79B76D99E2,
        0xF33E5FB3C4,
        0xAE2EABE2A8,
        0x1E4F43E470,
    )
    checksum = 1
    for value in values:
        top = checksum >> 35
        checksum = ((checksum & 0x07FFFFFFFF) << 5) ^ value
        for bit, term in enumerate(generator):
            if (top >> bit) & 1:
                checksum ^= term
    return checksum ^ 1


def cashaddr_valid(data: buf, prefix: bytes) -> bool:
    """
    Verify a Bitcoin Cash CashAddr string against its 40 bit `BCH` checksum. The CashAddr format
    shares the Bech32 character set but uses a wider checksum with its own generator polynomial.
    An optional `prefix:` component is accepted and must match the given prefix.
    """
    address = bytes(data).lower()
    payload = address
    if B':' in address:
        head, _, payload = address.partition(B':')
        if head != prefix:
            return False
    values = []
    for character in payload:
        value = _BECH32_INVERSE.get(character)
        if value is None:
            return False
        values.append(value)
    expanded = [c & 31 for c in prefix] + [0] + values
    return _cashaddr_polymod(expanded) == 0


def _crc16_xmodem(data: buf) -> int:
    crc = 0
    for byte in bytes(data):
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ 0x1021
            else:
                crc <<= 1
            crc &= 0xFFFF
    return crc


def _eip55_body_valid(body: bytes) -> bool:
    if len(body) != 40:
        return False
    lower = body.lower()
    if any(c not in B'0123456789abcdefABCDEF' for c in body):
        return False
    if body == lower or body == body.upper():
        return True
    from Cryptodome.Hash import keccak
    digest = keccak.new(digest_bits=256, data=lower).hexdigest()
    for character, nibble in zip(bytes(body), digest):
        if character in B'0123456789':
            continue
        upper = character < 0x61
        if upper != (int(nibble, 16) >= 8):
            return False
    return True


def eip55_valid(data: buf) -> bool:
    """
    Validate an EVM `0x` address. A purely lower or upper case address carries no checksum and is
    accepted unconditionally. A mixed case address is verified against the `EIP55` checksum, which
    is computed from the `Keccak256` hash of the lower case hexadecimal digits.
    """
    address = bytes(data)
    if not address[:2] == B'0x' or len(address) != 42:
        return False
    return _eip55_body_valid(address[2:])


def solana_valid(data: buf) -> bool:
    """
    Validate a Solana address by confirming that it Base58 decodes to a 32 byte public key.
    """
    raw = _base58_decode(data)
    return raw is not None and len(raw) == 32


def _base58check_valid(data: buf) -> bool:
    return base58check(data) is not None


def _bitcoin_valid(data: buf) -> bool:
    if bytes(data[:3]).lower() == B'bc1':
        return bech32_valid(data, B'bc')
    return _base58check_valid(data)


def _litecoin_valid(data: buf) -> bool:
    if bytes(data[:4]).lower() == B'ltc1':
        return bech32_valid(data, B'ltc')
    return _base58check_valid(data)


def _harmony_valid(data: buf) -> bool:
    return bech32_valid(data, B'one') or bech32_valid(data, B'bnb')


def _avalanche_valid(data: buf) -> bool:
    body = bytes(data)
    if body[:2] in (B'X-', B'P-'):
        return bech32_valid(body[2:], B'avax')
    return False


def _ripple_valid(data: buf) -> bool:
    body = bytes(data)
    if body[:1] == B'X':
        return True
    return base58check(body, _RIPPLE) is not None


def _stellar_valid(data: buf) -> bool:
    import base64
    try:
        raw = base64.b32decode(bytes(data))
    except Exception:
        return False
    if len(raw) < 3:
        return False
    body, checksum = raw[:-2], raw[-2:]
    return _crc16_xmodem(body).to_bytes(2, 'little') == checksum


def _polkadot_valid(data: buf) -> bool:
    raw = _base58_decode(data)
    if raw is None or len(raw) < 3:
        return False
    body, checksum = raw[:-2], raw[-2:]
    digest = hashlib.blake2b(B'SS58PRE' + body, digest_size=64).digest()
    return digest[:2] == checksum


def _cardano_valid(data: buf) -> bool:
    body = bytes(data)
    if body[:4].lower() == B'addr':
        return bech32_valid(body, B'addr')
    raw = _base58_decode(body)
    if raw is None:
        return False
    import zlib

    from refinery.lib.cbor import CBORReader
    item = CBORReader(memoryview(raw), bigendian=True).read_item()
    if not isinstance(item, list) or len(item) != 2:
        return False
    tagged, checksum = item
    if not isinstance(tagged, dict) or tagged.get('tag') != 24:
        return False
    inner = tagged.get('value')
    if not isinstance(inner, (bytes, bytearray, memoryview)):
        return False
    return zlib.crc32(bytes(inner)) == checksum


def _bech32_valid_cosmos(data: buf):
    return bech32_valid(data, b'cosmos')


def _bech32_valid_terra(data: buf):
    return bech32_valid(data, b'terra')


def _cashaddr_valid_bitcoincash(data: buf):
    return cashaddr_valid(data, B'bitcoincash')


def _ronin_valid(data: buf) -> bool:
    body = bytes(data)
    if body[:6].lower() != B'ronin:':
        return False
    return _eip55_body_valid(body[6:])


def _wif_valid(data: buf) -> bool:
    payload = base58check(data)
    if payload is None:
        return False
    return payload[:1] == B'\x80' and len(payload) == 33


def _iota_valid(data: buf) -> bool:
    return bech32_valid(data, B'iota')


def _ton_valid(data: buf) -> bool:
    import base64
    body = bytes(data).translate(bytes.maketrans(B'-_', B'+/'))
    try:
        raw = base64.b64decode(body, validate=True)
    except Exception:
        return False
    if len(raw) != 36:
        return False
    payload, checksum = raw[:34], raw[34:]
    return _crc16_xmodem(payload).to_bytes(2, 'big') == checksum


def _monero_valid(data: buf) -> bool:
    raw = _monero_base58_decode(data)
    if raw is None or len(raw) <= 4:
        return False
    from Cryptodome.Hash import keccak
    body, checksum = raw[:-4], raw[-4:]
    return keccak.new(digest_bits=256, data=body).digest()[:4] == checksum


def _nem_valid(data: buf) -> bool:
    import base64
    body = bytes(data).replace(B'-', B'')
    try:
        raw = base64.b32decode(body)
    except Exception:
        return False
    if len(raw) != 25:
        return False
    from Cryptodome.Hash import keccak
    payload, checksum = raw[:21], raw[21:]
    return keccak.new(digest_bits=256, data=payload).digest()[:4] == checksum


VALIDATORS: dict[str, Callable[[buf], bool]] = {
    'BTC'    : _bitcoin_valid,
    'LTC'    : _litecoin_valid,
    'DOGE'   : _base58check_valid,
    'DASH'   : _base58check_valid,
    'ZCASH'  : _base58check_valid,
    'RVN'    : _base58check_valid,
    'TRON'   : _base58check_valid,
    'NEO'    : _base58check_valid,
    'ONT'    : _base58check_valid,
    'ATOM'   : _bech32_valid_cosmos,
    'TERRA'  : _bech32_valid_terra,
    'ONE'    : _harmony_valid,
    'ETH'    : eip55_valid,
    'AVAX'   : _avalanche_valid,
    'RONIN'  : _ronin_valid,
    'SOLANA' : solana_valid,
    'XRP'    : _ripple_valid,
    'BCH'    : _cashaddr_valid_bitcoincash,
    'XLM'    : _stellar_valid,
    'DOT'    : _polkadot_valid,
    'ADA'    : _cardano_valid,
    'IOTA'   : _iota_valid,
    'TON'    : _ton_valid,
    'XMR'    : _monero_valid,
    'XEM'    : _nem_valid,
    'WIF'    : _wif_valid,
}


def validate(kind: str, address: buf) -> bool:
    """
    Return whether the given address is valid for the wallet kind named by `kind`, where the name
    is a member name of `refinery.lib.patterns.wallets`. When no validator is registered for the
    kind, the address is considered valid; this guarantees that validation only ever rejects an
    address that a registered checker positively identifies as malformed.
    """
    validator = VALIDATORS.get(kind)
    if validator is None:
        return True
    try:
        return validator(address)
    except Exception:
        return False
