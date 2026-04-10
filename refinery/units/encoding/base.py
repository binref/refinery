from __future__ import annotations

import base64 as b64mod

from refinery.units.encoding.bigint import _DEFAULT_ALPHABET, _DEFAULT_ALPH_STR, _LARGER_ALPHABETS
from refinery.lib.types import Param, isq
from refinery.units import Arg, Unit


def _block_params(base: int) -> tuple[int, int]:
    """
    Compute optimal block parameters (m, n) for block-based encoding with the given base. Returns
    the pair (m, n) where m is the number of input bytes per block and n is the number of encoded
    characters per block, chosen to minimize the waste ratio `(base**n)/(256**m)`.
    """
    best_m = 1
    best_n = 1
    best_waste = float('inf')
    for m in range(1, 17):
        capacity = 256 ** m
        n = 1
        while base ** n < capacity:
            n += 1
        waste = base ** n / capacity
        if waste < best_waste:
            best_waste = waste
            best_m = m
            best_n = n
            if abs(waste - 1) < 1e-8:
                break
    return best_m, best_n


class base(Unit):
    """
    Block-based encoding and decoding with an arbitrary alphabet. The input is split into fixed-size
    blocks and each block is encoded independently, following the same convention as base32, base64,
    and base85. This unit generalizes that convention to alphabets of any size.
    """
    def __init__(
        self,
        base: Param[isq, Arg.NumSeq(metavar='base|alphabet', help=(
            R'Either the base to be used or an alphabet. If an explicit alphabet is given, its length '
            R'determines the base. If a numeric base is given, digits from the alphabet '
            F'"{_DEFAULT_ALPH_STR}" are used. '))] = 16,
        strict_digits: Param[bool, Arg.Switch('-d',
            help='Check that all input digits are part of the alphabet.')] = False,
    ):
        super().__init__(
            base=base,
            strict_digits=strict_digits,
        )

    @property
    def _args(self):
        base = self.args.base
        if isinstance(base, int):
            if base in _LARGER_ALPHABETS:
                return base, _LARGER_ALPHABETS[base]
            if base not in range(2, len(_DEFAULT_ALPHABET) + 1):
                raise ValueError(
                    F'base may only be an integer between 2 and {len(_DEFAULT_ALPHABET)}')
            return base, _DEFAULT_ALPHABET[:base]
        if len(set(base)) != len(base):
            raise ValueError('the given alphabet contains duplicate letters')
        return len(base), bytearray(base)

    def reverse(self, data):
        base, alphabet = self._args
        if base == 32:
            _b32_alphabet = b'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
            encoded = b64mod.b32encode(data).rstrip(b'=')
            if alphabet != _b32_alphabet:
                encoded = encoded.translate(bytes.maketrans(_b32_alphabet, alphabet))
            return bytearray(encoded)
        if base == 64:
            _b64_alphabet = _LARGER_ALPHABETS[64]
            encoded = b64mod.b64encode(data).rstrip(b'=')
            if alphabet != _b64_alphabet:
                encoded = encoded.translate(bytes.maketrans(_b64_alphabet, alphabet))
            return bytearray(encoded)
        if base == 85:
            _b85_alphabet = _LARGER_ALPHABETS[85]
            encoded = b64mod.b85encode(data)
            if alphabet != _b85_alphabet:
                encoded = encoded.translate(bytes.maketrans(_b85_alphabet, alphabet))
            return bytearray(encoded)
        m, n = _block_params(base)
        result = bytearray()
        for offset in range(0, len(data), m):
            block = data[offset:offset + m]
            k = len(block)
            if k < m:
                block = block + b'\x00' * (m - k)
                n_k = (k * n + m - 1) // m
            else:
                n_k = n
            number = int.from_bytes(block, byteorder='big')
            digits = bytearray(n)
            for i in range(n - 1, -1, -1):
                number, r = divmod(number, base)
                digits[i] = alphabet[r]
            result.extend(digits[:n_k])
        return result

    def process(self, data: bytearray):
        if not data:
            return data
        base, alphabet = self._args
        self.log_debug(F'decoding data using base {base}; alphabet {alphabet!r}')
        if not self.args.strict_digits and alphabet.upper() == alphabet:
            lcased = (c + 0x20 if 0x41 <= c <= 0x5a else c for c in data)
            if all(x == y for x, y in zip(data, lcased)):
                data = data.upper()
        if base == 32:
            _b32_alphabet = b'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
            if alphabet != _b32_alphabet:
                data = data.translate(bytes.maketrans(alphabet, _b32_alphabet))
            padding = (-len(data)) % 8
            return bytearray(b64mod.b32decode(bytes(data) + b'=' * padding))
        if base == 64:
            _b64_alphabet = _LARGER_ALPHABETS[64]
            if alphabet != _b64_alphabet:
                data = data.translate(bytes.maketrans(alphabet, _b64_alphabet))
            return bytearray(b64mod.b64decode(
                data + b'===', validate=self.args.strict_digits))
        if base == 85:
            _b85_alphabet = _LARGER_ALPHABETS[85]
            if alphabet != _b85_alphabet:
                data = data.translate(bytes.maketrans(alphabet, _b85_alphabet))
            return bytearray(b64mod.b85decode(data))
        m, n = _block_params(base)
        highest = alphabet[-1:]
        result = bytearray()
        lookup = {digit: k for k, digit in enumerate(alphabet)}
        for offset in range(0, len(data), n):
            block = data[offset:offset + n]
            j = len(block)
            if j < n:
                block = block + highest * (n - j)
                k = j * m // n
            else:
                k = m
            number = 0
            for digit in block:
                number = number * base + lookup[digit]
            result.extend(number.to_bytes(m, byteorder='big')[:k])
        return result
