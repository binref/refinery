from __future__ import annotations

import math
import re

from refinery.lib.types import Param, isq
from refinery.units import Arg, Unit

_DEFAULT_ALPH_STR = R'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
_DEFAULT_ALPHABET = B'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
_LARGER_ALPHABETS = {
    58: b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',
    62: b'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
    64: b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
    85: b'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~'
}


class base(Unit):
    """
    Encodes and decodes integers in arbitrary base.
    """
    def __init__(
        self,
        base: Param[isq, Arg.NumSeq(metavar='base|alphabet', help=(
            R'Either the base to be used or an alphabet. If an explicit alphabet is given, its length '
            R'determines the base. The default base 0 treats the input as a Python integer literal. If '
            F'a numeric base is given, digits from the alphabet "{_DEFAULT_ALPH_STR}" are used. '))] = 0,
        strip_padding: Param[bool, Arg.Switch('-s', help='Do not add leading zeros to the output.')] = False,
        little_endian: Param[bool, Arg.Switch('-e', help='Use little endian byte order instead of big endian.')] = False,
        strict_digits: Param[bool, Arg.Switch('-d', help='Check that all input digits are part of the alphabet.')] = False,
    ):
        super().__init__(
            base=base,
            strip_padding=strip_padding,
            little_endian=little_endian,
            strict_digits=strict_digits,
        )

    @property
    def _args(self):
        base = self.args.base
        if isinstance(base, int):
            if not base:
                return 0, B''
            if base in _LARGER_ALPHABETS:
                return base, _LARGER_ALPHABETS[base]
            if base not in range(2, len(_DEFAULT_ALPHABET) + 1):
                raise ValueError(F'base may only be an integer between 2 and {len(_DEFAULT_ALPHABET)}')
            return base, _DEFAULT_ALPHABET[:base]
        if len(set(base)) != len(base):
            raise ValueError('the given alphabet contains duplicate letters')
        return len(base), bytearray(base)

    @property
    def byteorder(self):
        return 'little' if self.args.little_endian else 'big'

    def reverse(self, data):
        base, alphabet = self._args
        self.log_info('using byte order', self.byteorder)
        number = int.from_bytes(data, byteorder=self.byteorder)

        if base == 0:
            return B'0x%X' % number
        if base > len(alphabet):
            raise ValueError(F'Only {len(alphabet)} available; not enough to encode base {base}')

        log2n = len(data) * 8
        logBn = int(log2n / math.log2(base))
        if base ** logBn <= number:
            logBn += 1
        result = bytearray()
        no_pad = self.args.strip_padding

        for _ in range(logBn):
            number, k = divmod(number, base)
            result.append(alphabet[k])
            if no_pad and number <= 0:
                break

        result.reverse()
        return result

    def process(self, data: bytearray):
        if not data:
            return data
        base, alphabet = self._args
        self.log_debug(F'decoding data using base {base}; alphabet {alphabet!r}')
        be_lenient = not self.args.strict_digits
        if be_lenient and alphabet.upper() == alphabet:
            lcased = (c + 0x20 if 0x41 <= c <= 0x5a else c for c in data)
            if all(x == y for x, y in zip(data, lcased)):
                data = data.upper()
        if base and base != 64 and be_lenient:
            check = '[^{}]'.format(
                ''.join(F'\\x{c:02x}' for c in sorted(set(alphabet)))).encode('ascii')
            if re.search(check, data) is not None:
                stripped = re.sub(check, B'', data)
                self.log_info(F'stripped {len(data) - len(stripped)} invalid digits from input data')
                data[:] = stripped
        if len(alphabet) <= len(_DEFAULT_ALPHABET):
            defaults = _DEFAULT_ALPHABET[:base]
            if alphabet != defaults:
                self.log_info('translating input data to a default alphabet for faster conversion')
                data_translated = data.translate(bytes.maketrans(alphabet, defaults))
                result = int(data_translated, base)
            else:
                result = int(data, base)
        elif len(alphabet) == 64 and len(data) >= 4:
            import base64
            _b64_alphabet = _LARGER_ALPHABETS[64]
            if alphabet != _b64_alphabet:
                data = data.translate(bytes.maketrans(alphabet, _b64_alphabet))
            return base64.b64decode(data + b'===', validate=self.args.strict_digits)
        elif len(alphabet) == 85 and len(data) >= 5:
            import base64
            _b85_alphabet = _LARGER_ALPHABETS[85]
            if alphabet != _b85_alphabet:
                data = data.translate(bytes.maketrans(alphabet, _b85_alphabet))
            return base64.b85decode(data)
        else:
            if len(data) > 100_000:
                self.log_warn('long alphabet & unable to use built-ins; reverting to (slow) fallback.')
            result = 0
            lookup = {digit: k for k, digit in enumerate(alphabet)}
            for digit in data:
                result *= base
                result += lookup[digit]
        if not base or self.args.strip_padding:
            size, r = divmod(result.bit_length(), 8)
            size += int(bool(r))
        else:
            log2n = int(len(data) * math.log2(base))
            test = 1 << log2n
            while test > result:
                log2n -= 1
                test >>= 1
            size = log2n // 8 + 1
        return result.to_bytes(size, byteorder=self.byteorder)
