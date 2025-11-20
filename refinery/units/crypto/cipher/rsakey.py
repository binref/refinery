from __future__ import annotations

import base64
import enum
import itertools
import textwrap

from Cryptodome.Util import number
from Cryptodome.Util.asn1 import DerSequence

from refinery.lib import json
from refinery.lib.types import Param
from refinery.units import Arg, Unit
from refinery.units.crypto.cipher.rsa import normalize_rsa_key


class RSAFormat(str, enum.Enum):
    PEM = 'PEM'
    DER = 'DER'
    XKMS = 'XKMS'
    TEXT = 'TEXT'
    JSON = 'JSON'
    BLOB = 'BLOB'


class rsakey(Unit):
    """
    Parse RSA keys in various formats; PEM, DER, Microsoft BLOB, and W3C-XKMS (XML) format are supported.
    The same formats are supported for the input format, but you can also specify a key in the following
    format, where both modulus and exponent have to be hex-encoded: `[modulus]:[exponent]`
    """
    def __init__(
        self,
        output: Param[str, Arg.Option(choices=RSAFormat,
            help='Select an output format ({choices}), default is {default}.')] = RSAFormat.PEM,
        public: Param[bool, Arg.Switch('-p',
            help='Force public key output even if the input is private.')] = False,
    ):
        super().__init__(output=Arg.AsOption(output, RSAFormat), public=public)

    def _xkms_wrap(self, number: int):
        size, r = divmod(number.bit_length(), 8)
        size += int(bool(r))
        return base64.b64encode(number.to_bytes(size, 'big'))

    def process(self, data):
        from refinery.lib.mscrypto import ALGORITHMS, TYPES
        fmt, key = normalize_rsa_key(data, force_public=self.args.public)
        self.log_info(F'parsing input as {fmt.value} format')
        out = self.args.output
        if out is RSAFormat.PEM:
            yield key.export_key('PEM')
            return
        if out is RSAFormat.DER:
            yield key.export_key('DER')
            return
        if out is RSAFormat.BLOB:
            def le(v: int, s: int):
                return v.to_bytes(s, 'little')
            buffer = bytearray()
            buffer.append(TYPES.PRIVATEKEYBLOB if key.has_private() else TYPES.PUBLICKEYBLOB)
            buffer.extend(le(2, 3))
            buffer.extend(le(ALGORITHMS.CALG_RSA_KEYX, 4))
            buffer.extend(B'RSA2' if key.has_private() else B'RSA1')
            size = 2
            while size < key.n.bit_length():
                size <<= 1
            self.log_info(F'using bit size {size}')
            buffer.extend(le(size, 4))
            size //= 8
            buffer.extend(le(key.e, 4))
            buffer.extend(le(key.n, size))
            if key.has_private():
                exp_1 = key.d % (key.p - 1)
                exp_2 = key.d % (key.q - 1)
                coeff = pow(key.q, -1, key.p)
                half = size // 2
                buffer.extend(le(key.p, half))
                buffer.extend(le(key.q, half))
                buffer.extend(le(exp_1, half))
                buffer.extend(le(exp_2, half))
                buffer.extend(le(coeff, half))
                buffer.extend(le(key.d, size))
            yield buffer
            return
        components = {
            'Modulus' : key.n,
            'Exponent': key.e,
        }
        if key.has_private():
            decoded = DerSequence()
            decoded.decode(key.export_key('DER'))
            it = itertools.islice(decoded, 3, None)
            for v in ('D', 'P', 'Q', 'DP', 'DQ', 'InverseQ'):
                try:
                    components[v] = next(it)
                except StopIteration:
                    break
        if out is RSAFormat.XKMS:
            for tag in components:
                components[tag] = base64.b64encode(number.long_to_bytes(components[tag])).decode('ascii')
            tags = '\n'.join(F'\t<{tag}>{value}</{tag}>' for tag, value in components.items())
            yield F'<RSAKeyPair>\n{tags}\n</RSAKeyPair>'.encode(self.codec)
            return
        components['BitSize'] = key.n.bit_length()
        for tag, value in components.items():
            if value.bit_length() > 32:
                components[tag] = F'{value:X}'
        if out is RSAFormat.JSON:
            yield json.dumps(components)
            return
        if out is RSAFormat.TEXT:
            table = list(json.flattened(components))
            for key, value in table:
                value = F'0x{value}' if isinstance(value, str) else str(value)
                value = '\n'.join(F'{L}' for L in textwrap.wrap(value, 80))
                yield F'-- {key + " ":-<77}\n{value!s}'.encode(self.codec)
