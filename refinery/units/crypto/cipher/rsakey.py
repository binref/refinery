#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import base64
import enum
import itertools
import json
import textwrap

from refinery.units import arg, Unit
from refinery.lib.json import flattened
from refinery.units.crypto.cipher.rsa import normalize_rsa_key

from Crypto.Util.asn1 import DerSequence
from Crypto.Util import number


class RSAFormat(str, enum.Enum):
    PEM = 'PEM'
    DER = 'DER'
    XKMS = 'XKMS'
    TEXT = 'TEXT'
    JSON = 'JSON'


class rsakey(Unit):
    """
    Parse RSA keys in various formats; PEM, DER, Microsoft BLOB, and W3C-XKMS (XML) format are supported.
    """
    def __init__(
        self,
        public: arg.switch('-p', help='Force public key output even if the input is private.') = False,
        output: arg(help='Select an output format (PEM/DER/XKMS/TEXT/JSON), default is PEM.') = RSAFormat.PEM
    ):
        super().__init__(public=public, output=arg.as_option(output, RSAFormat))

    def _xkms_wrap(self, number: int):
        size, r = divmod(number.bit_length(), 8)
        size += int(bool(r))
        return base64.b64encode(number.to_bytes(size, 'big'))

    def process(self, data):
        key = normalize_rsa_key(data, force_public=self.args.public)
        out = self.args.output
        if out is RSAFormat.PEM:
            yield key.export_key('PEM')
            return
        if out is RSAFormat.DER:
            yield key.export_key('DER')
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
            yield json.dumps(components, indent=4).encode(self.codec)
            return
        if out is RSAFormat.TEXT:
            table = list(flattened(components))
            for key, value in table:
                value = F'0x{value}' if isinstance(value, str) else str(value)
                value = '\n'.join(F'{L}' for L in textwrap.wrap(value, 80))
                yield F'-- {key+" ":-<77}\n{value!s}'.encode(self.codec)
