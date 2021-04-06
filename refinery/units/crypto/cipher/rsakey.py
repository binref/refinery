#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import base64
import enum
import itertools
import json
import textwrap

from ... import arg, Unit
from ....lib.json import flattened
from .rsa import normalize_rsa_key

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
    def __init__(self, output: arg.option(
        choices=RSAFormat,
        help='Select an output format ({choices}), default is {default}.') = RSAFormat.PEM
    ):
        super().__init__(output=arg.as_option(output, RSAFormat))

    def _xkms_wrap(self, number: int):
        size, r = divmod(number.bit_length(), 8)
        size += int(bool(r))
        return base64.b64encode(number.to_bytes(size, 'big'))

    def process(self, data):
        key = normalize_rsa_key(data)
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
        for tag in components:
            components[tag] = F'{components[tag]:X}'
        if out is RSAFormat.JSON:
            yield json.dumps(components).encode(self.codec)
            return
        if out is RSAFormat.TEXT:
            table = list(flattened(components))
            for key, value in table:
                value = '\n'.join(F'{L}' for L in textwrap.wrap(F'0x{value}', 80))
                yield F'-- {key+" ":-<77}\n{value!s}'.encode(self.codec)
