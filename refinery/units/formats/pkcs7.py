#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import asn1crypto
import asn1crypto.cms
import asn1crypto.core

from ...lib.json import BytesAsArrayEncoder

from contextlib import suppress
from datetime import datetime

from .. import Unit


class PKCS7Encoder(BytesAsArrayEncoder):

    @classmethod
    def _is_bigint(cls, obj):
        return isinstance(obj, int) and obj.bit_length() > 32

    @classmethod
    def _is_keyval(cls, obj):
        return (
            isinstance(obj, dict)
            and set(obj.keys()) == {'type', 'values'}
            and len(obj['values']) == 1
        )

    @classmethod
    def handled(cls, obj) -> bool:
        return (
            BytesAsArrayEncoder.handled(obj)
            or cls._is_bigint(obj)
            or cls._is_keyval(obj)
        )

    def default(self, obj):
        if self._is_bigint(obj):
            bl, up = divmod(obj.bit_length(), 8)
            bl += int(bool(up))
            return F'0x{obj:0{bl*2}x}'
        if self._is_keyval(obj):
            return dict(type=obj['type'], value=obj['values'][0])
        with suppress(TypeError):
            return super().default(obj)
        if isinstance(obj, (set, tuple)):
            return list(obj)
        if isinstance(obj, datetime):
            return str(obj)
        with suppress(AttributeError, ValueError):
            return obj.native
        with suppress(Exception):
            keys = list(obj)
            if all(isinstance(k, str) for k in keys):
                return {key: obj[key] for key in keys}
        with suppress(Exception):
            return list(obj)
        if isinstance(obj, asn1crypto.core.Any):
            return obj.dump()
        raise ValueError('Unable to parse data ask PKCS7')


class pkcs7(Unit):
    """
    Converts PKCS7 encoded data to a JSON representation.
    """
    def process(self, data: bytes):
        signature = asn1crypto.cms.ContentInfo.load(data)
        with PKCS7Encoder as encoder:
            return encoder.dumps(signature).encode(self.codec)
