#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import asn1crypto
import asn1crypto.cms
import asn1crypto.core
import asn1crypto.x509

from ...lib.json import BytesAsArrayEncoder

from contextlib import suppress
from datetime import datetime

from .. import Unit


class ParsedASN1ToJSON(BytesAsArrayEncoder):

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
            or cls._is_keyval(obj)
        )

    def default(self, obj):
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
        if isinstance(obj, asn1crypto.cms.CertificateChoices):
            return asn1crypto.x509.Certificate.load(obj.dump())
        if isinstance(obj, asn1crypto.core.Asn1Value):
            return obj.dump()
        raise ValueError(F'Unable to determine JSON encoding of {obj.__class__.__name__} object.')


class pkcs7(Unit):
    """
    Converts PKCS7 encoded data to a JSON representation.
    """
    def process(self, data: bytes):
        signature = asn1crypto.cms.ContentInfo.load(data)
        with ParsedASN1ToJSON as encoder:
            return encoder.dumps(signature).encode(self.codec)
