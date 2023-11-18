#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json

from contextlib import suppress
from datetime import datetime

from refinery.units import Unit
from refinery.lib.json import BytesAsArrayEncoder


class pkcs7(Unit):
    """
    Converts PKCS7 encoded data to a JSON representation.
    """
    @Unit.Requires('asn1crypto', 'default', 'extended')
    def _asn1crypto():
        import asn1crypto
        import asn1crypto.cms
        import asn1crypto.core
        import asn1crypto.x509
        return asn1crypto

    def process(self, data: bytes):
        asn1 = self._asn1crypto.core
        cms = self._asn1crypto.cms
        signature = cms.ContentInfo.load(data)

        def unsign(data):
            if isinstance(data, int):
                size = data.bit_length()
                if data < 0:
                    data = (1 << (size + 1)) - ~data - 1
                if data > 0xFFFFFFFF_FFFFFFFF:
                    size, r = divmod(size, 8)
                    size += bool(r)
                    data = data.to_bytes(size, 'big').hex()
                return data
            elif isinstance(data, dict):
                return {key: unsign(value) for key, value in data.items()}
            elif isinstance(data, list):
                return [unsign(x) for x in data]
            else:
                return data

        class SpcString(asn1.Choice):
            _alternatives = [
                ('unicode', asn1.BMPString, {'implicit': 0}),
                ('ascii', asn1.IA5String, {'implicit': 1})
            ]

        SpcUuid = asn1.OctetString

        class SpcSerializedObject(asn1.Sequence):
            _fields = [
                ('classId', SpcUuid),
                ('serializedData', asn1.OctetString),
            ]

        class SpcLink(asn1.Choice):
            _alternatives = [
                ('url', asn1.IA5String, {'implicit': 0}),
                ('monikier', SpcSerializedObject, {'implicit': 1}),
                ('file', SpcString, {'explicit': 2})
            ]

        class SpcSpOpusInfo(asn1.Sequence):
            _fields = [
                ('programName', SpcString, {'optional': True, 'explicit': 0}),
                ('moreInfo', SpcLink, {'optional': True, 'explicit': 1}),
            ]

        class SetOfInfos(asn1.SetOf):
            _child_spec = SpcSpOpusInfo

        cms.CMSAttributeType._map['1.3.6.1.4.1.311.2.1.12'] = 'authenticode_info'
        cms.CMSAttribute._oid_specs['authenticode_info'] = SetOfInfos

        class ParsedASN1ToJSON(BytesAsArrayEncoder):
            unit = self

            @classmethod
            def _is_keyval(cls, obj):
                return (
                    isinstance(obj, dict)
                    and set(obj.keys()) == {'type', 'values'}
                    and len(obj['values']) == 1
                )

            @classmethod
            def handled(cls, obj) -> bool:
                return BytesAsArrayEncoder.handled(obj) or cls._is_keyval(obj)

            def encode_bytes(self, obj: bytes):
                with suppress(Exception):
                    string = obj.decode('latin1')
                    if string.isprintable():
                        return string
                return super().encode_bytes(obj)

            def default(self, obj):
                if self._is_keyval(obj):
                    return dict(type=obj['type'], value=obj['values'][0])
                with suppress(TypeError):
                    return super().default(obj)
                if isinstance(obj, (set, tuple)):
                    return list(obj)
                if isinstance(obj, datetime):
                    return str(obj)
                dict_result = {}
                list_result = None
                if isinstance(obj, self.unit._asn1crypto.x509.Certificate):
                    dict_result.update(fingerprint=obj.sha1.hex())
                if isinstance(obj, asn1.BitString):
                    return {'bit_string': obj.native}
                with suppress(Exception):
                    list_result = list(obj)
                    if all(isinstance(k, str) for k in list_result):
                        dict_result.update((key, obj[key]) for key in list_result)
                if dict_result:
                    return dict_result
                if list_result is not None:
                    return list_result
                if isinstance(obj, self.unit._asn1crypto.cms.CertificateChoices):
                    return obj.chosen
                if isinstance(obj, asn1.Sequence):
                    children = obj.children
                    if children:
                        return children
                    return obj.dump()
                with suppress(Exception):
                    return obj.native
                if isinstance(obj, asn1.Any):
                    parsed = None
                    with suppress(Exception):
                        parsed = obj.parse()
                    if parsed:
                        return parsed
                    return obj.dump()
                if isinstance(obj, asn1.Asn1Value):
                    return obj.dump()
                raise ValueError(F'Unable to determine JSON encoding of {obj.__class__.__name__} object.')

        with ParsedASN1ToJSON as encoder:
            encoded = encoder.dumps(signature)
            converted = unsign(json.loads(encoded))
            return json.dumps(converted, indent=4).encode(self.codec)
