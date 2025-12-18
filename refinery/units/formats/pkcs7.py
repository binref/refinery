from __future__ import annotations

from contextlib import suppress

from refinery.lib import json
from refinery.lib.tools import asbuffer, convert
from refinery.units import Unit


class pkcs7(Unit):
    """
    Converts PKCS7 encoded data to a JSON representation.
    """
    @Unit.Requires('asn1crypto', ['default', 'extended'])
    def _asn1crypto():
        import asn1crypto
        import asn1crypto.cms
        import asn1crypto.core
        import asn1crypto.x509
        return asn1crypto

    def process(self, data):
        asn1 = self._asn1crypto.core
        cms = self._asn1crypto.cms
        x509 = self._asn1crypto.x509
        signature = cms.ContentInfo.load(convert(data, bytes))

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
                for key in list(data):
                    data[key] = unsign(data[key])
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

        def tojson(obj):
            if isinstance(obj, dict) and len(obj) == 2 and 'type' in obj and (values := obj.get('values')) and len(values) == 1:
                del obj['values']
                obj['value'] = values[0]
                return obj

            dict_result = {}
            list_result = None

            if isinstance(obj, x509.Certificate):
                dict_result.update(fingerprint=obj.sha1.hex())
            if isinstance(obj, asn1.BitString):
                return {'bit_string': obj.native}
            with suppress(Exception):
                list_result = list(obj)
                if all(isinstance(k, str) for k in list_result):
                    dict_result.update((key, obj[key]) for key in list_result)
                if all(k in range(0x100) for k in list_result):
                    return bytes(list_result).hex().upper()
            if dict_result:
                return json.preprocess(dict_result)
            if list_result is not None:
                return json.preprocess(list_result)

            if isinstance(obj, cms.CertificateChoices):
                out = obj.chosen
            elif isinstance(obj, asn1.Sequence):
                if children := obj.children:
                    return children
                out = obj.dump()
            else:
                try:
                    out = getattr(obj, 'native')
                except Exception:
                    if isinstance(obj, asn1.Any):
                        parsed = None
                        with suppress(Exception):
                            parsed = obj.parse()
                        out = parsed or obj.dump()
                    elif isinstance(obj, asn1.Asn1Value):
                        out = obj.dump()
                    elif (b := asbuffer(obj)):
                        return b.hex().upper()
                    else:
                        return json.standard_conversions(obj)
                else:
                    out = json.preprocess(out)

            return out

        return json.dumps(unsign(signature), tojson=tojson, pretty=False)
