from __future__ import annotations

from refinery.lib import json
from refinery.lib.asn1.cms import compute_certificate_fingerprints, parse_content_info
from refinery.units import Unit


class pkcs7(Unit):
    """
    Converts PKCS7 encoded data to a JSON representation.
    """
    def process(self, data):
        result = parse_content_info(data)
        compute_certificate_fingerprints(result, data)
        return json.dumps(result, pretty=False, tojson=self._default)

    @staticmethod
    def _default(obj):
        if isinstance(obj, (bytes, bytearray, memoryview)):
            return bytes(obj).hex().upper()
        return json.standard_conversions(obj)
