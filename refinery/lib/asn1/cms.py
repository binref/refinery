from __future__ import annotations

import hashlib
import re

from collections import OrderedDict
from datetime import datetime, timedelta, timezone

from refinery.lib.asn1 import ASN1Reader
from refinery.lib.asn1.defs import Certificate, ContentInfo, SignedContentInfo, SpcSpOpusInfo
from refinery.lib.asn1.schema import Choice, SchemaType, Seq, SeqOf, Set, SetOf

_TIME_VALUED_ATTRIBUTES = {'signingTime'}


def _parse_asn1_time(value):
    """
    Normalize an ASN.1 UTCTime or GeneralizedTime string to an ISO 8601 timestamp. Supports
    optional seconds, fractional seconds, and a Z or +/-HHMM timezone suffix. The input is
    returned unchanged if it does not match either grammar.
    """
    if not isinstance(value, str):
        return value
    m = re.fullmatch(r'(\d{8,14})([.,]\d+)?(Z|[+-]\d{2}(?:\d{2})?)?', value)
    if m is None:
        return value
    digits, frac, zone = m[1], m[2], m[3]
    if frac is None and len(digits) in (10, 12):
        # UTCTime: two-digit year with the conventional 1950..2049 pivot.
        yy = int(digits[:2])
        year = 2000 + yy if yy < 50 else 1900 + yy
        rest = digits[2:]
    else:
        # GeneralizedTime: four-digit year.
        year = int(digits[:4])
        rest = digits[4:]
    if len(rest) < 4 or len(rest) % 2:
        return value
    month, day, *hms = (int(rest[i:i + 2]) for i in range(0, len(rest), 2))
    hms += [0] * (3 - len(hms))
    hour, minute, second = hms[:3]
    micro = int((frac[1:] + '000000')[:6]) if frac else 0
    try:
        if zone is None or zone == 'Z':
            tzinfo = timezone.utc
        else:
            offset = timedelta(hours=int(zone[1:3]), minutes=int(zone[3:5] or 0))
            tzinfo = timezone(offset if zone[0] == '+' else -offset)
        dt = datetime(year, month, day, hour, minute, second, micro, tzinfo=tzinfo)
    except ValueError:
        return value
    return dt.isoformat(sep=' ')


def _flatten_name(name) -> OrderedDict:
    result: OrderedDict[str, str] = OrderedDict()
    if not isinstance(name, list):
        return result
    for rdn in name:
        if isinstance(rdn, list) and len(rdn) == 2 and isinstance(rdn[0], str):
            result[rdn[0]] = rdn[1]
        elif isinstance(rdn, list):
            for atv in rdn:
                if isinstance(atv, list) and len(atv) == 2 and isinstance(atv[0], str):
                    result[atv[0]] = atv[1]
                elif isinstance(atv, dict):
                    oid = atv.get('type', '')
                    val = atv.get('value', '')
                    if isinstance(oid, str) and oid:
                        result[oid] = val
        elif isinstance(rdn, dict):
            oid = rdn.get('type', '')
            val = rdn.get('value', '')
            if isinstance(oid, str) and oid:
                result[oid] = val
    return result


def _interpret_spc_opus(value) -> OrderedDict:
    result: OrderedDict = OrderedDict()
    items = value if isinstance(value, list) else [value]
    for item in items:
        if not isinstance(item, dict):
            continue
        tag = item.get('tag', '')
        val = item.get('value')
        if tag == 'context-0':
            result['programName'] = _extract_spc_string(val)
        elif tag == 'context-1':
            result['moreInfo'] = _extract_spc_link(val)
    return result


def _decode_text(value, primary: str) -> str:
    raw = bytes(value)
    try:
        return raw.decode(primary)
    except Exception:
        return raw.decode('latin-1')


def _extract_spc_string(value):
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray, memoryview)):
        return _decode_text(value, 'utf-16-be')
    if isinstance(value, dict):
        inner = value.get('value', value)
        if inner is value:
            return value
        return _extract_spc_string(inner)
    if isinstance(value, list):
        for item in value:
            result = _extract_spc_string(item)
            if isinstance(result, str):
                return result
    return value


def _extract_spc_link(value):
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray, memoryview)):
        return _decode_text(value, 'ascii')
    if isinstance(value, dict):
        tag = value.get('tag', '')
        inner = value.get('value', value)
        if tag == 'context-0':
            if isinstance(inner, (bytes, bytearray, memoryview)):
                return _decode_text(inner, 'ascii')
            return inner
        if tag == 'context-2':
            return _extract_spc_string(inner)
        if isinstance(inner, (bytes, bytearray, memoryview)):
            return _decode_text(inner, 'ascii')
        return _extract_spc_string(inner) if not isinstance(inner, dict) else inner
    return value


def _interpret_counter_signature(value) -> OrderedDict:
    result: OrderedDict = OrderedDict()
    if not isinstance(value, list) or len(value) < 5:
        return result
    sid_raw = value[1]
    if isinstance(sid_raw, list) and len(sid_raw) == 2:
        sid = OrderedDict()
        sid['issuer'] = _flatten_name(sid_raw[0])
        sid['serialNumber'] = sid_raw[1]
        result['sid'] = sid
    for item in value:
        if isinstance(item, dict) and item.get('tag') == 'context-0':
            attrs_raw = item.get('value', [])
            if isinstance(attrs_raw, list):
                result['signedAttrs'] = [
                    _postprocess_attribute(_interpret_generic_attribute(a)) for a in attrs_raw]
            break
    return result


def _interpret_generic_attribute(value) -> OrderedDict:
    result: OrderedDict = OrderedDict()
    if isinstance(value, list) and len(value) >= 2:
        result['type'] = value[0]
        vals = value[1] if isinstance(value[1], list) else [value[1]]
        if len(vals) == 1:
            result['value'] = vals[0]
        else:
            result['values'] = vals
    elif isinstance(value, dict):
        result['type'] = value.get('attrType', value.get('type', ''))
        result['value'] = value.get('attrValues', value.get('value', ''))
    return result


def _decode_attribute_value(oid: str, values: list) -> list:
    if oid == 'spcSpOpusInfo':
        decoded = []
        for v in values:
            if isinstance(v, (bytes, bytearray, memoryview)):
                try:
                    reader = ASN1Reader(memoryview(v), bigendian=True)
                    decoded.append(reader.decode_with_schema(SpcSpOpusInfo))
                except Exception:
                    decoded.append(v)
            else:
                decoded.append(_interpret_spc_opus(v))
        return decoded
    if oid == 'microsoftNestedSignature':
        decoded = []
        for v in values:
            if isinstance(v, (bytes, bytearray, memoryview)):
                try:
                    parsed = parse_content_info(v)
                    decoded.append(parsed)
                except Exception:
                    decoded.append(v)
            else:
                decoded.append(v)
        return decoded
    if oid == 'counterSignature':
        return [_interpret_counter_signature(v) for v in values]
    return values


def _unsign(data):
    if isinstance(data, bool):
        return data
    if isinstance(data, int):
        if data < 0:
            nbytes = ((~data).bit_length() + 8) // 8
            data += 1 << (8 * nbytes)
        if data > 0xFFFFFFFF_FFFFFFFF:
            nbytes = (data.bit_length() + 7) // 8
            data = data.to_bytes(nbytes, 'big').hex().upper()
        return data
    elif isinstance(data, dict):
        for key in list(data):
            data[key] = _unsign(data[key])
    elif isinstance(data, list):
        return [_unsign(x) for x in data]
    return data


_TRANSFORMS = {
    'name': _flatten_name,
    'time': _parse_asn1_time,
    'attributes': lambda value: (
        [_postprocess_attribute(attr) for attr in value] if isinstance(value, list) else value),
}


def _choice_alt(choice: Choice, obj: dict) -> SchemaType | None:
    keys = set(obj)
    for alt in choice.alternatives:
        if isinstance(alt.type, (Seq, Set)) and keys <= {f.name for f in alt.type.fields}:
            return alt.type
    return None


def _postprocess(obj, schema: SchemaType | None = None):
    if isinstance(obj, OrderedDict):
        if isinstance(schema, Choice):
            schema = _choice_alt(schema, obj)
        fields = {f.name: f for f in schema.fields} if isinstance(schema, (Seq, Set)) else {}
        for key in list(obj.keys()):
            field = fields.get(key)
            if field is not None and field.transform is not None:
                obj[key] = _TRANSFORMS[field.transform](obj[key])
            else:
                obj[key] = _postprocess(obj[key], field.type if field is not None else None)
        return obj
    if isinstance(obj, list):
        element = schema.element if isinstance(schema, (SeqOf, SetOf)) else None
        return [_postprocess(item, element) for item in obj]
    if isinstance(obj, bytes):
        return obj.hex().upper()
    return obj


def _postprocess_attribute(attr) -> OrderedDict:
    if not isinstance(attr, dict):
        return attr
    if 'type' in attr and 'attrType' not in attr:
        result = OrderedDict()
        oid = attr['type']
        result['type'] = oid
        if 'value' in attr:
            v = _postprocess(attr['value'])
            if oid in _TIME_VALUED_ATTRIBUTES:
                v = _parse_asn1_time(v)
            result['value'] = v
        elif 'values' in attr:
            vals = [_postprocess(v) for v in attr['values']]
            if oid in _TIME_VALUED_ATTRIBUTES:
                vals = [_parse_asn1_time(v) for v in vals]
            result['values'] = vals
        return result
    result = OrderedDict()
    oid = attr.get('attrType', '')
    values = attr.get('attrValues', [])
    result['type'] = oid
    decoded = _decode_attribute_value(oid, values)
    if len(decoded) == 1:
        v = _postprocess(decoded[0])
        if oid in _TIME_VALUED_ATTRIBUTES:
            v = _parse_asn1_time(v)
        result['value'] = v
    else:
        vals = [_postprocess(v) for v in decoded]
        if oid in _TIME_VALUED_ATTRIBUTES:
            vals = [_parse_asn1_time(v) for v in vals]
        result['values'] = vals
    return result


def parse_content_info(data: bytes | bytearray | memoryview) -> OrderedDict:
    """
    Parse a DER-encoded PKCS#7/CMS ContentInfo structure and return a fully post-processed
    OrderedDict ready for JSON serialization. Names are flattened, times are formatted,
    attribute values are decoded, negative ASN.1 integers are converted to unsigned
    representation, and each certificate is annotated with its SHA-1 fingerprint.
    """
    mv = memoryview(data)
    best_result = None
    best_schema: SchemaType | None = None
    best_spans: dict[int, tuple[int, int]] = {}
    best_remaining = len(mv) + 1
    for schema in (SignedContentInfo, ContentInfo):
        try:
            reader = ASN1Reader(mv, bigendian=True, span_schema=Certificate)
            result = reader.decode_with_schema(schema)
            remaining = reader.remaining_bytes
            if remaining < best_remaining:
                best_result = result
                best_schema = schema
                best_spans = reader.spans
                best_remaining = remaining
            if remaining == 0:
                break
        except Exception:
            continue
    if best_result is not None:
        result = _unsign(_postprocess(best_result, best_schema))
        _attach_certificate_fingerprints(result, mv, best_spans)
    else:
        try:
            result = ASN1Reader(mv, bigendian=True).read_tlv()
        except Exception:
            result = None
    if not isinstance(result, OrderedDict):
        raise RuntimeError('The ContentInfo data did not parse as a dictionary.')
    return result


def _attach_certificate_fingerprints(
    result,
    raw: memoryview,
    spans: dict[int, tuple[int, int]],
) -> None:
    """
    Annotate each parsed certificate with the SHA-1 hash of its exact DER encoding, using the byte
    spans recorded by the reader during the single decode pass.
    """
    if not isinstance(result, dict):
        return
    content = result.get('content')
    if not isinstance(content, dict):
        return
    certs = content.get('certificates')
    if not isinstance(certs, list):
        return
    for cert in certs:
        if not isinstance(cert, dict):
            continue
        span = spans.get(id(cert))
        if span is None:
            continue
        start, end = span
        cert['fingerprint'] = hashlib.sha1(bytes(raw[start:end])).hexdigest()
