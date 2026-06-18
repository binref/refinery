from __future__ import annotations

import hashlib
import re

from collections import OrderedDict
from datetime import datetime, timezone

from refinery.lib.asn1 import ASN1Reader
from refinery.lib.asn1.defs import ContentInfo, SignedContentInfo, SpcSpOpusInfo

_TIME_VALUED_ATTRIBUTES = {'signingTime'}


def _parse_asn1_time(value):
    if not isinstance(value, str):
        return value
    if m := re.fullmatch(r'(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z', value):
        yy = int(m[1])
        year = 2000 + yy if yy < 50 else 1900 + yy
        try:
            dt = datetime(year, int(m[2]), int(m[3]), int(m[4]), int(m[5]), int(m[6]), tzinfo=timezone.utc)
            return dt.isoformat(sep=' ')
        except ValueError:
            return value
    if m := re.fullmatch(r'(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z', value):
        try:
            dt = datetime(int(m[1]), int(m[2]), int(m[3]), int(m[4]), int(m[5]), int(m[6]), tzinfo=timezone.utc)
            return dt.isoformat(sep=' ')
        except ValueError:
            return value
    return value


def _flatten_name(name: list) -> OrderedDict:
    result: OrderedDict[str, str] = OrderedDict()
    if not isinstance(name, list):
        return result
    for rdn in name:
        items = rdn if isinstance(rdn, list) else [rdn]
        for atv in items:
            if not isinstance(atv, dict):
                continue
            oid = atv.get('type', '')
            val = atv.get('value', '')
            if isinstance(oid, str) and oid:
                result[oid] = val
    return result


def _flatten_generic_name(name) -> OrderedDict:
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


def _extract_spc_string(value):
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray, memoryview)):
        try:
            return bytes(value).decode('utf-16-be')
        except Exception:
            return bytes(value).decode('latin-1')
    if isinstance(value, dict):
        inner = value.get('value', value)
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
        try:
            return bytes(value).decode('ascii')
        except Exception:
            return bytes(value).decode('latin-1')
    if isinstance(value, dict):
        tag = value.get('tag', '')
        inner = value.get('value', value)
        if tag == 'context-0':
            if isinstance(inner, (bytes, bytearray, memoryview)):
                try:
                    return bytes(inner).decode('ascii')
                except Exception:
                    return bytes(inner).decode('latin-1')
            return inner
        if tag == 'context-2':
            return _extract_spc_string(inner)
        if isinstance(inner, (bytes, bytearray, memoryview)):
            try:
                return bytes(inner).decode('ascii')
            except Exception:
                return bytes(inner).decode('latin-1')
        return _extract_spc_string(inner) if not isinstance(inner, dict) else inner
    return value


def _interpret_counter_signature(value) -> OrderedDict:
    result: OrderedDict = OrderedDict()
    if not isinstance(value, list) or len(value) < 5:
        return result
    sid_raw = value[1]
    if isinstance(sid_raw, list) and len(sid_raw) == 2:
        sid = OrderedDict()
        sid['issuer'] = _flatten_generic_name(sid_raw[0])
        sid['serialNumber'] = sid_raw[1]
        result['sid'] = sid
    for item in value:
        if isinstance(item, dict) and item.get('tag') == 'context-0':
            attrs_raw = item.get('value', [])
            if isinstance(attrs_raw, list):
                result['signedAttrs'] = [
                    _interpret_generic_attribute(a) for a in attrs_raw]
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


def _postprocess(obj, raw: bytes | memoryview | None = None):
    if isinstance(obj, OrderedDict):
        for key in list(obj.keys()):
            value = obj[key]
            if key in ('issuer', 'subject'):
                if isinstance(value, list):
                    obj[key] = _flatten_name(value)
                elif isinstance(value, dict):
                    obj[key] = _postprocess(value)
            elif key == 'validity' and isinstance(value, dict):
                obj[key] = OrderedDict(
                    (k, _parse_asn1_time(_postprocess(v)))
                    for k, v in value.items()
                )
            elif key in ('signedAttrs', 'unsignedAttrs') and isinstance(value, list):
                obj[key] = [_postprocess_attribute(attr) for attr in value]
            elif key == 'certificates' and isinstance(value, list):
                obj[key] = [_postprocess(cert) for cert in value]
            elif key == 'signerInfos' and isinstance(value, list):
                obj[key] = [_postprocess(si) for si in value]
            elif key == 'content' and isinstance(value, dict):
                obj[key] = _postprocess(value, raw)
            elif key == 'tbsCertificate' and isinstance(value, dict):
                obj[key] = _postprocess(value)
            elif key == 'sid' and isinstance(value, dict):
                obj[key] = _postprocess(value)
            else:
                obj[key] = _postprocess(value)
        return obj
    if isinstance(obj, list):
        return [_postprocess(item) for item in obj]
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
    best_spans: dict[int, tuple[int, int]] = {}
    best_remaining = len(mv) + 1
    for schema in (SignedContentInfo, ContentInfo):
        try:
            reader = ASN1Reader(mv, bigendian=True, record_spans=True)
            result = reader.decode_with_schema(schema)
            remaining = reader.remaining_bytes
            if remaining < best_remaining:
                best_result = result
                best_spans = reader.spans
                best_remaining = remaining
            if remaining == 0:
                break
        except Exception:
            continue
    if best_result is not None:
        result = _unsign(_postprocess(best_result, mv))
        _attach_certificate_fingerprints(result, mv, best_spans)
    else:
        reader = ASN1Reader(mv, bigendian=True)
        result = reader.read_tlv()
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
