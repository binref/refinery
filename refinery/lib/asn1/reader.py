from __future__ import annotations

import codecs

from collections import OrderedDict
from typing import TYPE_CHECKING, Any, Union

from refinery.lib.structures import StructReader

from refinery.lib.asn1.schema import (
    CLASS_UNIVERSAL,
    _MISSING,
    ANY,
    SEQUENCE,
    SET,
    ASN1SchemaMismatch,
    Choice,
    SchemaType,
    Seq,
    SeqOf,
    SetOf,
)

if TYPE_CHECKING:
    ASN1Value = Union[
        None,
        bool,
        int,
        float,
        str,
        bytes,
        list,
        dict[str, Any],
        OrderedDict[str, Any],
        object,
    ]


class ASN1Reader(StructReader[memoryview]):

    _EOC = object()

    _STRING_ENCODINGS = {
        12: 'utf-8',      # UTF8String
        18: 'ascii',      # NumericString
        19: 'ascii',      # PrintableString
        20: 'latin-1',    # T61String / TeletexString
        22: 'ascii',      # IA5String
        23: 'ascii',      # UTCTime
        24: 'ascii',      # GeneralizedTime
        25: 'latin-1',    # GraphicString
        26: 'ascii',      # VisibleString / ISO646String
        27: 'latin-1',    # GeneralString
        28: 'utf-32-be',  # UniversalString
        30: 'utf-16-be',  # BMPString
    }

    _TAG_CLASS_NAMES = ('universal', 'application', 'context', 'private')

    _OID_NAMES = {
        '2.5.4.3'                    : 'commonName',
        '2.5.4.4'                    : 'surname',
        '2.5.4.5'                    : 'serialNumber',
        '2.5.4.6'                    : 'countryName',
        '2.5.4.7'                    : 'localityName',
        '2.5.4.8'                    : 'stateOrProvinceName',
        '2.5.4.9'                    : 'streetAddress',
        '2.5.4.10'                   : 'organizationName',
        '2.5.4.11'                   : 'organizationalUnitName',
        '2.5.4.12'                   : 'title',
        '2.5.4.17'                   : 'postalCode',
        '2.5.4.42'                   : 'givenName',
        '2.5.4.43'                   : 'initials',
        '2.5.4.46'                   : 'dnQualifier',
        '2.5.4.65'                   : 'pseudonym',
        '2.5.29.14'                  : 'subjectKeyIdentifier',
        '2.5.29.15'                  : 'keyUsage',
        '2.5.29.17'                  : 'subjectAltName',
        '2.5.29.18'                  : 'issuerAltName',
        '2.5.29.19'                  : 'basicConstraints',
        '2.5.29.20'                  : 'cRLNumber',
        '2.5.29.21'                  : 'cRLReason',
        '2.5.29.31'                  : 'cRLDistributionPoints',
        '2.5.29.32'                  : 'certificatePolicies',
        '2.5.29.33'                  : 'policyMappings',
        '2.5.29.35'                  : 'authorityKeyIdentifier',
        '2.5.29.36'                  : 'policyConstraints',
        '2.5.29.37'                  : 'extKeyUsage',
        '2.5.29.46'                  : 'freshestCRL',
        '2.5.29.54'                  : 'inhibitAnyPolicy',
        '1.3.6.1.5.5.7.1.1'          : 'authorityInfoAccess',
        '1.3.6.1.5.5.7.1.11'         : 'subjectInfoAccess',
        '1.3.6.1.5.5.7.48.1'         : 'ocsp',
        '1.3.6.1.5.5.7.48.2'         : 'caIssuers',
        '1.3.6.1.5.5.7.3.1'          : 'serverAuth',
        '1.3.6.1.5.5.7.3.2'          : 'clientAuth',
        '1.3.6.1.5.5.7.3.3'          : 'codeSigning',
        '1.3.6.1.5.5.7.3.4'          : 'emailProtection',
        '1.3.6.1.5.5.7.3.8'          : 'timeStamping',
        '1.3.6.1.5.5.7.3.9'          : 'ocspSigning',
        '1.2.840.113549.1.1.1'       : 'rsaEncryption',
        '1.2.840.113549.1.1.5'       : 'sha1WithRSAEncryption',
        '1.2.840.113549.1.1.7'       : 'rsaOAEP',
        '1.2.840.113549.1.1.8'       : 'sha256WithRSAEncryption-mgf1',
        '1.2.840.113549.1.1.10'      : 'rsaPSS',
        '1.2.840.113549.1.1.11'      : 'sha256WithRSAEncryption',
        '1.2.840.113549.1.1.12'      : 'sha384WithRSAEncryption',
        '1.2.840.113549.1.1.13'      : 'sha512WithRSAEncryption',
        '1.2.840.113549.1.1.14'      : 'sha224WithRSAEncryption',
        '1.2.840.10045.2.1'          : 'ecPublicKey',
        '1.2.840.10045.4.3.1'        : 'ecdsaWithSHA224',
        '1.2.840.10045.4.3.2'        : 'ecdsaWithSHA256',
        '1.2.840.10045.4.3.3'        : 'ecdsaWithSHA384',
        '1.2.840.10045.4.3.4'        : 'ecdsaWithSHA512',
        '1.3.101.110'                : 'x25519',
        '1.3.101.111'                : 'x448',
        '1.3.101.112'                : 'ed25519',
        '1.3.101.113'                : 'ed448',
        '1.2.840.10045.3.1.7'        : 'secp256r1',
        '1.3.132.0.34'               : 'secp384r1',
        '1.3.132.0.35'               : 'secp521r1',
        '1.3.132.0.10'               : 'secp256k1',
        '1.3.14.3.2.26'              : 'sha1',
        '2.16.840.1.101.3.4.2.1'     : 'sha256',
        '2.16.840.1.101.3.4.2.2'     : 'sha384',
        '2.16.840.1.101.3.4.2.3'     : 'sha512',
        '2.16.840.1.101.3.4.2.4'     : 'sha224',
        '2.16.840.1.101.3.4.2.6'     : 'sha512-256',
        '2.16.840.1.101.3.4.2.8'     : 'sha3-256',
        '2.16.840.1.101.3.4.2.9'     : 'sha3-384',
        '2.16.840.1.101.3.4.2.10'    : 'sha3-512',
        '1.2.840.113549.1.7.1'       : 'data',
        '1.2.840.113549.1.7.2'       : 'signedData',
        '1.2.840.113549.1.7.3'       : 'envelopedData',
        '1.2.840.113549.1.7.5'       : 'digestedData',
        '1.2.840.113549.1.7.6'       : 'encryptedData',
        '1.2.840.113549.1.9.1'       : 'emailAddress',
        '1.2.840.113549.1.9.2'       : 'unstructuredName',
        '1.2.840.113549.1.9.3'       : 'contentType',
        '1.2.840.113549.1.9.4'       : 'messageDigest',
        '1.2.840.113549.1.9.5'       : 'signingTime',
        '1.2.840.113549.1.9.14'      : 'extensionRequest',
        '1.2.840.113549.1.9.15'      : 'smimeCapabilities',
        '1.2.840.113549.1.12.1.3'    : 'pbeWithSHAAnd3KeyTripleDES',
        '1.2.840.113549.1.12.1.6'    : 'pbeWithSHAAnd40BitRC2',
        '1.2.840.113549.1.12.10.1.1' : 'keyBag',
        '1.2.840.113549.1.12.10.1.2' : 'pkcs8ShroudedKeyBag',
        '1.2.840.113549.1.12.10.1.3' : 'certBag',
        '1.2.840.113549.1.12.10.1.5' : 'secretBag',
        '1.2.840.113549.1.12.10.1.6' : 'safeContentsBag',
        '2.16.840.1.101.3.4.1.2'     : 'aes128-CBC',
        '2.16.840.1.101.3.4.1.6'     : 'aes128-GCM',
        '2.16.840.1.101.3.4.1.22'    : 'aes192-CBC',
        '2.16.840.1.101.3.4.1.26'    : 'aes192-GCM',
        '2.16.840.1.101.3.4.1.42'    : 'aes256-CBC',
        '2.16.840.1.101.3.4.1.46'    : 'aes256-GCM',
        '1.2.840.113549.1.9.16.1.4'  : 'timestampToken',
        '1.2.840.113549.1.9.16.2.12' : 'signingCertificate',
        '0.9.2342.19200300.100.1.1'  : 'uid',
        '0.9.2342.19200300.100.1.25' : 'domainComponent',
        '1.3.6.1.4.1.311.20.2.3'     : 'userPrincipalName',
        '1.3.6.1.4.1.311.60.2.1.3'   : 'jurisdictionCountry',
        '1.2.840.113549.2.7'         : 'hmacWithSHA1',
        '1.2.840.113549.2.9'         : 'hmacWithSHA256',
        '1.2.840.113549.2.10'        : 'hmacWithSHA384',
        '1.2.840.113549.2.11'        : 'hmacWithSHA512',
    }

    _OID_NAMES_REV = {v: k for k, v in _OID_NAMES.items()}

    def _read_tag(self) -> tuple[int, bool, int]:
        b = self.u8()
        tag_class = (b >> 6) & 3
        constructed = bool(b & 0x20)
        tag_number = b & 0x1F
        if tag_number == 0x1F:
            tag_number = 0
            while True:
                b = self.u8()
                tag_number = (tag_number << 7) | (b & 0x7F)
                if not (b & 0x80):
                    break
        return tag_class, constructed, tag_number

    def _read_length(self) -> int:
        b = self.u8()
        if b < 0x80:
            return b
        if b == 0x80:
            return -1
        n = b & 0x7F
        length = 0
        for _ in range(n):
            length = (length << 8) | self.u8()
        return length

    def _read_children(self, length: int) -> list[ASN1Value]:
        if length < 0:
            children: list[ASN1Value] = []
            while True:
                item = self.read_tlv()
                if item is self._EOC:
                    break
                children.append(item)
            return children
        end = self.tell() + length
        children = []
        while self.tell() < end:
            children.append(self.read_tlv())
        return children

    @staticmethod
    def _try_decode_nested(data: bytes) -> ASN1Value | None:
        if len(data) < 2:
            return None
        try:
            reader = ASN1Reader(memoryview(data), bigendian=True)
            result = reader.read_tlv()
            if result is not reader._EOC and reader.remaining_bytes == 0:
                return result
        except Exception:
            pass
        return None

    @classmethod
    def _decode_oid(cls, data: bytes | memoryview) -> str:
        subids: list[int] = []
        value = 0
        for b in data:
            value = (value << 7) | (b & 0x7F)
            if not (b & 0x80):
                subids.append(value)
                value = 0
        if not subids:
            return ''
        first = subids[0]
        if first < 40:
            components = [0, first]
        elif first < 80:
            components = [1, first - 40]
        else:
            components = [2, first - 80]
        components.extend(subids[1:])
        dotted = '.'.join(str(c) for c in components)
        return cls._OID_NAMES.get(dotted, dotted)

    @staticmethod
    def _decode_relative_oid(data: bytes | memoryview) -> str:
        subids: list[int] = []
        value = 0
        for b in data:
            value = (value << 7) | (b & 0x7F)
            if not (b & 0x80):
                subids.append(value)
                value = 0
        return '.'.join(str(c) for c in subids)

    @staticmethod
    def _decode_real(content: bytes | memoryview) -> float:
        if not content:
            return 0.0
        fb = content[0]
        if fb == 0x40:
            return float('inf')
        if fb == 0x41:
            return float('-inf')
        if fb & 0x80:
            sign = -1 if (fb & 0x40) else 1
            base = [2, 8, 16, 2][(fb >> 4) & 3]
            scale = (fb >> 2) & 3
            ef = fb & 3
            idx = 1
            if ef < 3:
                elen = ef + 1
            else:
                elen = content[idx]
                idx += 1
            exp = int.from_bytes(content[idx:idx + elen], 'big', signed=True)
            idx += elen
            n = int.from_bytes(content[idx:], 'big', signed=False)
            return float(sign * n * (2 ** scale) * (base ** exp))
        return float(codecs.decode(content[1:], 'ascii'))

    def _decode_universal_primitive(self, tag_number: int, content: bytes | memoryview) -> ASN1Value:
        if tag_number == 1:  # BOOLEAN
            return bool(content[-1]) if content else False
        if tag_number == 2:  # INTEGER
            return int.from_bytes(content, 'big', signed=True) if content else 0
        if tag_number == 3:  # BIT STRING
            if not content:
                return b''
            unused = content[0]
            payload = bytes(content[1:])
            if unused == 0:
                nested = self._try_decode_nested(payload)
                if nested is not None:
                    return nested
            return payload
        if tag_number == 4:  # OCTET STRING
            content = bytes(content)
            nested = self._try_decode_nested(content)
            return nested if nested is not None else content
        if tag_number == 5:  # NULL
            return None
        if tag_number == 6:  # OBJECT IDENTIFIER
            return self._decode_oid(content)
        if tag_number == 9:  # REAL
            return self._decode_real(content)
        if tag_number == 10:  # ENUMERATED
            return int.from_bytes(content, 'big', signed=True) if content else 0
        if tag_number == 13:  # RELATIVE-OID
            return self._decode_relative_oid(content)
        enc = self._STRING_ENCODINGS.get(tag_number)
        if enc is not None:
            return bytes(content).decode(enc)
        return bytes(content)

    @staticmethod
    def _unwrap_single(children: list) -> ASN1Value:
        if len(children) == 1 and isinstance(children[0], (list, dict)):
            return children[0]
        return children

    def read_tlv(self) -> ASN1Value:
        tag_class, constructed, tag_number = self._read_tag()

        if tag_class == 0 and not constructed and tag_number == 0:
            self._read_length()
            return self._EOC

        length = self._read_length()

        if tag_class == 0:
            if constructed:
                return self._unwrap_single(self._read_children(length))
            content = bytes(self.read_exactly(length)) if length > 0 else b''
            return self._decode_universal_primitive(tag_number, content)

        if constructed:
            value = self._unwrap_single(self._read_children(length))
        else:
            content = bytes(self.read_exactly(length)) if length > 0 else b''
            nested = self._try_decode_nested(content)
            value = nested if nested is not None else content

        return {'tag': F'{self._TAG_CLASS_NAMES[tag_class]}-{tag_number}', 'value': value}

    def _expected_tag(self, schema_type: SchemaType) -> tuple[int, bool, int] | None:
        if schema_type is ANY:
            return None
        if isinstance(schema_type, int):
            constructed = schema_type in (SEQUENCE, SET)
            return (CLASS_UNIVERSAL, constructed, schema_type)
        if isinstance(schema_type, Seq):
            return (CLASS_UNIVERSAL, True, SEQUENCE)
        if isinstance(schema_type, SeqOf):
            return (CLASS_UNIVERSAL, True, SEQUENCE)
        if isinstance(schema_type, SetOf):
            return (CLASS_UNIVERSAL, True, SET)
        if isinstance(schema_type, Choice):
            return None
        return None

    def _decode_schema_primitive(self, tag_number: int, length: int) -> ASN1Value:
        content = bytes(self.read_exactly(length)) if length > 0 else b''
        return self._decode_universal_primitive(tag_number, content)

    def _decode_constructed_children(self, length: int, element_schema: SchemaType) -> list[ASN1Value]:
        end = self.tell() + length
        children: list[ASN1Value] = []
        while self.tell() < end:
            children.append(self.decode_with_schema(element_schema))
        if isinstance(element_schema, (SetOf, SeqOf)):
            return [item for child in children for item in child]
        return children

    def _decode_seq(self, schema: Seq, length: int) -> OrderedDict[str, ASN1Value]:
        end = self.tell() + length
        result: OrderedDict[str, ASN1Value] = OrderedDict()

        for field in schema.fields:
            if self.tell() >= end:
                if field.optional:
                    if field.default is not _MISSING:
                        result[field.name] = field.default
                    continue
                raise ASN1SchemaMismatch(
                    F'required field {field.name!r} missing: no more data')

            pos = self.tell()
            tag_class, constructed, tag_number = self._read_tag()
            fld_length = self._read_length()

            matched = False
            value: ASN1Value = None

            if field.explicit is not None:
                if tag_class == field.tag_class and tag_number == field.explicit and constructed:
                    value = self.decode_with_schema(field.type)
                    matched = True
            elif field.implicit is not None:
                if tag_class == field.tag_class and tag_number == field.implicit:
                    value = self._decode_implicit(field.type, fld_length, constructed)
                    matched = True
            else:
                expected = self._expected_tag(field.type)
                if expected is None:
                    self.seekrel(-self.tell() + pos)
                    if isinstance(field.type, Choice):
                        value = self._decode_choice(field.type, end)
                    else:
                        value = self.read_tlv()
                    matched = True
                elif (tag_class, constructed, tag_number) == expected:
                    value = self._decode_typed_body(field.type, fld_length, constructed)
                    matched = True

            if not matched:
                self.seekrel(-self.tell() + pos)
                if field.optional:
                    if field.default is not _MISSING:
                        result[field.name] = field.default
                    continue
                raise ASN1SchemaMismatch(
                    F'required field {field.name!r}: expected tag mismatch')

            result[field.name] = value

        return result

    def _decode_implicit(self, schema_type: SchemaType, length: int, constructed: bool) -> ASN1Value:
        if isinstance(schema_type, int):
            if schema_type in (SEQUENCE, SET):
                return self._decode_constructed_children(length, ANY)
            return self._decode_schema_primitive(schema_type, length)
        if isinstance(schema_type, Seq):
            return self._decode_seq(schema_type, length)
        if isinstance(schema_type, SeqOf):
            return self._decode_constructed_children(length, schema_type.element)
        if isinstance(schema_type, SetOf):
            return self._decode_constructed_children(length, schema_type.element)
        content = bytes(self.read_exactly(length)) if length > 0 else b''
        nested = self._try_decode_nested(content)
        return nested if nested is not None else content

    def _decode_typed_body(self, schema_type: SchemaType, length: int, constructed: bool) -> ASN1Value:
        if isinstance(schema_type, int):
            if constructed:
                return self._read_children(length)
            return self._decode_schema_primitive(schema_type, length)
        if isinstance(schema_type, Seq):
            return self._decode_seq(schema_type, length)
        if isinstance(schema_type, SeqOf):
            return self._decode_constructed_children(length, schema_type.element)
        if isinstance(schema_type, SetOf):
            return self._decode_constructed_children(length, schema_type.element)
        if constructed:
            return self._read_children(length)
        content = bytes(self.read_exactly(length)) if length > 0 else b''
        return self._decode_universal_primitive(0, content)

    def _decode_choice(self, schema: Choice, end: int | None = None) -> ASN1Value:
        pos = self.tell()
        tag_class, constructed, tag_number = self._read_tag()
        fld_length = self._read_length()

        has_untagged = False
        for alt in schema.alternatives:
            if alt.explicit is not None:
                if tag_class == alt.tag_class and tag_number == alt.explicit and constructed:
                    return self.decode_with_schema(alt.type)
            elif alt.implicit is not None:
                if tag_class == alt.tag_class and tag_number == alt.implicit:
                    return self._decode_implicit(alt.type, fld_length, constructed)
            else:
                has_untagged = True
                expected = self._expected_tag(alt.type)
                if expected is None or (tag_class, constructed, tag_number) == expected:
                    return self._decode_typed_body(alt.type, fld_length, constructed)

        if not has_untagged:
            raise ASN1SchemaMismatch(
                F'no CHOICE alternative matched: class={tag_class} number={tag_number}')

        self.seekrel(-self.tell() + pos)
        return self.read_tlv()

    def decode_with_schema(self, schema: SchemaType) -> ASN1Value:
        if schema is ANY:
            return self.read_tlv()

        if isinstance(schema, int):
            tag_class, constructed, tag_number = self._read_tag()
            length = self._read_length()
            if tag_class != CLASS_UNIVERSAL or tag_number != schema:
                raise ASN1SchemaMismatch(
                    F'expected universal tag {schema}, got class={tag_class} number={tag_number}')
            return self._decode_typed_body(schema, length, constructed)

        if isinstance(schema, Seq):
            tag_class, constructed, tag_number = self._read_tag()
            length = self._read_length()
            if tag_class != CLASS_UNIVERSAL or tag_number != SEQUENCE or not constructed:
                raise ASN1SchemaMismatch(
                    F'expected SEQUENCE, got class={tag_class} constructed={constructed} number={tag_number}')
            return self._decode_seq(schema, length)

        if isinstance(schema, SeqOf):
            tag_class, constructed, tag_number = self._read_tag()
            length = self._read_length()
            if tag_class != CLASS_UNIVERSAL or tag_number != SEQUENCE or not constructed:
                raise ASN1SchemaMismatch('expected SEQUENCE OF')
            return self._decode_constructed_children(length, schema.element)

        if isinstance(schema, SetOf):
            tag_class, constructed, tag_number = self._read_tag()
            length = self._read_length()
            if tag_class != CLASS_UNIVERSAL or tag_number != SET or not constructed:
                raise ASN1SchemaMismatch('expected SET OF')
            return self._decode_constructed_children(length, schema.element)

        if isinstance(schema, Choice):
            return self._decode_choice(schema)

        raise ASN1SchemaMismatch(F'unknown schema type: {type(schema)}')
