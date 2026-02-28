import base64
import json
import unittest

from .. import TestUnitBase


class TestASN1(TestUnitBase):

    def _decode(self, hex_input: str, **kwargs):
        data = bytes.fromhex(hex_input)
        return data | self.load(**kwargs) | json.loads

    def _decode_b64(self, b64_input: str, **kwargs):
        data = base64.b64decode(b64_input)
        return data | self.load(**kwargs) | json.loads

    def test_integer(self):
        self.assertEqual(self._decode('02012a'), 42)

    def test_boolean_true(self):
        self.assertIs(self._decode('0101ff'), True)

    def test_boolean_false(self):
        self.assertIs(self._decode('010100'), False)

    def test_null(self):
        self.assertIsNone(self._decode('0500'))

    def test_oid(self):
        self.assertEqual(
            self._decode('06092a864886f70d01010b'),
            'sha256WithRSAEncryption',
        )

    def test_oid_unknown(self):
        self.assertEqual(
            self._decode('06052b0601027f'),
            '1.3.6.1.2.127',
        )

    def test_octet_string(self):
        self.assertEqual(self._decode('040568656c6c6f'), 'hello')

    def test_utf8_string(self):
        self.assertEqual(self._decode('0c0474657374'), 'test')

    def test_printable_string(self):
        self.assertEqual(self._decode('13024142'), 'AB')

    def test_ia5_string(self):
        self.assertEqual(self._decode('16026869'), 'hi')

    def test_utc_time(self):
        self.assertEqual(
            self._decode('170d3231303130313132303030305a'),
            '210101120000Z',
        )

    def test_generalized_time(self):
        self.assertEqual(
            self._decode('180f32303231303130313132303030305a'),
            '20210101120000Z',
        )

    def test_bit_string(self):
        result = self._decode('030500deadbeef')
        self.assertEqual(result, '\xde\xad\xbe\xef')

    def test_sequence(self):
        result = self._decode('3006020101020102')
        self.assertEqual(result, [1, 2])

    def test_nested_sequence(self):
        result = self._decode('300b300502012a050004024142')
        self.assertEqual(result, [[42, None], 'AB'])

    def test_set(self):
        result = self._decode('310602010a020114')
        self.assertEqual(result, [10, 20])

    def test_negative_integer(self):
        self.assertEqual(self._decode('0201ff'), -1)

    def test_large_integer(self):
        self.assertEqual(self._decode('02020100'), 256)

    def test_empty_sequence(self):
        self.assertEqual(self._decode('3000'), [])

    def test_hex_encoding_option(self):
        result = self._decode('040500deadbeef', encode='hex')
        self.assertEqual(result, '00DEADBEEF')

    def test_complex_structure(self):
        data = '301c020101300d06092a864886f70d01010b05000101ff0c0548656c6c6f'
        result = self._decode(data)
        self.assertEqual(result, [
            1,
            ['sha256WithRSAEncryption', None],
            True,
            'Hello',
        ])

    def test_example_pkcs1_rsa_key(self):
        result = self._decode_b64(
            'MIICXQIBAAKBgQCmy23ifN9pi5LO4MR3LUhU0v+LZmv78H+jd+R6kFcWZf1qW4yf'
            'KTDkryjjLlIhYqxmzXCqGyaIjj7uJoorWf7KfkxpOuJrh4swJ/WGhCn9i+voW/7T'
            'sOXfDp1yqrEhaQKwdPot1ZAB78TNsecwX/SODTEMCk95jvx1j5cDxPlskwIDAQAB'
            'AoGBAINn4bp+BsVwYMj768y4sDOjyBBbMNfcMbLn0el9rh7HW09fsPnzycFg/iV9'
            'aNdEle6oDAr4OPN8nbeiRVjCHijEnVdHCwAtkKODyuu1ghpZWD0VUC8AEskjX4Bs'
            'Ysl/HjyvvHIRj89gdDFoElgB4GzHKTzeZNJBM5qtUW57zBCBAkEA0A6N5l98MglL'
            'cypWKM7+3DXteWt86mKXYUVF33HY28Z+oUVlU0v8m8XxpoAjkicYnC1JOSSlvWRk'
            'EWlTMgHW5QJBAM06yIHMR6p3apgpwOUp49DbtaQ8NmhCV4NBoFHa+vT2Fk8twOcq'
            'O9OzP4svhKbPNfB4HnxGbmd/+OVT3lySxhcCQHRPPpqD1K0wLwKxrzrfBPDcIOaY'
            '5VsuRIw3KqmQPngWTiIf5lYbi5sVnFLFHZ2Nx58/XcjZKOJopdxp8f1ps9UCQQC3'
            'rOqSsF9bg3DVKllHQAxyepDAolsXSHjGMk/nspJz9mLVDl/dBAFzYLN4QFj6ae0e'
            'gILYOrjIzNHXfQ4/z+SVAkBPebkAzpGFgzVzu6VOGx0Vft/ow3/DKNJSDM58yASp'
            'ootY2TdibrrV/ellNLvuTiku6AEM/8jbHlRsmfxRe0xn'
        )
        self.assertIsInstance(result, dict)
        self.assertEqual(result['version'], 0)
        self.assertEqual(result['publicExponent'], 65537)

    def test_example_ed25519_cert(self):
        result = self._decode_b64(
            'MIIBfzCCATGgAwIBAgIUfI5kSdcO2S0+LkpdL3b2VUJGx0YwBQYDK2VwMDUxCzAJ'
            'BgNVBAYTAklUMQ8wDQYDVQQHDAZNaWxhbm8xFTATBgNVBAMMDFRlc3QgZWQyNTUx'
            'OTAeFw0yMDA5MDIxMzI1MjZaFw0zMDA5MDIxMzI1MjZaMDUxCzAJBgNVBAYTAklU'
            'MQ8wDQYDVQQHDAZNaWxhbm8xFTATBgNVBAMMDFRlc3QgZWQyNTUxOTAqMAUGAytl'
            'cAMhADupL/3LF2beQKKS95PeMPgKI6gxIV3QB9hjJC7/aCGFo1MwUTAdBgNVHQ4E'
            'FgQUa6W9z536I1l4EmQXrh5y2JqASugwHwYDVR0jBBgwFoAUa6W9z536I1l4EmQX'
            'rh5y2JqASugwDwYDVR0TAQH/BAUwAwEB/zAFBgMrZXADQQBvc3e+KJZaMzbX5TT9'
            'kPP9QH8fAvkAV/IWDxZrBL9lhLaY0tDSv0zWbw624uidBKPgmVD5wm3ec60dNVeF'
            'ZYYG'
        )
        self.assertIsInstance(result, dict)
        tbs = result['tbsCertificate']
        self.assertIsInstance(tbs, dict)
        self.assertEqual(tbs['version'], 2)
        self.assertEqual(result['signatureAlgorithm']['algorithm'], 'ed25519')
        validity = tbs['validity']
        self.assertEqual(validity['notBefore'], '200902132526Z')
        self.assertEqual(validity['notAfter'], '300902132526Z')

    def test_example_crl(self):
        result = self._decode_b64(
            'MIIBYDCBygIBATANBgkqhkiG9w0BAQUFADBDMRMwEQYKCZImiZPyLGQBGRYDY29t'
            'MRcwFQYKCZImiZPyLGQBGRYHZXhhbXBsZTETMBEGA1UEAxMKRXhhbXBsZSBDQRcN'
            'MDUwMjA1MTIwMDAwWhcNMDUwMjA2MTIwMDAwWjAiMCACARIXDTA0MTExOTE1NTcw'
            'M1owDDAKBgNVHRUEAwoBAaAvMC0wHwYDVR0jBBgwFoAUCGivhTPIOUp6+IKTjnBq'
            'SiCELDIwCgYDVR0UBAMCAQwwDQYJKoZIhvcNAQEFBQADgYEAItwYffcIzsx10NBq'
            'm60Q9HYjtIFutW2+DvsVFGzIF20f7pAXom9g5L2qjFXejoRvkvifEBInr0rUL4Xi'
            'NkR9qqNMJTgV/wD9Pn7uPSYS69jnK2LiK8NGgO94gtEVxtCccmrLznrtZ5mLbnC'
            'BfUNCdMGmr8FVF6IzTNYGmCuk/C4='
        )
        self.assertIsInstance(result, dict)
        tbs = result['tbsCertList']
        self.assertEqual(tbs['version'], 1)
        self.assertEqual(tbs['signature']['algorithm'], 'sha1WithRSAEncryption')
        self.assertEqual(tbs['issuer'][2]['value'], 'Example CA')
        self.assertEqual(tbs['thisUpdate'], '050205120000Z')

    def test_example_ldap_message(self):
        result = self._decode_b64(
            'MDUCAQVKEWRjPWV4YW1wbGUsZGM9Y29toB0wGwQWMS4yLjg0MC4x'
            'MTM1NTYuMS40LjgwNQEB/w=='
        )
        self.assertIsInstance(result, dict)
        self.assertEqual(result['messageID'], 5)
        self.assertEqual(result['protocolOp'], 'dc=example,dc=com')
        controls = result['controls']
        self.assertIsInstance(controls, list)
        self.assertEqual(len(controls), 1)
        self.assertEqual(controls[0]['controlType'], '1.2.840.113556.1.4.805')
        self.assertIs(controls[0]['criticality'], True)

    def test_example_timestamp_request(self):
        result = self._decode_b64(
            'ME4CAQEwLzALBglghkgBZQMEAgEEIEbUJK38SA8/2dz78XnG7DJf'
            'IYsSer3shYMmZa1VLFIRAhUA/1AduFa4EwRirIpvChE2VrV/JWYB'
            'Af8='
        )
        self.assertIsInstance(result, dict)
        self.assertEqual(result['version'], 1)
        message_imprint = result['messageImprint']
        self.assertIsInstance(message_imprint, dict)
        self.assertEqual(message_imprint['hashAlgorithm']['algorithm'], 'sha256')
        self.assertIs(result['certReq'], True)

    def test_example_pkcs10_csr(self):
        result = self._decode_b64(
            'MIHQMIGDAgEAMA8xDTALBgNVBAMMBHRlc3QwKjAFBgMrZXADIQD7'
            'Fua9ZF+wPXVdDCBwQr+Aqny6OFvs25wZ/P4LyVsYmKBBMD8GCSqG'
            'SIb3DQEJDjEyMDAwLgYDVR0RBCcwJaAjBgorBgEEAYI3FAIDoBUM'
            'E2FkZHJlc3NAZG9tYWluLnRlc3QwBQYDK2VwA0EAUp5FenHF1rZz'
            'RGU+7wiF+/D1bfyDRF0dzWz2sl44nltu8iLjHO3aIfOTYWpqZlaD'
            'g1Bq3L7Fcb7If4yZAsE5Cw=='
        )
        self.assertIsInstance(result, dict)
        cri = result['certificationRequestInfo']
        self.assertEqual(cri['version'], 0)
        subject = cri['subject']
        self.assertEqual(subject[0]['type'], 'commonName')
        self.assertEqual(subject[0]['value'], 'test')
        self.assertEqual(result['signatureAlgorithm']['algorithm'], 'ed25519')

    def test_example_cmp_pki_message(self):
        result = self._decode_b64(
            'MIICPjCB1QIBAqQCMACkRjBEMQswCQYDVQQGEwJERTEMMAoGA1UE'
            'ChMDTlNOMREwDwYDVQQLEwhQRyBSREUgMzEUMBIGA1UEAxMLTWFy'
            'dGluJ3MgQ0GgERgPMjAxMDA3MDUwNzM1MzhaoTwwOgYJKoZIhvZ9'
            'B0INMC0EEJ5EpSD3zKjvmzHEK5+aoAAwCQYFKw4DAhoFAAICAfQw'
            'CgYIKwYBBQUIAQKiCwQJb/KGO0ILNJqApBIEEJGOKFG/9crkwU+z'
            '/I5ICa6lEgQQnnbd7EB2QjRCwOHt9QWdBKCCAUkwggFFMIIBQTCB'
            'qAIBADCBoqaBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAqVTO'
            'tjEEYELkomc3sMOyToo5a9YeC91IMn52cVx7doY4AeO6J9e8p+Ct'
            'WNbzVF8aRgHUhh31m+/X3MkQOaY5i8nF33uxAxDLMDXttHjsqrF/'
            'tsgYuuHSs/Znz4PA1kLkdhKE9DLiGlCFaJH5QY5Hzl6bcS3ApuWC'
            'ny0RRzIA1/cCAwEAAaGBkzANBgkqhkiG9w0BAQUFAAOBgQArOldj'
            'g75fDx7BaFp0oAknLDREvB1KyE+BV96R+lB+tRRhwv3dyc/GTvRw'
            '4GtaeDjWCjNPaDCl9ZvvVljaR2aMZvhaQV+DUmCMjFSP3DPiGusz'
            'BA6R2azXNKtnpJ3SGx2vk0+Iv05tXLhdnqQJZs5a3S3R30kn4Vw+'
            '4WQm3kb0fKAXAxUA9K8u+7hv5Rg6GDn6aoPxbUo6fpU='
        )
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 3)
        header = result[0]
        self.assertIsInstance(header, list)
        self.assertEqual(header[0], 2)
        self.assertEqual(header[1]['tag'], 'context-4')
        self.assertEqual(header[2]['tag'], 'context-4')
        recipient_dn = header[2]['value']
        self.assertIsInstance(recipient_dn, list)

    def test_context_specific_tags(self):
        result = self._decode('a00302012a')
        self.assertEqual(result, {'tag': 'context-0', 'value': [42]})

    def test_application_tag(self):
        result = self._decode('4a0474657374')
        self.assertEqual(result['tag'], 'application-10')

    def test_constructed_application_tag(self):
        result = self._decode('630302010100'[:10])
        self.assertEqual(result['tag'], 'application-3')
        self.assertEqual(result['value'], [1])

    def test_octet_string_with_nested_asn1(self):
        result = self._decode('04053003020101')
        self.assertEqual(result, [1])

    def test_bit_string_with_nested_asn1(self):
        result = self._decode('0306003003020101')
        self.assertEqual(result, [1])

    def test_example_cms_signed_data(self):
        result = self._decode_b64(
            'MIIBkgYJKoZIhvcNAQcCoIIBgzCCAX8CAQExDzANBglghkgBZQMEAgEFADAYBgkq'
            'hkiG9w0BBwGgCwQJSGVsbG8gQ01ToIHTMIHQMIGyoAMCAQICAjA5MAoGCCqGSM49'
            'BAMCMA8xDTALBgNVBAMMBFRlc3QwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAw'
            'MDAwWjAPMQ0wCwYDVQQDDARUZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE'
            'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB'
            'AQEBAQEBAQEBAQEBAQEBATAKBggqhkjOPQQDAgMNADAKAgMA3q0CAwC+7zF5MHcC'
            'AQEwFTAPMQ0wCwYDVQQDDARUZXN0AgIwOTANBglghkgBZQMEAgEFADAKBggqhkjO'
            'PQQDAgRAq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6ur'
            'q6urq6urq6urq6urq6urq6urq6urqw=='
        )
        self.assertIsInstance(result, dict)
        self.assertEqual(result['contentType'], 'signedData')
        signed_data = result['content']
        self.assertIsInstance(signed_data, dict)
        self.assertEqual(signed_data['version'], 1)
        self.assertEqual(signed_data['digestAlgorithms'][0]['algorithm'], 'sha256')
        self.assertEqual(signed_data['encapContentInfo']['eContentType'], 'data')
        certs = signed_data['certificates']
        self.assertEqual(len(certs), 1)
        cert = certs[0]
        self.assertIsInstance(cert, dict)
        tbs = cert['tbsCertificate']
        self.assertEqual(tbs['version'], 2)
        self.assertEqual(tbs['issuer'][0]['type'], 'commonName')
        self.assertEqual(tbs['issuer'][0]['value'], 'Test')
        self.assertEqual(cert['signatureAlgorithm']['algorithm'], 'ecdsaWithSHA256')
        signers = signed_data['signerInfos']
        self.assertEqual(len(signers), 1)
        signer = signers[0]
        self.assertIsInstance(signer, dict)
        self.assertEqual(signer['version'], 1)
        signer_id = signer['sid']
        self.assertIsInstance(signer_id, dict)
        self.assertEqual(signer_id['issuer'][0]['value'], 'Test')
        self.assertEqual(signer_id['serialNumber'], 12345)
        self.assertEqual(signer['digestAlgorithm']['algorithm'], 'sha256')
        self.assertEqual(signer['signatureAlgorithm']['algorithm'], 'ecdsaWithSHA256')

    def test_oid_arc2(self):
        self.assertEqual(self._decode('06035504 03'.replace(' ', '')), 'commonName')

    def test_high_tag_number(self):
        # df 21 01 42: private class, long-form tag 33, length 1, content 0x42
        result = self._decode('df210142')
        self.assertEqual(result['tag'], 'private-33')

    def test_indefinite_length(self):
        # 30 80 ... 00 00: SEQUENCE with indefinite length, terminated by EOC
        result = self._decode('30800201010000')
        self.assertEqual(result, [1])

    def test_real_zero(self):
        result = self._decode('0900')
        self.assertEqual(result, 0.0)

    def test_real_positive_infinity(self):
        from refinery.lib.asn1.reader import ASN1Reader
        reader = ASN1Reader(bytes.fromhex('090140'))
        self.assertEqual(reader.read_tlv(), float('inf'))

    def test_real_negative_infinity(self):
        from refinery.lib.asn1.reader import ASN1Reader
        reader = ASN1Reader(bytes.fromhex('090141'))
        self.assertEqual(reader.read_tlv(), float('-inf'))

    def test_real_binary(self):
        # 80 02 03: base-2 binary, exponent=2, mantissa=3 -> 3 * 2^2 = 12.0
        result = self._decode('0903800203')
        self.assertEqual(result, 12.0)

    def test_relative_oid(self):
        result = self._decode('0d03550403')
        self.assertEqual(result, '85.4.3')

    def test_empty_bit_string(self):
        result = self._decode('0300')
        self.assertEqual(result, '')

    def test_unknown_universal_tag(self):
        # tag 8 (EXTERNAL) has no dedicated handler
        result = self._decode('0802abcd')
        self.assertIsInstance(result, str)

    def test_enumerated(self):
        result = self._decode('0a0102')
        self.assertEqual(result, 2)

    def test_empty_oid(self):
        result = self._decode('0600')
        self.assertEqual(result, '')

    def test_private_tag(self):
        result = self._decode('e103020105')
        self.assertEqual(result['tag'], 'private-1')
        self.assertEqual(result['value'], [5])

    def test_schema_mismatch_integer(self):
        from refinery.lib.asn1.reader import ASN1Reader
        from refinery.lib.asn1.schema import ASN1SchemaMismatch, INTEGER
        reader = ASN1Reader(bytes.fromhex('0500'))
        with self.assertRaises(ASN1SchemaMismatch):
            reader.decode_with_schema(INTEGER)

    def test_schema_mismatch_sequence(self):
        from refinery.lib.asn1.reader import ASN1Reader
        from refinery.lib.asn1.schema import ASN1SchemaMismatch, Seq, F, INTEGER
        schema = Seq(F('x', INTEGER))
        reader = ASN1Reader(bytes.fromhex('020101'))
        with self.assertRaises(ASN1SchemaMismatch):
            reader.decode_with_schema(schema)

    def test_schema_mismatch_set_of(self):
        from refinery.lib.asn1.reader import ASN1Reader
        from refinery.lib.asn1.schema import ASN1SchemaMismatch, SetOf, INTEGER
        schema = SetOf(INTEGER)
        # SEQUENCE tag (0x30) instead of expected SET tag (0x31)
        reader = ASN1Reader(bytes.fromhex('3003020101'))
        with self.assertRaises(ASN1SchemaMismatch):
            reader.decode_with_schema(schema)

    def test_choice_explicit_tag(self):
        from refinery.lib.asn1.reader import ASN1Reader
        from refinery.lib.asn1.schema import Choice, F, INTEGER, OCTET_STRING
        schema = Choice(
            F('num', INTEGER, explicit=0),
            F('str', OCTET_STRING, explicit=1),
        )
        reader = ASN1Reader(bytes.fromhex('a00302012a'))
        result = reader.decode_with_schema(schema)
        self.assertEqual(result, 42)

    def test_choice_all_tagged_mismatch(self):
        from refinery.lib.asn1.reader import ASN1Reader
        from refinery.lib.asn1.schema import ASN1SchemaMismatch, Choice, F, INTEGER, OCTET_STRING
        schema = Choice(
            F('num', INTEGER, implicit=0),
            F('str', OCTET_STRING, implicit=1),
        )
        reader = ASN1Reader(bytes.fromhex('020101'))
        with self.assertRaises(ASN1SchemaMismatch):
            reader.decode_with_schema(schema)

    def test_choice_fallback_to_tlv(self):
        from refinery.lib.asn1.reader import ASN1Reader
        from refinery.lib.asn1.schema import Choice, F, INTEGER, OCTET_STRING
        schema = Choice(
            F('num', INTEGER),
            F('str', OCTET_STRING),
        )
        # BOOLEAN doesn't match INTEGER or OCTET STRING; falls back to read_tlv
        reader = ASN1Reader(bytes.fromhex('0101ff'))
        result = reader.decode_with_schema(schema)
        self.assertIs(result, True)

    def test_implicit_primitive_in_seq(self):
        from refinery.lib.asn1.reader import ASN1Reader
        from refinery.lib.asn1.schema import Seq, F, INTEGER
        schema = Seq(F('version', INTEGER, implicit=0))
        reader = ASN1Reader(bytes.fromhex('3003800105'))
        result = reader.decode_with_schema(schema)
        self.assertEqual(result['version'], 5)

    def test_implicit_seq_of_in_field(self):
        from refinery.lib.asn1.reader import ASN1Reader
        from refinery.lib.asn1.schema import Seq, SeqOf, F, INTEGER
        schema = Seq(F('items', SeqOf(INTEGER), implicit=0))
        reader = ASN1Reader(bytes.fromhex('3008a006020101020102'))
        result = reader.decode_with_schema(schema)
        self.assertEqual(result['items'], [1, 2])

    def test_implicit_seq_in_field(self):
        from refinery.lib.asn1.reader import ASN1Reader
        from refinery.lib.asn1.schema import Seq, F, INTEGER, BOOLEAN
        inner = Seq(F('val', INTEGER), F('flag', BOOLEAN))
        schema = Seq(F('inner', inner, implicit=0))
        reader = ASN1Reader(bytes.fromhex('3008a0060201010101ff'))
        result = reader.decode_with_schema(schema)
        self.assertEqual(result['inner']['val'], 1)
        self.assertIs(result['inner']['flag'], True)

    def test_compiler_imports(self):
        from refinery.lib.asn1.compiler import compile_asn1
        from refinery.lib.asn1.schema import INTEGER
        result = compile_asn1("""
            Test DEFINITIONS ::= BEGIN
                IMPORTS AlgorithmIdentifier FROM PKIX1;
                Foo ::= SEQUENCE { version INTEGER }
            END
        """, externals={'AlgorithmIdentifier': INTEGER})
        self.assertIn('Foo', result)

    def test_compiler_exports(self):
        from refinery.lib.asn1.compiler import compile_asn1
        result = compile_asn1("""
            Test DEFINITIONS ::= BEGIN
                EXPORTS Certificate, Name;
                Foo ::= INTEGER
            END
        """)
        self.assertIn('Foo', result)

    def test_compiler_extension_markers(self):
        from refinery.lib.asn1.compiler import compile_asn1
        from refinery.lib.asn1.schema import Seq
        result = compile_asn1("""
            Test DEFINITIONS ::= BEGIN
                Foo ::= SEQUENCE {
                    version INTEGER,
                    ...,
                    extra BOOLEAN OPTIONAL
                }
            END
        """)
        self.assertIsInstance(result['Foo'], Seq)
        self.assertEqual(len(result['Foo'].fields), 2)

    def test_compiler_choice_extension_markers(self):
        from refinery.lib.asn1.compiler import compile_asn1
        from refinery.lib.asn1.schema import Choice
        result = compile_asn1("""
            Test DEFINITIONS ::= BEGIN
                Foo ::= CHOICE {
                    num INTEGER,
                    ...,
                    str OCTET STRING
                }
            END
        """)
        self.assertIsInstance(result['Foo'], Choice)
        self.assertEqual(len(result['Foo'].alternatives), 2)

    def test_compiler_integer_constraint(self):
        from refinery.lib.asn1.compiler import compile_asn1
        from refinery.lib.asn1.schema import INTEGER
        result = compile_asn1("""
            Test DEFINITIONS ::= BEGIN
                Version ::= INTEGER (0..MAX)
            END
        """)
        self.assertIs(result['Version'], INTEGER)

    def test_compiler_integer_named_numbers(self):
        from refinery.lib.asn1.compiler import compile_asn1
        from refinery.lib.asn1.schema import INTEGER
        result = compile_asn1("""
            Test DEFINITIONS ::= BEGIN
                Version ::= INTEGER { v1(0), v2(1), v3(2) }
            END
        """)
        self.assertIs(result['Version'], INTEGER)

    def test_compiler_bit_string_named_bits(self):
        from refinery.lib.asn1.compiler import compile_asn1
        from refinery.lib.asn1.schema import BIT_STRING
        result = compile_asn1("""
            Test DEFINITIONS ::= BEGIN
                KeyUsage ::= BIT STRING {
                    digitalSignature (0),
                    keyEncipherment  (2)
                }
            END
        """)
        self.assertIs(result['KeyUsage'], BIT_STRING)

    def test_compiler_octet_string_size_constraint(self):
        from refinery.lib.asn1.compiler import compile_asn1
        from refinery.lib.asn1.schema import OCTET_STRING
        result = compile_asn1("""
            Test DEFINITIONS ::= BEGIN
                Hash ::= OCTET STRING (SIZE (20))
            END
        """)
        self.assertIs(result['Hash'], OCTET_STRING)

    def test_compiler_enumerated_with_values(self):
        from refinery.lib.asn1.compiler import compile_asn1
        from refinery.lib.asn1.schema import ENUMERATED
        result = compile_asn1("""
            Test DEFINITIONS ::= BEGIN
                Status ::= ENUMERATED { good(0), revoked(1), unknown(2) }
            END
        """)
        self.assertIs(result['Status'], ENUMERATED)

    def test_compiler_any_defined_by(self):
        from refinery.lib.asn1.compiler import compile_asn1
        from refinery.lib.asn1.schema import ANY, Seq
        result = compile_asn1("""
            Test DEFINITIONS ::= BEGIN
                Foo ::= SEQUENCE {
                    type  OBJECT IDENTIFIER,
                    value ANY DEFINED BY type
                }
            END
        """)
        self.assertIsInstance(result['Foo'], Seq)
        self.assertIs(result['Foo'].fields[1].type, ANY)

    def test_compiler_default_values(self):
        from refinery.lib.asn1.compiler import compile_asn1
        from refinery.lib.asn1.schema import Seq
        result = compile_asn1("""
            Test DEFINITIONS ::= BEGIN
                Foo ::= SEQUENCE {
                    ver    INTEGER DEFAULT 0,
                    flag   BOOLEAN DEFAULT TRUE,
                    off    BOOLEAN DEFAULT FALSE,
                    nul    NULL DEFAULT NULL
                }
            END
        """)
        foo = result['Foo']
        self.assertIsInstance(foo, Seq)
        self.assertEqual(foo.fields[0].default, 0)
        self.assertIs(foo.fields[1].default, True)
        self.assertIs(foo.fields[2].default, False)
        self.assertIsNone(foo.fields[3].default)

    def test_compiler_default_named_value(self):
        from refinery.lib.asn1.compiler import compile_asn1
        result = compile_asn1("""
            Test DEFINITIONS ::= BEGIN
                Foo ::= SEQUENCE {
                    status INTEGER DEFAULT someValue
                }
            END
        """)
        self.assertEqual(result['Foo'].fields[0].default, 'someValue')

    def test_compiler_set_body(self):
        from refinery.lib.asn1.compiler import compile_asn1
        from refinery.lib.asn1.schema import Seq
        result = compile_asn1("""
            Test DEFINITIONS ::= BEGIN
                Foo ::= SET {
                    name  OCTET STRING,
                    value INTEGER OPTIONAL
                }
            END
        """)
        self.assertIsInstance(result['Foo'], Seq)
        self.assertEqual(len(result['Foo'].fields), 2)

    def test_compiler_sequence_size_constraint_of(self):
        from refinery.lib.asn1.compiler import compile_asn1
        from refinery.lib.asn1.schema import SeqOf
        result = compile_asn1("""
            Test DEFINITIONS ::= BEGIN
                Names ::= SEQUENCE (SIZE (1..MAX)) OF OCTET STRING
            END
        """)
        self.assertIsInstance(result['Names'], SeqOf)

    def test_compiler_set_size_constraint_of(self):
        from refinery.lib.asn1.compiler import compile_asn1
        from refinery.lib.asn1.schema import SetOf
        result = compile_asn1("""
            Test DEFINITIONS ::= BEGIN
                Things ::= SET (SIZE (1..MAX)) OF INTEGER
            END
        """)
        self.assertIsInstance(result['Things'], SetOf)

    def test_compiler_typeref_with_constraint(self):
        from refinery.lib.asn1.compiler import compile_asn1
        from refinery.lib.asn1.schema import Seq, INTEGER
        result = compile_asn1("""
            Test DEFINITIONS ::= BEGIN
                Version ::= INTEGER
                Foo ::= SEQUENCE {
                    ver Version (0..2)
                }
            END
        """)
        self.assertIsInstance(result['Foo'], Seq)
        self.assertIs(result['Foo'].fields[0].type, INTEGER)

    def test_compiler_tagged_top_level(self):
        from refinery.lib.asn1.compiler import compile_asn1
        from refinery.lib.asn1.schema import INTEGER
        result = compile_asn1("""
            Test DEFINITIONS ::= BEGIN
                Foo ::= [0] IMPLICIT INTEGER
            END
        """)
        self.assertIs(result['Foo'], INTEGER)

    def test_compiler_unresolved_typeref_fallback(self):
        from refinery.lib.asn1.compiler import compile_asn1
        from refinery.lib.asn1.schema import ANY, Seq
        result = compile_asn1("""
            Test DEFINITIONS ::= BEGIN
                Foo ::= SEQUENCE {
                    value UnknownType
                }
            END
        """)
        self.assertIsInstance(result['Foo'], Seq)
        self.assertIs(result['Foo'].fields[0].type, ANY)

    def test_compiler_builtin_string_types(self):
        from refinery.lib.asn1.compiler import compile_asn1
        result = compile_asn1("""
            Test DEFINITIONS ::= BEGIN
                Foo ::= SEQUENCE {
                    a T61String,
                    b BMPString,
                    c VisibleString,
                    d NumericString,
                    e GeneralString,
                    f UniversalString
                }
            END
        """)
        fields = result['Foo'].fields
        self.assertEqual(fields[0].type, 20)
        self.assertEqual(fields[1].type, 30)
        self.assertEqual(fields[2].type, 26)
        self.assertEqual(fields[3].type, 18)
        self.assertEqual(fields[4].type, 27)
        self.assertEqual(fields[5].type, 28)

    def test_compiler_choice_with_explicit_tags(self):
        from refinery.lib.asn1.compiler import compile_asn1
        from refinery.lib.asn1.schema import Choice
        result = compile_asn1("""
            Test DEFINITIONS EXPLICIT TAGS ::= BEGIN
                Foo ::= CHOICE {
                    num [0] INTEGER,
                    str [1] OCTET STRING
                }
            END
        """)
        choice = result['Foo']
        self.assertIsInstance(choice, Choice)
        self.assertEqual(choice.alternatives[0].explicit, 0)
        self.assertEqual(choice.alternatives[1].explicit, 1)

    def test_compiler_syntax_error(self):
        from refinery.lib.asn1.compiler import compile_asn1
        with self.assertRaises(SyntaxError):
            compile_asn1("Test DEFINITIONS ::= BEGIN Foo ::= @invalid END")

    def test_compiler_nested_constraint(self):
        from refinery.lib.asn1.compiler import compile_asn1
        from refinery.lib.asn1.schema import INTEGER
        result = compile_asn1("""
            Test DEFINITIONS ::= BEGIN
                Foo ::= INTEGER (0..MAX (CONSTRAINED BY {}))
            END
        """)
        self.assertIs(result['Foo'], INTEGER)

    def test_compiler_bit_string_size_constraint(self):
        from refinery.lib.asn1.compiler import compile_asn1
        from refinery.lib.asn1.schema import BIT_STRING
        result = compile_asn1("""
            Test DEFINITIONS ::= BEGIN
                Flags ::= BIT STRING (SIZE (8))
            END
        """)
        self.assertIs(result['Flags'], BIT_STRING)

    def test_compiler_application_tag_in_choice(self):
        from refinery.lib.asn1.compiler import compile_asn1
        from refinery.lib.asn1.schema import CLASS_APPLICATION
        result = compile_asn1("""
            Test DEFINITIONS IMPLICIT TAGS ::= BEGIN
                Foo ::= CHOICE {
                    bar [APPLICATION 5] OCTET STRING
                }
            END
        """)
        alt = result['Foo'].alternatives[0]
        self.assertEqual(alt.tag_class, CLASS_APPLICATION)
        self.assertEqual(alt.implicit, 5)

    def test_compiler_imports_with_oid(self):
        from refinery.lib.asn1.compiler import compile_asn1
        result = compile_asn1("""
            Test DEFINITIONS ::= BEGIN
                IMPORTS
                    AlgorithmIdentifier FROM PKIX1Explicit88 {
                        iso(1) identified-organization(3) dod(6) internet(1)
                    };
                Foo ::= INTEGER
            END
        """)
        self.assertIn('Foo', result)

    def test_compiler_builtin_type_with_constraint(self):
        from refinery.lib.asn1.compiler import compile_asn1
        result = compile_asn1("""
            Test DEFINITIONS ::= BEGIN
                DirectoryString ::= UTF8String (SIZE (1..64))
            END
        """)
        self.assertEqual(result['DirectoryString'], 12)
