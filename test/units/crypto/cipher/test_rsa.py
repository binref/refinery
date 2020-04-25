#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from inspect import getdoc

from ... import TestUnitBase


class TestRSA(TestUnitBase):

    def setUp(self):
        super().setUp()

        @getdoc
        class PRIVATE:
            """
            -----BEGIN RSA PRIVATE KEY-----
            MIIEpgIBAAKCAQEAvqDfS0NirdaOZI27Xcm4gFG7zlO4hnuU8WggfmaD0CN+IvRS
            2NOLaL2BQ+POEYckX749V9o7eQpUA+r4PKNhbaHDavGxTuFj814lz+Zc3m1li/7N
            n6ud8oBirpeIXR6m/2LgioOaU29AIc0LuDfsSLMgVop+P2XBXXpkPh4AB+7oQwHi
            DCFm4ZjirYTrfIOTqozAJ80yNuut5gNrpxRPtzKhPle57phavfjlBMe2FItmOreJ
            fl8cWW4QATbK5p5ndcd7Pj88XEcK/JA6VMjEmbnwjF4WS3abMuHuqmrJBAAybcJ6
            M/+Y4JmAnfru4P7vlIlLkpRWPU75SRJZH8fudQIDAQABAoIBAQCkYtAL9DEtXZ9v
            QPW5XBHZviHpPDMc7Yc0YinbNoYmv+SvOegTiOFoUjsdk14JqXOJiOEXWF7+8xQe
            SMsGZ5HF28BMAd53+k+Z9689yBZ/zPDLt9AUCAdtrp7qlkwGmT9Dbj3Z1MEJgB9a
            xpp7ouYEj0ustUNHYnVMKhY1puM58qEJFKNwJrHzbq/LuPLMXUH3M1bgolDOe9Rl
            PMFV9KVhUB6ERP/HNMxPI4HWgSzck0JaJWcqgo3pJf4u1idChV5gKXZkjvJe9WZr
            ox+SbIEZau2ejejxSc1hOilN6CyIzXYkVJlvDpHJ4twU9R+ODhFmQbymZfXDkybu
            H1m1ph6hAoGBAPg8+pQYfIgZoeGijykJU7WiQK+vyo5UQ8K4xNfPvUAcQkl3W30B
            BALawa+5xxVF3QmDFdTpHLIVonKhPe7qT06THz02i/B/eDblhSs75zi3sIXkroLH
            zvUApknJ2RzfrLiUwbdC2cE7sz/UeEOl2Oz423t/n+6xGz/hrLaagbBtAoGBAMSW
            wZWeQdp/+Y/226gboFJowdjaNdjkxwsTOGDQin2OeaVB24c/P6XZiCaYBH6zBZL9
            vpvDy4eD0KemMOtY9mxCCEHhWrU63qGRvkBQsScKoxIgpX2e+Z8WwMDkv3LDbgVL
            BwzFDhWb/a+Ln68rz/g7xP326/XTScJgSd0Ts0EpAoGBAIOwXcJY5x+QcYdwpH/B
            me3egHBzUoKFA1l2ib5vT1eGZkfxENDUzBrzkBK3/Hw1jtgv+VH0xKtYvNAQ5/kp
            xh7J/6WKnVxdUxnUUvwnkDdPg07UjRuGAi2JRa4ZbZtasZdOGyIsTbasBCCVh6Nj
            hRvZvR3cC60luW3/O4+3kZtVAoGBAKQK5KjT8UHB7l7acDrcKrD5p2Ar3ikJ5qnw
            NOhcvGO/IvTqeqRl+9eKKNmDmqSbADjDMm3KOSjwrolm3YVVq/N0Om22/bki0ani
            8u26J8lbT+4NferQYJ4HH3sWpka+my0hiVV3jaQskckNaoeCuLz8Kwp9JDLyR6dC
            MAChsr/ZAoGBAJ5H7OWgK5ZQFzm8lr9y/P7KYdjizZUuVJxergSztUTMOyncZGJn
            Zu0uqyIMpSfAVZscb2n9byUlenEDqkQX3HA2PVr2tQO+F9JMYiZcx7a4hEIOh1nB
            501n9Y80uuhZS9yWzSitWLvzbac24T93l92ZEpRjq5xOwV0e1uY9xsRU
            -----END RSA PRIVATE KEY-----
            """

        @getdoc
        class PUBLIC:
            """
            -----BEGIN PUBLIC KEY-----
            MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvqDfS0NirdaOZI27Xcm4
            gFG7zlO4hnuU8WggfmaD0CN+IvRS2NOLaL2BQ+POEYckX749V9o7eQpUA+r4PKNh
            baHDavGxTuFj814lz+Zc3m1li/7Nn6ud8oBirpeIXR6m/2LgioOaU29AIc0LuDfs
            SLMgVop+P2XBXXpkPh4AB+7oQwHiDCFm4ZjirYTrfIOTqozAJ80yNuut5gNrpxRP
            tzKhPle57phavfjlBMe2FItmOreJfl8cWW4QATbK5p5ndcd7Pj88XEcK/JA6VMjE
            mbnwjF4WS3abMuHuqmrJBAAybcJ6M/+Y4JmAnfru4P7vlIlLkpRWPU75SRJZH8fu
            dQIDAQAB
            -----END PUBLIC KEY-----
            """

        self.key_private = PRIVATE.encode('ASCII')
        self.key_public = PUBLIC.encode('ASCII')

    def test_rsautl(self):
        # result of: openssl rsautl -sign -inkey private.pem
        data = bytes.fromhex(
            '9C EA E3 B8 21 25 45 E0 1A EC 16 98 25 FA 8F 09'  # ....!%E.....%...
            'B4 85 7F 21 B4 9F CC 7A F5 28 93 30 1D 94 42 29'  # ...!...z.(.0..B)
            'DE 5B 95 C1 55 BD A2 26 73 91 BD 8C D3 78 BD C1'  # .[..U..&s....x..
            'EB DF C6 21 57 71 B4 3C E7 FA B8 32 9F DC DB 55'  # ...!Wq.<...2...U
            'FB 6D CF 6E DA 0E AE 36 7C 1B E6 8F 59 5C 83 98'  # .m.n...6|...Y\..
            '1B AC 57 18 0F 45 42 C1 BB 44 0D 94 68 5F 30 84'  # ..W..EB..D..h_0.
            'EE E2 16 53 00 D0 FC 86 F1 9A 81 D5 9D 5D 9A 2A'  # ...S.........].*
            '49 83 97 00 59 71 42 D0 62 7A 3E 08 EE 8C 5E 65'  # I...YqB.bz>...^e
            'C9 CE 85 56 49 C6 2E 48 40 A9 E8 D0 8D 82 23 76'  # ...VI..H@.....#v
            '55 B8 E5 B0 70 56 D1 CE 85 A8 16 3C FE A3 CD 46'  # U...pV.....<...F
            '1E C1 60 E0 8A 7E 98 0F 40 F1 99 D8 6B 04 2F 56'  # ..`..~..@...k./V
            'E2 2A ED FB 54 CB BC 74 E8 AD 88 A4 51 52 D5 7B'  # .*..T..t....QR.{
            'D7 3C 80 E3 66 AA 2E E5 E1 9F 77 50 CD 16 9E E9'  # .<..f.....wP....
            '62 E1 FC 50 40 2A FB CC 3F 99 F7 94 95 77 34 AC'  # b..P@*..?....w4.
            '41 F1 C3 D4 23 53 70 2B 63 4E 7D 42 9B 09 3A 80'  # A...#Sp+cN}B..:.
            'D2 B1 C2 E4 D5 EA 01 9E 20 9C 5A 5B F2 DF C3 E6'  # ..........Z[....
        )
        cipher = self.load(self.key_public)
        self.assertEqual(cipher(data), B'Taste the real thing.')

    def test_invertible_01(self):
        M = self.generate_random_buffer(200)
        E = self.load(self.key_public, reverse=True)
        D = self.load(self.key_private)
        C = E(M)
        self.assertEqual(D(C), M)

    def test_invertible_02(self):
        M = self.generate_random_buffer(200)
        E = self.load(self.key_private, rsautl=True, reverse=True)
        D = self.load(self.key_public)
        C = E(M)
        self.assertEqual(D(C), M)


class TestMicrosoftKeyBlobs(TestUnitBase):

    def setUp(self):
        super().setUp()

        self.PASSTHROUGH = bytes.fromhex(
            '07 02 00 00 00 A4 00 00 52 53 41 32 00 02 00 00 01 00 00 00 AB EF FA C6'
            '7D E8 DE FB 68 38 09 92 D9 42 7E 6B 89 9E 21 D7 52 1C 99 3C 17 48 4E 3A'
            '44 02 F2 FA 74 57 DA E4 D3 C0 35 67 FA 6E DF 78 4C 75 35 1C A0 74 49 E3'
            '20 13 71 35 65 DF 12 20 F5 F5 F5 C1 ED 5C 91 36 75 B0 A9 9C 04 DB 0C 8C'
            'BF 99 75 13 7E 87 80 4B 71 94 B8 00 A0 7D B7 53 DD 20 63 EE F7 83 41 FE'
            '16 A7 6E DF 21 7D 76 C0 85 D5 65 7F 00 23 57 45 52 02 9D EA 69 AC 1F FD'
            '3F 8C 4A D0 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'
            '00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00'
            '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 64 D5 AA B1'
            'A6 03 18 92 03 AA 31 2E 48 4B 65 20 99 CD C6 0C 15 0C BF 3E FF 78 95 67'
            'B1 74 5B 60 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'
            '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'
            '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'
        )

    def test_passthrough_key(self):
        unit = self.load(self.PASSTHROUGH, padding='PKCS15')
        for k in (8, 12, 16, 32, 50):
            data = self.generate_random_buffer(k)
            blob = B'\0\x02' + (61 - k) * B'\x01' + B'\0' + data
            self.assertEqual(data, unit(blob))
