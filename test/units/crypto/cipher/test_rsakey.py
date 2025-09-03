import re
import inspect
import json

from ... import TestUnitBase


class TestRSAKeyParser(TestUnitBase):
    def test_xml_format(self):
        @inspect.getdoc
        class data:
            """
            <RSAKeyPair>
              <Modulus>
                4IlzOY3Y9fXoh3Y5f06wBbtTg94Pt6vcfcd1KQ0FLm0S36aGJtTSb6pYKfyX7PqCUQ8wgL6xUJ5GRPEsu9gyz8ZobwfZ
                sGCsvu40CWoT9fcFBZPfXro1Vtlh/xl/yYHm+Gzqh0Bw76xtLHSfLfpVOrmZdwKmSFKMTvNXOFd0V18=
              </Modulus>
              <Exponent>AQAB</Exponent>
              <D>
                pAPDJ0d2NDRspoa1eUkBSy6K0shissfXSAlqi5H3NvJ11ujNFZBgJzFHNWRNlc1nY860n1asLzduHO4Ovygt9DmQbzTY
                bghb1WVq2EHzE9ctOV7+M8v/KeQDCz0Foo+38Y6idjeweVfTLyvehwYifQRmXskbr4saw+yRRKt/IQ==
              </D>
              <P>9tbgIiFMXwpw/yf85bNQap3lD7WFlsZA+qgKtJubDFXCAR35N4KKFMjykw6SzaVmIbk80ga/tFUxydytypgt0Q==</P>
              <Q>6N6wESUJ0gJRAd6K6JhQ9Xd3YaRFk2sIVZZzXfTIWxKTInOLf9Nwf/Wkqrt0/Twiato4kSqGW2wU6K5MnvqOLw==</Q>
              <DP>l0zwh5sXf+4bgxsUtgtqkF+GJ1Hht6B/9eSI41m5+R6b0yl3OCJI1yKxJZi6PVlTt/oeILLIURYjdZNR56vN8Q==</DP>
              <DQ>LPAkW/qgzYUi6tBuT/pszSHTyOTxhERIZHPXKY9+RozsFd7kUbOU5yyZLVVleyTqo2IfPmxNZ0ERO+G+6YMCgw==</DQ>
              <InverseQ>
                WIjZoVA4hGqrA7y730v0nG+4tCol+/bkBS9u4oiJIW9LJZ7Qq1CTyr9AcewhJcV/+wLpIZa4M83ixpXub41fKA==
              </InverseQ>
            </RSAKeyPair>
            """
        data = re.sub(R'\s+', '', data).encode('utf8')
        unit = self.load('XKMS')
        result = re.sub(BR'\s+', B'', unit(data))
        self.assertEqual(result, data)

    def test_ms_key_private_blob(self):
        data = bytes.fromhex(
            '07 02 00 00 00 A4 00 00 52 53 41 32 00 02 00 00 01 00 01 00 6B DF 51 EF DB 6F 10 5C 32 BF 87 1C'
            'D1 4C 24 7E E7 2A 14 10 6D EB 2C D5 8C 0B 95 7B C7 5D C6 87 12 EA A9 CD 57 7D 3E CB E9 6A 46 D0'
            'E1 AE 2F 86 D9 50 F9 98 71 DD 39 FC 0E 60 A9 D3 F2 38 BB 8D 5D 2C BC 1E C3 38 FE 00 5E CA CF CD'
            'B4 13 89 16 D2 07 BC 9B E1 20 31 0B 81 28 17 0C C7 73 94 EE 67 BE 7B 78 4E C7 91 73 A8 34 5A 24'
            '9D 92 0D E8 91 61 24 DC B5 EB DF 71 66 DC E1 77 D4 78 14 98 79 44 B0 19 F6 F0 7D 63 CF 62 67 78'
            'D0 7B 10 AE 6B DB 40 B3 B2 EB 2E 9F 31 34 2D CB BF A2 6A A6 1F E9 03 42 F2 63 9B B7 33 D0 FE 20'
            '83 26 1F 56 A8 24 F5 6D 19 51 A5 92 31 E4 2B BC 11 C8 26 75 A0 51 E9 83 CA EE 4B F0 59 EB A4 81'
            'D6 1F 49 42 2B 75 89 A7 9F 84 7F 1F C3 8F 70 B6 7E 06 5E 8B C9 53 65 80 B7 16 F2 5E 5E DE 0B 57'
            '47 43 86 85 8A FB 37 AC 66 34 BA 09 1A B1 21 0B AA FA 6C B7 75 A7 3E 23 18 58 95 90 B5 29 A4 1E'
            '15 76 52 56 BB 3D 6B 1D 2A D1 9F 5C 8A C0 55 EA C3 29 A2 1E'
        )
        key = data | self.load('json') | json.loads
        self.assertEqual(key['Exponent'], 65537)
        self.assertEqual(int(key['Modulus'], 16),
            0x8DBB38F2D3A9600EFC39DD7198F950D9862FAEE1D0466AE9CB3E7D57CDA9EA1287C65DC77B950B8CD52CEB6D10142AE77E244CD11C87BF325C106FDBEF51DF6B)
