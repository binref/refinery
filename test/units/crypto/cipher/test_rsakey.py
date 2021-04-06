#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
import inspect

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
