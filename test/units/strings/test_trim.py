#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestTrim(TestUnitBase):

    def test_left_and_right(self):
        trim = self.load()
        self.assertEqual(trim(b'   abc   '), b'abc')

    def test_left(self):
        trim = self.load('-l')
        self.assertEqual(trim(b'   abc   '), b'abc   ')

    def test_right(self):
        trim = self.load('-r')
        self.assertEqual(trim(b'   abc   '), b'   abc')

    def test_mutli_char_01(self):
        trim = self.load(b'x:')
        self.assertEqual(trim(b'x:x:x::abc'), b':abc')

    def test_mutli_char_02(self):
        trim = self.load(b'ab', b'cd')
        self.assertEqual(trim(b'abcdabefcdcd'), b'ef')

    def test_everything_trimmed(self):
        trim = self.load(b'\0')
        self.assertEqual(trim(bytearray(201)), B'')

    def test_trim_from_variable(self):
        pipe = self.ldu('put', 'junk', 'cut:-1:') [ self.ldu('trim', 'var:junk', left=False) ] # noqa
        self.assertEqual(pipe(B'AAAAAABBBBBB'), B'AAAAAA')

    def test_trim_flareon10(self):
        fo10 = (
            B'FlArEonFlArEonFlArEonFlArEonFlArEonFlArEonFlArEonFlArEonFlArEonFlArEonFlArEon'
            B'FlArEonFlArEeJwVkLtPWmEchgNIalosxdjooC6OLlWnbj3q2xyS4yVGNA6YOMhkKtG1GwuXnMXJP'
            B'wPv6HQO4KvoAbH324VqrxQrahU2+Dm8efLle7/nTb4nPjVWUkOlIBHv0vQhg1gJaLpPuDqHPsHajH'
            B'tSsL5we9iYJTbnia1nRKKH2H40GMaO2wNDjaAszAciqAoLhLFImHeIZBuRaiTSrcTuPYIuYk+47yE'
            B'yU8TBKHH4lLA6iWwDkXMSR8J8B3F8l3gxTryUvHIQrx8Sb4Rv7xPv2mX7PfFBeh+HiU/TxOd+4ovc'
            B'f5V3hSbim/RPZPdU8n2E+DFA/JTdX2PE7wniTzNR1Ii/LUTJRpw9IP6J+9xOlP3EhZe4FN+V+P6L7'
            B'1p8N+KqSKpKImtZllIpKDFDqRlm0aG7lhyZblNdjmrOuBK1eWtmr6mE7d5aUglVHz/Pqbr8VCgd9K'
            B'fqTrG9kg==FlArEonFlArEonFlArEonFlArEonFlArEonFlArEonFlArEonFlArEonFlA')
        goal = (
            B'eJwVkLtPWmEchgNIalosxdjooC6OLlWnbj3q2xyS4yVGNA6YOMhkKtG1GwuXnMXJPwPv6HQO4KvoA'
            B'bH324VqrxQrahU2+Dm8efLle7/nTb4nPjVWUkOlIBHv0vQhg1gJaLpPuDqHPsHajHtSsL5we9iYJT'
            B'bnia1nRKKH2H40GMaO2wNDjaAszAciqAoLhLFImHeIZBuRaiTSrcTuPYIuYk+47yEyU8TBKHH4lLA'
            B'6iWwDkXMSR8J8B3F8l3gxTryUvHIQrx8Sb4Rv7xPv2mX7PfFBeh+HiU/TxOd+4ovcf5V3hSbim/RP'
            B'ZPdU8n2E+DFA/JTdX2PE7wniTzNR1Ii/LUTJRpw9IP6J+9xOlP3EhZe4FN+V+P6L71p8N+KqSKpKI'
            B'mtZllIpKDFDqRlm0aG7lhyZblNdjmrOuBK1eWtmr6mE7d5aUglVHz/Pqbr8VCgd9KfqTrG9kg==')

        self.assertEqual(goal, fo10 | self.load(B'FlArEon', unpad=True) | bytes)
        self.assertEqual(goal, fo10 | self.load(B'flareon', nocase=True, unpad=True) | bytes)
