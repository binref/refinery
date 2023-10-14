#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase


class TestVStack(TestUnitBase):

    def test_flareon10(self):
        data = (
            B'     FlArEonFl                                        ArE                \n'
            B'   onFlArEonFlAr                                     EonFl               \n'
            B' ArEonFlArEonFlArE                                  onFlArE              \n'
            B'onFlArEonFlArEonFlA                                rEonFlArE             \n'
            B'onFlArEe   JwVkLtPWmEchgNI      alosxdj           ooC6OLlWnbj            \n'
            B'3q2xyS4     yVGNA6Y OMhkKtG    1GwuXnM           XJPwPv6HQO4Kv           \n'
            B'oAbH324     VqrxQra  hU2+Dm8  efLle7/           nTb4nPj VWUkOlI          \n'
            B'BHv0vQh g1g JaLpPuD   qHPsHajHtSsL5w           e9iYJTb   nia1nRK         \n'
            B'KH2H40G MaO 2wNDjaA    szAciqAoLhLF           ImHeIZB     uRaiTSr        \n'
            B'cTuPYIu     Yk+47yE     yU8TBKHH4l           LA6iWwDkXMSR8J8B3F8l3       \n'
            B'gxTryUv     HIQrx8S     b4Rv7xPv2m          X7PfFBeh+HiU/TxOd+4ovcf      \n'
            B'5V3hSbim   /RPZPdU8    n2E+DFA/JTdX        2PE7wniTzNR1Ii/LUTJRpw9IP     \n'
            B'6J+9xOlP3EhZe4FN+V+   P6L71p8N+KqSKp      KImtZll             IpKDFDq    \n'
            B' Rlm0aG7lhyZblNdjm   rOuBK1e  Wtmr6mE    7d5aUgl               VHz/Pqb   \n'
            B'   r8VCgd9KfqTrG    9kg== F    lArEonF  lArEonF                 lArEonF  \n'
            B'     lArEonFlA     rEonFlA      rEonFlArEonFlA                   rEonFlA \n'
        )
        dc = data | self.load_pipeline('''
            resub | trim -ui flareon | b64 | zl | vstack -p9: -ax64 [| trim h:00 | pop key | xor eat:key ]
        ''') | bytes
        self.assertEqual(dc, b'Patience is rewarded sooner or later - but usually later.')
