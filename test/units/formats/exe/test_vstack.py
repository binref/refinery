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
            resub | trim -ui flareon | b64 | zl | vstack -w10 -p9: -ax64 [| sorted -a size | trim h:00 | pop key | xor eat:key ]
        ''') | bytes
        self.assertEqual(dc, b'Patience is rewarded sooner or later - but usually later.')

    def test_stringcrypt_01(self):
        data = self.download_sample('e7a198902409517fc723d40b79c27b1776509d63c461b8f5daf5bb664f9e0589')
        test = data | self.load_pipeline(
            'put b [| rex Y:488D4C[2]E8[4]488BC8E8 | eat b | vaddr offset | vstack -w40 var:offset | xtp | defang ]') | {str}
        self.assertSetEqual(test, {
            'https[:]//discord[.]com/channels/1145547606802563172/1154889021567279115/1154889238077263952',
            'https[:]//raw.githubusercontent[.]com/ToXicVibezz/Galaxy/main/Galaxy.dll',
        })

    def test_write_skip_regression_01(self):
        h = bytes.fromhex
        data = h(
            '554889E54881EC880000004889BD78FFFFFF48B82A233337285B404148BA462B202E20205F594889'
            '45C0488955C848B8424033212D3D375748BA5D5B4335392C3E2A488945D0488955D848B840555F5A'
            '7073756D48BA6C6F72656D697073488945E0488955E8C645F00048B86C6F72656D69707348BA756D'
            '6C6F72656D69488945804889558848B87073756D6C6F726548BA6D697073756D6C6F488945904889'
            '559848B872656D697073756D48BA6C6F72656D697073488945A0488955A8C645B000488B8578FFFF'
            'FF4889C7E846FEFFFF8945F4C745FC00000000C745F800000000EB358B45F84863D0488B8578FFFF'
            'FF4801D00FB6108B45F848980FB644058031C28B45F848980FB64405C038C275048345FC018345F8'
            '018B45F83B45F47CC38B45FCC9'
        )
        unit = self.load(patch_range=slice(10, 50), arch='x64')
        test = data | unit | {bytes}
        self.assertSetEqual(test, {
            h('2A233337285B4041462B202E20205F59424033212D3D37575D5B4335392C3E2A40555F5A7073756D6C6F72656D69707300'),
            h('6C6F72656D697073756D6C6F72656D697073756D6C6F72656D697073756D6C6F72656D697073756D6C6F72656D69707300'),
        })

    def test_shellcode_example(self):
        data = self.download_sample('e850f3849ea82980cf23844ad3caadf73856b2d5b0c4179847d82ce4016e80ee')
        unit = self.load_pipeline(r'officecrypt | xt oleObject1 | xt native | rex y:E9[] | vstack -a=x32 -w=80 | xtp -ff')
        self.assertEqual(data | unit | str, 'htt''p:/''/103.153.79''.104/windows10/csrss.exe')
