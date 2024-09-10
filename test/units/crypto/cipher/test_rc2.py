#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase


class TestRC2(TestUnitBase):

    def test_dotnet_eks_derivation(self):
        data = b'U4dbuch3yV0yPCA7W+zIag'
        rc2 = self.load(b'System', derive_eks=True, mode='cbc')
        b64 = self.ldu('b64')
        self.assertEqual(data | b64 | rc2 | str, 'InvokeMethod')

    def test_bare_pycryptodome_vectors(self):
        vectors = {
            10: b'\xb8\x96\xb7\x2a\x5b\x4a\x03\x0c',
            20: b'\x22\x0b\xfd\x7a\xf4\x32\x8c\xb0',
            30: b'\xf8\x1d\xbe\xfe\xff\x9e\x70\xf4',
            40: b'\x52\xe3\x32\xd1\xb5\xd6\xb0\x77',
            50: b'\xb5\xc0\x92\xd6\xef\x75\x34\x85',
            60: b'\xdc\xc3\xa7\xdd\xa6\x5f\x5b\x7a',
            70: b'\x32\x55\x67\x68\x7a\x39\x8a\xfe',
            80: b'\xac\xb0\xd2\xe4\x63\xbb\xec\xb2',
            90: b'\x6a\xf7\x13\x91\xf0\xe1\x44\xbc',
        }
        for k, vec in vectors.items():
            rc2 = self.load(B'A' * k, mode='ecb', reverse=True, raw=True)
            self.assertEqual(bytes(range(8)) | rc2 | bytes, vec)
