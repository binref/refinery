#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase


class TestPyInstallerExtractor(TestUnitBase):

    def test_regular_entry_point_extraction(self):
        data = self.download_sample('1edcad6274bc18804a87ca7e4e8d0ae86649ec3970f25c9323de7c5370f2d8d7')
        unit = self.load(user_code=True)
        carve = self.ldu('carve', 'b64', single=True, decode=True)
        result = str(data | unit | carve)
        self.assertIn("s.connect(('10.0.2.15',3334))", result)
        self.assertIn("uct.unpack('>I',s.recv(4))[0]", result)

    def test_password_protected_archive(self):
        data = self.download_sample('1edcad6274bc18804a87ca7e4e8d0ae86649ec3970f25c9323de7c5370f2d8d7')
        unit = self.load('*/unittest/case.py', unmarshal=2)
        result = str(data | unit)
        self.assertIn(R'difflib.ndiff(pprint.pformat(seq1).splitlines(), pprint.pformat(seq2).splitlines())', result)

    def test_plaintext_entry_point_extraction(self):
        data = self.download_sample('904df5d6b900fcdac44c002f03ab1fbc698b8d421a22639819b3b208aaa6ea2c')
        unit = self.load(user_code=True, decompile=True)
        result = str(data | unit)
        self.assertIn('AESCipher("RVX0WKdzfwd4ynICDqJL9YjUjly1ehv7")', result)

    def test_unprotected_library_extraction(self):
        data = self.download_sample('904df5d6b900fcdac44c002f03ab1fbc698b8d421a22639819b3b208aaa6ea2c')
        unit = self.load('out00-PYZ/uuid.py', unmarshal=2)
        result = str(data | unit)
        self.assertIn('6ba7b810-9dad-11d1-80b4-00c04fd430c8', result)
