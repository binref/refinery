#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase


class TestCryptDeriveKey(TestUnitBase):

    def test_SHA2(self):
        from refinery.lib.argformats import multibin
        self.assertEqual(
            multibin('take[:32]:sha256:PASSWORD'),
            multibin('CryptDeriveKey[32,SHA256]:PASSWORD'))
