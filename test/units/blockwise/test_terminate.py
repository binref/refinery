#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestTerminate(TestUnitBase):

    def test_terminate_dot(self):
        unit = self.load('.')
        self.assertEqual(bytes(b'hello.world' | unit), b'hello')

    def test_terminate_unicode(self):
        unit = self.load('H:0000', blocksize=2)
        data = 'Foobar'.encode('utf-16le') + B'\0\0Ixnay'
        self.assertEqual(bytes(data | unit | self.ldu('u16')), b'Foobar')
