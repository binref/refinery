#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from ... import TestUnitBase


class TestConcat(TestUnitBase):

    def test_trivial(self):
        self.assertEqual(self.load()(b"'T'+'b'"), b'"Tb"')

    def test_uneven(self):
        self.assertEqual(self.load()(b"'T'+'b'+'c'"), b'"Tbc"')

    def test_even_amp(self):
        self.assertEqual(self.load()(b'"bla" & "foo"'), b'"blafoo"')

    def test_uneven_amp(self):
        self.assertEqual(self.load()(b'"bla" & "foo" & "bar"'), b'"blafoobar"')

    def test_uneven_special_chars(self):
        self.assertEqual(self.load()(b'"bla " & "\\foo" & "bar baz"'), b'"bla \\foobar baz"')
