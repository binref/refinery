#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.lib.loader import load_pipeline
from .. import temporary_clipboard, thread_group, TestUnitBase


class TestEmitter(TestUnitBase):

    def test_append(self):
        emit = self.load('x::', 'World')
        self.assertEqual(emit(B'Hello'), B'Hello\nWorld')

    def test_prepend(self):
        emit = self.load('Hello', 'x::')
        self.assertEqual(emit(B'World'), B'Hello\nWorld')

    def test_prepend_and_append(self):
        emit = self.load('Hello', 'x::', 'World')
        self.assertEqual(emit(B'cruel'), B'Hello\ncruel\nWorld')

    @thread_group('clipboard')
    def test_emit_keeps_metadata_01(self):
        with temporary_clipboard('baz'):
            pl = load_pipeline('emit a [| put foo bar | emit | pf {foo}{} ]')
            pl = bytes(pl())
        self.assertEqual(pl, b'barbaz')

    @thread_group('clipboard')
    def test_emit_keeps_metadata_02(self):
        with temporary_clipboard('baz'):
            pl = load_pipeline('emit bort | push [| rex (?P<foo>...)t | pop | emit | pf {foo}{} ]')
            pl = bytes(pl())
        self.assertEqual(pl, b'borbaz')
