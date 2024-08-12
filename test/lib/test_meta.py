#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import Iterable, List

from refinery.lib.meta import metavars
from refinery.lib.frame import Chunk
from refinery.lib.loader import load_pipeline as L, load_detached as U
from refinery.units import Unit

from .. import TestBase


class TestMeta(TestBase):

    def test_binary_printer_for_integer_arrays(self):
        data = Chunk()
        data['k'] = [t for t in b'refinery']
        meta = metavars(data)
        self.assertEqual(meta.format_bin('{k:itob}', 'utf8', data), b'refinery')

    def test_binary_formatter_fallback(self):
        data = self.generate_random_buffer(3210)
        meta = metavars(data)
        self.assertEqual(meta.format_bin('{size!r}', 'utf8', data).strip(), b'03.210 kB')

    def test_binary_formatter_literal(self):
        meta = metavars(B'')
        self.assertEqual(meta.format_bin('{726566696E657279!H}', 'utf8'), b'refinery')

    def test_hex_byte_strings(self):
        pl = L('emit Hello [| cm -2 | cfmt {sha256!r} ]')
        self.assertEqual(pl(), b'185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969')

    def test_intrinsic_properties_are_recomputed(self):
        pl = L('emit FOO-BAR [| cm size | snip :1 | cfmt {size} ]')
        self.assertEqual(pl(), B'1')

    def test_magic_values_update(self):
        pl = L('emit FOO-BAR [| cm sha256 | snip :3 | cfmt {sha256} ]')
        self.assertEqual(pl(), b'9520437ce8902eb379a7d8aaa98fc4c94eeb07b6684854868fa6f72bf34b0fd3')

    def test_costly_variable_is_discarded(self):
        out, = L('emit rep[0x2000]:X [| cm sha256 | snip 1: ]')
        self.assertNotIn('sha256', out.meta.keys())

    def test_cheap_variable_is_not_discarded(self):
        out, = L('emit rep[0x100]:X [| cm sha256 | snip 1: | mvg ]')
        self.assertIn('sha256', set(out.meta.keys()))
        self.assertEqual(out.meta['sha256'], '439d26737c1313821f1b5e953a866e680a3712086f7b27ffc2e3e3f224e04f3f')

    def test_history_storage(self):
        class spy(Unit):
            chunks: List[Chunk] = []

            def filter(self, inputs: Iterable[Chunk]) -> Iterable[Chunk]:
                for chunk in inputs:
                    spy.chunks.append(chunk.copy())
                    yield chunk

        spy.chunks.clear()
        B'' | U('put x alpha [') | U('nop [[') | U('put x alpha') | spy | U('nop ]]]') | None
        self.assertEqual(len(spy.chunks), 1)
        self.assertDictEqual(spy.chunks[0].meta.history, {'x': [
            (False, b'alpha'), (True, 0), (True, 0)]})

        spy.chunks.clear()
        B'' | U('put x alpha [') | U('nop [[') | U('put x alpha') | U('mvg ]') | spy | U('nop ]]') | None
        self.assertEqual(len(spy.chunks), 1)
        self.assertDictEqual(spy.chunks[0].meta.history, {'x': [
            (False, b'alpha'), (True, 0)]})

        spy.chunks.clear()
        B'' | U('put x alpha [') | U('nop [[') | U('put x beta') | spy | U('nop ]]]') | None
        self.assertEqual(len(spy.chunks), 1)
        self.assertDictEqual(spy.chunks[0].meta.history, {'x': [
            (False, b'alpha'), (True, 0), (False, b'beta')]})

        spy.chunks.clear()
        B'' | U('put x alpha [') | U('nop [[') | U('put x beta') | U('mvg ]') | spy | U('nop ]]') | None
        self.assertEqual(len(spy.chunks), 1)
        self.assertDictEqual(spy.chunks[0].meta.history, {'x': [
            (False, b'alpha'), (False, b'beta')]})

    def test_regression_nulled_history(self):
        pl = L('emit FOO [[| put b [| emit BAR ]| rex . | swap k | swap b | cfmt {}/{k} | sep / ]]')
        self.assertEqual(pl(), B'FOO/B/FOO/A/FOO/R')

    def test_wrapper_works_after_deserialization(self):
        e1 = L('emit range:0x100 [| cm entropy | cfmt {entropy!r} ]') | str
        e2 = L('emit range:0x100 | cfmt {entropy!r}') | str
        self.assertEqual(e1, e2)
        self.assertEqual(e1, '100.00%')
