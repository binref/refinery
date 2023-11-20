#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.lib.loader import load_pipeline as L
from .. import TestUnitBase


class TestMetaEat(TestUnitBase):

    def test_still_works_as_prefix(self):
        pl = L('emit foo [| put baz bar | cca eat:baz ]')
        self.assertEqual(pl(), B'foobar')

    def test_also_works_as_unit(self):
        pl = L('emit foo [| put baz bar | eat baz ]')
        self.assertEqual(pl(), B'bar')

    def test_actually_eats_variables(self):
        pl = L('emit foo [| put baz bar | eat baz | cfmt {baz}{} ]')
        self.assertEqual(pl(), B'{baz}bar')

    def test_eats_variables_inside_frames(self):
        pl = L('emit foo [| put baz bar [| eat baz | cfmt {baz} ]]')
        self.assertEqual(pl(), B'{baz}')

    def test_respects_scope(self):
        pl = L('emit foo [| put baz bar [| eat baz ]| eat baz ]')
        self.assertEqual(pl(), B'bar')

    def test_array(self):
        pl = L('emit foo [| put k btoi[1]:test | eat k | cfmt {k}{} ]')
        self.assertEqual(pl(), B'{k}test')

    def test_integer(self):
        pl = L('emit foo [| put k 10 | eat k | cfmt {k}{} ]')
        self.assertEqual(pl(), B'{k}10')
