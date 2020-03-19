#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from . import TestMetaBase
from refinery import rep, scope, cca, ccp, chop


class TestScope(TestMetaBase):

    def test_only_local_scope(self):
        pipeline = rep [ scope(1) | rep [ scope(0) | cca(B'.') ]] # noqa
        self.assertEqual(pipeline(B'FOO'), B'FOOFOO.FOO')

    def test_layer1_rescope(self):
        pipeline = rep [ scope(0) | cca(B',') | scope(1) | cca(B'.') ] # noqa
        self.assertEqual(pipeline(B'FOO'), B'FOO,FOO.')

    def test_layer2_rescope(self):
        pipeline = rep(6) [ scope('4:') | chop(1) [ scope('1:') | cca(B'A') | scope(0) | ccp(B'-') ]] # noqa
        self.assertEqual(pipeline(B'NA'), B'NANANANA-NAA-NAA')
