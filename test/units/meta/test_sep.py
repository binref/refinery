#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from . import TestMetaBase


class TestSep(TestMetaBase):

    def test_delayed_arguments_copy(self):
        unit = self.load('c:-1:')
        self.assertEqual(
            unit(
                B'Foo',
                B'Bar',
                B'Baz',
            ), [
                B'Foo', B'o',
                B'Bar', B'r',
                B'Baz',
            ]
        )

    def test_delayed_arguments_cut(self):
        unit = self.load('x:-1:')
        self.assertEqual(
            unit(
                B'Foo',
                B'Bar',
                B'Baz',
            ), [
                B'Fo', B'o',
                B'Ba', B'r',
                B'Ba',
            ]
        )
