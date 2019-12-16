#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import TestUnitBase


class TestInstrumentationWithMap(TestUnitBase):

    def test_conflicting_arguments(self):
        with self.assertRaises(ValueError):
            self.load(
                'commandline index',
                index=b'keyword index',
                image=b'keyword image'
            )

    def test_missing_arguments(self):
        with self.assertRaises(ValueError):
            self.load(index=b'lonely argument')

    def test_map_only_keywords(self):
        mp = self.load(index=b'es', image=b'uz')
        self.assertEqual(mp(b'helloes'), b'hullouz')

    def test_map_commandline_and_one_keyword(self):
        mp = self.load('es', image=b'uz')
        self.assertEqual(mp(b'helloes'), b'hullouz')

    def test_map_duplicated_but_matching(self):
        mp = self.load('es', index=b'es', image=b'uz')
        self.assertEqual(mp(b'helloes'), b'hullouz')
