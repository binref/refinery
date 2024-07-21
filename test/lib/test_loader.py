#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.lib.loader import get_all_entry_points

from .. import TestBase


class TestLoader(TestBase):

    def test_load_stuff(self):
        ep = {u.name for u in get_all_entry_points()}
        self.assertIn('md5', ep)

    def test_loader_imports(self):
        from refinery.lib import loader
        from refinery import aes
        from refinery import rex
        from refinery import b64
        from refinery.units.crypto.cipher.aes import aes as aes_
        from refinery.units.pattern.rex import rex as rex_
        from refinery.units.encoding.b64 import b64 as b64_
        self.assertIs(aes, aes_)
        self.assertIs(b64, b64_)
        self.assertIs(rex, rex_)
        self.assertIs(aes, loader.get_entry_point('aes'))
        self.assertIs(b64, loader.get_entry_point('b64'))
        self.assertIs(rex, loader.get_entry_point('rex'))

    def test_unique_entry_point_names(self):
        entry_points = {}
        for entry in get_all_entry_points():
            self.assertNotIn(entry.__qualname__, entry_points)
            entry_points[entry.__qualname__] = entry
        self.assertGreaterEqual(len(entry_points), 10)
