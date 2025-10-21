from __future__ import annotations

from refinery.lib.loader import get_all_entry_points

from .. import TestBase

import sys
import shutil

from pathlib import Path


class TestLoader(TestBase):

    def test_load_stuff(self):
        ep = {u.name for u in get_all_entry_points()}
        self.assertIn('md5', ep)

    def test_regression_units_not_installed(self):
        names = {u.name for u in get_all_entry_points()}

        if sys.platform == 'win32':
            root = Path(sys.prefix) / 'Scripts'
            suffix = '.exe'
        else:
            root = Path(sys.prefix) / 'bin'
            suffix = ''

        self.assertTrue(root.exists(),
            msg=F'Scripts directory not found: {root}')

        for name in names:
            if path := shutil.which(name):
                path = Path(path)
            else:
                path = root / name
                path = path.with_suffix(suffix)
            self.assertTrue(path.exists(), msg=F'The unit {name} was not found in: {root}')
            self.assertTrue(path.is_file(), msg=F'The unit {name} exists, but is not a file.')

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
