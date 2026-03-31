from __future__ import annotations

import re
import sys
import shutil

from pathlib import Path

from refinery.lib.loader import get_all_entry_points
from refinery.lib.tools import normalize_to_identifier

from .. import TestBase


class TestLoader(TestBase):

    def test_load_stuff(self):
        ep = {u.name for u in get_all_entry_points()}
        self.assertIn('md5', ep)

    def test_regression_units_not_installed(self):
        import refinery

        names = {u.name for u in get_all_entry_points()}
        root = Path(sys.prefix)

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
            self.assertTrue(path.exists(),
                msg=F'The unit {name} does not exist under its expected path: {root}')
            self.assertTrue(path.is_file(),
                msg=F'The unit {name} exists, but is not a file: {path}')
            self.assertTrue(hasattr(refinery, normalize_to_identifier(name)),
                msg=F'The unit {name} is not exported by the refinery base module.')

        stub_path = Path(refinery.__file__).with_suffix('.pyi')
        self.assertTrue(stub_path.exists(),
            msg='The type stub file refinery/__init__.pyi does not exist.')
        stub_text = stub_path.read_text(encoding='utf-8')
        stub_exports = set(re.findall(r'import (\w+) as \1', stub_text))
        stub_exports -= {'Unit', 'Arg'}
        class_names = {u.__name__ for u in get_all_entry_points()}
        self.assertEqual(class_names, stub_exports,
            msg='The type stub file refinery/__init__.pyi is out of date.')

        from refinery.__unit__ import UNITS
        self.assertEqual(class_names, set(UNITS),
            msg='The unit map file refinery/__unit__.py is out of date.')

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
