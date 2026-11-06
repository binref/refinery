from __future__ import annotations

import ast
import pathlib
import subprocess
import sys

from typing import Iterator

from test import TestBase

import refinery
import refinery.lib.scripts.js

_PACKAGE = pathlib.Path(refinery.lib.scripts.js.__file__).parent
_ROOT = pathlib.Path(refinery.__file__).parent.parent
_PASSES = 'refinery.lib.scripts.js.deobfuscation'


def _package_of(path: pathlib.Path) -> str:
    return '.'.join(('refinery', 'lib', 'scripts', 'js', *path.relative_to(_PACKAGE).parent.parts))


def _callee_name(call: ast.Call) -> str | None:
    if isinstance(callee := call.func, ast.Name):
        return callee.id
    if isinstance(callee, ast.Attribute):
        return callee.attr
    return None


def _imported_modules(path: pathlib.Path) -> Iterator[str]:
    package = _package_of(path)
    for node in ast.walk(ast.parse(path.read_text(encoding='utf-8'))):
        if isinstance(node, ast.Import):
            yield from (alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ''
            if node.level:
                anchor = package.rsplit('.', node.level - 1)[0]
                base = F'{anchor}.{base}' if base else anchor
            yield base
            yield from (F'{base}.{alias.name}' for alias in node.names)
        elif (
            isinstance(node, ast.Call)
            and _callee_name(node) in ('import_module', '__import__')
            and node.args
            and isinstance(name := node.args[0], ast.Constant)
            and isinstance(name.value, str)
        ):
            yield name.value


def _names_the_passes(module: str) -> bool:
    return module == _PASSES or module.startswith(F'{_PASSES}.')


class TestTheDeobfuscationPassesAreTheTopLayerOfTheJsPackage(TestBase):

    def test_no_module_outside_the_passes_imports_them(self):
        importers = []
        for path in sorted(_PACKAGE.rglob('*.py')):
            relative = path.relative_to(_PACKAGE)
            if relative.parts[0] == 'deobfuscation':
                continue
            if any(_names_the_passes(module) for module in _imported_modules(path)):
                importers.append(relative.as_posix())
        self.assertEqual(importers, [])

    def test_the_printer_imports_in_a_fresh_interpreter(self):
        program = F'import sys; sys.path.insert(0, {str(_ROOT)!r}); import refinery.lib.scripts.js.synth'
        run = subprocess.run([sys.executable, '-I', '-c', program], capture_output=True, text=True)
        self.assertEqual(run.stderr, '')
