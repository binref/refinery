from __future__ import annotations

import inspect
import unittest

from typing import NamedTuple

from test import opportunity
from test.lib.scripts.js.analysis.differential import behavior, node_executable

from refinery.units.scripting.djs import djs


class _Row(NamedTuple):
    node_behavior: tuple[str, str | None]
    text: str


def _deobfuscated(source: str) -> str:
    return source.encode('utf8') | djs | str


def _assert_both_ways(testcase: unittest.TestCase, rows: dict[str, _Row]) -> None:
    _assert_behaves(testcase, rows)
    _assert_writes(testcase, rows)


def _assert_behaves(testcase: unittest.TestCase, rows: dict[str, _Row]) -> None:
    testcase.assertEqual({source: behavior(source) for source in rows}, _behaviors(rows))
    testcase.assertEqual(
        {source: behavior(_deobfuscated(source)) for source in rows}, _behaviors(rows))


def _assert_writes(testcase: unittest.TestCase, rows: dict[str, _Row]) -> None:
    testcase.assertEqual({source: _deobfuscated(source) for source in rows}, _row_text(rows))


def _behaviors(rows: dict[str, _Row]) -> dict[str, tuple[str, str | None]]:
    return {source: row.node_behavior for source, row in rows.items()}


def _row_text(rows: dict[str, _Row]) -> dict[str, str]:
    return {source: row.text for source, row in rows.items()}


_A_WRITE_THROUGH_AN_ALIAS_OF_THE_GLOBAL_OBJECT: dict[str, _Row] = {
    'var g = globalThis; g.String = fake; var r = String.fromCharCode(65);'
    ' console.log(r);': _Row(
        ('', 'ReferenceError'),
        'globalThis.String = fake;\nvar r = String.fromCharCode(65);\nconsole.log(r);',
    ),
    'var g = globalThis; g["String"] = fake; var r = String.fromCharCode(65);'
    ' console.log(r);': _Row(
        ('', 'ReferenceError'),
        'globalThis.String = fake;\nvar r = String.fromCharCode(65);\nconsole.log(r);',
    ),
    'var g = globalThis; g.zzz = fake; var r = String.fromCharCode(65);'
    ' console.log(r);': _Row(
        ('', 'ReferenceError'), 'fake;\nconsole.log(\'A\');',
    ),
}


_A_WRITE_THE_RECEIVER_SUPPLIES: dict[str, _Row] = {
    'function t() { this[k] = v; } t(); var r = String.fromCharCode(65);'
    ' console.log(r);': _Row(
        ('', 'ReferenceError'),
        'function t() {\n  this[k] = v;\n}\nt();\nvar r = String.fromCharCode(65);\nconsole.log(r);',
    ),
}


_A_WRITE_ANOTHER_RECEIVER_TAKES: dict[str, _Row] = {
    'var o = {}; function t() { this[k] = v; } t.call(o);'
    ' var r = String.fromCharCode(65); console.log(r);': _Row(
        ('', 'ReferenceError'),
        'var o = {};\nfunction t() {\n  this[k] = v;\n}\nt.call(o);\n'
        "console.log('A');",
    ),
}


_A_WRITE_ANOTHER_RECEIVER_TAKES_LEFT_STANDING: dict[str, str] = {
    'var o = {}; function t() { this[k] = v; } t.call(o);'
    ' var r = String.fromCharCode(65); console.log(r);': inspect.cleandoc("""
        var o = {};
        function t() {
          this[k] = v;
        }
        t.call(o);
        var r = String.fromCharCode(65);
        console.log(r);
    """),
}


_THE_OBJECT_HANDED_TO_A_CALL: dict[str, _Row] = {
    'function t(x) { x[k] = v; } t(globalThis); var r = String.fromCharCode(65);'
    ' console.log(r);': _Row(
        ('', 'ReferenceError'),
        'function t(x) {\n  x[k] = v;\n}\nt(globalThis);\n'
        'var r = String.fromCharCode(65);\nconsole.log(r);',
    ),
    'Reflect.set(globalThis, "String", 9); var r = String.fromCharCode(65);'
    ' console.log(r);': _Row(
        ('', 'TypeError'),
        'Reflect.set(globalThis, "String", 9);\nvar r = String.fromCharCode(65);\nconsole.log(r);',
    ),
    'function p(x) { return 1; } p(globalThis); var r = String.fromCharCode(65);'
    ' console.log(r);': _Row(
        ('A\n', None), "console.log('A');",
    ),
}


_A_DESTRUCTURED_INTRINSIC: dict[str, _Row] = {
    'const {eval} = globalThis; eval("String = 9"); var r = String.fromCharCode(65);'
    ' console.log(r);': _Row(
        ('', 'TypeError'),
        'const { eval } = globalThis;\neval("String = 9");\n'
        'var r = String.fromCharCode(65);\nconsole.log(r);',
    ),
    'var g = globalThis; const {eval} = g; eval("String = 9");'
    ' var r = String.fromCharCode(65); console.log(r);': _Row(
        ('', 'TypeError'),
        'var g = globalThis;\nconst { eval } = g;\neval("String = 9");\n'
        'var r = String.fromCharCode(65);\nconsole.log(r);',
    ),
    'var obj = { keys: 1 }; const {keys} = obj; var r = String.fromCharCode(65);'
    ' console.log(r, keys);': _Row(
        ('A 1\n', None), "var obj = { keys: 1 };\nconst { keys } = obj;\nconsole.log('A', keys);",
    ),
}


_AN_INSTALL_ON_THE_GLOBAL_OBJECT: dict[str, _Row] = {
    'globalThis.__defineGetter__("String", function () { return 9; });'
    ' var r = String.fromCharCode(65); console.log(r);': _Row(
        ('', 'TypeError'),
        'globalThis.__defineGetter__("String", function() {\n  return 9;\n});\n'
        'var r = String.fromCharCode(65);\nconsole.log(r);',
    ),
    'window.__defineGetter__("String", function () { return 9; });'
    ' var r = String.fromCharCode(65); console.log(r);': _Row(
        ('', 'ReferenceError'),
        'window.__defineGetter__("String", function() {\n  return 9;\n});\n'
        'var r = String.fromCharCode(65);\nconsole.log(r);',
    ),
    'Object.defineProperty(globalThis, "String", { value: 9 });'
    ' var r = String.fromCharCode(65); console.log(r);': _Row(
        ('', 'TypeError'),
        'Object.defineProperty(globalThis, "String", { value: 9 });\n'
        'var r = String.fromCharCode(65);\nconsole.log(r);',
    ),
    'var o = {}; o.__defineGetter__("x", function () { return 9; });'
    ' var r = String.fromCharCode(65); console.log(r);': _Row(
        ('A\n', None),
        'var o = {};\no.__defineGetter__("x", function() {\n  return 9;\n});\n'
        "console.log('A');",
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAWriteThroughAnAliasOfTheGlobalObject(unittest.TestCase):

    def test_each_row_behaves_and_writes_as_recorded(self):
        _assert_both_ways(self, _A_WRITE_THROUGH_AN_ALIAS_OF_THE_GLOBAL_OBJECT)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAWriteTheReceiverSupplies(unittest.TestCase):

    def test_each_row_behaves_and_writes_as_recorded(self):
        _assert_both_ways(self, _A_WRITE_THE_RECEIVER_SUPPLIES)

    def test_a_write_another_receiver_takes_behaves_as_recorded(self):
        _assert_behaves(self, _A_WRITE_ANOTHER_RECEIVER_TAKES)

    def test_a_write_another_receiver_takes_writes_the_source_or_the_folded_text(self):
        for source, row in _A_WRITE_ANOTHER_RECEIVER_TAKES.items():
            with self.subTest(source=source):
                self.assertIn(
                    _deobfuscated(source),
                    (_A_WRITE_ANOTHER_RECEIVER_TAKES_LEFT_STANDING[source], row.text),
                )

    @opportunity
    def test_a_write_another_receiver_takes_writes_the_folded_text(self):
        _assert_writes(self, _A_WRITE_ANOTHER_RECEIVER_TAKES)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestTheObjectHandedToACall(unittest.TestCase):

    def test_each_row_behaves_and_writes_as_recorded(self):
        _assert_both_ways(self, _THE_OBJECT_HANDED_TO_A_CALL)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestADestructuredIntrinsic(unittest.TestCase):

    def test_each_row_behaves_and_writes_as_recorded(self):
        _assert_both_ways(self, _A_DESTRUCTURED_INTRINSIC)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnInstallOnTheGlobalObject(unittest.TestCase):

    def test_each_row_behaves_and_writes_as_recorded(self):
        _assert_both_ways(self, _AN_INSTALL_ON_THE_GLOBAL_OBJECT)
