"""
Five spellings through which a program can replace a builtin while the tracker records nothing.

A write need not name the global it writes. A local holding the object (`var g = globalThis;
g.String = fake`) writes the `String` the file never mentions; a receiver a sloppy call supplies
(`this[k] = v` in a bare call) is the global object; a call handed the object
(`t(globalThis)`, `Reflect.set(globalThis, …)`) can write any property of it; a destructuring
pattern reads the `eval` intrinsic off the object as a value (`const {eval} = globalThis`); and an
accessor install names the key it replaces (`globalThis.__defineGetter__('String', …)`). Each was
invisible to every tracker — no write fact, no surface, no per-name record — so the fold kept
trusting the builtin the program had replaced.

The five fixes share one vocabulary rather than five spellings of their own: the write target's
base is read through `may_be_the_global_object` (the spelled names, a file-given alias, or the
receiver a call supplies), the hand-over is judged by the observation gate that already owns the
global object handed to a call, the destructuring is judged as the value-read of the intrinsic it
is, and the install is judged by the key `_installed_key` already parses. Each refusing row has a
fold twin — the same program through a receiver or object that is not the global — so the refusal
cannot widen on its own.

Every recorded behavior is Node's, and each corpus is asserted twice: against Node, which makes
the behavior a measurement, and against the deobfuscation, which must both behave the same way and
write the text the row pins — a builtin the fold kept trusting would appear folded where the
program's own text left it standing.
"""
from __future__ import annotations

import unittest

from typing import NamedTuple

from test.lib.scripts.js.analysis.differential import behavior, node_executable

from refinery.units.scripting.js import js


class _Row(NamedTuple):
    """
    One program replacing a builtin through a spelling no tracker read: what Node's behavior for it
    is, and the text the deobfuscation writes for it.
    """
    node_behavior: tuple[str, str | None]
    text: str


def _deobfuscated(source: str) -> str:
    return source.encode('utf8') | js | str


def _assert_both_ways(testcase: unittest.TestCase, rows: dict[str, _Row]) -> None:
    """
    Node answers each program with the behavior the row records, and the deobfuscation both behaves
    the same way and writes the text the row pins.
    """
    testcase.assertEqual({source: behavior(source) for source in rows}, _behaviors(rows))
    testcase.assertEqual(
        {source: behavior(_deobfuscated(source)) for source in rows}, _behaviors(rows))
    testcase.assertEqual({source: _deobfuscated(source) for source in rows}, _row_text(rows))


def _behaviors(rows: dict[str, _Row]) -> dict[str, tuple[str, str | None]]:
    return {source: row.node_behavior for source, row in rows.items()}


def _row_text(rows: dict[str, _Row]) -> dict[str, str]:
    return {source: row.text for source, row in rows.items()}


#: A write through a local holding the global object, mapped to Node's behavior for it and to the
#: text the deobfuscation writes. Both the dot spelling and the computed-literal spelling write the
#: global the key names; the twin writes a global nothing trusts and the call folds.
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


#: A write through the receiver a sloppy bare call supplies — `this` in the body of a function
#: called with no receiver — mapped to Node's behavior and to the deobfuscation's text. The twin
#: hands the function another object and the call folds.
_A_WRITE_THE_RECEIVER_SUPPLIES: dict[str, _Row] = {
    'function t() { this[k] = v; } t(); var r = String.fromCharCode(65);'
    ' console.log(r);': _Row(
        ('', 'ReferenceError'),
        'function t() {\n  this[k] = v;\n}\nt();\nvar r = String.fromCharCode(65);\nconsole.log(r);',
    ),
    'var o = {}; function t() { this[k] = v; } t.call(o);'
    ' var r = String.fromCharCode(65); console.log(r);': _Row(
        ('', 'ReferenceError'),
        'var o = {};\nfunction t() {\n  this[k] = v;\n}\nt.call(o);\n'
        'var r = String.fromCharCode(65);\nconsole.log(r);',
    ),
}


#: The global object handed to a call, mapped to Node's behavior and to the deobfuscation's text.
#: A callee that could read a property of the object it was handed could write one, and the
#: observation gate that already owns the question decides which hand-overs those are; the twin
#: hands the object to a function that touches nothing and the call folds.
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
        ('A\n', None), "function p(x) {\n  return 1;\n}\np(globalThis);\nconsole.log('A');",
    ),
}


#: A destructuring pattern reading a reflective intrinsic off the global object, mapped to Node's
#: behavior and to the deobfuscation's text. `const {eval} = globalThis` is the value-read of the
#: intrinsic under the one spelling the identifier walk cannot see, through the object itself as
#: through an alias of it; the twin destructures an ordinary object and the call folds.
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


#: An accessor install on the global object, mapped to Node's behavior and to the deobfuscation's
#: text. The receiver spelling and the argument spelling both install the named key as a global; the
#: twin installs on a local object and the call folds.
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
