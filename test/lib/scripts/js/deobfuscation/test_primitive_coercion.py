"""
Converting an object to a primitive runs the conversions the program installed on it.

`o + 3`, `` `x${o}` ``, `String(o)`, `Number(o)`, `q[o]`, `o in q`, `o * 3`, `+o`, `o++`,
`o < 'b'` and `o == 5` all ask the object for a primitive, and an object that owns a `valueOf`,
a `toString` or a `Symbol.toPrimitive` — or one whose prototype chain had one installed — answers
with whatever that code returns. The interpreter models an object as a plain data dictionary, so
it cannot run that code, and the one honest answer is to refuse the fold and leave the call to the
engine: every row below stands, and the running program prints what Node prints.

The guard is one question asked at every route that holds the effect model — the operators, the
template hole, the computed member key, the `in` key, the `String` and `Number` globals — because
the conversion a program installs decides what each of them answers, and an operator the guard
omits is a surface the same program defeats. Strict equality is the one operator that coerces
nothing and is exempt.

The price of the refusal is paid only where it is owed: an object with no conversion of its own
and an unwritten chain still folds to the string and number the language says, and so does a list
whose elements do. Each refusing row's program, minus the conversion it installed, is a row that
folds — the pair is what keeps the refusal from widening on its own.
"""
from __future__ import annotations

import unittest

from typing import NamedTuple

from test.lib.scripts.js.analysis.differential import behavior, node_executable

from refinery.units.scripting.js import js


class _Row(NamedTuple):
    """
    One program converting an object to a primitive: what Node prints for it, and the text the
    deobfuscation writes for it.
    """
    printed: str
    text: str


def _standing(body: str) -> str:
    """
    The text the deobfuscation writes for a program whose call stands: the function with its body
    intact, the call, and the print.
    """
    return F'function f() {{\n  {body}\n}}\nvar x = f();\nconsole.log(x);'


def _deobfuscated(source: str) -> str:
    return source.encode('utf8') | js | str


def _printed(rows: dict[str, _Row]) -> dict[str, tuple[str, str | None]]:
    """
    What Node has to make of each program of *rows*: the text the row records, with nothing thrown.
    """
    return {source: (row.printed, None) for source, row in rows.items()}


def _row_text(rows: dict[str, _Row]) -> dict[str, str]:
    return {source: row.text for source, row in rows.items()}


def _assert_both_ways(testcase: unittest.TestCase, rows: dict[str, _Row]) -> None:
    """
    Node answers each program with the value the row records, and the deobfuscation both answers
    the same way and writes the text the row pins.
    """
    testcase.assertEqual({source: behavior(source) for source in rows}, _printed(rows))
    testcase.assertEqual(
        {source: behavior(_deobfuscated(source)) for source in rows}, _printed(rows))
    testcase.assertEqual({source: _deobfuscated(source) for source in rows}, _row_text(rows))


#: A program whose object owns the conversion an operator needs, mapped to what Node prints for it
#: and to the text the deobfuscation writes: the call stands, the running program supplies the
#: value the installed conversion answers.
_AN_OWN_CONVERSION_ANSWERS: dict[str, _Row] = {
    'function f() { var o = {valueOf: function () { return 5; }}; return o + 3; }'
    ' var x = f(); console.log(x);': _Row(
        '8\n', _standing('var o = { valueOf: function() {\n    return 5;\n  } };\n  return o + 3;')),
    "function f() { var o = {toString: function () { return 'A'; }}; return 'x' + o; }"
    " var x = f(); console.log(x);": _Row(
        'xA\n', _standing("var o = { toString: function() {\n    return 'A';\n  } };\n  return 'x' + o;")),
    "function f() { var o = {toString: function () { return 'A'; }}; return `x${o}`; }"
    ' var x = f(); console.log(x);': _Row(
        'xA\n', _standing("var o = { toString: function() {\n    return 'A';\n  } };\n  return `x${o}`;")),
    "function f() { var o = {toString: function () { return 'A'; }}; return String(o); }"
    ' var x = f(); console.log(x);': _Row(
        'A\n', _standing("var o = { toString: function() {\n    return 'A';\n  } };\n  return String(o);")),
    'function f() { var o = {valueOf: function () { return 5; }}; return Number(o); }'
    ' var x = f(); console.log(x);': _Row(
        '5\n', _standing('var o = { valueOf: function() {\n    return 5;\n  } };\n  return Number(o);')),
    "function f() { var o = {toString: function () { return 'k'; }}; var q = {k: 7};"
    ' return q[o]; } var x = f(); console.log(x);': _Row(
        '7\n',
        _standing("var o = { toString: function() {\n    return 'k';\n  } };\n  var q = { k: 7 };\n  return q[o];")),
    "function f() { var o = {toString: function () { return 'k'; }}; var q = {k: 7};"
    ' return o in q; } var x = f(); console.log(x);': _Row(
        'true\n',
        _standing("var o = { toString: function() {\n    return 'k';\n  } };\n  var q = { k: 7 };\n  return o in q;")),
    'function f() { var o = {valueOf: function () { return 5; }}; return o * 3; }'
    ' var x = f(); console.log(x);': _Row(
        '15\n', _standing('var o = { valueOf: function() {\n    return 5;\n  } };\n  return o * 3;')),
    'function f() { var o = {valueOf: function () { return 5; }}; return +o; }'
    ' var x = f(); console.log(x);': _Row(
        '5\n', _standing('var o = { valueOf: function() {\n    return 5;\n  } };\n  return +o;')),
    'function f() { var o = {valueOf: function () { return 5; }}; return o++; }'
    ' var x = f(); console.log(x);': _Row(
        '5\n', _standing('var o = { valueOf: function() {\n    return 5;\n  } };\n  return o++;')),
    "function f() { var o = {toString: function () { return 'a'; }}; return o < 'b'; }"
    " var x = f(); console.log(x);": _Row(
        'true\n', _standing("var o = { toString: function() {\n    return 'a';\n  } };\n  return o < 'b';")),
    'function f() { var o = {valueOf: function () { return 5; }}; return o == 5; }'
    ' var x = f(); console.log(x);': _Row(
        'true\n', _standing('var o = { valueOf: function() {\n    return 5;\n  } };\n  return o == 5;')),
    "function f() { var o = {toString: function () { return 'A'; }}; return [o] + ''; }"
    " var x = f(); console.log(x);": _Row(
        'A\n', _standing("var o = { toString: function() {\n    return 'A';\n  } };\n  return [o] + '';")),
}


#: A program installing a conversion on a prototype chain, mapped to what Node prints for it and
#: to the text the deobfuscation writes. The object owns nothing; the chain supplies what the
#: program wrote there, and the chain is the effect model's to vouch for.
_A_WRITTEN_CHAIN_ANSWERS: dict[str, _Row] = {
    'function f() { Object.prototype.valueOf = function () { return 5; }; var o = {p: 1};'
    ' return o + 3; } var x = f(); console.log(x);': _Row(
        '8\n',
        _standing('Object.prototype.valueOf = function() {\n    return 5;\n  };\n  var o = { p: 1 };\n  return o + 3;')),
    'function f() { Array.prototype.valueOf = function () { return 5; }; var u = [1];'
    ' return u + 3; } var x = f(); console.log(x);': _Row(
        '8\n',
        _standing('Array.prototype.valueOf = function() {\n    return 5;\n  };\n  var u = [1];\n  return u + 3;')),
}


#: The same programs with the conversion taken out, mapped to what Node prints for them and to the
#: text the deobfuscation writes: the call folds to the value the language itself says, which is
#: what the refusal above declines to guess at.
_THE_UNINSTALLED_CONVERSION_FOLDS: dict[str, _Row] = {
    'function f() { var u = [1]; return u + 3; } var x = f(); console.log(x);': _Row(
        '13\n', "console.log('13');",
    ),
    'function f() { var o = {p: 1}; return o + 3; } var x = f(); console.log(x);': _Row(
        '[object Object]3\n', "console.log('[object Object]3');",
    ),
    'function f() { var o = {p: 1}; return String(o); } var x = f(); console.log(x);': _Row(
        '[object Object]\n', "console.log('[object Object]');",
    ),
    'function f() { var o = {p: 1}; return `x${o}`; } var x = f(); console.log(x);': _Row(
        'x[object Object]\n', "console.log('x[object Object]');",
    ),
    "function f() { var q = {k: 7}; var o = 'k'; return q[o]; } var x = f();"
    ' console.log(x);': _Row('7\n', 'console.log(7);'),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnOwnConversionAnswers(unittest.TestCase):

    def test_each_row_behaves_and_writes_as_recorded(self):
        _assert_both_ways(self, _AN_OWN_CONVERSION_ANSWERS)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAWrittenChainAnswers(unittest.TestCase):

    def test_each_row_behaves_and_writes_as_recorded(self):
        _assert_both_ways(self, _A_WRITTEN_CHAIN_ANSWERS)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestTheUninstalledConversionFolds(unittest.TestCase):

    def test_each_row_behaves_and_writes_as_recorded(self):
        _assert_both_ways(self, _THE_UNINSTALLED_CONVERSION_FOLDS)
