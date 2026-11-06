from __future__ import annotations

import inspect
import unittest

from typing import NamedTuple

from test.lib.scripts.js.analysis.differential import behavior, node_executable

from refinery.units.scripting.djs import djs


class _Row(NamedTuple):
    printed: str
    text: str
    left_as: str | None = None


#: A key spelled `1.0` or `1e0` is the index 1, but `"03"` and `"+1"` are not canonical spellings of
#: an index: they make an ordinary property and leave the length alone.
_A_STORE_GROWING_AN_ARRAY: dict[str, _Row] = {
    'function f() { var u = [1]; var v = u; u[3] = 5; return v.length + "|" + v[1] + "|"'
    ' + v[2] + "|" + v[3]; } console.log(f());': _Row(
        '4|undefined|undefined|5\n', "console.log('4|undefined|undefined|5');",
    ),
    'function f() { var u = [1]; u[1.0] = 5; return u.length + "|" + u[1]; }'
    ' console.log(f());': _Row('2|5\n', "console.log('2|5');"),
    'function f() { var u = [1]; u[1e0] = 5; return u.length + "|" + u[1]; }'
    ' console.log(f());': _Row('2|5\n', "console.log('2|5');"),
    'function f() { var a = [1, 2, 3]; a.length = 2; return a.length + "|" + a[2]; }'
    ' console.log(f());': _Row('2|undefined\n', "console.log('2|undefined');"),
    'function f() { var a = [1]; a.length = 3; return a.length + "|" + a[1] + "|" + (1 in a); }'
    ' console.log(f());': _Row('3|undefined|false\n', "console.log('3|undefined|false');"),
    'function f() { var u = [1]; u["03"] = 5; return u.length + "|" + u[3]; }'
    ' console.log(f());': _Row(
        '1|undefined\n',
        "console.log('1|undefined');",
        inspect.cleandoc(
            """
            function f() {
              var u = [1];
              u["03"] = 5;
              return u.length + "|" + u[3];
            }
            console.log(f());
            """
        ),
    ),
    'function f() { var u = [1]; u["+1"] = 5; return u.length + "|" + u[3]; }'
    ' console.log(f());': _Row(
        '1|undefined\n',
        "console.log('1|undefined');",
        inspect.cleandoc(
            """
            function f() {
              var u = [1];
              u["+1"] = 5;
              return u.length + "|" + u[3];
            }
            console.log(f());
            """
        ),
    ),
    'function f() { var u = []; u[1000001] = 5; return u.length; }'
    ' console.log(f());': _Row(
        '1000002\n',
        'console.log(1000002);',
        inspect.cleandoc(
            """
            function f() {
              var u = [];
              u[1000001] = 5;
              return u.length;
            }
            console.log(f());
            """
        ),
    ),
}


_A_METHOD_READING_A_HOLE: dict[str, _Row] = {
    'function f() { var a = [1]; a[2] = 3; var out = ""; for (var x of a) out += x + "|";'
    ' return out; } console.log(f());': _Row(
        '1|undefined|3|\n', "console.log('1|undefined|3|');",
    ),
    'function f() { var a = [1]; a[2] = 3; var out = ""; for (var k in a) out += k + "|";'
    ' return out; } console.log(f());': _Row('0|2|\n', "console.log('0|2|');"),
    'function f() { var a = [1]; a[2] = 3; return a[1] === undefined; }'
    ' console.log(f());': _Row('true\n', 'console.log(true);'),
    'function f() { var a = [1]; a[2] = 3; return a.at(1); }'
    ' console.log(f());': _Row('undefined\n', 'console.log(void 0);'),
    'function f() { var a = [1]; a[2] = 3; a.length = 2; var p = a.pop();'
    ' return p + "|" + a.length; } console.log(f());': _Row(
        'undefined|1\n', "console.log('undefined|1');",
    ),
    'function f() { var a = []; a[1] = 1; var s = a.shift(); return s + "|" + a.length; }'
    ' console.log(f());': _Row('undefined|1\n', "console.log('undefined|1');"),
    'function f() { var a = []; a[1] = 1; return a.includes(undefined); }'
    ' console.log(f());': _Row('true\n', 'console.log(true);'),
    'function f() { var a = []; a[1] = 3; return a.find(function (x) { return x === undefined; }); }'
    ' console.log(f());': _Row('undefined\n', 'console.log(void 0);'),
    'function f() { var a = []; a[1] = 3; return a.findIndex(function (x)'
    ' { return x === undefined; }); } console.log(f());': _Row('0\n', 'console.log(0);'),
    'function f() { var a = [1]; a[2] = 3; var b = Array.from(a);'
    ' return b.length + "|" + (1 in b) + "|" + b[1]; } console.log(f());': _Row(
        '3|true|undefined\n', "console.log('3|true|undefined');",
    ),
}


#: A `map` that skips a hole keeps the hole in its result, so `1 in r` is `false`.
_A_METHOD_SKIPPING_A_HOLE: dict[str, _Row] = {
    'function f() { var a = [1]; a[2] = 3; var r = a.map(function (x) { return x * 10; });'
    ' return r.length + "|" + (1 in r) + "|" + r.join(","); } console.log(f());': _Row(
        '3|false|10,,30\n', "console.log('3|false|10,,30');",
    ),
    'function f() { var a = [1]; a[2] = 3; var r = a.filter(function () { return true; });'
    ' return r.length + "|" + (1 in r); } console.log(f());': _Row(
        '2|true\n', "console.log('2|true');",
    ),
    'function f() { var a = []; a[1] = 1; return a.every(function () { return false; }); }'
    ' console.log(f());': _Row('false\n', 'console.log(false);'),
    'function f() { var a = []; a[1] = 1; return a.some(function () { return true; }); }'
    ' console.log(f());': _Row('true\n', 'console.log(true);'),
    'function f() { var a = []; a[1] = 2; a[2] = 3; return a.reduce(function (a, b)'
    ' { return a + b; }); } console.log(f());': _Row('5\n', 'console.log(5);'),
    'function f() { var a = []; a[1] = 1; try { return a.reduce(function (a, b)'
    ' { return a + b; }); } catch (e) { return e.name; } } console.log(f());': _Row(
        '1\n', 'console.log(1);',
    ),
    'function f() { var a = []; a[1] = 1; var f2 = a.flat(); return f2.length + "|" + f2[0]; }'
    ' console.log(f());': _Row('1|1\n', "console.log('1|1');"),
    'function f() { var inner = [1]; inner[2] = 2; var a = [1, inner]; var f2 = a.flat();'
    ' return f2.length + "|" + (1 in f2) + "|" + f2[1]; } console.log(f());': _Row(
        '3|true|1\n', "console.log('3|true|1');",
    ),
    'function f() { var a = [1]; a[2] = 3; var k = Object.keys(a);'
    ' return k.length + "|" + k.join("|"); } console.log(f());': _Row(
        '2|0|2\n', "console.log('2|0|2');",
    ),
    'function f() { var a = []; a[1] = 1; return a.indexOf(undefined); }'
    ' console.log(f());': _Row('-1\n', 'console.log(-1);'),
}


_THE_SHAPE_OF_A_HOLEY_ARRAY: dict[str, _Row] = {
    'function f() { var a = [1]; a[2] = 3; return (1 in a) + "|" + (0 in a); }'
    ' console.log(f());': _Row('false|true\n', "console.log('false|true');"),
    'function f() { var a = [1]; a[2] = 3; a.reverse();'
    ' return a.length + "|" + (1 in a) + "|" + a[0] + "|" + a[2]; }'
    ' console.log(f());': _Row('3|false|3|1\n', "console.log('3|false|3|1');"),
    'function f() { var a = [1]; a[2] = 3; var s = a.slice();'
    ' return s.length + "|" + (1 in s); } console.log(f());': _Row(
        '3|false\n', "console.log('3|false');",
    ),
    'function f() { var a = [1]; a[2] = 3; var r = a.splice(0, 3);'
    ' return r.length + "|" + (1 in r); } console.log(f());': _Row(
        '3|false\n', "console.log('3|false');",
    ),
    'function f() { var a = [1]; a[1] = 1; var c = a.concat([4]);'
    ' return c.length + "|" + (1 in c); } console.log(f());': _Row(
        '3|true\n', "console.log('3|true');",
    ),
    'function f() { var a = [1]; a[2] = 3; a.fill(7); return a.join(","); }'
    ' console.log(f());': _Row('7,7,7\n', "console.log('7,7,7');"),
    "function f() { var a = [1]; a[2] = 3; return a.join('-'); }"
    " console.log(f());": _Row('1--3\n', "console.log('1--3');"),
    'function f() { var a = [1]; a[2] = 3; return String(a); }'
    ' console.log(f());': _Row('1,,3\n', "console.log('1,,3');"),
    "function f() { var a = [1]; a[2] = 3; return a + '|'; }"
    " console.log(f());": _Row('1,,3|\n', "console.log('1,,3|');"),
}


_INCLUDES_COMPARING_AS_THE_SPECIFICATION_SAYS: dict[str, _Row] = {
    'function f() { return [NaN].includes(NaN); } console.log(f());': _Row(
        'true\n', 'console.log(true);',
    ),
    'function f() { var a = [1]; a[1] = 2; a[2] = 3; return a.includes(2, 2) + "|"'
    ' + a.includes(1, -2); } console.log(f());': _Row(
        'false|false\n', "console.log('false|false');",
    ),
}


_A_RESULT_HOLDING_A_HOLE: dict[str, _Row] = {
    'function g() { var u = []; u[2] = 5; return [u]; } function f() { return g(); }'
    ' console.log(JSON.stringify(f()));': _Row(
        '[[null,null,5]]\n',
        "console.log('[[null,null,5]]');",
        inspect.cleandoc(
            """
            function g() {
              var u = [];
              u[2] = 5;
              return [u];
            }
            function f() {
              return g();
            }
            console.log(JSON.stringify(f()));
            """
        ),
    ),
}


def _deobfuscated(source: str) -> str:
    return source.encode('utf8') | djs | str


def _printed(rows: dict[str, _Row]) -> dict[str, tuple[str, str | None]]:
    return {source: (row.printed, None) for source, row in rows.items()}


def _assert_both_ways(testcase: unittest.TestCase, rows: dict[str, _Row]) -> None:
    testcase.assertEqual({source: behavior(source) for source in rows}, _printed(rows))
    testcase.assertEqual(
        {source: behavior(_deobfuscated(source)) for source in rows}, _printed(rows))
    for source, row in rows.items():
        written = (row.text,) if row.left_as is None else (row.text, row.left_as)
        with testcase.subTest(source=source):
            testcase.assertIn(_deobfuscated(source), written)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAStoreGrowingAnArrayPastItsEnd(unittest.TestCase):

    def test_each_row_behaves_and_writes_as_recorded(self):
        _assert_both_ways(self, _A_STORE_GROWING_AN_ARRAY)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAMethodReadingAHole(unittest.TestCase):

    def test_each_row_behaves_and_writes_as_recorded(self):
        _assert_both_ways(self, _A_METHOD_READING_A_HOLE)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAMethodSkippingAHole(unittest.TestCase):

    def test_each_row_behaves_and_writes_as_recorded(self):
        _assert_both_ways(self, _A_METHOD_SKIPPING_A_HOLE)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestTheShapeOfAHoleyArray(unittest.TestCase):

    def test_each_row_behaves_and_writes_as_recorded(self):
        _assert_both_ways(self, _THE_SHAPE_OF_A_HOLEY_ARRAY)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestIncludesComparingAsTheSpecificationSays(unittest.TestCase):

    def test_each_row_behaves_and_writes_as_recorded(self):
        _assert_both_ways(self, _INCLUDES_COMPARING_AS_THE_SPECIFICATION_SAYS)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAResultHoldingAHole(unittest.TestCase):

    def test_each_row_behaves_and_writes_as_recorded(self):
        _assert_both_ways(self, _A_RESULT_HOLDING_A_HOLE)
