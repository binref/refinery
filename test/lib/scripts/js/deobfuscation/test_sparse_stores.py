"""
A store that grows an array past its end, and the holes it leaves.

`var v = u; u[87] = 5` leaves `v.length` at 88, so the growth cannot be modelled by a copy or a
wrapper: the positions the store skipped over have to live in the one array both names hold, as
slots no read treats as elements. Those slots are holes — positions an array holds no property
at, distinct from elements holding `undefined` — and every method that visits an array's elements
takes a position on them, which Node measures and each row records:

- a hole reads as `undefined` (an indexed read, `at`, `pop`, `shift`, `includes`, `find`,
  `Array.from`, the `for-of` iterator) or is skipped (`indexOf`, `map`, `filter`, `forEach`,
  `every`, `some`, `reduce`, `flat`, the `for-in` enumeration, `Object.keys`), and a `map` that
  skips one keeps a hole in its result;
- a hole is absent for `in` and `Object.keys`, and renders as the empty string under `join`,
  `String` and `+`;
- `includes` compares with SameValueZero, so `[NaN].includes(NaN)` is `true`, and it honours its
  `fromIndex` argument — both of which it did not before this grew holes;

A store the length cap refuses still refuses — a real engine grows a billion-slot array where
this one declines — and a list holding a hole, at any depth, has no literal to fold to, so the
call that produced it stands. Both are pinned by rows whose programs print what Node prints, so
the refusal is a refusal to fold and never a wrong value.

Every recorded value is Node's, and each corpus is asserted twice: against Node, which makes the
value a measurement, and against the deobfuscation, which must produce that value and write the
text the row pins.
"""
from __future__ import annotations

import inspect
import unittest

from typing import NamedTuple

from test.lib.scripts.js.analysis.differential import behavior, node_executable

from refinery.units.scripting.js import js


class _Row(NamedTuple):
    """
    One program growing an array past its end: what Node prints for it, and the text the
    deobfuscation writes for it.
    """
    printed: str
    text: str


#: A program whose store grows an array past its end and reads the array back, mapped to what Node
#: prints for it and to the text the deobfuscation writes. The store may spell its index in any
#: form that names a canonical index — a fractional or exponent spelling folds like a plain one —
#: and a key no canonical spelling names is an ordinary property the array does not accept.
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


#: A program reading a hole back through a method that visits the array's elements, mapped to what
#: Node prints for it and to the text the deobfuscation writes. The hole is built by the store in
#: every row, so what each row measures is the method's position on a hole and not the literal
#: elision this package's array builder refuses.
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


#: A program reading a hole back through a method that skips it, mapped to what Node prints for it
#: and to the text the deobfuscation writes. A `map` that skips a hole keeps one in its result, so
#: the join behind the row renders the empty string it does in Node.
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


#: A program observing a hole through the shape of the array itself — membership, enumeration,
#: rendering, the positions its copying methods keep — mapped to what Node prints for it and to
#: the text the deobfuscation writes.
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


#: The two `includes` defects this grew holes against: its equality was strict (`[NaN]` did not
#: include itself) and its `fromIndex` argument was ignored. Mapped to what Node prints for each
#: and to the text the deobfuscation writes.
_INCLUDES_COMPARING_AS_THE_SPECIFICATION_SAYS: dict[str, _Row] = {
    'function f() { return [NaN].includes(NaN); } console.log(f());': _Row(
        'true\n', 'console.log(true);',
    ),
    'function f() { var a = [1]; a[1] = 2; a[2] = 3; return a.includes(2, 2) + "|"'
    ' + a.includes(1, -2); } console.log(f());': _Row(
        'false|false\n', "console.log('false|false');",
    ),
}


#: A program producing a list that holds a hole, mapped to what Node prints for it and to the text
#: the deobfuscation writes: the call stands, because a hole has no literal to fold to — not at
#: the top level and not nested inside a result, where the residual would flip an `in` the hole
#: answered.
_A_RESULT_HOLDING_A_HOLE: dict[str, _Row] = {
    'function g() { var u = []; u[2] = 5; return [u]; } function f() { return g(); }'
    ' console.log(JSON.stringify(f()));': _Row(
        '[[null,null,5]]\n',
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
    return source.encode('utf8') | js | str


def _printed(rows: dict[str, _Row]) -> dict[str, tuple[str, str | None]]:
    """
    What Node has to make of each program of *rows*: the text the row records, with nothing thrown.
    """
    return {source: (row.printed, None) for source, row in rows.items()}


def _deobfuscated_text(rows: dict[str, _Row]) -> dict[str, str]:
    return {source: row.text for source, row in rows.items()}


def _assert_both_ways(testcase: unittest.TestCase, rows: dict[str, _Row]) -> None:
    """
    Node answers each program with the value the row records, and the deobfuscation both answers
    the same way and writes the text the row pins.
    """
    testcase.assertEqual({source: behavior(source) for source in rows}, _printed(rows))
    testcase.assertEqual(
        {source: behavior(_deobfuscated(source)) for source in rows}, _printed(rows))
    testcase.assertEqual({source: _deobfuscated(source) for source in rows}, _deobfuscated_text(rows))


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
