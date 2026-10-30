"""
Converting an object to a primitive runs the conversions the program installed on it.

`o + 3`, `` `x${o}` ``, `String(o)`, `Number(o)`, `q[o]`, `o in q`, `o * 3`, `+o`, `o++`,
`o < 'b'` and `o == 5` all ask the object for a primitive, and an object that owns a `valueOf`,
a `toString` or a `Symbol.toPrimitive` — or one whose prototype chain had one installed — answers
with whatever that code returns. The interpreter models an object as a plain data dictionary, so
it cannot run that code, and the one honest answer is to refuse the fold and leave the call to the
engine: every row below stands, and the running program prints what Node prints.

The guard is one question asked at every route that holds the effect model — the operators, the
template hole, the computed member key, the `in` key, every argument a built-in is handed, and the
operand of a unary operator the constant fold reads — because the conversion a program installs
decides what each of them answers, and a route the guard omits is a surface the same program
defeats. Strict equality is the one operator that coerces nothing and is exempt.

The price of the refusal is paid only where it is owed: an object with no conversion of its own
and an unwritten chain still folds to the string and number the language says, and so does a list
whose elements do. Each refusing row's program, minus the conversion it installed, is a row that
folds — the pair is what keeps the refusal from widening on its own.
"""
from __future__ import annotations

import inspect
import unittest

from typing import NamedTuple

from test.lib.scripts.js.analysis.differential import behavior, node_executable
from test.lib.scripts.js.ledger import Program, Reading, before_and_after, folded, prints

from refinery.units.scripting.djs import djs


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
    return source.encode('utf8') | djs | str


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


#: The same operator, run on a primitive and then on an object that owns a conversion, mapped to
#: what Node prints for it and to the text the deobfuscation writes: the fold the first reading
#: earned does not extend to the object the second reads.
_A_PRIMITIVE_FIRST_OBJECT_SECOND: dict[str, _Row] = {
    'function f() { var v = 5; var out = 0; for (var i = 0; i < 2; i++)'
    ' { out += v * 2; v = { valueOf: function () { return 7; } }; } return out; }'
    ' var x = f(); console.log(x);': _Row(
        '24\n',
        'function f() {\n  var v = 5;\n  var out = 0;\n  for (var i = 0; i < 2; i++) {\n'
        '    out += v * 2;\n    v = { valueOf: function() {\n      return 7;\n    } };\n  }\n'
        '  return out;\n}\nvar x = f();\nconsole.log(x);'),
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


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAPrimitiveFirstObjectSecond(unittest.TestCase):

    def test_each_row_behaves_and_writes_as_recorded(self):
        _assert_both_ways(self, _A_PRIMITIVE_FIRST_OBJECT_SECOND)


_JOIN_ANSWERS_9 = "Array.prototype.join = function () { return '9'; };\n"

_VALUE_OF_ANSWERS_5 = 'Array.prototype.valueOf = function () { return 5; };\n'

#: A program replacing a method that converting an array runs and then converting an array, mapped
#: to what Node prints: a built-in handed the array and a unary operator over it each run the
#: replacement. The rows at the top level are the constant fold's, and the rows inside a function
#: are the interpreter's, one for a global function, a static method and a string method each.
AN_ARRAY_CONVERTED_THROUGH_A_REPLACED_CHAIN = {
    'by Number': Program(F'{_JOIN_ANSWERS_9}console.log(Number([5]));', prints('9'), Reading.SCRIPT),
    'by parseInt': Program(F'{_JOIN_ANSWERS_9}console.log(parseInt([5]));', prints('9'), Reading.SCRIPT),
    'by String': Program(F'{_JOIN_ANSWERS_9}console.log(String([5]));', prints('9'), Reading.SCRIPT),
    'by a unary plus': Program(F'{_JOIN_ANSWERS_9}console.log(+[5]);', prints('9'), Reading.SCRIPT),
    'by a unary plus asking valueOf': Program(
        F'{_VALUE_OF_ANSWERS_5}console.log(+[]);',
        prints('5'),
        Reading.SCRIPT,
    ),
    'by a sum over a unary plus': Program(
        F'{_VALUE_OF_ANSWERS_5}console.log(+[] + 1);',
        prints('6'),
        Reading.SCRIPT,
    ),
    'by parseInt in a function': Program(
        F'{_JOIN_ANSWERS_9}function f() {{ return parseInt([5]); }}\nconsole.log(f());',
        prints('9'),
        Reading.SCRIPT,
    ),
    'by Math.max in a function': Program(
        F'{_JOIN_ANSWERS_9}function f() {{ return Math.max([5], 1); }}\nconsole.log(f());',
        prints('9'),
        Reading.SCRIPT,
    ),
    'by a string method in a function': Program(
        F"{_JOIN_ANSWERS_9}function f() {{ return 'a9b'.indexOf([5]); }}\nconsole.log(f());",
        prints('1'),
        Reading.SCRIPT,
    ),
    'a function with its own conversion searched for by a string method': Program(
        inspect.cleandoc('''
            function W(a) { return a + 1; }
            W.toString = function () { return "x"; };
            function f() { return 'axb'.indexOf(W); }
            console.log(f());
        '''),
        prints('1'),
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAConversionThroughAReplacedChainIsNotFolded(unittest.TestCase):

    def test_each_program_still_prints_what_node_prints(self):
        rows = AN_ARRAY_CONVERTED_THROUGH_A_REPLACED_CHAIN
        self.assertEqual(
            {label: row.read() for label, row in rows.items()},
            {label: row.required() for label, row in rows.items()},
        )


class TestTheSameConversionsFoldWhereNothingWasReplaced(unittest.TestCase):

    _TOP_LEVEL = 'console.log(Number([5]), parseInt([5]), String([5]), +[5], +[], +[] + 1);'

    _IN_A_FUNCTION = inspect.cleandoc('''
        function f() { return parseInt([5]) + Math.max([5], 1) + 'a5b'.indexOf([5]); }
        console.log(f());
    ''')

    def test_the_constant_fold_writes_each_value(self):
        self.assertEqual("console.log(5, 5, '5', 5, 0, 1);", folded(self._TOP_LEVEL))

    def test_the_interpreter_writes_each_value(self):
        self.assertEqual('console.log(11);', folded(self._IN_A_FUNCTION))

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_prints_the_values_written(self):
        self.assertEqual(
            (before_and_after(self._TOP_LEVEL), before_and_after(self._IN_A_FUNCTION)),
            ((('5 5 5 5 0 1\n', None),) * 2, (('11\n', None),) * 2),
        )
