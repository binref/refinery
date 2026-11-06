from __future__ import annotations

import inspect
import unittest

from typing import NamedTuple

from test import opportunity
from test.lib.scripts.js.analysis.differential import behavior, node_executable
from test.lib.scripts.js.ledger import (
    Program,
    Reading,
    before_and_after,
    folded,
    printed,
    prints,
    returned_from_a_body,
)

from refinery.units.scripting.djs import djs


class _Row(NamedTuple):
    """
    `text` is what the deobfuscation writes while the call stands, and `answer`, where given, what
    it writes once it folds the call to the value the conversion answers.
    """
    printed: str
    text: str
    answer: str | None = None

    @property
    def texts(self) -> tuple[str, ...]:
        return (self.text,) if self.answer is None else (self.text, self.answer)


def _standing(body: str) -> str:
    return F'function f() {{\n  {body}\n}}\nvar x = f();\nconsole.log(x);'


def _deobfuscated(source: str) -> str:
    return source.encode('utf8') | djs | str


def _printed(rows: dict[str, _Row]) -> dict[str, tuple[str, str | None]]:
    return {source: (row.printed, None) for source, row in rows.items()}


def _assert_both_ways(testcase: unittest.TestCase, rows: dict[str, _Row]) -> None:
    testcase.assertEqual({source: behavior(source) for source in rows}, _printed(rows))
    testcase.assertEqual(
        {source: behavior(_deobfuscated(source)) for source in rows}, _printed(rows))
    written = {source: _deobfuscated(source) for source in rows}
    testcase.assertEqual(
        {source: text for source, text in written.items() if text not in rows[source].texts},
        {},
    )


_AN_OWN_CONVERSION_ANSWERS: dict[str, _Row] = {
    'function f() { var o = {valueOf: function () { return 5; }}; return o + 3; }'
    ' var x = f(); console.log(x);': _Row(
        '8\n',
        _standing('var o = { valueOf: function() {\n    return 5;\n  } };\n  return o + 3;'),
        'console.log(8);',
    ),
    "function f() { var o = {toString: function () { return 'A'; }}; return 'x' + o; }"
    " var x = f(); console.log(x);": _Row(
        'xA\n',
        _standing("var o = { toString: function() {\n    return 'A';\n  } };\n  return 'x' + o;"),
        "console.log('xA');",
    ),
    "function f() { var o = {toString: function () { return 'A'; }}; return `x${o}`; }"
    ' var x = f(); console.log(x);': _Row(
        'xA\n',
        _standing("var o = { toString: function() {\n    return 'A';\n  } };\n  return `x${o}`;"),
        "console.log('xA');",
    ),
    "function f() { var o = {toString: function () { return 'A'; }}; return String(o); }"
    ' var x = f(); console.log(x);': _Row(
        'A\n',
        _standing("var o = { toString: function() {\n    return 'A';\n  } };\n  return String(o);"),
        "console.log('A');",
    ),
    'function f() { var o = {valueOf: function () { return 5; }}; return Number(o); }'
    ' var x = f(); console.log(x);': _Row(
        '5\n',
        _standing('var o = { valueOf: function() {\n    return 5;\n  } };\n  return Number(o);'),
        'console.log(5);',
    ),
    "function f() { var o = {toString: function () { return 'k'; }}; var q = {k: 7};"
    ' return q[o]; } var x = f(); console.log(x);': _Row(
        '7\n',
        _standing("var o = { toString: function() {\n    return 'k';\n  } };\n  var q = { k: 7 };\n  return q[o];"),
        'console.log(7);',
    ),
    "function f() { var o = {toString: function () { return 'k'; }}; var q = {k: 7};"
    ' return o in q; } var x = f(); console.log(x);': _Row(
        'true\n',
        _standing("var o = { toString: function() {\n    return 'k';\n  } };\n  var q = { k: 7 };\n  return o in q;"),
        'console.log(true);',
    ),
    'function f() { var o = {valueOf: function () { return 5; }}; return o * 3; }'
    ' var x = f(); console.log(x);': _Row(
        '15\n',
        _standing('var o = { valueOf: function() {\n    return 5;\n  } };\n  return o * 3;'),
        'console.log(15);',
    ),
    'function f() { var o = {valueOf: function () { return 5; }}; return +o; }'
    ' var x = f(); console.log(x);': _Row(
        '5\n',
        _standing('var o = { valueOf: function() {\n    return 5;\n  } };\n  return +o;'),
        'console.log(5);',
    ),
    'function f() { var o = {valueOf: function () { return 5; }}; return o++; }'
    ' var x = f(); console.log(x);': _Row(
        '5\n',
        _standing('var o = { valueOf: function() {\n    return 5;\n  } };\n  return o++;'),
        'console.log(5);',
    ),
    "function f() { var o = {toString: function () { return 'a'; }}; return o < 'b'; }"
    " var x = f(); console.log(x);": _Row(
        'true\n',
        _standing("var o = { toString: function() {\n    return 'a';\n  } };\n  return o < 'b';"),
        'console.log(true);',
    ),
    'function f() { var o = {valueOf: function () { return 5; }}; return o == 5; }'
    ' var x = f(); console.log(x);': _Row(
        'true\n',
        _standing('var o = { valueOf: function() {\n    return 5;\n  } };\n  return o == 5;'),
        'console.log(true);',
    ),
    "function f() { var o = {toString: function () { return 'A'; }}; return [o] + ''; }"
    " var x = f(); console.log(x);": _Row(
        'A\n',
        _standing("var o = { toString: function() {\n    return 'A';\n  } };\n  return [o] + '';"),
        "console.log('A');",
    ),
}


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


_A_PRIMITIVE_FIRST_OBJECT_SECOND: dict[str, _Row] = {
    'function f() { var v = 5; var out = 0; for (var i = 0; i < 2; i++)'
    ' { out += v * 2; v = { valueOf: function () { return 7; } }; } return out; }'
    ' var x = f(); console.log(x);': _Row(
        '24\n',
        'function f() {\n  var v = 5;\n  var out = 0;\n  for (var i = 0; i < 2; i++) {\n'
        '    out += v * 2;\n    v = { valueOf: function() {\n      return 7;\n    } };\n  }\n'
        '  return out;\n}\nvar x = f();\nconsole.log(x);',
        'console.log(24);',
    ),
}


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


class TestAnOwnConversionFoldsToWhatItAnswers(unittest.TestCase):

    @opportunity
    def test_each_row_folds_to_the_value_its_conversion_answers(self):
        rows = _AN_OWN_CONVERSION_ANSWERS | _A_PRIMITIVE_FIRST_OBJECT_SECOND
        self.assertEqual(
            {source: _deobfuscated(source) for source in rows},
            {source: row.answer for source, row in rows.items()},
        )


_JOIN_ANSWERS_9 = 'Array.prototype.join = function () { return "9"; };\n'

_VALUE_OF_ANSWERS_5 = 'Array.prototype.valueOf = function () { return 5; };\n'

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
        F'{_JOIN_ANSWERS_9}function f() {{ return "a9b".indexOf([5]); }}\nconsole.log(f());',
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
        self.assertEqual('console.log(5, 5, \'5\', 5, 0, 1);', folded(self._TOP_LEVEL))

    def test_the_interpreter_writes_each_value(self):
        self.assertEqual('console.log(11);', folded(self._IN_A_FUNCTION))

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_prints_the_values_written(self):
        self.assertEqual(
            (before_and_after(self._TOP_LEVEL), before_and_after(self._IN_A_FUNCTION)),
            ((('5 5 5 5 0 1\n', None),) * 2, (('11\n', None),) * 2),
        )


#: An engine joins an array that holds itself with the empty string in place of the cycle, so the
#: concatenation prints `!`.
AN_ARRAY_HOLDING_ITSELF = {
    'searched for by an array method': Program(
        returned_from_a_body('var a = []; a.push(a); return a.indexOf(a);'),
        prints('0'),
    ),
    'concatenated by an operator': Program(
        returned_from_a_body('var a = []; a.push(a); return a + "!";'),
        prints('!'),
    ),
}


class TestAnArrayHoldingItself(unittest.TestCase):

    def test_the_deobfuscation_writes_the_concatenation_as_it_reads(self):
        text = AN_ARRAY_HOLDING_ITSELF['concatenated by an operator'].text
        self.assertEqual(folded(text), printed(text))

    def test_the_deobfuscation_writes_the_search_as_it_reads_or_as_the_index_it_finds(self):
        text = AN_ARRAY_HOLDING_ITSELF['searched for by an array method'].text
        self.assertIn(folded(text), (printed(text), 'console.log(0);'))

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_each_program_still_prints_what_node_prints(self):
        rows = AN_ARRAY_HOLDING_ITSELF
        self.assertEqual(
            {label: row.read() for label, row in rows.items()},
            {label: row.required() for label, row in rows.items()},
        )


class TestASearchOfAnArrayHoldingItselfFolds(unittest.TestCase):

    @opportunity
    def test_the_search_folds_to_the_index_it_finds(self):
        text = AN_ARRAY_HOLDING_ITSELF['searched for by an array method'].text
        self.assertEqual('console.log(0);', folded(text))


_JOIN_PRINTS_RAN = 'Array.prototype.join = function () { console.log("ran"); return "9"; };\n'

A_DISCARDED_CALL_CONVERTING_THROUGH_A_REPLACED_CHAIN = {
    'parseInt': Program(
        F'{_JOIN_PRINTS_RAN}parseInt([5]);\nconsole.log(1);',
        prints('ran', '1'),
        Reading.SCRIPT,
    ),
    'Math.max': Program(
        F'{_JOIN_PRINTS_RAN}Math.max([5]);\nconsole.log(1);',
        prints('ran', '1'),
        Reading.SCRIPT,
    ),
    'isNaN': Program(
        F'{_JOIN_PRINTS_RAN}isNaN([5]);\nconsole.log(1);',
        prints('ran', '1'),
        Reading.SCRIPT,
    ),
    'an unread variable in a function': Program(
        F'{_JOIN_PRINTS_RAN}function f() {{ var x = parseInt([5]); return 1; }}\nconsole.log(f());',
        prints('ran', '1'),
        Reading.SCRIPT,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestADiscardedConversionThroughAReplacedChainStays(unittest.TestCase):

    def test_each_program_still_prints_what_node_prints(self):
        rows = A_DISCARDED_CALL_CONVERTING_THROUGH_A_REPLACED_CHAIN
        self.assertEqual(
            {label: row.read() for label, row in rows.items()},
            {label: row.required() for label, row in rows.items()},
        )


class TestADiscardedCallOverPrimitivesIsRemoved(unittest.TestCase):

    def test_the_calls_are_removed(self):
        self.assertEqual(
            'console.log(1);',
            folded('parseInt("5");\nMath.max(1, 2);\nisNaN(3);\nconsole.log(1);'),
        )
