from __future__ import annotations

import inspect
import unittest

from typing import NamedTuple

from test import TestBase, opportunity
from test.lib.scripts.js.analysis.differential import behavior, code_units, node_executable

from refinery.units.scripting.djs import djs


class _Store(NamedTuple):
    call: str
    printed: str
    setup: str = 'var v = 0;'
    read: str = 'v'

    @property
    def program(self) -> str:
        return F'{self.setup}\nconsole.log({self.call});\nconsole.log({self.read});'


class _Rewrite(NamedTuple):
    source: str
    result: str
    cleaned: str | None = None

    @property
    def texts(self) -> tuple[str, ...]:
        return (self.result,) if self.cleaned is None else (self.result, self.cleaned)


_A_FUNCTION_THAT_WRITES = inspect.cleandoc(
    """
    var v = 0;
    function bump() {
      v = 3;
      return 1.5;
    }
    """
)

_A_FUNCTION_THAT_WRITES_AND_NAMES_A_METHOD = inspect.cleandoc(
    """
    var v = 0;
    function pick() {
      v = 5;
      return 'floor';
    }
    """
)

_A_STORE_INSIDE_THE_CALL: dict[str, _Store] = {
    'an assigned argument': _Store('Math.floor(v = 4.7)', '4\n4.7\n'),
    'a compound assignment': _Store('Math.floor(v += 3.5)', '3\n3.5\n'),
    'a postfix update': _Store('Math.floor(v++)', '0\n1\n'),
    'a logical assignment': _Store('Math.floor(v ??= 2.5)', '2\n2.5\n', 'var v = null;'),
    'a comma operand': _Store('Math.max(1, (v = 9, 2))', '2\n9\n'),
    'a summand': _Store('String.fromCharCode(65 + (v = 1))', 'B\n1\n'),
    'a template substitution': _Store('parseInt(`${v = 7}`)', '7\n7\n'),
    'a spread element': _Store('Math.max(...[v = 5, 2])', '5\n5\n'),
    'a destructuring assignment': _Store('Math.max(1, ([v] = [9])[0])', '9\n9\n'),
    'a delete': _Store(
        'Math.max(1, delete o.k ? 2 : 3)', '2\nundefined\n', 'var o = {k: 1};', 'o.k'
    ),
    'a property store': _Store('Math.max(1, a[0] = 5)', '5\n5\n', 'var a = [0];', 'a[0]'),
    'a called function that writes': _Store(
        'Math.floor(bump())', '1\n3\n', _A_FUNCTION_THAT_WRITES
    ),
    'an immediately invoked arrow': _Store('Math.floor((() => v = 4.5)())', '4\n4.5\n'),
    'an argument of an optional call': _Store('Math?.floor(v = 3.5)', '3\n3.5\n'),
    'an argument of a nested fold': _Store('Math.floor(Math.max(v = 2.7, 1))', '2\n2.7\n'),
    'an argument of a literal receiver': _Store("'abcb'.indexOf('b', v = 2)", '3\n2\n'),
    'an element of the literal receiver': _Store("[v = 1, 2].join('-')", '1-2\n1\n'),
    'an element of a chained receiver': _Store("[v = 1, 2].map(String).join('-')", '1-2\n1\n'),
    'a call in the literal receiver': _Store(
        "[bump(), 2].join('-')", '1.5-2\n3\n', _A_FUNCTION_THAT_WRITES
    ),
    'a receiver folded from a concatenation': _Store("('a' + (v = 'b')).indexOf('b')", '1\nb\n'),
    'the key that names the method': _Store("Math[v = 'floor'](1.9)", '1\nfloor\n'),
    'the key that names a string method': _Store("'abcb'[v = 'indexOf']('b')", '1\nindexOf\n'),
    'the key that names an array method': _Store("[1, 2][v = 'join']('-')", '1-2\njoin\n'),
    'the key that names a constructor method': _Store(
        "String[v = 'fromCharCode'](65)", 'A\nfromCharCode\n'
    ),
    'a comma operand inside the key': _Store("Math[(v = 9, 'floor')](1.9)", '1\n9\n'),
    'a called function that names the method': _Store(
        'Math[pick()](1.9)', '1\n5\n', _A_FUNCTION_THAT_WRITES_AND_NAMES_A_METHOD
    ),
}
"""
Each position a store can be written in inside a call that would otherwise fold, mapped to the
program that performs it and to what Node prints for that program. The value the fold would answer
with is printed first, so the first line stays whether or not the fold happened and only the second
line says whether the store survived it.
"""

_FOLDED: dict[str, str] = {
    'Math.floor(4.7)': '4',
    'Math.max(1, 2 + 3)': '5',
    'String.fromCharCode(72, 105)': "'Hi'",
    "'abcb'.indexOf('b', 2)": '3',
    "'abc'.toUpperCase()": "'ABC'",
    "[1, 2, 3].join('-')": "'1-2-3'",
    "[1, 2, 3].slice(1).join('')": "'23'",
    'Math.floor(Math.max(1.5, 2.5))': '2',
    "String.fromCharCode('abc'.charCodeAt(1))": "'b'",
    "[1, 2].map(function (x) { return x * 2; }).join('')": "'24'",
    "parseInt('42', 10)": '42',
}

_FOLDS_BESIDE_A_STORE: dict[str, _Rewrite] = {
    'a store in a later statement': _Rewrite(
        inspect.cleandoc(
            """
            var v = 0;
            console.log(Math.floor(4.7));
            v = 1;
            console.log(v);
            """
        ),
        inspect.cleandoc(
            """
            var v = 0;
            console.log(4);
            v = 1;
            console.log(v);
            """
        ),
        inspect.cleandoc(
            """
            console.log(4);
            console.log(1);
            """
        ),
    ),
    'a store in a sibling argument': _Rewrite(
        inspect.cleandoc(
            """
            var v = 0;
            console.log(Math.floor(4.7), (v = 2, 3));
            console.log(v);
            """
        ),
        inspect.cleandoc(
            """
            var v = 0;
            console.log(4, (v = 2, 3));
            console.log(v);
            """
        ),
        inspect.cleandoc(
            """
            console.log(4, 3);
            console.log(2);
            """
        ),
    ),
    'a store the argument reads back': _Rewrite(
        inspect.cleandoc(
            """
            var v = 4.7;
            console.log(Math.floor(v));
            """
        ),
        'console.log(4);',
    ),
    'a store in a function written down and never called': _Rewrite(
        inspect.cleandoc(
            """
            var v = 0;
            console.log(Math.max(1, (function () {
              v = 5;
            }, 2)));
            console.log(v);
            """
        ),
        inspect.cleandoc(
            """
            console.log(2);
            console.log(0);
            """
        ),
    ),
    'a called function that stores nothing': _Rewrite(
        inspect.cleandoc(
            """
            function half() {
              return 2.5;
            }
            console.log(Math.floor(half()));
            """
        ),
        'console.log(2);',
    ),
}
"""
A program whose call the fold must still reach, mapped to the text `refinery.djs` leaves it as and,
where a later read takes a store the program keeps, to the cleaner text that carries the store into
the read. Each of them stores somewhere the fold does not reach — a neighbouring statement, a
sibling argument, a function written down and never called — or reads back a store the fold may
carry through, and the call is decided by what is written in it either way. A refusal here is
invisible to Node, which is why the text is what these rows assert.
"""


def _deobfuscated(source: str) -> str:
    return source.encode('utf8') | djs(strict=True) | str


def _fold(expression: str) -> str:
    printed = _deobfuscated(F'console.log({expression});')
    return printed.removeprefix('console.log(').removesuffix(');')


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAStorePerformedWhileTheCallIsEvaluated(TestBase):

    def test_node_prints_what_each_row_records(self):
        for position, store in _A_STORE_INSIDE_THE_CALL.items():
            with self.subTest(position=position):
                self.assertEqual(behavior(store.program), (store.printed, None))

    def test_the_deobfuscated_program_prints_the_same(self):
        for position, store in _A_STORE_INSIDE_THE_CALL.items():
            deobfuscated = _deobfuscated(store.program)
            with self.subTest(position=position):
                self.assertEqual(
                    behavior(deobfuscated),
                    (store.printed, None),
                    F'deobfuscation changed observable behavior; result was:\n{deobfuscated}',
                )


class TestACallNothingInWhichStoresIsFoldedAway(TestBase):

    def test_each_call_folds_to_the_value_it_computes(self):
        for expression, folded in _FOLDED.items():
            with self.subTest(expression=expression):
                self.assertEqual(_fold(expression), folded)

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_values_each_call_and_the_text_it_folded_to_alike(self):
        self.assertEqual(code_units(list(_FOLDED)), code_units(list(_FOLDED.values())))


class TestAStoreTheFoldDoesNotReachDoesNotStopIt(TestBase):

    def test_each_program_is_left_as_a_text_the_row_records(self):
        for name, rewrite in _FOLDS_BESIDE_A_STORE.items():
            with self.subTest(name=name):
                self.assertIn(_deobfuscated(rewrite.source), rewrite.texts)

    @opportunity
    def test_a_store_a_later_read_takes_is_carried_into_the_read(self):
        rows = {name: rewrite for name, rewrite in _FOLDS_BESIDE_A_STORE.items() if rewrite.cleaned}
        self.assertEqual(
            {name: _deobfuscated(rewrite.source) for name, rewrite in rows.items()},
            {name: rewrite.cleaned for name, rewrite in rows.items()},
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_prints_the_same_for_each_program_and_each_text_it_may_be_left_as(self):
        for name, rewrite in _FOLDS_BESIDE_A_STORE.items():
            for text in rewrite.texts:
                with self.subTest(name=name, text=text):
                    self.assertEqual(behavior(rewrite.source), behavior(text))
