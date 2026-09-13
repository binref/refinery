"""
The interpreter's `arguments` object: a value modelled from the argument values the call passes.

Admitting one is a question about the whole body, because the object a call builds is linked to
things the call also binds. In sloppy mode the elements alias the parameters, so a parameter
written anywhere — a plain, compound or logical assignment, an update, a `for-in`/`for-of` head, a
pattern leaf, a write from a nested function that resolves to it — is a value read back off the
object that the argument values cannot answer for. In strict mode the object is an unlinked copy
and no parameter write matters. And the name `arguments` itself denotes the object only where
nothing displaced it: a parameter, a lexical declaration, an initialized `var`, a catch
parameter or an assignment each put something else under the name.

What the admitted object answers is only `length` and the elements at canonical indices the call
filled. Every other key — the `callee` a computed spelling reaches, an index past the end, a key
that is no canonical index — refuses like any other read whose answer lives on a prototype chain.
A body that uses the object any other way — handing it to a call, binding a second name to it,
spreading it, coercing it, writing through it — never receives one at all, so the read declines
the way every unresolved name does and the call stands.

Every recorded value here is Node's, and each corpus is asserted twice: against Node, which makes
the value a measurement, and against the deobfuscation, which must both produce that value and
keep producing it after the call is folded or left standing. Each row also records the text the
deobfuscation writes, which pins that an admitted object really folds and a refused one really
stands — every refusing row's program, minus the feature that refused, is another row's.
"""
from __future__ import annotations

import inspect
import unittest

from typing import NamedTuple

from test.lib.scripts.js.analysis.differential import behavior, node_executable

from refinery.units.scripting.js import js


class _Row(NamedTuple):
    """
    One program reading an `arguments` object: what Node prints for it, and the text the
    deobfuscation writes for it.
    """
    printed: str
    text: str


#: A body whose admitted object answers what it reads. Each is also the fold twin of a refusing
#: row below: the same program with the refusing feature taken out folds, so a regression to
#: blanket refusal fails its own pair.
_AN_ADMITTED_OBJECT_ANSWERS: dict[str, _Row] = {
    'function f() { return arguments.length; } console.log(f(1, 2));': _Row(
        '2\n', 'console.log(2);',
    ),
    'function f() { return arguments.length; } console.log(f());': _Row(
        '0\n', 'console.log(0);',
    ),
    "function f() { return arguments[0]; } console.log(f('a'));": _Row(
        'a\n', "console.log('a');",
    ),
    "function f() { return arguments[1]; } console.log(f('a', 'b'));": _Row(
        'b\n', "console.log('b');",
    ),
    "function f() { for (var p = 0; p < arguments.length; p++) return arguments[p]; }"
    " console.log(f('q'));": _Row('q\n', "console.log('q');"),
    "function f(a) { return arguments.length; } console.log(f(1));": _Row(
        '1\n', 'console.log(1);',
    ),
    "var r = (function () { 'use strict'; return arguments.length; })(3); console.log(r);": _Row(
        '1\n', 'console.log(1);',
    ),
    "var r = (function (a) { 'use strict'; a = 2; return arguments[0]; })(1);"
    " console.log(r);": _Row('1\n', 'console.log(1);'),
    'var r = (function () { var arguments; return arguments.length; })(1); console.log(r);':
        _Row('1\n', 'console.log(1);'),
    'var r = (function () { var arguments = [7]; return arguments[0]; })(1); console.log(r);':
        _Row('7\n', 'console.log(7);'),
}

#: A body whose object the call cannot model, mapped to what Node prints for it and to the text
#: the deobfuscation writes. Each holds a feature the value modelled from the call's arguments
#: cannot stand in for — a parameter written under sloppy aliasing, a key the object itself
#: does not decide, a bare read of the name — so the call is left standing and the running
#: program supplies the answer.
_AN_OBJECT_THE_CALL_CANNOT_MODEL: dict[str, _Row] = {
    'function f(a) { a = 2; return arguments[0]; } console.log(f(1));': _Row(
        '2\n',
        inspect.cleandoc(
            """
            function f(a) {
              a = 2;
              return arguments[0];
            }
            console.log(f(1));
            """
        ),
    ),
    'function f(a) { a++; return arguments[0]; } console.log(f(1));': _Row(
        '2\n',
        inspect.cleandoc(
            """
            function f(a) {
              a++;
              return arguments[0];
            }
            console.log(f(1));
            """
        ),
    ),
    'function f(a) { for (a of [5]) {} return arguments[0]; } console.log(f(1));': _Row(
        '5\n',
        inspect.cleandoc(
            """
            function f(a) {
              for (a of [5]) {}
              return arguments[0];
            }
            console.log(f(1));
            """
        ),
    ),
    'function f(a) { var g = function () { a = 9; }; g(); return arguments[0]; }'
    ' console.log(f(1));': _Row(
        '9\n',
        inspect.cleandoc(
            """
            function f(a) {
              var g = function() {
                a = 9;
              };
              g();
              return arguments[0];
            }
            console.log(f(1));
            """
        ),
    ),
    "function f() { return arguments['callee'].name; } console.log(f());": _Row(
        'f\n',
        inspect.cleandoc(
            """
            function f() {
              return arguments.callee.name;
            }
            console.log(f());
            """
        ),
    ),
    'function f() { return Array.isArray(arguments); } console.log(f());': _Row(
        'false\n',
        inspect.cleandoc(
            """
            function f() {
              return Array.isArray(arguments);
            }
            console.log(f());
            """
        ),
    ),
    "function f() { return arguments[5]; } console.log(f('a'));": _Row(
        'undefined\n',
        inspect.cleandoc(
            """
            function f() {
              return arguments[5];
            }
            console.log(f('a'));
            """
        ),
    ),
    "function f() { return arguments['+1']; } console.log(f('a'));": _Row(
        'undefined\n',
        inspect.cleandoc(
            """
            function f() {
              return arguments['+1'];
            }
            console.log(f('a'));
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


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnAdmittedArgumentsObjectAnswersWhatItReads(unittest.TestCase):

    def test_node_answers_each_program_the_way_the_row_records(self):
        rows = _AN_ADMITTED_OBJECT_ANSWERS
        self.assertEqual({source: behavior(source) for source in rows}, _printed(rows))

    def test_the_deobfuscation_answers_it_the_same_way(self):
        rows = _AN_ADMITTED_OBJECT_ANSWERS
        self.assertEqual(
            {source: behavior(_deobfuscated(source)) for source in rows},
            _printed(rows),
        )

    def test_the_deobfuscation_writes_the_text_the_row_records(self):
        rows = _AN_ADMITTED_OBJECT_ANSWERS
        self.assertEqual({source: _deobfuscated(source) for source in rows}, _deobfuscated_text(rows))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnObjectTheCallCannotModelStands(unittest.TestCase):

    def test_node_answers_each_program_the_way_the_row_records(self):
        rows = _AN_OBJECT_THE_CALL_CANNOT_MODEL
        self.assertEqual({source: behavior(source) for source in rows}, _printed(rows))

    def test_the_deobfuscation_answers_it_the_same_way(self):
        rows = _AN_OBJECT_THE_CALL_CANNOT_MODEL
        self.assertEqual(
            {source: behavior(_deobfuscated(source)) for source in rows},
            _printed(rows),
        )

    def test_the_deobfuscation_writes_the_text_the_row_records(self):
        rows = _AN_OBJECT_THE_CALL_CANNOT_MODEL
        self.assertEqual({source: _deobfuscated(source) for source in rows}, _deobfuscated_text(rows))
