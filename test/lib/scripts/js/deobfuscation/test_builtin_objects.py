"""
Operators and reads whose answer only the built-in objects give.

An array converted by an operator runs `Array.prototype.join`, a key no value owns is answered by
the prototype chain, and two array literals compared are two objects. The engine answers each of
these the same way wherever the program leaves the built-in objects alone, so the deobfuscation
folds them there: `false + []` is `'false'`, `[][[]]` is `undefined`, `[] == []` is `false`.

A program that does write a built-in object stops all of them, and it need not name the object it
writes: `''.constructor.prototype.nope = 5` writes `String.prototype`, and so does a function handed
`''` that writes through `o.__proto__`. Each program below writes one that way, and the
deobfuscation has to print what the program printed.

Every answer is Node's, under the deobfuscation that suspects code it cannot read (`-s`) and under
the default one that assumes such code changes nothing.

SECURITY: every program here is written out by the module itself and Node runs only those. Nothing
from `samples` may ever be handed to the engine.
"""
from __future__ import annotations

import inspect
import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import behavior, code_units, node_executable

from refinery.lib.scripts.js.analysis.conversions import CONVERSION_KEYS, RECEIVER_INSTALL_METHODS
from refinery.lib.scripts.js.analysis.intrinsics import _SURFACE_KEYS, SPECIES_KEYS
from refinery.lib.scripts.js.analysis.model import (
    _DISPLACING_CHAIN_KEYS,
    _PROTOTYPE_KEEPING_KEYS,
    _PROTOTYPE_REFLECTING_CALLEES,
    REFLECTIVE_INTRINSICS,
)
from refinery.lib.scripts.js.deobfuscation.simplify import REVEALING_STRINGS
from refinery.lib.scripts.js.model import ACCESSOR_INSTALL_METHODS, CONVERSION_INSTALL_METHODS
from refinery.units.scripting.djs import djs

#: An expression only the built-in objects answer for, mapped to the text it folds to.
_FOLDED: dict[str, str] = {
    'false + []'     : "'false'",
    '[] + []'        : "''",
    '1 + [0]'        : "'10'",
    '[1] * [2]'      : '2',
    '[] == []'       : 'false',
    '[] != []'       : 'true',
    "[] == ''"       : 'true',
    '[] == null'     : 'false',
    "[][[]] + ''"         : "'undefined'",
    "'abc'.nope"          : 'void 0',
    "'abc'[[] + 3] + ''"  : "'undefined'",
    "'abc'[[1]] + ''"     : "'b'",
}

#: A program that writes a built-in object through a value it reads without spelling the owner, or
#: hands such a value to code that may, mapped to what it prints.
_A_WRITE_NO_NAME_SHOWS: dict[str, str] = {
    "([] + [])['constructor']['prototype']['nope'] = 5; console.log('abc'.nope);": '5\n',
    "var s = 'x'; s.constructor.prototype.nope = 5; console.log('abc'.nope);": '5\n',
    "Array.prototype.__proto__.nope = 5; console.log([].nope, 'abc'.nope);": '5 5\n',
    "Object.getPrototypeOf('').nope = 5; console.log('abc'.nope);": '5\n',
    "Math.__proto__.nope = 5; console.log('abc'.nope);": '5\n',
    "var {constructor: S} = ''; S.prototype.nope = 5; console.log('abc'.nope);": '5\n',
    "(class {}).__proto__.__proto__.nope = 5; console.log('abc'.nope);": '5\n',
    "(new Date).__proto__.__proto__.nope = 5; console.log('abc'.nope);": '5\n',
    "(function () { arguments.__proto__.nope = 5; })(); console.log('abc'.nope);": '5\n',
    "function g(o) { o.__proto__.nope = 5; } g(''); console.log('abc'.nope);": '5\n',
    "''.__proto__.__defineGetter__('nope', function () { return 5; }); console.log('abc'.nope);": '5\n',
    "(1 + '').constructor.prototype.nope = 5; console.log('abc'.nope);": '5\n',
    "var o = {s: ''}; o.s.constructor.prototype.nope = 5; console.log('abc'.nope);": '5\n',
    "var e = ''; e.constructor.prototype.xyz = function () {}; console.log(typeof 'abc'.xyz);": 'function\n',
    "[].__proto__.push(5); console.log([][0]);": '5\n',
    "var p = [].__proto__; p.push(5); console.log([][0]);": '5\n',
    "[].__proto__[[] + 'push'](5); console.log([][0]);": '5\n',
    "[].constructor.prototype.join = function () { return 'J'; }; console.log([] + []);": 'JJ\n',
    inspect.cleandoc("""
        var k1 = process.argv.length > 99 ? '' : 'constructor';
        var k2 = process.argv.length > 99 ? '' : 'prototype';
        function g(o) { o.nope = 5; }
        g(''[k1][k2]);
        console.log('abc'.nope);
    """): '5\n',
    inspect.cleandoc("""
        var h = {};
        var k = Math.random() < 2 ? 'a' : 'b';
        h[k] = function (o) { o.nope = 5; };
        h[k](Object.prototype);
        console.log('abc'.nope + '');
    """): '5\n',
    "String.prototype.nope = 5; console.log('abc'.nope + '', [][[]] + '');": '5 undefined\n',
    "Array.prototype.join = function () { return 'J'; }; console.log(false + [], [] + []);": 'falseJ JJ\n',
}

#: A program whose string of code writes the built-in objects, which only the model that suspects
#: code it cannot read accounts for, mapped to what it prints.
_A_WRITE_IN_A_STRING_OF_CODE: dict[str, str] = {
    inspect.cleandoc("""
        var x = process.argv.length > 99 ? '' : 'Array.prototype.join = function () { return "J"; }; String.prototype.nope = 5;';
        [].constructor.constructor(x)();
        console.log([] + [], 'abc'.nope, [][[]]);
    """): 'JJ 5 undefined\n',
}

_FOLDED_PROGRAM = "var a = false + [], b = [] + [], c = 1 + [0], d = [][[]] + '', e = 'abc'.nope + ''; console.log(a, b, c, d, e);"


def _deobfuscated(source: str, strict: bool) -> str:
    return source.encode('utf8') | djs(strict=strict) | str


def _fold(expression: str) -> str:
    """
    The expression `refinery.djs` folds *expression* to inside a `console.log` argument.
    """
    printed = _deobfuscated(F'console.log({expression});', strict=True)
    return printed.removeprefix('console.log(').removesuffix(');')


class TestAnOperatorOrAReadOnlyTheBuiltinsAnswer(TestBase):

    def test_each_expression_folds_to_the_value_the_builtins_give(self):
        for expression, folded in _FOLDED.items():
            with self.subTest(expression=expression):
                self.assertEqual(_fold(expression), folded)

    def test_a_program_of_them_prints_its_values_as_constants(self):
        for strict in (True, False):
            with self.subTest(strict=strict):
                self.assertEqual(
                    _deobfuscated(_FOLDED_PROGRAM, strict),
                    "console.log('false', '', '10', 'undefined', 'undefined');",
                )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_answers_each_expression_with_the_value_it_folds_to(self):
        expressions = list(_FOLDED)
        self.assertEqual(code_units(expressions), code_units(list(_FOLDED.values())))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAWriteThroughABuiltinNoNameShows(TestBase):

    def test_node_prints_what_the_row_records(self):
        for source, prints in (_A_WRITE_NO_NAME_SHOWS | _A_WRITE_IN_A_STRING_OF_CODE).items():
            with self.subTest(source=source):
                self.assertEqual(behavior(source), (prints, None))

    def test_each_deobfuscation_prints_it_too(self):
        for source, prints in _A_WRITE_NO_NAME_SHOWS.items():
            for strict in (True, False):
                with self.subTest(source=source, strict=strict):
                    self.assertEqual(behavior(_deobfuscated(source, strict)), (prints, None))

    def test_the_suspecting_deobfuscation_prints_what_a_string_of_code_changed(self):
        for source, prints in _A_WRITE_IN_A_STRING_OF_CODE.items():
            with self.subTest(source=source):
                self.assertEqual(behavior(_deobfuscated(source, strict=True)), (prints, None))


class TestTheStringsAFoldRenewsTheModelsFor(TestBase):

    def test_every_name_a_reader_looks_for_is_one(self):
        for names in (
            ACCESSOR_INSTALL_METHODS,
            CONVERSION_INSTALL_METHODS,
            CONVERSION_KEYS,
            RECEIVER_INSTALL_METHODS,
            REFLECTIVE_INTRINSICS,
            SPECIES_KEYS,
            _SURFACE_KEYS,
            _PROTOTYPE_KEEPING_KEYS,
            _PROTOTYPE_REFLECTING_CALLEES,
            _DISPLACING_CHAIN_KEYS,
            frozenset({'caller', 'toPrimitive', 'Reflect'}),
        ):
            with self.subTest(names=sorted(names)):
                self.assertLessEqual(names, REVEALING_STRINGS)
