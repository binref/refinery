"""
Operators and reads whose answer only the built-in objects give.

An array converted by an operator runs `Array.prototype.join`, a key no value owns is answered by
the prototype chain, and two array literals compared are two objects. The engine answers each of
these the same way wherever the program leaves the built-in objects alone, so the deobfuscation
folds them there: `false + []` is `'false'`, `[][[]]` is `undefined`, `[] == []` is `false`.

A method read off a value is a function the language installs. It has a `name`, its `constructor`
is `Function`, and it is the same function however it is reached: `[].at === [].at`, and
`''.trimLeft` is `''.trimStart`. Converted to a string it is the text the host's engine writes for
it, which hosts write differently, so that text is folded only where the host is pinned to Node. A
constructor read off a value is written as the global name holding it where that name still does.

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
from refinery.lib.scripts.js.analysis.effects import build_effects
from refinery.lib.scripts.js.analysis.intrinsics import _SURFACE_KEYS, SPECIES_KEYS
from refinery.lib.scripts.js.analysis.model import (
    _DISPLACING_CHAIN_KEYS,
    _PROTOTYPE_KEEPING_KEYS,
    _PROTOTYPE_REFLECTING_CALLEES,
    REFLECTIVE_INTRINSICS,
    build_semantic_model,
)
from refinery.lib.scripts.js.deobfuscation.simplify import REVEALING_STRINGS
from refinery.lib.scripts.js.model import ACCESSOR_INSTALL_METHODS, CONVERSION_INSTALL_METHODS
from refinery.lib.scripts.js.parser import JsParser
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
    "var {constructor: S = 0} = ''; S.prototype.nope = 5; console.log('abc'.nope);": '5\n',
    "var {constructor: {prototype: P}} = ''; P.nope = 5; console.log('abc'.nope);": '5\n',
    "var P; ({constructor: P} = ''); P.prototype.nope = 5; console.log('abc'.nope);": '5\n',
    "(class {}).__proto__.__proto__.nope = 5; console.log('abc'.nope);": '5\n',
    "(new Date).__proto__.__proto__.nope = 5; console.log('abc'.nope);": '5\n',
    "(function () { arguments.__proto__.nope = 5; })(); console.log('abc'.nope);": '5\n',
    "function g(o) { o.__proto__.nope = 5; } g(''); console.log('abc'.nope);": '5\n',
    "''.__proto__.__defineGetter__('nope', function () { return 5; }); console.log('abc'.nope);": '5\n',
    "(1 + '').constructor.prototype.nope = 5; console.log('abc'.nope);": '5\n',
    "var o = {s: ''}; o.s.constructor.prototype.nope = 5; console.log('abc'.nope);": '5\n',
    "var e = ''; e.constructor.prototype.xyz = function () {}; console.log(typeof 'abc'.xyz);": 'function\n',
    '[].__proto__.push(5); console.log([][0]);': '5\n',
    'var p = [].__proto__; p.push(5); console.log([][0]);': '5\n',
    "[].__proto__[[] + 'push'](5); console.log([][0]);": '5\n',
    '[].__proto__[String.fromCharCode(112, 117, 115, 104)](5); console.log([][0]);': '5\n',
    "[].__proto__[(0, 'push')](5); console.log([][0]);": '5\n',
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

#: A program whose write on a built-in object shows only once a fold spells the key it goes through,
#: mapped to what it prints: `caller` joined in an array beside a read the write decides, and `Date`
#: built from its character codes where it names a property of the global object.
_A_WRITE_A_FOLD_SPELLS: dict[str, str] = {
    inspect.cleandoc("""
        var done = false;
        function getM() { if (!done) { done = true; evil(); } return Math; }
        function evil() { var g = evil[a[0]]; g().floor = function () { return 42; }; }
        var a = [['cal', 'ler'].join(''), [].nope];
        getM().PI;
        console.log(Math.floor(1.5));
    """): '42\n',
    inspect.cleandoc("""
        function getGlobal() { return globalThis; }
        var g = getGlobal();
        g[String.fromCharCode(68, 97, 116, 101)].now = function () { return 5e12; };
        console.log(Date.now() > 4102444800000);
    """): 'true\n',
}

#: A program reading functions the language installs, mapped to what it prints and to the text it
#: deobfuscates to in any host.
_A_BUILTIN_FUNCTION_READ: dict[str, tuple[str, str]] = {
    inspect.cleandoc("""
        console.log([].at === [].at, [].at === [].map, ''.trimLeft === ''.trimStart, [].at == ''.at);
    """): (
        'true false true false\n',
        'console.log(true, false, true, false);',
    ),
    inspect.cleandoc("""
        console.log(''.trimLeft.name, [].at.name, String.name, ''.constructor === String, typeof [].at);
    """): (
        'trimStart at String true function\n',
        "console.log('trimStart', 'at', 'String', true, 'function');",
    ),
}

#: A program calling or constructing with a constructor read off a value, mapped to what it prints
#: and to the text the default model deobfuscates it to in any host. The model that suspects code it
#: cannot read counts no call through `constructor` (`test_unfixed_defects`), and keeps every fold
#: from leaning on one.
_A_CONSTRUCTOR_CALLED: dict[str, tuple[str, str]] = {
    inspect.cleandoc("""
        console.log(typeof new (''.constructor)(5), true.constructor.name);
    """): (
        'object Boolean\n',
        "console.log(typeof new String(5), 'Boolean');",
    ),
    inspect.cleandoc("""
        console.log([].at.constructor('return 7')());
    """): (
        '7\n',
        'console.log(7);',
    ),
    inspect.cleandoc("""
        console.log([].constructor.constructor('return 7')(), ''.constructor.constructor('return 8')());
    """): (
        '7 8\n',
        'console.log(7, 8);',
    ),
}

#: A program converting functions the language installs, mapped to what it prints and to the text it
#: deobfuscates to where the host is pinned to Node.
_A_BUILTIN_FUNCTION_CONVERTED: dict[str, tuple[str, str]] = {
    inspect.cleandoc("""
        console.log((Number + [])[11], ([].at + '')[3], (''.trimLeft + '')[13], +[].at);
    """): (
        'm c S NaN\n',
        "console.log('m', 'c', 'S', 0 / 0);",
    ),
}

#: A program that changes what a function the language installs answers, or what a constructor's
#: name holds, mapped to what it prints.
_A_BUILTIN_FUNCTION_CHANGED: dict[str, str] = {
    "function g(o) { o.__proto__.__proto__.nope = 5; } g([].at); console.log('abc'.nope);": '5\n',
    inspect.cleandoc("""
        function g(o) { o.constructor = function () { return function () { return 'X'; }; }; }
        g([].at);
        console.log([].at.constructor('return 1')());
    """): 'X\n',
    'function g(o) { o.constructor = 5; } g([].at); console.log([].at.constructor === Function);': 'false\n',
    inspect.cleandoc("""
        function g(o) { o.constructor = function () { return function () { return 'X'; }; }; }
        g(Object);
        console.log(Object.constructor('return 1')());
    """): 'X\n',
    inspect.cleandoc("""
        function g(o) { Object.setPrototypeOf(o, null); }
        g([].at);
        console.log([].at.constructor === Function);
    """): 'false\n',
    "var {at: m} = []; Object.defineProperty(m, 'name', {value: 'q'}); console.log([].at.name);": 'q\n',
    inspect.cleandoc("""
        var h = {};
        var k = Math.random() < 2 ? 'a' : 'b';
        h[k] = function (o) { o.toString = function () { return 'XYZ'; }; };
        h[k](Function);
        console.log((Function + '')[0]);
    """): 'X\n',
    inspect.cleandoc("""
        var h = {};
        var k = Math.random() < 2 ? 'a' : 'b';
        h[k] = function (o) { Object.defineProperty(o, 'name', {value: 'Q'}); };
        h[k](Boolean);
        h[k](Object);
        console.log(Boolean.name, Object.name, true.constructor.name);
    """): 'Q Q Q\n',
    inspect.cleandoc("""
        var h = {};
        var k = Math.random() < 2 ? 'a' : 'b';
        h[k] = function (o) { o.toString = function () { return 'XYZ'; }; };
        var f = Function.prototype.call;
        h[k](f);
        console.log(([].at.call + '')[0]);
    """): 'X\n',
    inspect.cleandoc("""
        Object[[] + 'defineProperty'](Function.prototype, 'toString', {value: function () { return 'XYZ'; }});
        console.log(([].at + '')[0]);
    """): 'X\n',
    inspect.cleandoc("""
        var h = {};
        var k = Math.random() < 2 ? 'a' : 'b';
        h[k] = function (o) { o.__proto__.__proto__.zz = 7; };
        h[k]([].at);
        console.log([].zz, 'abc'.zz);
    """): '7 7\n',
    inspect.cleandoc("""
        var h = {};
        var k = Math.random() < 2 ? 'a' : 'b';
        h[k] = function (o) { o.toString = function () { return 'T'; }; };
        h[k](Function.prototype);
        console.log(([].at + '')[0]);
    """): 'T\n',
    "Function.prototype.toString = function () { return 'T'; }; console.log((Number + [])[0], String.name);": 'T String\n',
    "Object.defineProperty(String, 'name', {value: 'q'}); console.log(String.name, ''.constructor.name);": 'q q\n',
    "globalThis[typeof process == 'object' ? 'String' : 'x'] = 5; console.log(typeof ''.constructor);": 'function\n',
    "Reflect.set(globalThis, 'String', 5); console.log(typeof ''.constructor);": 'function\n',
    "Reflect.set(globalThis, 'Function', 5); console.log(typeof [].at.constructor);": 'function\n',
    "String = 5; console.log(typeof ''.constructor);": 'function\n',
    "globalThis.String = 5; console.log(typeof ''.constructor);": 'function\n',
}

_FOLDED_PROGRAM = "var a = false + [], b = [] + [], c = 1 + [0], d = [][[]] + '', e = 'abc'.nope + ''; console.log(a, b, c, d, e);"


def _deobfuscated(source: str, strict: bool, environment: str = 'universal') -> str:
    return source.encode('utf8') | djs(strict=strict, environment=environment) | str


#: Each model and host a deobfuscation below is asked under: the model that suspects code it cannot
#: read or the default one, in a host nothing is assumed of or in Node.
_EVERY_MODE = [
    (strict, environment)
    for strict in (True, False)
    for environment in ('universal', 'node')
]


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


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAWriteAFoldSpells(TestBase):

    def test_node_prints_what_the_row_records(self):
        for source, prints in _A_WRITE_A_FOLD_SPELLS.items():
            with self.subTest(source=source):
                self.assertEqual(behavior(source), (prints, None))

    def test_each_deobfuscation_prints_it_too(self):
        for source, prints in _A_WRITE_A_FOLD_SPELLS.items():
            for strict in (True, False):
                with self.subTest(source=source, strict=strict):
                    self.assertEqual(behavior(_deobfuscated(source, strict)), (prints, None))


class TestAFunctionTheLanguageInstalls(TestBase):

    def test_a_read_of_one_folds_in_every_host(self):
        for source, (_, folded) in _A_BUILTIN_FUNCTION_READ.items():
            for strict, environment in _EVERY_MODE:
                with self.subTest(source=source, strict=strict, environment=environment):
                    self.assertEqual(_deobfuscated(source, strict, environment), folded)

    def test_a_constructor_called_off_a_value_folds_under_the_default_model_in_every_host(self):
        for source, (_, folded) in _A_CONSTRUCTOR_CALLED.items():
            for environment in ('universal', 'node'):
                with self.subTest(source=source, environment=environment):
                    self.assertEqual(_deobfuscated(source, False, environment), folded)

    def test_a_conversion_of_one_folds_where_the_host_is_node(self):
        for source, (_, folded) in _A_BUILTIN_FUNCTION_CONVERTED.items():
            with self.subTest(source=source):
                self.assertEqual(_deobfuscated(source, False, 'node'), folded)

    def test_a_conversion_of_one_is_kept_where_the_host_is_not_settled(self):
        for source in _A_BUILTIN_FUNCTION_CONVERTED:
            with self.subTest(source=source):
                self.assertIn('[].at', _deobfuscated(source, False))

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_prints_what_each_row_records(self):
        rows = _A_BUILTIN_FUNCTION_READ | _A_CONSTRUCTOR_CALLED | _A_BUILTIN_FUNCTION_CONVERTED
        printed = {source: prints for source, (prints, _) in rows.items()}
        for source, prints in (printed | _A_BUILTIN_FUNCTION_CHANGED).items():
            with self.subTest(source=source):
                self.assertEqual(behavior(source), (prints, None))

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_each_deobfuscation_of_a_program_reading_one_prints_what_it_printed(self):
        rows = _A_BUILTIN_FUNCTION_READ | _A_CONSTRUCTOR_CALLED | _A_BUILTIN_FUNCTION_CONVERTED
        for source, (prints, _) in rows.items():
            for strict, environment in _EVERY_MODE:
                with self.subTest(source=source, strict=strict, environment=environment):
                    self.assertEqual(behavior(_deobfuscated(source, strict, environment)), (prints, None))

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_each_deobfuscation_of_a_program_changing_one_prints_what_it_printed(self):
        for source, prints in _A_BUILTIN_FUNCTION_CHANGED.items():
            for strict, environment in _EVERY_MODE:
                with self.subTest(source=source, strict=strict, environment=environment):
                    self.assertEqual(behavior(_deobfuscated(source, strict, environment)), (prints, None))


class TestTheGuardOfTheFolds(TestBase):

    @staticmethod
    def _followed(source: str) -> bool:
        model = build_semantic_model(JsParser(source).parse())
        return build_effects(model).builtin_writes_followed()

    def test_a_read_under_an_unknown_key_stored_into_a_name_hands_nothing_off(self):
        self.assertTrue(self._followed('var a = [1, 2, 3], i = 0, k; k = a[i];'))

    def test_the_name_holding_it_is_handed_off_where_it_is_read(self):
        self.assertFalse(self._followed('var a = [1, 2, 3], i = 0, k; k = a[i]; f(k);'))

    def test_a_logical_assignment_hands_off_the_value_the_name_held(self):
        self.assertFalse(self._followed('var k = [].at; f(k ||= 1);'))

    def test_object_function_and_boolean_read_as_properties_and_written_through_or_handed_off(self):
        for source in (
            'globalThis.Object.prototype.nope = 5;',
            "window['Function'].prototype.nope = 5;",
            'f(global.Boolean);',
        ):
            with self.subTest(source=source):
                self.assertFalse(self._followed(source))


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
