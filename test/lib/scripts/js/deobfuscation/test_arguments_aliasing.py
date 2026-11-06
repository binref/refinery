"""
An `arguments` object whose elements alias the parameters of its function. In a sloppy function
whose parameters are plain names, element `i` and parameter `i` are one location, so a write to
either is read back through the other.
"""
from __future__ import annotations

import inspect
import unittest

from test import TestBase, opportunity
from test.lib.scripts.js.analysis.differential import behavior, node_executable

from refinery.units.scripting.djs import djs


def _deobfuscated(source: str, *, module: bool = False) -> str:
    return source.encode('utf8') | djs(module=module, strict=True) | str


def _printed(rows: dict[str, str]) -> dict[str, tuple[str, str | None]]:
    return {source: (printed, None) for source, printed in rows.items()}


def _said_by_node(rows: dict[str, str]) -> dict[str, tuple[str, str | None]]:
    return {source: behavior(source) for source in rows}


def _said_after_deobfuscation(rows: dict[str, str]) -> dict[str, tuple[str, str | None]]:
    return {source: behavior(_deobfuscated(source)) for source in rows}


#: A body the `Function` constructor compiles is sloppy unless it declares otherwise itself, even
#: where the code calling the constructor is strict.
_A_LIST_OF_PLAIN_NAMES_IN_A_SLOPPY_BODY: dict[str, str] = {
    'function f(a) { a = 2; return arguments[0]; } console.log(f(1));': '2\n',
    'function f(a) { arguments[0] = 2; return a; } console.log(f(1));': '2\n',
    'function f(a, b) { b = 2; return arguments[1]; } console.log(f(0, 1));': '2\n',
    'function f(a, b) { arguments[1] = 2; return b; } console.log(f(0, 1));': '2\n',
    'var f = function (a) { a = 2; return arguments[0]; }; console.log(f(1));': '2\n',
    'var f = function g(a) { arguments[0] = 2; return a; }; console.log(f(1));': '2\n',
    'function* f(a) { a = 2; yield arguments[0]; } console.log(f(1).next().value);': '2\n',
    'async function f(a) { arguments[0] = 2; return a; } f(1).then(function (v) { console.log(v); });': '2\n',
    'var o = { m(a) { a = 2; return arguments[0]; } }; console.log(o.m(1));': '2\n',
    'var o = { set s(a) { arguments[0] = 2; console.log(a); } }; o.s = 1;': '2\n',
    'function f(a, a) { a = 2; return arguments[1]; } console.log(f(0, 1));': '2\n',
    "'use strict'; var f = new Function('a', 'a = 2; return arguments[0];'); console.log(f(1));": '2\n',
}

#: `1` is the value the call passed. Strict code, which includes everything inside a class, and a
#: parameter list holding a default, a rest element or a pattern anywhere each give the parameters
#: an independent copy.
_AN_OBJECT_THAT_ALIASES_NOTHING: dict[str, str] = {
    "function f(a) { 'use strict'; a = 2; return arguments[0]; } console.log(f(1));": '1\n',
    'function f(a) { "use strict"; arguments[0] = 2; return a; } console.log(f(1));': '1\n',
    "'use strict'; function f(a) { a = 2; return arguments[0]; } console.log(f(1));": '1\n',
    "function o() { 'use strict'; function f(a) { a = 2; return arguments[0]; } return f(1); } console.log(o());": '1\n',
    'class C { m(a) { a = 2; return arguments[0]; } } console.log(new C().m(1));': '1\n',
    'class C { m() { function f(a) { a = 2; return arguments[0]; } return f(1); } } console.log(new C().m());': '1\n',
    'function f(a = 0) { a = 2; return arguments[0]; } console.log(f(1));': '1\n',
    'function f(...a) { a[0] = 2; return arguments[0]; } console.log(f(1));': '1\n',
    'function f([a]) { arguments[0] = 2; return a; } console.log(f([1]));': '1\n',
    'function f({a}) { arguments[0] = 2; return a; } console.log(f({a: 1}));': '1\n',
    'function f(a, b = 0) { a = 2; return arguments[0]; } console.log(f(1, 0));': '1\n',
    'function f(a, ...b) { arguments[0] = 2; return a; } console.log(f(1));': '1\n',
    'function f() { var a = 1; arguments[0] = 2; return a; } console.log(f(1));': '1\n',
    'function f(a) { var g = (b) => { b = 2; return arguments[0]; }; return g(9); } console.log(f(1));': '1\n',
    'function f(a) { function g(b) { arguments[0] = 2; return a; } return g(9); } console.log(f(1));': '1\n',
}

#: Only a string literal statement among those that open a body or a script, written without
#: parentheses or escapes, is a directive; every `'use strict'` here is an ordinary statement.
_A_USE_STRICT_THAT_GOVERNS_NOTHING: dict[str, str] = {
    "function f(a) { ('use strict'); a = 2; return arguments[0]; } console.log(f(1));": '2\n',
    "function f(a) { 0; 'use strict'; a = 2; return arguments[0]; } console.log(f(1));": '2\n',
    "function f(a) { 'use\\u0020strict'; a = 2; return arguments[0]; } console.log(f(1));": '2\n',
    "function f(a) { { 'use strict'; } a = 2; return arguments[0]; } console.log(f(1));": '2\n',
    "function f(a) { if (true) { 'use strict'; } a = 2; return arguments[0]; } console.log(f(1));": '2\n',
    "{ 'use strict'; } function f(a) { a = 2; return arguments[0]; } console.log(f(1));": '2\n',
    "if (true) { 'use strict'; } function f(a) { a = 2; return arguments[0]; } console.log(f(1));": '2\n',
    "var s = 'use strict'; function f(a) { a = 2; return arguments[0]; } console.log(f(1));": '2\n',
}

_A_READ_THROUGH_THE_OBJECT: dict[str, str] = {
    "arguments['0']"                                : '2\n',
    "arguments['0' + '']"                           : '2\n',
    'arguments[i]'                                  : '2\n',
    "arguments['00']"                               : 'undefined\n',
    'arguments[5]'                                  : 'undefined\n',
    'arguments.length'                              : '1\n',
    'arguments.callee.length'                       : '1\n',
    'Object.keys(arguments).length'                 : '1\n',
    '[...arguments][0]'                             : '2\n',
    'Array.from(arguments)[0]'                      : '2\n',
    '((b) => b[0])(arguments)'                      : '2\n',
    '(function (x) { return x; }).apply(null, arguments)': '2\n',
    'JSON.stringify(arguments)'                     : '{"0":2}\n',
}

_A_WRITE_THROUGH_THE_OBJECT: dict[str, str] = {
    "arguments['0'] = 2"                : '2\n',
    'arguments[i] = 2'                  : '2\n',
    'arguments[0]++'                    : '2\n',
    'arguments[0] += 1'                 : '2\n',
    'var b = arguments; b[0] = 2'       : '2\n',
    'Object.assign(arguments, {0: 2})'  : '2\n',
    "arguments['00'] = 2"               : '1\n',
    'arguments[5] = 2'                  : '1\n',
    'arguments.length = 0'              : '1\n',
    'delete arguments[0]; arguments[0] = 2': '1\n',
}

#: An arrow and a direct `eval` read the object of the function around them, even where the
#: evaluated code is strict; a nested function has an object of its own.
_WHERE_THE_REFERENCE_TO_THE_OBJECT_STANDS: dict[str, str] = {
    '{ return arguments[0]; }'                                          : '2\n',
    'for (var q = 0; q < 1; q++) { return arguments[0]; }'              : '2\n',
    'try { return arguments[0]; } finally { }'                          : '2\n',
    'with ({}) { return arguments[0]; }'                                : '2\n',
    'return (() => { return arguments[0]; })();'                        : '2\n',
    'return (() => arguments[0])();'                                    : '2\n',
    'return (() => (() => arguments[0])())();'                          : '2\n',
    'return ((x = arguments[0]) => x)();'                               : '2\n',
    "return eval('arguments[0]');"                                      : '2\n',
    'return eval("\'use strict\'; arguments[0]");'                      : '2\n',
    'return (function () { return arguments[0]; })(7);'                 : '7\n',
    'return (function () { return (() => arguments[0])(); })(7);'       : '7\n',
}

_AN_ALIASING_NOTHING_OBSERVES: dict[str, str] = {
    'function f(a) { a = 2; return a; } console.log(f(1));':
        'console.log(2);',
    'function f(a, b) { a = 2; b = 3; return a + b; } console.log(f(0, 0));':
        'console.log(5);',
    'function f(a) { a = 2; return arguments.length; } console.log(f(1));':
        'console.log(1);',
    'function f(a, b) { b = 7; return arguments[0]; } console.log(f(1, 0));':
        'console.log(1);',
    "function f(a) { 'use strict'; a = 2; return arguments[0]; } console.log(f(1));":
        'console.log(1);',
    'function f(a) { var arguments; a = 5; return arguments.length; } console.log(f(1));':
        'console.log(1);',
}

_AN_ALIASING_NOTHING_OBSERVES_IN_A_CALL_THAT_MAY_STAND: dict[str, tuple[str, str]] = {
    'function f(a = 0) { a = 2; return arguments[0]; } console.log(f(1));': (
        inspect.cleandoc(
            """
            function f(a = 0) {
              return arguments[0];
            }
            console.log(f(1));
            """
        ),
        'console.log(1);',
    ),
    'function f(a) { arguments = [7]; a = 5; return arguments[0]; } console.log(f(1));': (
        inspect.cleandoc(
            """
            function f(a) {
              arguments = [7];
              return arguments[0];
            }
            console.log(f(1));
            """
        ),
        'console.log(7);',
    ),
}

_AN_ALIASING_THAT_IS_OBSERVED: dict[str, tuple[str, str]] = {
    'function f(a) { a = 2; return arguments[0]; } console.log(f(1));': (
        inspect.cleandoc(
            """
            function f(a) {
              a = 2;
              return arguments[0];
            }
            console.log(f(1));
            """
        ),
        'console.log(2);',
    ),
    'function f(a) { arguments[0] = 2; return a; } console.log(f(1));': (
        inspect.cleandoc(
            """
            function f(a) {
              arguments[0] = 2;
              return a;
            }
            console.log(f(1));
            """
        ),
        'console.log(2);',
    ),
    'function f(a) { var arguments; a = 5; return arguments[0]; } console.log(f(1));': (
        inspect.cleandoc(
            """
            function f(a) {
              var arguments;
              a = 5;
              return arguments[0];
            }
            console.log(f(1));
            """
        ),
        'console.log(5);',
    ),
}

#: A key that is no array index, mapped to what Node prints: `1:2:3` is every parameter still
#: holding what the call passed. A key names an index only when its string form is the canonical
#: decimal spelling of one, so a sign, a leading zero, a fraction, surrounding space, an exponent
#: and a digit outside ASCII each name an ordinary property.
_A_KEY_THAT_REACHES_NO_ELEMENT: dict[str, str] = {
    'arguments[1e400] = 9' : '1:2:3\n',
    'arguments[1e21] = 9'  : '1:2:3\n',
    'arguments[-1] = 9'    : '1:2:3\n',
    'arguments[1.5] = 9'   : '1:2:3\n',
    "arguments['01'] = 9"  : '1:2:3\n',
    "arguments['+1'] = 9"  : '1:2:3\n',
    "arguments[' 1'] = 9"  : '1:2:3\n',
    "arguments['1e0'] = 9" : '1:2:3\n',
    "arguments['²'] = 9"   : '1:2:3\n',
    "arguments['١'] = 9"   : '1:2:3\n',
}

#: A number key names the element its value converts to, however the source spells it; `-0` converts
#: to `'0'`.
_A_KEY_THAT_REACHES_AN_ELEMENT: dict[str, str] = {
    'arguments[1] = 9'   : '1:9:3\n',
    'arguments[1.0] = 9' : '1:9:3\n',
    'arguments[1e0] = 9' : '1:9:3\n',
    'arguments[0x1] = 9' : '1:9:3\n',
    "arguments['1'] = 9" : '1:9:3\n',
    'arguments[-0] = 9'  : '9:2:3\n',
}

_A_KEY_THE_TOOL_CANNOT_COMPUTE: dict[str, str] = {
    'function f(a, b) { var k = Math.random() < 2 ? 1 : 0; a = 5; arguments[k] = 9;'
    " return a + ':' + b; } console.log(f(1, 2));": '5:9\n',
    'function f(a, b) { var k = Math.random() < 2 ? 0 : 1; a = 5; arguments[k] = 9;'
    " return a + ':' + b; } console.log(f(1, 2));": '9:2\n',
}

_A_NAME_THAT_DENOTES_SOMETHING_OTHER_THAN_THE_OBJECT: dict[str, str] = {
    "function f(arguments, b) { b = 3; arguments[1] = 9; return b + ':' + arguments[1]; }"
    ' console.log(f([1], 2));': '3:9\n',
    "function f(a) { var arguments = [7]; arguments[0] = 9; return a + ':' + arguments[0]; }"
    ' console.log(f(1));': '1:9\n',
    'function f(a) { try { throw [1]; } catch (arguments) { arguments[0] = 9; } return a; }'
    ' console.log(f(1));': '1\n',
    'function f(a) { arguments = [1]; arguments[0] = 9; return a; } console.log(f(1));': '1\n',
}

_A_DECLARATION_THAT_LEAVES_THE_OBJECT_WHERE_IT_WAS: dict[str, str] = {
    'function f(a) { var arguments; arguments[0] = 9; return a; } console.log(f(1));': '9\n',
    'function f(a) { var arguments; a = 5; arguments[0] = 9; return a; } console.log(f(1));': '9\n',
    'function f(a) { var arguments; a = 5; return arguments[0]; } console.log(f(1));': '5\n',
    'function f(a) { a = 5; var arguments; return arguments[0]; } console.log(f(1));': '5\n',
    'function f(a, b) { var arguments; b = 5; return arguments[1]; } console.log(f(1, 2));': '5\n',
}

_A_DECLARATION_THAT_PUTS_AN_ARRAY_UNDER_THE_NAME: dict[str, str] = {
    'function f(a) { var arguments = [7]; a = 5; return arguments[0]; } console.log(f(1));': '7\n',
    'function f(a) { var arguments = [7]; arguments[0] = 9; return a; } console.log(f(1));': '1\n',
    'function f(a) { arguments = [7]; a = 5; return arguments[0]; } console.log(f(1));': '7\n',
    'function f(a) { arguments = [7]; arguments[0] = 9; return a; } console.log(f(1));': '1\n',
}

_A_PARENTHESIZED_RECEIVER: dict[str, str] = {
    'function f(a) { (arguments)[0] = 9; return a; } console.log(f(1));': '9\n',
    'function f(a) { ((arguments))[0] = 9; return a; } console.log(f(1));': '9\n',
    'function f(a) { a = 2; return (arguments)[0]; } console.log(f(1));': '2\n',
}

_A_MODULE_IS_STRICT_WITH_NOTHING_SAYING_SO: dict[str, str] = {
    'function f(a) { a = 2; return arguments[0]; } export const v = f(1); console.log(v);': '1\n',
    'function f(a) { arguments[0] = 2; return a; } export const v = f(1); console.log(v);': '1\n',
}


def _reading(expression: str) -> str:
    return F'var i = 0; function f(a) {{ a = 2; return {expression}; }} console.log(f(1));'


def _writing(statement: str) -> str:
    return F'var i = 0; function f(a) {{ {statement}; return a; }} console.log(f(1));'


def _standing(tail: str) -> str:
    return F'function f(a) {{ a = 2; {tail} }} console.log(f(1));'


def _keyed(statement: str) -> str:
    return (
        F"function f(a, b, c) {{ {statement}; return a + ':' + b + ':' + c; }}"
        F' console.log(f(1, 2, 3));'
    )


_READS = {_reading(k): v for k, v in _A_READ_THROUGH_THE_OBJECT.items()}

_WRITES = {_writing(k): v for k, v in _A_WRITE_THROUGH_THE_OBJECT.items()}

_PLACES = {_standing(k): v for k, v in _WHERE_THE_REFERENCE_TO_THE_OBJECT_STANDS.items()}

_KEYS_THAT_MISS = {_keyed(k): v for k, v in _A_KEY_THAT_REACHES_NO_ELEMENT.items()}

_KEYS_THAT_HIT = {_keyed(k): v for k, v in _A_KEY_THAT_REACHES_AN_ELEMENT.items()}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestASloppyListOfPlainNamesIsAliasedByTheObject(TestBase):

    def test_node_reads_back_the_value_written_under_the_other_name(self):
        rows = _A_LIST_OF_PLAIN_NAMES_IN_A_SLOPPY_BODY
        self.assertEqual(_said_by_node(rows), _printed(rows))

    def test_the_deobfuscation_reads_it_back_too(self):
        rows = _A_LIST_OF_PLAIN_NAMES_IN_A_SLOPPY_BODY
        self.assertEqual(_said_after_deobfuscation(rows), _printed(rows))


#: A function the `Function` constructor built is compiled in the global scope, so it cannot read
#: `i`, which only the function around the construction declares, and throws.
_A_CALL_TO_A_NAME_THE_CONSTRUCTOR_BUILT: dict[str, tuple[str, str | None]] = {
    "var f = Function('a', 'b', 'return arguments[1];'); console.log(f(1, 2));": ('2\n', None),
    "var f = Function('return arguments.length'); console.log(f(1, 2));": ('2\n', None),
    "var f = Function('a', 'a = 2; return arguments[0];'); console.log(f(1));": ('2\n', None),
    "var f = Function('a', 'arguments[0] = 2; return a;'); console.log(f(1));": ('2\n', None),
    "var f = Function('a', 'return a;'); console.log(f(1));": ('1\n', None),
    "'use strict'; var f = Function('a', \"'use strict'; a = 2; return arguments[0];\");"
    ' console.log(f(1));': ('1\n', None),
    "(function () { var i = 0; var f = Function('a', 'return arguments[i];');"
    ' console.log(f(1)); })();': ('', 'ReferenceError'),
    'var k = \'q\'; global[k] = 5; var f = Function(\'a\', \'return arguments[0].split(",")\');'
    " console.log(f('x,y,z')[1]);": ('y\n', None),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestACallToANameTheConstructorBuilt(TestBase):

    def test_node_answers_each_program_the_way_the_row_records(self):
        rows = _A_CALL_TO_A_NAME_THE_CONSTRUCTOR_BUILT
        self.assertEqual(_said_by_node(rows), dict(rows))

    def test_the_deobfuscation_answers_each_program_the_same_way(self):
        rows = _A_CALL_TO_A_NAME_THE_CONSTRUCTOR_BUILT
        self.assertEqual(_said_after_deobfuscation(rows), dict(rows))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAFunctionWhoseObjectAliasesNothing(TestBase):

    def test_node_answers_each_read_with_the_value_the_call_passed(self):
        rows = _AN_OBJECT_THAT_ALIASES_NOTHING
        self.assertEqual(_said_by_node(rows), _printed(rows))

    def test_the_deobfuscation_answers_it_the_same_way(self):
        rows = _AN_OBJECT_THAT_ALIASES_NOTHING
        self.assertEqual(_said_after_deobfuscation(rows), _printed(rows))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAUseStrictThatIsNoDirectiveLeavesTheBodySloppy(TestBase):

    def test_node_leaves_the_body_aliased(self):
        rows = _A_USE_STRICT_THAT_GOVERNS_NOTHING
        self.assertEqual(_said_by_node(rows), _printed(rows))

    def test_the_deobfuscation_leaves_it_aliased_too(self):
        rows = _A_USE_STRICT_THAT_GOVERNS_NOTHING
        self.assertEqual(_said_after_deobfuscation(rows), _printed(rows))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestHowTheObjectIsReached(TestBase):

    def test_node_answers_each_read_the_way_the_row_records(self):
        self.assertEqual(_said_by_node(_READS), _printed(_READS))

    def test_the_deobfuscation_answers_each_read_the_same_way(self):
        self.assertEqual(_said_after_deobfuscation(_READS), _printed(_READS))

    def test_node_answers_each_write_the_way_the_row_records(self):
        self.assertEqual(_said_by_node(_WRITES), _printed(_WRITES))

    def test_the_deobfuscation_answers_each_write_the_same_way(self):
        self.assertEqual(_said_after_deobfuscation(_WRITES), _printed(_WRITES))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestWhereTheReferenceToTheObjectStands(TestBase):

    def test_node_answers_each_placement_the_way_the_row_records(self):
        self.assertEqual(_said_by_node(_PLACES), _printed(_PLACES))

    def test_the_deobfuscation_answers_each_placement_the_same_way(self):
        self.assertEqual(_said_after_deobfuscation(_PLACES), _printed(_PLACES))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAModuleIsStrictCode(TestBase):

    def test_node_answers_the_module_with_the_value_the_call_passed(self):
        rows = _A_MODULE_IS_STRICT_WITH_NOTHING_SAYING_SO
        self.assertEqual(
            {source: behavior(source, module=True) for source in rows},
            _printed(rows),
        )

    def test_the_deobfuscation_answers_the_module_the_same_way(self):
        rows = _A_MODULE_IS_STRICT_WITH_NOTHING_SAYING_SO
        self.assertEqual(
            {
                source: behavior(_deobfuscated(source, module=True), module=True)
                for source in rows
            },
            _printed(rows),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestWhichKeysReachAnElement(TestBase):

    def test_node_leaves_every_parameter_alone_for_a_key_that_is_no_index(self):
        self.assertEqual(_said_by_node(_KEYS_THAT_MISS), _printed(_KEYS_THAT_MISS))

    def test_the_deobfuscation_leaves_them_alone_too(self):
        self.assertEqual(_said_after_deobfuscation(_KEYS_THAT_MISS), _printed(_KEYS_THAT_MISS))

    def test_node_writes_the_named_parameter_for_a_key_that_is_an_index(self):
        self.assertEqual(_said_by_node(_KEYS_THAT_HIT), _printed(_KEYS_THAT_HIT))

    def test_the_deobfuscation_writes_the_same_parameter(self):
        self.assertEqual(_said_after_deobfuscation(_KEYS_THAT_HIT), _printed(_KEYS_THAT_HIT))


class TestAKeyHostileToAnIntegerConversionIsStillRead(TestBase):
    """
    Keys that Python's `int` mishandles: it raises on an infinity and on some digits outside ASCII,
    and reads others as ASCII digits. None of these keys names a parameter.
    """

    def test_a_numeric_key_denoting_an_infinity_is_left_as_written_or_folded(self):
        self.assertIn(
            _deobfuscated(_keyed('arguments[1e400] = 9')),
            (
                inspect.cleandoc(
                    """
                    function f(a, b, c) {
                      arguments[1e400] = 9;
                      return a + ':' + b + ':' + c;
                    }
                    console.log(f(1, 2, 3));
                    """
                ),
                "console.log('1:2:3');",
            ),
        )

    def test_a_string_key_spelled_with_a_digit_outside_ascii_is_left_as_written_or_folded(self):
        self.assertIn(
            _deobfuscated(_keyed("arguments['١'] = 9")),
            (
                inspect.cleandoc(
                    """
                    function f(a, b, c) {
                      arguments['١'] = 9;
                      return a + ':' + b + ':' + c;
                    }
                    console.log(f(1, 2, 3));
                    """
                ),
                "console.log('1:2:3');",
            ),
        )

    def test_a_string_key_spelled_with_a_superscript_digit_is_left_as_written_or_folded(self):
        self.assertIn(
            _deobfuscated(_keyed("arguments['²'] = 9")),
            (
                inspect.cleandoc(
                    """
                    function f(a, b, c) {
                      arguments['²'] = 9;
                      return a + ':' + b + ':' + c;
                    }
                    console.log(f(1, 2, 3));
                    """
                ),
                "console.log('1:2:3');",
            ),
        )

    @opportunity
    def test_a_call_writing_through_a_key_hostile_to_an_integer_conversion_folds_to_its_value(self):
        for statement in ('arguments[1e400] = 9', "arguments['١'] = 9", "arguments['²'] = 9"):
            with self.subTest(statement=statement):
                self.assertEqual("console.log('1:2:3');", _deobfuscated(_keyed(statement)))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAKeyNoReadingOfTheTextComputes(TestBase):

    def test_node_writes_the_one_parameter_the_key_names_at_runtime(self):
        rows = _A_KEY_THE_TOOL_CANNOT_COMPUTE
        self.assertEqual(_said_by_node(rows), _printed(rows))

    def test_the_deobfuscation_writes_the_same_one(self):
        rows = _A_KEY_THE_TOOL_CANNOT_COMPUTE
        self.assertEqual(_said_after_deobfuscation(rows), _printed(rows))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestABodyThatBindsTheNameArgumentsItself(TestBase):

    def test_node_reaches_no_parameter_through_a_name_bound_to_something_else(self):
        rows = _A_NAME_THAT_DENOTES_SOMETHING_OTHER_THAN_THE_OBJECT
        self.assertEqual(_said_by_node(rows), _printed(rows))

    def test_the_deobfuscation_reaches_no_parameter_either(self):
        rows = _A_NAME_THAT_DENOTES_SOMETHING_OTHER_THAN_THE_OBJECT
        self.assertEqual(_said_after_deobfuscation(rows), _printed(rows))

    def test_node_keeps_the_aliasing_across_a_declaration_with_no_initializer(self):
        rows = _A_DECLARATION_THAT_LEAVES_THE_OBJECT_WHERE_IT_WAS
        self.assertEqual(_said_by_node(rows), _printed(rows))

    def test_the_deobfuscation_keeps_it_too(self):
        rows = _A_DECLARATION_THAT_LEAVES_THE_OBJECT_WHERE_IT_WAS
        self.assertEqual(_said_after_deobfuscation(rows), _printed(rows))

    def test_node_reaches_no_parameter_through_a_name_a_declaration_gave_a_value(self):
        rows = _A_DECLARATION_THAT_PUTS_AN_ARRAY_UNDER_THE_NAME
        self.assertEqual(_said_by_node(rows), _printed(rows))

    def test_the_deobfuscation_reaches_none_through_it_either(self):
        rows = _A_DECLARATION_THAT_PUTS_AN_ARRAY_UNDER_THE_NAME
        self.assertEqual(_said_after_deobfuscation(rows), _printed(rows))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAReceiverWrittenInParentheses(TestBase):

    def test_node_reaches_the_element_the_bare_spelling_reaches(self):
        rows = _A_PARENTHESIZED_RECEIVER
        self.assertEqual(_said_by_node(rows), _printed(rows))

    def test_the_deobfuscation_reaches_it_too(self):
        rows = _A_PARENTHESIZED_RECEIVER
        self.assertEqual(_said_after_deobfuscation(rows), _printed(rows))


class TestTheAliasingIsHonouredWithoutForfeitingTheSimplification(TestBase):

    def test_a_write_the_aliasing_does_not_reach_is_removed(self):
        rows = _AN_ALIASING_NOTHING_OBSERVES
        self.assertEqual({source: _deobfuscated(source) for source in rows}, rows)

    def test_a_write_the_aliasing_does_not_reach_is_removed_from_a_call_left_standing_or_folded(self):
        rows = _AN_ALIASING_NOTHING_OBSERVES_IN_A_CALL_THAT_MAY_STAND
        for source, (standing, folded) in rows.items():
            with self.subTest(source=source):
                self.assertIn(_deobfuscated(source), (standing, folded))

    @opportunity
    def test_a_call_whose_write_the_aliasing_does_not_reach_folds_to_its_value(self):
        rows = _AN_ALIASING_NOTHING_OBSERVES_IN_A_CALL_THAT_MAY_STAND
        self.assertEqual(
            {source: _deobfuscated(source) for source in rows},
            {source: folded for source, (_, folded) in rows.items()},
        )

    def test_a_call_whose_write_the_aliasing_reaches_is_left_as_written_or_folded(self):
        for source, (written, folded) in _AN_ALIASING_THAT_IS_OBSERVED.items():
            with self.subTest(source=source):
                self.assertIn(_deobfuscated(source), (written, folded))

    @opportunity
    def test_a_call_whose_write_the_aliasing_reaches_folds_to_the_value_read_back(self):
        rows = _AN_ALIASING_THAT_IS_OBSERVED
        self.assertEqual(
            {source: _deobfuscated(source) for source in rows},
            {source: folded for source, (_, folded) in rows.items()},
        )


_A_VALUE_READ_AHEAD_OF_AN_UNDECIDABLE_WRITE: dict[str, str] = {
    'function f(a, b) { var t = a; arguments[b] = 9; return t; }'
    ' console.log(f(1, 0));': '1\n',
    'function f(a, b) { var t = a * 2; arguments[b] = 9; return t; }'
    ' console.log(f(3, 0));': '6\n',
    "function f(a, b) { var t = 'x' + a; arguments[b] = 9; return t; }"
    ' console.log(f(1, 0));': 'x1\n',
    'function f(a, b) { var t = !a; arguments[b] = 9; return t; }'
    ' console.log(f(1, 0));': 'false\n',
    'function f(p) { var t = p + 1; arguments[Math.random() < 2 ? 0 : 1] = 99; return t; }'
    ' console.log(f(1));': '2\n',
    'function f(a, b) { var t = a; arguments[0] = 9; return t; }'
    ' console.log(f(1, 0));': '1\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAValueReadAheadOfAWriteThroughAKeyNothingComputes(TestBase):

    def test_node_answers_each_program_with_the_value_read_ahead_of_the_write(self):
        rows = _A_VALUE_READ_AHEAD_OF_AN_UNDECIDABLE_WRITE
        self.assertEqual(_said_by_node(rows), _printed(rows))

    def test_the_deobfuscation_answers_each_program_the_same_way(self):
        rows = _A_VALUE_READ_AHEAD_OF_AN_UNDECIDABLE_WRITE
        self.assertEqual(_said_after_deobfuscation(rows), _printed(rows))


_A_PARAMETER_WRITTEN_AT_A_POSITION_NOTHING_DECIDES: dict[str, str] = {
    'function f(a, b) { var o = { p: a }; arguments[b] = 9; console.log(o.p); } f(1, 0);': '1\n',
    'function f(a, b) { var o = { p: a }; arguments[b] += 9; console.log(o.p); } f(1, 0);': '1\n',
    'function f(a, b) { var o = { p: a }; function g() { return o.p; } arguments[b] = 9;'
    ' console.log(g()); } f(1, 0);': '1\n',
    'function g(x) { x[0] = 9; } function f(a) { var t = a; g(arguments); console.log(t, a); }'
    ' f(1);': '1 9\n',
    'function f(a) { var t = a; var q = arguments; q[0] = 9; console.log(t, a); } f(1);': '1 9\n',
    'function f(a, b) { var o = { p: a }; arguments[0] = 9; console.log(o.p); } f(1, 0);': '1\n',
}

_A_NAME_THAT_IS_NOT_THE_OBJECT_AFTER_ALL: dict[str, str] = {
    "function f(a) { function arguments() {} arguments[0] = {}; console.log('q' in a); }"
    ' f({q: 1});': 'true\n',
    "function f(a) { var [arguments] = [[7]]; arguments[0] = {}; console.log('q' in a); }"
    ' f({q: 1});': 'true\n',
    "function f(a) { with ({arguments: [7]}) { arguments[0] = {}; } console.log('q' in a); }"
    ' f({q: 1});': 'true\n',
    "function f(a) { for (var arguments of [[7]]) { arguments[0] = {}; } console.log('q' in a); }"
    ' f({q: 1});': 'true\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAParameterWrittenAtAPositionNothingDecides(TestBase):

    def test_node_answers_each_program_with_the_value_read_ahead_of_the_write(self):
        rows = _A_PARAMETER_WRITTEN_AT_A_POSITION_NOTHING_DECIDES
        self.assertEqual(_said_by_node(rows), _printed(rows))

    def test_the_deobfuscation_answers_each_program_the_same_way(self):
        rows = _A_PARAMETER_WRITTEN_AT_A_POSITION_NOTHING_DECIDES
        self.assertEqual(_said_after_deobfuscation(rows), _printed(rows))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAWrittenNameThatIsNotTheObject(TestBase):

    def test_node_leaves_the_parameter_untouched(self):
        rows = _A_NAME_THAT_IS_NOT_THE_OBJECT_AFTER_ALL
        self.assertEqual(_said_by_node(rows), _printed(rows))

    def test_the_deobfuscation_leaves_it_untouched_too(self):
        rows = _A_NAME_THAT_IS_NOT_THE_OBJECT_AFTER_ALL
        self.assertEqual(_said_after_deobfuscation(rows), _printed(rows))


#: An element aliases a parameter only where the call passed an argument at that position, so the
#: same body answers differently under two arities. A position past the end of the parameter list
#: aliases nothing, however many arguments arrive.
_A_WRITE_AT_A_POSITION_THE_CALL_MAY_NOT_HAVE_FILLED: dict[str, str] = {
    'function f(a, b) { arguments[1] = 9; return b; } console.log(f(1), f(1, 2));':
        'undefined 9\n',
    'function f(a, b) { b = 3; arguments[1] = 9; return b; } console.log(f(1), f(1, 2));':
        '3 9\n',
    'function f(a, b) { b = 3; return arguments[1]; } console.log(f(1), f(1, 2));':
        'undefined 3\n',
    'function f(a, b) { arguments[1] = 9; return b; } console.log(f(1));':
        'undefined\n',
    'function f(a, b) { arguments[1] = 9; return b; } console.log(f(1, 2));':
        '9\n',
    'function f(a) { arguments[0] = 9; return a; } console.log(f());':
        'undefined\n',
    'function f(a) { arguments[0] = 9; return a; } console.log(f(1));':
        '9\n',
    'function f(a) { arguments[1] = 9; return a; } console.log(f(1, 2));':
        '1\n',
    'function f(a) { a = 5; return arguments.length; } console.log(f(), f(1), f(1, 2));':
        '0 1 2\n',
}

#: Deleting an element breaks its link to the parameter and leaves the parameter as it was:
#: afterwards, a write to either is no longer read back through the other.
_AN_ELEMENT_DELETED_AHEAD_OF_THE_WRITE: dict[str, str] = {
    'function f(a) { delete arguments[0]; arguments[0] = 9; return a; } console.log(f(1));':
        '1\n',
    'function f(a) { delete arguments[0]; a = 5; return arguments[0]; } console.log(f(1));':
        'undefined\n',
    'function f(a) { delete arguments[0]; return a; } console.log(f(1));':
        '1\n',
    'function f(a, b) { delete arguments[1]; arguments[1] = 9; return b; } console.log(f(1, 2));':
        '2\n',
    "function f(a, b) { delete arguments[0]; b = 3; return arguments[0] + ':' + arguments[1]; }"
    ' console.log(f(1, 2));':
        'undefined:3\n',
    "function f(a, b) { a = 5; delete arguments[1]; arguments[1] = 9; return a + ':' + b; }"
    ' console.log(f(1, 2));':
        '5:2\n',
}

_A_STORE_A_MENTION_OF_THE_OBJECT_KEEPS_ALIVE: dict[str, str] = {
    'function g(x) { console.log(x[0]); } function f(a) { a = 2; g(arguments); } f(1);':
        '2\n',
    'function f(a) { a = 2; console.log(Array.prototype.slice.call(arguments)[0]); } f(1);':
        '2\n',
    'function f(a) { a = 2; (function () { console.log(arguments[0]); }).apply(null, arguments); }'
    ' f(1);':
        '2\n',
    'function f(a) { a = 2; [].forEach.call(arguments, function (v) { console.log(v); }); } f(1);':
        '2\n',
    'function f(a) { a = 2; var h = arguments; console.log(h[0]); } f(1);':
        '2\n',
    'function f(a) { a = 2; console.log(JSON.stringify(arguments)); } f(1);':
        '{"0":2}\n',
    'function f(a) { a = 2; delete arguments; console.log(arguments[0]); } f(1);':
        '2\n',
    'function f(a) { a = 2; console.log(delete arguments); } f(1);':
        'false\n',
    'function f(a) { var g = () => { arguments[0] = 9; }; g(); console.log(a); } f(1);':
        '9\n',
    'function f(a) { var g = () => { arguments[0] = 9; }; a = 2; g(); console.log(a); } f(1);':
        '9\n',
    'function f(a) { var g = () => { arguments[0] = 9; }; g(); a = 2;'
    ' console.log(arguments[0]); } f(1);':
        '2\n',
    'function f(a) { a = 2; var g = () => arguments[0]; console.log(g()); } f(1);':
        '2\n',
}

#: Every way a body can bind the name `arguments`, mapped to what Node answers: the type
#: `Object.prototype.toString` gives the value the name then holds, or the error where the text is
#: no program. A `var` without an initializer keeps the object, a function expression's own name is
#: shadowed by the object, and a class may not be named `arguments` because a class name is strict
#: code.
_EVERY_WAY_A_BODY_BINDS_THE_NAME_ITSELF: dict[str, tuple[str, str | None]] = {
    'function f(arguments) { console.log(Object.prototype.toString.call(arguments)); } f(1);':
        ('[object Number]\n', None),
    'function f(p) { var arguments;'
    ' console.log(Object.prototype.toString.call(arguments)); } f(1);':
        ('[object Arguments]\n', None),
    'function f(p) { var arguments = [7];'
    ' console.log(Object.prototype.toString.call(arguments)); } f(1);':
        ('[object Array]\n', None),
    'function f(p) { let arguments;'
    ' console.log(Object.prototype.toString.call(arguments)); } f(1);':
        ('[object Undefined]\n', None),
    'function f(p) { let arguments = [7];'
    ' console.log(Object.prototype.toString.call(arguments)); } f(1);':
        ('[object Array]\n', None),
    'function f(p) { class arguments {}'
    ' console.log(Object.prototype.toString.call(arguments)); } f(1);':
        ('', 'SyntaxError'),
    'function f(p) { function arguments() {}'
    ' console.log(Object.prototype.toString.call(arguments)); } f(1);':
        ('[object Function]\n', None),
    'function f(p) { try { throw [7]; } catch (arguments) {'
    ' console.log(Object.prototype.toString.call(arguments)); } } f(1);':
        ('[object Array]\n', None),
    'function f(p) { arguments = [7];'
    ' console.log(Object.prototype.toString.call(arguments)); } f(1);':
        ('[object Array]\n', None),
    'var f = function arguments(p) {'
    ' console.log(Object.prototype.toString.call(arguments)); }; f(1);':
        ('[object Arguments]\n', None),
}

_THE_ALIASING_UNDER_A_NAME_THE_BODY_BINDS: dict[str, str] = {
    'function f(p) { var arguments; p = 5; console.log(arguments[0]); } f(1);': '5\n',
    'function f(p) { var arguments; arguments[0] = 9; console.log(p); } f(1);': '9\n',
    'var f = function arguments(p) { p = 5; console.log(arguments[0]); }; f(1);': '5\n',
    'var f = function arguments(p) { arguments[0] = 9; console.log(p); }; f(1);': '9\n',
    'function f(p) { var arguments = [7]; p = 5; console.log(arguments[0]); } f(1);': '7\n',
    'function f(p) { var arguments = [7]; arguments[0] = 9; console.log(p); } f(1);': '1\n',
    'function f(p) { let arguments = [7]; p = 5; console.log(arguments[0]); } f(1);': '7\n',
    'function f(p) { let arguments = [7]; arguments[0] = 9; console.log(p); } f(1);': '1\n',
    'function f(p) { let arguments; p = 5; console.log(arguments); } f(1);': 'undefined\n',
    'function f(p) { arguments = [7]; p = 5; console.log(arguments[0]); } f(1);': '7\n',
    'function f(p) { function arguments() {} p = 5; console.log(arguments.name); } f(1);':
        'arguments\n',
    'function f(p) { function arguments() {} arguments[0] = 9; console.log(p); } f(1);': '1\n',
    'function f(p) { try { throw [7]; } catch (arguments) { p = 5; console.log(arguments[0]); } }'
    ' f(1);': '7\n',
    'function f(p) { try { throw [7]; } catch (arguments) { arguments[0] = 9; } console.log(p); }'
    ' f(1);': '1\n',
    'function f(arguments, b) { b = 5; console.log(arguments[1]); } f([0, 7], 1);': '7\n',
    'function f(arguments, b) { arguments[1] = 9; console.log(b); } f([0, 7], 1);': '1\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestHowManyArgumentsTheCallSupplied(TestBase):

    def test_node_answers_each_arity_the_way_the_row_records(self):
        rows = _A_WRITE_AT_A_POSITION_THE_CALL_MAY_NOT_HAVE_FILLED
        self.assertEqual(_said_by_node(rows), _printed(rows))

    def test_the_deobfuscation_answers_each_arity_the_same_way(self):
        rows = _A_WRITE_AT_A_POSITION_THE_CALL_MAY_NOT_HAVE_FILLED
        self.assertEqual(_said_after_deobfuscation(rows), _printed(rows))

    def test_node_answers_a_deleted_element_the_way_the_row_records(self):
        rows = _AN_ELEMENT_DELETED_AHEAD_OF_THE_WRITE
        self.assertEqual(_said_by_node(rows), _printed(rows))

    def test_the_deobfuscation_answers_a_deleted_element_the_same_way(self):
        rows = _AN_ELEMENT_DELETED_AHEAD_OF_THE_WRITE
        self.assertEqual(_said_after_deobfuscation(rows), _printed(rows))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAStoreAMentionOfTheObjectKeepsAlive(TestBase):

    def test_node_answers_each_mention_the_way_the_row_records(self):
        rows = _A_STORE_A_MENTION_OF_THE_OBJECT_KEEPS_ALIVE
        self.assertEqual(_said_by_node(rows), _printed(rows))

    def test_the_deobfuscation_answers_each_mention_the_same_way(self):
        rows = _A_STORE_A_MENTION_OF_THE_OBJECT_KEEPS_ALIVE
        self.assertEqual(_said_after_deobfuscation(rows), _printed(rows))


_A_STORE_NO_MENTION_OF_THE_OBJECT_KEEPS_ALIVE: dict[str, tuple[str, str]] = {
    'function g(x) { console.log(1); } function f(a) { a = 2; g(9); } f(1);': (
        inspect.cleandoc(
            """
            function g(x) {
              console.log(1);
            }
            function f(a) {
              g(9);
            }
            f(1);
            """
        ),
        'console.log(1);',
    ),
    'function f(a) { a = 2; var h = [9]; console.log(h[0]); } f(1);': (
        inspect.cleandoc(
            """
            function f(a) {
              console.log(9);
            }
            f(1);
            """
        ),
        'console.log(9);',
    ),
}


class TestAStoreNoMentionOfTheObjectKeepsAlive(TestBase):

    def test_the_store_is_removed_and_the_calls_left_standing_or_folded(self):
        for source, (standing, folded) in _A_STORE_NO_MENTION_OF_THE_OBJECT_KEEPS_ALIVE.items():
            with self.subTest(source=source):
                self.assertIn(_deobfuscated(source), (standing, folded))

    @opportunity
    def test_the_calls_fold_to_what_they_print(self):
        rows = _A_STORE_NO_MENTION_OF_THE_OBJECT_KEEPS_ALIVE
        self.assertEqual(
            {source: _deobfuscated(source) for source in rows},
            {source: folded for source, (_, folded) in rows.items()},
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestEveryWayABodyCanBindTheNameArguments(TestBase):

    def test_node_answers_each_binding_the_way_the_row_records(self):
        rows = _EVERY_WAY_A_BODY_BINDS_THE_NAME_ITSELF
        self.assertEqual(_said_by_node(rows), dict(rows))

    def test_the_deobfuscation_answers_each_binding_the_same_way(self):
        rows = _EVERY_WAY_A_BODY_BINDS_THE_NAME_ITSELF
        self.assertEqual(_said_after_deobfuscation(rows), dict(rows))

    def test_node_answers_the_aliasing_under_each_binding_the_way_the_row_records(self):
        rows = _THE_ALIASING_UNDER_A_NAME_THE_BODY_BINDS
        self.assertEqual(_said_by_node(rows), _printed(rows))

    def test_the_deobfuscation_answers_the_aliasing_under_each_binding_the_same_way(self):
        rows = _THE_ALIASING_UNDER_A_NAME_THE_BODY_BINDS
        self.assertEqual(_said_after_deobfuscation(rows), _printed(rows))


#: The legacy `callee.arguments` answers with the value the call passed, not the one the body
#: stored.
_A_USE_THAT_CAN_TOUCH_NO_PARAMETER: dict[str, str] = {
    'function f(a) { a = 2; console.log(typeof arguments); } f(1);': 'object\n',
    "function f(a) { a = 2; if (arguments) console.log('t'); } f(1);": 't\n',
    'function f(a) { a = 2; console.log(!arguments); } f(1);': 'false\n',
    'function f(a) { a = 2; console.log(void arguments); } f(1);': 'undefined\n',
    "function f(a) { a = 2; console.log(arguments ? 'y' : 'n'); } f(1);": 'y\n',
    'function f(a) { a = 2; for (var k in arguments) console.log(k); } f(1);': '0\n',
    "function f(a) { a = 2; while (arguments) { console.log('w'); break; } } f(1);": 'w\n',
    'function f(a) { a = 2; console.log(arguments.callee.arguments[0]); } f(1);': '1\n',
}

_THE_STORE_SUCH_A_USE_RELEASES: dict[str, tuple[str, str]] = {
    'function f(a) { a = 2; console.log(typeof arguments); } f(1);': (
        inspect.cleandoc(
            """
            function f(a) {
              console.log(typeof arguments);
            }
            f(1);
            """
        ),
        "console.log('object');",
    ),
    "function f(a) { a = 2; if (arguments) console.log('t'); } f(1);": (
        inspect.cleandoc(
            """
            function f(a) {
              if (arguments) {
                console.log('t');
              }
            }
            f(1);
            """
        ),
        "console.log('t');",
    ),
    'function f(a) { a = 2; console.log(!arguments); } f(1);': (
        inspect.cleandoc(
            """
            function f(a) {
              console.log(!arguments);
            }
            f(1);
            """
        ),
        'console.log(false);',
    ),
    'function f(a) { a = 2; console.log(void arguments); } f(1);': (
        inspect.cleandoc(
            """
            function f(a) {
              console.log(void arguments);
            }
            f(1);
            """
        ),
        'console.log(void 0);',
    ),
    "function f(a) { a = 2; console.log(arguments ? 'y' : 'n'); } f(1);": (
        inspect.cleandoc(
            """
            function f(a) {
              console.log(arguments ? 'y' : 'n');
            }
            f(1);
            """
        ),
        "console.log('y');",
    ),
    'function f(a) { a = 2; for (var k in arguments) console.log(k); } f(1);': (
        inspect.cleandoc(
            """
            function f(a) {
              for (var k in arguments) {
                console.log(k);
              }
            }
            f(1);
            """
        ),
        "console.log('0');",
    ),
    "function f(a) { a = 2; while (arguments) { console.log('w'); break; } } f(1);": (
        inspect.cleandoc(
            """
            function f(a) {
              while (arguments) {
                console.log('w');
                break;
              }
            }
            f(1);
            """
        ),
        "console.log('w');",
    ),
}

_A_WALK_THAT_READS_THE_STORE_BACK: dict[str, str] = {
    'function f(a) { a = 2; for (var v of arguments) console.log(v); } f(1);': '2\n',
    'function f(a) { a = 2; console.log([...arguments][0]); } f(1);': '2\n',
}

_A_CONVERSION_THAT_HANDS_THE_OBJECT_TO_CODE: dict[str, str] = {
    'function f(a) { a = 2; Object.prototype.toString = function () { return String(this[0]); };'
    ' console.log(+arguments); } f(1);': '2\n',
    'function f(a) { a = 2; Object.prototype.toString = function () { return String(this[0]); };'
    ' console.log(arguments == 2); } f(1);': 'true\n',
}

_A_CALL_FOLDED_PAST_A_USE_THAT_TOUCHES_NOTHING: dict[str, str] = {
    'function f(a) { var t = typeof arguments; return a + 1; } console.log(f(2));':
        'console.log(3);',
    'function f(a) { var t = arguments; return a + 1; } console.log(f(2));':
        'console.log(3);',
}

_A_CALL_A_WRITING_USE_KEEPS_ALIVE: dict[str, str] = {
    'function f(a) { arguments[0] = 9; return a + 1; } console.log(f(2));': '10\n',
    'function f(a) { arguments[0]++; return a + 1; } console.log(f(2));': '4\n',
    'function g(x) { x[0] = 9; } function f(a) { g(arguments); return a + 1; }'
    ' console.log(f(2));': '10\n',
    'function f(a) { var h = arguments; h[0] = 9; return a + 1; } console.log(f(2));': '10\n',
    'function f(a) { (() => { arguments[0] = 9; })(); return a + 1; } console.log(f(2));': '10\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAUseThatCanTouchNoParameter(TestBase):

    def test_node_answers_each_use_without_the_stored_value(self):
        rows = _A_USE_THAT_CAN_TOUCH_NO_PARAMETER
        self.assertEqual(_said_by_node(rows), _printed(rows))

    def test_the_deobfuscation_answers_each_use_the_same_way(self):
        rows = _A_USE_THAT_CAN_TOUCH_NO_PARAMETER
        self.assertEqual(_said_after_deobfuscation(rows), _printed(rows))

    def test_node_answers_the_foldable_call_with_the_folded_value(self):
        rows = _A_CALL_FOLDED_PAST_A_USE_THAT_TOUCHES_NOTHING
        self.assertEqual(_said_by_node(rows), {source: ('3\n', None) for source in rows})


class TestTheSimplificationAHarmlessUseDoesNotForfeit(TestBase):

    def test_the_store_is_removed_and_the_use_kept_or_the_call_folded(self):
        for source, (kept, folded) in _THE_STORE_SUCH_A_USE_RELEASES.items():
            with self.subTest(source=source):
                self.assertIn(_deobfuscated(source), (kept, folded))

    @opportunity
    def test_the_call_beside_a_harmless_use_folds_to_what_it_prints(self):
        rows = _THE_STORE_SUCH_A_USE_RELEASES
        self.assertEqual(
            {source: _deobfuscated(source) for source in rows},
            {source: folded for source, (_, folded) in rows.items()},
        )

    def test_the_call_is_folded_to_its_value(self):
        rows = _A_CALL_FOLDED_PAST_A_USE_THAT_TOUCHES_NOTHING
        self.assertEqual({source: _deobfuscated(source) for source in rows}, rows)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAWalkThatReadsTheElements(TestBase):

    def test_node_reads_the_stored_value_back_out_of_the_walk(self):
        rows = _A_WALK_THAT_READS_THE_STORE_BACK
        self.assertEqual(_said_by_node(rows), _printed(rows))

    def test_the_deobfuscation_reads_it_back_too(self):
        rows = _A_WALK_THAT_READS_THE_STORE_BACK
        self.assertEqual(_said_after_deobfuscation(rows), _printed(rows))


#: An `arguments` object has no `@@asyncIterator` of its own, so `for await` runs the one the
#: program put on `Object.prototype` with the object as `this`, and that writes the parameter:
#: `f(2)` answers `10`, not `3`.
_A_WALK_THAT_HANDS_THE_OBJECT_TO_CODE: dict[str, str] = {
    'Object.prototype[Symbol.asyncIterator] = function () { this[0] = 9;'
    ' return { next() { return Promise.resolve({ done: true }); } }; };'
    ' async function f(a) { for await (const v of arguments) {} return a + 1; }'
    ' f(2).then(function (r) { console.log(r); });': '10\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnAsynchronousWalkHandsTheObjectToCode(TestBase):

    def test_node_answers_the_call_with_the_value_the_protocol_wrote(self):
        rows = _A_WALK_THAT_HANDS_THE_OBJECT_TO_CODE
        self.assertEqual(_said_by_node(rows), _printed(rows))

    def test_the_deobfuscation_answers_the_call_the_same_way(self):
        rows = _A_WALK_THAT_HANDS_THE_OBJECT_TO_CODE
        self.assertEqual(_said_after_deobfuscation(rows), _printed(rows))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAConversionHandsTheObjectToCode(TestBase):

    def test_node_reads_the_parameter_through_the_poisoned_protocol(self):
        rows = _A_CONVERSION_THAT_HANDS_THE_OBJECT_TO_CODE
        self.assertEqual(_said_by_node(rows), _printed(rows))

    def test_the_deobfuscation_preserves_the_read(self):
        rows = _A_CONVERSION_THAT_HANDS_THE_OBJECT_TO_CODE
        self.assertEqual(_said_after_deobfuscation(rows), _printed(rows))


_A_MENTION_A_STATEMENT_DISCARDS: dict[str, str] = {
    'Object.prototype[Symbol.toPrimitive] = function () { this[0] = 9; return 0; };'
    ' function f(a) { arguments; return a + 1; } console.log(f(2));': '3\n',
    'Object.prototype[Symbol.toPrimitive] = function () { this[0] = 9; return 0; };'
    ' function f(a) { (arguments); return a + 1; } console.log(f(2));': '3\n',
    'Object.prototype[Symbol.toPrimitive] = function () { this[0] = 9; return 0; };'
    ' function f(a) { +arguments; return a + 1; } console.log(f(2));': '10\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAMentionAStatementDiscards(TestBase):

    def test_node_answers_each_use_the_way_the_row_records(self):
        rows = _A_MENTION_A_STATEMENT_DISCARDS
        self.assertEqual(_said_by_node(rows), _printed(rows))

    def test_the_deobfuscation_answers_each_use_the_same_way(self):
        rows = _A_MENTION_A_STATEMENT_DISCARDS
        self.assertEqual(_said_after_deobfuscation(rows), _printed(rows))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAUseThatCanWriteAParameter(TestBase):

    def test_node_answers_each_call_with_the_written_value(self):
        rows = _A_CALL_A_WRITING_USE_KEEPS_ALIVE
        self.assertEqual(_said_by_node(rows), _printed(rows))

    def test_the_deobfuscation_answers_each_call_the_same_way(self):
        rows = _A_CALL_A_WRITING_USE_KEEPS_ALIVE
        self.assertEqual(_said_after_deobfuscation(rows), _printed(rows))
