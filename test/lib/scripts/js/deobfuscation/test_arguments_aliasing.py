"""
An `arguments` object whose elements alias the parameters of the function that has it.

Such an object is not a copy of the call's arguments: element `i` and parameter `i` are one location.
Writing the parameter is read back off the object, and writing the object is read back under the
parameter's name, so a write to either is a write neither a sweep over the parameter's uses nor a
sweep over the object's can see alone.

Which functions have one was measured with Node, across every axis below, and the measurement is what
each corpus records:

- The mode the body runs in. A sloppy body has the aliasing and a strict one an independent copy, and
  a body comes to be strict through its own Directive Prologue, through the prologue of the script or
  of any function around it, through standing anywhere in a class definition, or through being module
  code, which is strict with nothing saying so. A string that is not a directive changes no mode: one
  behind a statement, one written with an escape, one in parentheses and one inside a nested block
  all leave the body sloppy, however a rewrite that moves or unwraps it spells it afterwards.
- The kind of function. A declaration, an expression, a generator, an async function, a method, a
  setter, and a body the `Function` constructor compiles all have an object of their own. An arrow has
  none and reads the one belonging to the function around it; a nested function has its own, and the
  enclosing parameters are not what its elements alias.
- The shape of the parameter list. Aliasing needs a list of plain names: a default, a rest element or
  a destructuring pattern anywhere in the list gives every parameter in it an independent copy, and a
  list of no parameters has nothing for an element to alias. Two parameters spelled with one name are
  still a list of plain names.
- How the object is reached. `arguments[0]`, `arguments['0']` and a key computed at runtime name a
  parameter; `arguments.length`, `arguments.callee`, a key that is no index and an index past the end
  of the list observe no parameter's value; and a spread, an `Array.from`, an `apply`, a second name
  bound to the object and the object handed to a call put every parameter in reach. A write lands
  through the same spellings, except that deleting an element first breaks the link the write would
  otherwise have travelled.
- Where the reference stands. A block, a loop, a `try`, a `with`, an arrow at any depth and a direct
  `eval` all reach the enclosing object, whatever mode the eval's own code declares. A nested regular
  function introduces its own, and an arrow inside that nested function reads the nested one.
- How the key is spelled. An element is reached only through the canonical decimal spelling of its
  index, so a sign, a leading zero, a fraction, surrounding space, an exponent, a number no such
  spelling names and a digit outside ASCII all name an ordinary property and reach no parameter. The
  receiver may be written in parentheses, which is no operation and changes nothing.
- Whether the name `arguments` still denotes the object. A parameter of that name, a `var` given a
  value, a catch parameter and an assignment over the object each leave the name denoting something
  whose elements alias nothing; a `var` with no initializer is initialized from the object the
  function was given and leaves the aliasing where it was.

Every absolute value here is Node's. Each corpus is asserted twice: once against Node, which is what
makes the recorded value a measurement rather than a claim, and once against the text the
deobfuscation produces, which is the law.
"""
from __future__ import annotations

import inspect
import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import behavior, node_executable

from refinery.units.scripting.js import js


def _deobfuscated(source: str, *, module: bool = False) -> str:
    return source.encode('utf8') | js(module=module) | str


def _printed(rows: dict[str, str]) -> dict[str, tuple[str, str | None]]:
    """
    What Node has to make of each program of *rows*: the text the row records, with nothing thrown.
    """
    return {source: (printed, None) for source, printed in rows.items()}


def _said_by_node(rows: dict[str, str]) -> dict[str, tuple[str, str | None]]:
    return {source: behavior(source) for source in rows}


def _said_after_deobfuscation(rows: dict[str, str]) -> dict[str, tuple[str, str | None]]:
    return {source: behavior(_deobfuscated(source)) for source in rows}


#: A sloppy function whose parameter list is a run of plain names, mapped to what Node prints for it.
#: One name is written and the other spelling of it is read, in both directions, so `2` is the value
#: the body wrote and `1` would be the one the call passed.
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

#: A function whose object aliases no parameter, mapped to what Node prints for it. `1` is the value
#: the call passed, which is what a read answers when the write it should have been read back from
#: reached an independent location.
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

#: A `use strict` that declares nothing, mapped to what Node prints for the sloppy function standing
#: beside it. A directive is a statement whose expression is the literal and which opens the list it
#: stands in, so a parenthesized one, one behind an ordinary statement, one written with an escape and
#: one inside a nested block are all ordinary string-valued statements.
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

#: An expression that reads through the object, mapped to what Node prints when a sloppy function of
#: one parameter returns it after writing that parameter. `2` is the written value read back, `1` is a
#: count rather than a value, and `undefined` is a key the list holds no element at.
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

#: A statement that writes through the object, mapped to what Node prints when a sloppy function of
#: one parameter runs it and then returns the parameter. A key that is no index, an index past the end
#: of the list and the length are locations no parameter stands at, and a deleted element is one whose
#: link to its parameter is gone before the write lands.
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

#: The tail of a sloppy one-parameter body that has already written its parameter, mapped to what Node
#: prints for it. `2` is the enclosing object answering; `7` is a nested function's own object, which
#: holds the argument that nested call was made with and no parameter of the function around it.
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

#: A program whose function has an object aliasing its parameters that nothing in it reads a
#: parameter through, mapped to the text the deobfuscation writes for it. Each write is dead in fact
#: and not merely unread by name, so the tool is free to remove it and does.
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
    'function f(a = 0) { a = 2; return arguments[0]; } console.log(f(1));': inspect.cleandoc(
        """
        function f(a = 0) {
          return arguments[0];
        }
        console.log(f(1));
        """
    ),
    'function f(a) { arguments = [7]; a = 5; return arguments[0]; } console.log(f(1));':
        inspect.cleandoc(
            """
            function f(a) {
              arguments = [7];
              return arguments[0];
            }
            console.log(f(1));
            """
        ),
}

#: A program whose write the aliasing carries to the other name, mapped to the text the deobfuscation
#: writes for it. Each is a row of `_AN_ALIASING_NOTHING_OBSERVES` with the aliasing brought into
#: what the body does, so that what the tool does with it is pinned as text and not only as an
#: answer Node gives.
_AN_ALIASING_THAT_IS_OBSERVED: dict[str, str] = {
    'function f(a) { a = 2; return arguments[0]; } console.log(f(1));': inspect.cleandoc(
        """
        function f(a) {
          a = 2;
          return arguments[0];
        }
        console.log(f(1));
        """
    ),
    'function f(a) { arguments[0] = 2; return a; } console.log(f(1));': inspect.cleandoc(
        """
        function f(a) {
          arguments[0] = 2;
          return a;
        }
        console.log(f(1));
        """
    ),
    'function f(a) { var arguments; a = 5; return arguments[0]; } console.log(f(1));':
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
}

#: A key that is legal JavaScript and no array index, mapped to what Node prints when a sloppy
#: function of three parameters writes through it and then returns all three. `1:2:3` is every
#: parameter still holding what the call passed, so the write landed on the object and on no
#: parameter. A key is an index only where it is the canonical decimal spelling of one, which rules
#: out a sign, a leading zero, a fraction, surrounding space, an exponent, a number no decimal
#: spelling of an integer names, and a digit outside ASCII.
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

#: A key that does reach an element, mapped to what Node prints for the same body. The value stands
#: at the position the key names however the source spelled the number, and `-0` names the first.
_A_KEY_THAT_REACHES_AN_ELEMENT: dict[str, str] = {
    'arguments[1] = 9'   : '1:9:3\n',
    'arguments[1.0] = 9' : '1:9:3\n',
    'arguments[1e0] = 9' : '1:9:3\n',
    'arguments[0x1] = 9' : '1:9:3\n',
    "arguments['1'] = 9" : '1:9:3\n',
    'arguments[-0] = 9'  : '9:2:3\n',
}

#: A program writing through the object at a key no reading of the text computes, mapped to what
#: Node prints for it. The key is `1`, so the write lands on the second parameter and the value the
#: first was given a statement earlier is the one it still holds.
_A_KEY_THE_TOOL_CANNOT_COMPUTE: dict[str, str] = {
    'function f(a, b) { var k = Date.now() > 0 ? 1 : 0; a = 5; arguments[k] = 9;'
    " return a + ':' + b; } console.log(f(1, 2));": '5:9\n',
    'function f(a, b) { var k = Date.now() > 0 ? 0 : 1; a = 5; arguments[k] = 9;'
    " return a + ':' + b; } console.log(f(1, 2));": '9:2\n',
}

#: A body that binds the name `arguments` itself, mapped to what Node prints for it. A parameter of
#: that name, a `var` given a value, a catch parameter and an assignment over the object each leave
#: the name denoting something whose elements alias no parameter, so a write through it is read back
#: only through the name it was written through.
_A_NAME_THAT_DENOTES_SOMETHING_OTHER_THAN_THE_OBJECT: dict[str, str] = {
    "function f(arguments, b) { b = 3; arguments[1] = 9; return b + ':' + arguments[1]; }"
    ' console.log(f([1], 2));': '3:9\n',
    "function f(a) { var arguments = [7]; arguments[0] = 9; return a + ':' + arguments[0]; }"
    ' console.log(f(1));': '1:9\n',
    'function f(a) { try { throw [1]; } catch (arguments) { arguments[0] = 9; } return a; }'
    ' console.log(f(1));': '1\n',
    'function f(a) { arguments = [1]; arguments[0] = 9; return a; } console.log(f(1));': '1\n',
}

#: A `var arguments` with no initializer, mapped to what Node prints for it. The declaration binds
#: the name the function was already given the object under and initializes it from that object,
#: wherever in the body it is written, so the aliasing is untouched in both of its directions: `9`
#: is a write through the object read back under the parameter's name, and `5` is a write to the
#: parameter read back off the object.
_A_DECLARATION_THAT_LEAVES_THE_OBJECT_WHERE_IT_WAS: dict[str, str] = {
    'function f(a) { var arguments; arguments[0] = 9; return a; } console.log(f(1));': '9\n',
    'function f(a) { var arguments; a = 5; arguments[0] = 9; return a; } console.log(f(1));': '9\n',
    'function f(a) { var arguments; a = 5; return arguments[0]; } console.log(f(1));': '5\n',
    'function f(a) { a = 5; var arguments; return arguments[0]; } console.log(f(1));': '5\n',
    'function f(a, b) { var arguments; b = 5; return arguments[1]; } console.log(f(1, 2));': '5\n',
}

#: The same name given a value instead, mapped to what Node prints for the same two directions. An
#: initializer and an assignment each put an array under the name, so a read through it answers the
#: element that array holds rather than the parameter, and a write through it lands on the array and
#: leaves the parameter holding what the call passed.
_A_DECLARATION_THAT_PUTS_AN_ARRAY_UNDER_THE_NAME: dict[str, str] = {
    'function f(a) { var arguments = [7]; a = 5; return arguments[0]; } console.log(f(1));': '7\n',
    'function f(a) { var arguments = [7]; arguments[0] = 9; return a; } console.log(f(1));': '1\n',
    'function f(a) { arguments = [7]; a = 5; return arguments[0]; } console.log(f(1));': '7\n',
    'function f(a) { arguments = [7]; arguments[0] = 9; return a; } console.log(f(1));': '1\n',
}

#: A receiver written in parentheses, mapped to what Node prints for it. A grouping is not an
#: operation, so each of these reaches the element its bare spelling reaches.
_A_PARENTHESIZED_RECEIVER: dict[str, str] = {
    'function f(a) { (arguments)[0] = 9; return a; } console.log(f(1));': '9\n',
    'function f(a) { ((arguments))[0] = 9; return a; } console.log(f(1));': '9\n',
    'function f(a) { a = 2; return (arguments)[0]; } console.log(f(1));': '2\n',
}

#: A module, which is strict code with no directive saying so, mapped to what Node prints for it. The
#: same body spelled in a script prints `2`, so the file's kind is the whole of the difference.
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
    A key is read for the index it names and not converted through Python's `int`, which raises on a
    Number literal denoting an infinity and reads digits outside ASCII as the value they would have
    in ASCII. Each program here is one no pass has anything to do to, so what the tool writes for it
    is the program itself.
    """

    def test_a_numeric_key_denoting_an_infinity_is_read(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                function f(a, b, c) {
                  arguments[1e400] = 9;
                  return a + ':' + b + ':' + c;
                }
                console.log(f(1, 2, 3));
                """
            ),
            _deobfuscated(_keyed('arguments[1e400] = 9')),
        )

    def test_a_string_key_spelled_with_a_digit_outside_ascii_is_read(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                function f(a, b, c) {
                  arguments['١'] = 9;
                  return a + ':' + b + ':' + c;
                }
                console.log(f(1, 2, 3));
                """
            ),
            _deobfuscated(_keyed("arguments['١'] = 9")),
        )

    def test_a_string_key_spelled_with_a_superscript_digit_is_read(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                function f(a, b, c) {
                  arguments['²'] = 9;
                  return a + ':' + b + ':' + c;
                }
                console.log(f(1, 2, 3));
                """
            ),
            _deobfuscated(_keyed("arguments['²'] = 9")),
        )


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

    def test_a_write_the_aliasing_reaches_is_left_standing(self):
        rows = _AN_ALIASING_THAT_IS_OBSERVED
        self.assertEqual({source: _deobfuscated(source) for source in rows}, rows)


#: A value taken out of a parameter ahead of a write through the object at a key no reading of the
#: text computes, mapped to what Node prints for it. Such a write lands on exactly one parameter and
#: which one is not decidable, so what every parameter held stops holding there, and a value read
#: before it is not the value a read after it would find. The last row writes at a key that *is*
#: decidable, where the parameter the write lands on is named and the ones beside it are untouched.
_A_VALUE_READ_AHEAD_OF_AN_UNDECIDABLE_WRITE: dict[str, str] = {
    'function f(a, b) { var t = a; arguments[b] = 9; return t; }'
    ' console.log(f(1, 0));': '1\n',
    'function f(a, b) { var t = a * 2; arguments[b] = 9; return t; }'
    ' console.log(f(3, 0));': '6\n',
    "function f(a, b) { var t = 'x' + a; arguments[b] = 9; return t; }"
    ' console.log(f(1, 0));': 'x1\n',
    'function f(a, b) { var t = !a; arguments[b] = 9; return t; }'
    ' console.log(f(1, 0));': 'false\n',
    'function f(p) { var t = p + 1; arguments[Date.now() > 0 ? 0 : 1] = 99; return t; }'
    ' console.log(f(1));': '2\n',
    'function f(a, b) { var t = a; arguments[0] = 9; return t; }'
    ' console.log(f(1, 0));': '1\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAValueReadAheadOfAWriteThroughAKeyNothingComputes(TestBase):
    """
    A write through the object at a key the text does not decide is a write of one parameter and a
    write of no *particular* parameter. Both halves are load-bearing. Attributing it to every
    parameter would let a fold answer a later read with a value only one of them can hold; attributing
    it to none leaves nothing saying that the value a parameter held stopped holding there, and a fold
    is then free to carry a read taken ahead of the write past it.
    """

    def test_node_answers_each_program_with_the_value_read_ahead_of_the_write(self):
        rows = _A_VALUE_READ_AHEAD_OF_AN_UNDECIDABLE_WRITE
        self.assertEqual(_said_by_node(rows), _printed(rows))

    def test_the_deobfuscation_answers_each_program_the_same_way(self):
        rows = _A_VALUE_READ_AHEAD_OF_AN_UNDECIDABLE_WRITE
        self.assertEqual(_said_after_deobfuscation(rows), _printed(rows))


#: A program whose parameter is written through the object at a position nothing in the text decides,
#: mapped to what Node prints for it. Each reads the parameter's value out ahead of that write, through
#: a route a different query answers: an object literal folded into its access site, a compound write,
#: a closure over the value, and the object escaping into a call or into a second name. A value-stability
#: query that answers over such a binding says it holds one value for its lifetime, which it does not.
#: The last row writes at a position the text does decide, where the parameter it lands on is named.
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

#: A function that has no `arguments` object aliasing its parameters, though the name is written in it,
#: mapped to what Node prints. A function declaration of that name means no such object is created at
#: all; a destructuring declarator and a `with` object each put something else under the name. `true`
#: is the parameter untouched, which is what every row asserts.
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
    """
    Such a write lands on one parameter and names none, so no parameter of the function holds one
    value for its lifetime afterwards. Every query that reports value stability has to say so, not
    only the one that computes reaching definitions, and an object the function hands out or binds to
    a second name is the same fact reached by another route.
    """

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


#: A body that writes its own object at a position the call may not have filled, mapped to what Node
#: prints for it. An element aliases a parameter only where the call passed an argument at that
#: position, so one text answers two ways under two arities: `undefined` is a parameter the call
#: left out, which a write through the object never reaches, and the written value is the one it
#: did pass.
#: A position past the end of the parameter list is nothing to alias however many arguments arrive.
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

#: The same two directions with the element deleted first, mapped to what Node prints. Deleting an
#: element breaks the link between it and the parameter and leaves both standing: a write through
#: the object afterwards lands on an ordinary property and the parameter keeps what the call
#: passed, and a write to the parameter is no longer read back off the object, which holds nothing
#: at that key.
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

#: A body that mentions its own object without naming a parameter through it, mapped to what Node
#: prints for it. Handing the object to a call, binding a second name to it and writing an element
#: from a nested arrow each put every parameter in reach, so the store to the parameter is one whose
#: value comes back. `delete` of the bare name stores nothing: the binding is not configurable, the
#: operator answers `false`, and the object is still the one the function was given.
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

#: Every way a body can bind the name `arguments` itself, mapped to the pair Node answers with: what
#: `Object.prototype.toString` calls the thing the name then denotes, and the error where the text
#: is no program at all. A parameter, an initialized `var`, a `let` of either shape, a function
#: declaration, a catch parameter and an assignment each put something else under the name; a `var`
#: with no initializer redeclares a name the function already has and leaves the object where it
#: was; and a function expression's own name is bound outside the object's, so the object shadows
#: it. A class binds its name as strict code, where `arguments` is a name no binding may take.
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

#: The same bindings asked what the aliasing still does, mapped to what Node prints. `5` and `9` are
#: a write read back under the other name, which is the aliasing still standing; `7` is the array
#: the binding put under the name answering instead, and `1` is the parameter untouched because the
#: write landed on that array. A `var` with no initializer and a function expression's own name
#: leave both directions where they were, and every other binding takes both.
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
    """
    Which elements alias a parameter is decided by the call and not by the function alone, so a
    write through the object at a fixed position reaches a parameter under one arity and no
    parameter under another. A rewrite that answers a later read out of such a write has to hold
    under both.
    """

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
    """
    A store to a parameter that no read of that parameter's name follows is still a store something
    reads, wherever the body brings the object within reach of a reader. Dropping it as dead is the
    one rewrite that turns each of these programs into a different one.
    """

    def test_node_answers_each_mention_the_way_the_row_records(self):
        rows = _A_STORE_A_MENTION_OF_THE_OBJECT_KEEPS_ALIVE
        self.assertEqual(_said_by_node(rows), _printed(rows))

    def test_the_deobfuscation_answers_each_mention_the_same_way(self):
        rows = _A_STORE_A_MENTION_OF_THE_OBJECT_KEEPS_ALIVE
        self.assertEqual(_said_after_deobfuscation(rows), _printed(rows))


#: A row of `_A_STORE_A_MENTION_OF_THE_OBJECT_KEEPS_ALIVE` with the mention of the object taken out,
#: mapped to the text the deobfuscation writes for it. Nothing observes the store any more and it is
#: gone, so what the mention buys is pinned as text and the law beside it is not one a tool that
#: rewrote nothing would satisfy.
_A_STORE_NO_MENTION_OF_THE_OBJECT_KEEPS_ALIVE: dict[str, str] = {
    'function g(x) { console.log(1); } function f(a) { a = 2; g(9); } f(1);': inspect.cleandoc(
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
    'function f(a) { a = 2; var h = [9]; console.log(h[0]); } f(1);': inspect.cleandoc(
        """
        function f(a) {
          console.log(9);
        }
        f(1);
        """
    ),
}


class TestAStoreNoMentionOfTheObjectKeepsAlive(TestBase):

    def test_the_deobfuscation_writes_the_text_the_row_records(self):
        rows = _A_STORE_NO_MENTION_OF_THE_OBJECT_KEEPS_ALIVE
        self.assertEqual({source: _deobfuscated(source) for source in rows}, rows)


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


#: A use of the object that observes only what it is — its type, its truth, its key set, or the
#: function it belongs to — mapped to what Node prints when a sloppy function stores to its
#: parameter first. No recorded value shows the store: such a use can neither write a parameter
#: nor hand the object to code that could, and the legacy `callee` route answers with the value
#: the call passed rather than the one the body stored.
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

#: The store ahead of such a use, mapped to the text the deobfuscation writes for it: the use
#: stays and the store is gone, because no construct that runs afterwards can read the parameter
#: back out of the object.
_THE_STORE_SUCH_A_USE_RELEASES: dict[str, str] = {
    'function f(a) { a = 2; console.log(typeof arguments); } f(1);': inspect.cleandoc(
        """
        function f(a) {
          console.log(typeof arguments);
        }
        f(1);
        """
    ),
    "function f(a) { a = 2; if (arguments) console.log('t'); } f(1);": inspect.cleandoc(
        """
        function f(a) {
          if (arguments) {
            console.log('t');
          }
        }
        f(1);
        """
    ),
    'function f(a) { a = 2; console.log(!arguments); } f(1);': inspect.cleandoc(
        """
        function f(a) {
          console.log(!arguments);
        }
        f(1);
        """
    ),
    'function f(a) { a = 2; console.log(void arguments); } f(1);': inspect.cleandoc(
        """
        function f(a) {
          console.log(void arguments);
        }
        f(1);
        """
    ),
    "function f(a) { a = 2; console.log(arguments ? 'y' : 'n'); } f(1);": inspect.cleandoc(
        """
        function f(a) {
          console.log(arguments ? 'y' : 'n');
        }
        f(1);
        """
    ),
    'function f(a) { a = 2; for (var k in arguments) console.log(k); } f(1);': inspect.cleandoc(
        """
        function f(a) {
          for (var k in arguments) {
            console.log(k);
          }
        }
        f(1);
        """
    ),
    "function f(a) { a = 2; while (arguments) { console.log('w'); break; } } f(1);":
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
}

#: A walk that reads every element out of the object, mapped to what Node prints for the same
#: store: the stored value comes back out of the walk, so the store is observed even though the
#: walk cannot write a parameter either. A `for-of` head reads the values where the `for-in` head
#: one keyword away reads only the keys.
_A_WALK_THAT_READS_THE_STORE_BACK: dict[str, str] = {
    'function f(a) { a = 2; for (var v of arguments) console.log(v); } f(1);': '2\n',
    'function f(a) { a = 2; console.log([...arguments][0]); } f(1);': '2\n',
}

#: A conversion of the object, mapped to what Node prints when the body has poisoned the protocol
#: the conversion enters. `ToPrimitive` runs whatever `Object.prototype` holds with the object as
#: `this`, so `+arguments` and `arguments == 2` hand the object to code that reads the parameter
#: through it — which `typeof`, `void` and `!` never do.
_A_CONVERSION_THAT_HANDS_THE_OBJECT_TO_CODE: dict[str, str] = {
    'function f(a) { a = 2; Object.prototype.toString = function () { return String(this[0]); };'
    ' console.log(+arguments); } f(1);': '2\n',
    'function f(a) { a = 2; Object.prototype.toString = function () { return String(this[0]); };'
    ' console.log(arguments == 2); } f(1);': 'true\n',
}

#: A call whose body computes only from its parameter beside a use that can touch no parameter,
#: mapped to the text the deobfuscation writes for it: the call is folded to its value. The first
#: row's use is one the position classification admits and the second's is not — binding the
#: object to a name is taken for a hand-off to anything that name reaches, and the call folds only
#: once the declarator nothing reads is swept and the use goes with it.
_A_CALL_FOLDED_PAST_A_USE_THAT_TOUCHES_NOTHING: dict[str, str] = {
    'function f(a) { var t = typeof arguments; return a + 1; } console.log(f(2));':
        'console.log(3);',
    'function f(a) { var t = arguments; return a + 1; } console.log(f(2));':
        'console.log(3);',
}

#: The same call beside a use that writes a parameter or hands the object to code that does,
#: mapped to what Node prints for it: the value written through the object, not the one the call
#: passed, so the fold above would answer every one of these with the wrong number.
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
    """
    What a body does with its object decides what may still be assumed about its parameters. Each
    of these uses takes the object to a type name, a truth value, a key set or the function it
    belongs to, and none of those is a route a parameter's value travels — Node's answer shows no
    trace of the store — so a store ahead of such a use is still the deobfuscator's to reason
    about.
    """

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

    def test_the_store_is_removed_and_the_use_is_kept(self):
        rows = _THE_STORE_SUCH_A_USE_RELEASES
        self.assertEqual({source: _deobfuscated(source) for source in rows}, rows)

    def test_the_call_is_folded_to_its_value(self):
        rows = _A_CALL_FOLDED_PAST_A_USE_THAT_TOUCHES_NOTHING
        self.assertEqual({source: _deobfuscated(source) for source in rows}, rows)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAWalkThatReadsTheElements(TestBase):
    """
    A spread and a `for-of` head read every element and write none: the values escape and the
    object does not. The walk cannot write a parameter, but the stored value is what it reads
    back, so the store has to outlive the removal its `for-in` neighbour permits.
    """

    def test_node_reads_the_stored_value_back_out_of_the_walk(self):
        rows = _A_WALK_THAT_READS_THE_STORE_BACK
        self.assertEqual(_said_by_node(rows), _printed(rows))

    def test_the_deobfuscation_reads_it_back_too(self):
        rows = _A_WALK_THAT_READS_THE_STORE_BACK
        self.assertEqual(_said_after_deobfuscation(rows), _printed(rows))


#: An asynchronous walk of the object beside the protocol it looks up, which the body has poisoned,
#: mapped to what Node prints. `f(2)` answers with `10` and not `3`, so the parameter came back
#: written by code the walk handed the object to.
_A_WALK_THAT_HANDS_THE_OBJECT_TO_CODE: dict[str, str] = {
    'Object.prototype[Symbol.asyncIterator] = function () { this[0] = 9;'
    ' return { next() { return Promise.resolve({ done: true }); } }; };'
    ' async function f(a) { for await (const v of arguments) {} return a + 1; }'
    ' f(2).then(function (r) { console.log(r); });': '10\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnAsynchronousWalkHandsTheObjectToCode(TestBase):
    """
    `for await` is one keyword away from the walk above and reaches the object a different way: it
    asks for `@@asyncIterator`, which §10.2.11 gives the object none of, so the lookup leaves the
    object for `Object.prototype` and calls whatever stands there with the object as `this`. A body
    that puts a parameter write there is answered with the written value, which is the measurement
    behind `_reads_every_element_alone` admitting the synchronous head and refusing this one.
    """

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


#: A mention of the object standing on its own as a statement, beside the conversion one character
#: away from it, mapped to what Node prints for each. `Object.prototype` holds a conversion that
#: writes element `0` in every row, so a position that enters it answers `10` and a position that
#: stays out of it answers `3`. An expression statement takes the value of its expression and throws
#: it away: no property of the object is touched and the object is handed to nobody, so the last
#: row is the only one of the three whose parameter comes back written. Wrapping the mention in
#: parentheses is no operation and leaves it the same statement.
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
    """
    A statement that is nothing but the name is the mention that reaches least: the value it takes
    goes nowhere, so it reads no element and hands the object to no code that could write one. This
    is the measurement behind that position being classified with `typeof` and `void` rather than
    with the hand-offs, which `test.lib.scripts.js.analysis.test_model` records as the answer the
    parameters of such a body carry.
    """

    def test_node_answers_each_use_the_way_the_row_records(self):
        rows = _A_MENTION_A_STATEMENT_DISCARDS
        self.assertEqual(_said_by_node(rows), _printed(rows))

    def test_the_deobfuscation_answers_each_use_the_same_way(self):
        rows = _A_MENTION_A_STATEMENT_DISCARDS
        self.assertEqual(_said_after_deobfuscation(rows), _printed(rows))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAUseThatCanWriteAParameter(TestBase):
    """
    An element written, an element updated, the object handed to a call, and the object written
    from behind a second name or a nested arrow each put a value under a parameter's name that
    the call did not pass. Node answers each call with that value, so folding any of these calls
    the way the harmless uses permit would answer with the wrong number.
    """

    def test_node_answers_each_call_with_the_written_value(self):
        rows = _A_CALL_A_WRITING_USE_KEEPS_ALIVE
        self.assertEqual(_said_by_node(rows), _printed(rows))

    def test_the_deobfuscation_answers_each_call_the_same_way(self):
        rows = _A_CALL_A_WRITING_USE_KEEPS_ALIVE
        self.assertEqual(_said_after_deobfuscation(rows), _printed(rows))
