"""
Converting a function to a string answers the source it was written with. The parser records the
span of every function it reads, and the value domain hands that text back for `String(fn)`, for a
concatenation, and for the join an array performs on its elements; the length of one is the length
of that text. A function a transform built instead carries no span and is written back the way the
synthesizer would write it. Retired from `test.lib.scripts.js.test_release_blockers`.
"""
from __future__ import annotations

import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import node_executable
from test.lib.scripts.js.ledger import before_and_after, each_program_still_prints, folded

from refinery.lib.scripts.js.deobfuscation.helpers import function_source
from refinery.lib.scripts.js.model import JsFunctionExpression, JsMethodDefinition
from refinery.lib.scripts.js.parser import JsParser

#: A program reading the text of a function value, mapped to the file `refinery.js` folds it to. The
#: read is written inside a function body, which is where the tool answers it at all; the folded
#: text holds the source the function was written with, character for character, as a string
#: literal. Each expected value was confirmed against Node: `String` of a declaration keeps its
#: name, a function expression drops it, an arrow is the arrow, and a method keeps its name; a loose
#: `==` against that text coerces the function to it and matches.
A_FUNCTION_STRINGIFIES_TO_ITS_WRITTEN_SOURCE = {
    'a declaration handed to String': (
        'function W(a) { return a + 1; }\n'
        'function f() { return String(W); }\n'
        'console.log(f());\n',
        "console.log('function W(a) { return a + 1; }');",
    ),
    'the length of the text of a declaration': (
        'function W(a) { return a + 1; }\n'
        'function f() { return String(W).length; }\n'
        'console.log(f());\n',
        'console.log(31);',
    ),
    'a local function expression concatenated onto a string': (
        "function f() { var W = function (a) { return a + 1; }; return '' + W; }\n"
        'console.log(f());\n',
        "console.log('function (a) { return a + 1; }');",
    ),
    'a local function expression joined by an array': (
        "function f() { var W = function (a) { return a + 1; }; return [W].join(''); }\n"
        'console.log(f());\n',
        "console.log('function (a) { return a + 1; }');",
    ),
    'an arrow function handed to String': (
        'function f() { var g = (a) => a + 1; return String(g); }\n'
        'console.log(f());\n',
        "console.log('(a) => a + 1');",
    ),
    'a shorthand method handed to String': (
        'function f() { var o = { m(a) { return a + 1; } }; return String(o.m); }\n'
        'console.log(f());\n',
        "console.log('m(a) { return a + 1; }');",
    ),
    'a declaration interpolated into a template': (
        'function W(a) { return a + 1; }\n'
        'function f() { return `<${W}>`; }\n'
        'console.log(f());\n',
        "console.log('<function W(a) { return a + 1; }>');",
    ),
    'a declaration added to a number': (
        'function W(a) { return a + 1; }\n'
        'function f() { return W + 1; }\n'
        'console.log(f());\n',
        "console.log('function W(a) { return a + 1; }1');",
    ),
    'a declaration loosely equal to its own source text': (
        'function W(a) { return a + 1; }\n'
        'function f() { return W == "function W(a) { return a + 1; }" ? "yes" : "no"; }\n'
        'console.log(f());\n',
        "console.log('yes');",
    ),
    'a declaration copied into a local': (
        'function W(a) { return a + 1; }\n'
        'function f() { var g = W; return String(g); }\n'
        'console.log(f());\n',
        "console.log('function W(a) { return a + 1; }');",
    ),
    'a declaration handed to a function that reads its length': (
        'function W(a) { return a + 1; }\n'
        'function size(g) { return g.length; }\n'
        'console.log(size(W));\n'
        'function f() { return String(W); }\n'
        'console.log(f());\n',
        'function W(a) {\n'
        '  return a + 1;\n'
        '}\n'
        'function size(g) {\n'
        '  return g.length;\n'
        '}\n'
        'console.log(size(W));\n'
        "console.log('function W(a) { return a + 1; }');",
    ),
}


class TestAFunctionStringifiesToItsWrittenSource(TestBase):
    def test_the_fold_writes_the_source_the_function_was_written_with(self):
        for label, (source, expected) in A_FUNCTION_STRINGIFIES_TO_ITS_WRITTEN_SOURCE.items():
            with self.subTest(label):
                self.assertEqual(folded(source, module=True), expected)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestTheStringifiedFunctionRunsTheSameBeforeAndAfter(TestBase):
    def test_the_deobfuscation_prints_what_the_program_prints(self):
        for label, (source, _) in A_FUNCTION_STRINGIFIES_TO_ITS_WRITTEN_SOURCE.items():
            with self.subTest(label):
                before, after = before_and_after(source)
                self.assertEqual(before, after)


#: A class member's function stringifies to its MethodDefinition source, which excludes a leading
#: `static` token — the one token V8 drops from a class-body member, whether it is the modifier or
#: the method's own name (`static() {}` stringifies without it). A `get`, `set`, `async` or `*` is
#: kept. Each expected value was confirmed against Node's `Function.prototype.toString`. The fold
#: does not resolve a class-member read to its function, so the recorded span is read through
#: `function_source` on the parsed method value rather than through a deobfuscation.
A_CLASS_MEMBER_EXCLUDES_A_LEADING_STATIC = {
    'a static method': (
        'class C { static m(a) { return a + 1; } }',
        'm(a) { return a + 1; }',
    ),
    'a static generator': (
        'class C { static *g() { return 1; } }',
        '*g() { return 1; }',
    ),
    'a static getter': (
        'class C { static get x() { return 1; } }',
        'get x() { return 1; }',
    ),
    'a static setter': (
        'class C { static set x(v) { return v; } }',
        'set x(v) { return v; }',
    ),
    'a static async method': (
        'class C { static async m() { return 1; } }',
        'async m() { return 1; }',
    ),
    'a non-static getter keeps its start': (
        'class C { get x() { return 1; } }',
        'get x() { return 1; }',
    ),
    'a method named static drops the leading token': (
        'class C { static() { return 1; } }',
        '() { return 1; }',
    ),
    'a static modifier before a method named static': (
        'class C { static static() { return 1; } }',
        'static() { return 1; }',
    ),
}


def _first_method_value(source: str) -> JsFunctionExpression:
    for node in JsParser(source).parse().walk_in_order():
        if isinstance(node, JsMethodDefinition) and isinstance(node.value, JsFunctionExpression):
            return node.value
    raise AssertionError('no method definition in source')


class TestAClassMemberExcludesALeadingStatic(TestBase):
    def test_the_recorded_source_excludes_a_leading_static_token(self):
        for label, (source, expected) in A_CLASS_MEMBER_EXCLUDES_A_LEADING_STATIC.items():
            with self.subTest(label):
                self.assertEqual(function_source(_first_method_value(source)), expected)


#: Programs that give a function a `toString` of its own before converting it, each through a
#: route that reaches the function somewhere other than the conversion, mapped to what Node prints
#: for each. The text the function was written with is not what such a conversion answers.
A_FUNCTION_GIVEN_A_TOSTRING_OF_ITS_OWN = {
    'function W(a) { return a + 1; }\n'
    'W.toString = function () { return "x"; };\n'
    'function f() { return String(W); }\n'
    'console.log(f(), typeof W);\n':
        'x function\n',
    'function W(a) { return a + 1; }\n'
    'class X { static [Symbol.hasInstance](v) { v.toString = function () { return "x"; }; return false; } }\n'
    'console.log(W instanceof X);\n'
    'function f() { return String(W); }\n'
    'console.log(f());\n':
        'false\nx\n',
    'function W(a) { return a + 1; }\n'
    'function tag(s, v) { v.toString = function () { return "x"; }; return ""; }\n'
    'tag`${W}`;\n'
    'function f() { return String(W); }\n'
    'console.log(f());\n':
        'x\n',
    '{ function W(a) { return a + 1; } }\n'
    'W.toString = function () { return "x"; };\n'
    'function f() { return String(W); }\n'
    'console.log(f());\n':
        'x\n',
    'function W(a) { return a + 1; }\n'
    'var g = W;\n'
    'g.toString = function () { return "x"; };\n'
    'function f() { return String(W); }\n'
    'console.log(f());\n':
        'x\n',
    'function W(a) { return a + 1; }\n'
    'function mark(g) { g.toString = function () { return "x"; }; }\n'
    'mark(W);\n'
    'function f() { return String(W); }\n'
    'console.log(f());\n':
        'x\n',
    'function W(a) { return a + 1; }\n'
    'function mark() { arguments[0].toString = function () { return "x"; }; }\n'
    'mark(W);\n'
    'function f() { return String(W); }\n'
    'console.log(f());\n':
        'x\n',
    'function W(a) { return a + 1; }\n'
    'function same(g) { return g; }\n'
    'same(W).toString = function () { return "x"; };\n'
    'function f() { return String(W); }\n'
    'console.log(f());\n':
        'x\n',
    'function W(a) { return a + 1; }\n'
    'globalThis.String = function () { return "x"; };\n'
    'function f() { return String(W); }\n'
    'console.log(f());\n':
        'x\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAFunctionGivenAToStringOfItsOwnIsConvertedByIt(TestBase):
    def test_the_deobfuscation_prints_what_the_program_prints(self):
        rows = A_FUNCTION_GIVEN_A_TOSTRING_OF_ITS_OWN
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )
