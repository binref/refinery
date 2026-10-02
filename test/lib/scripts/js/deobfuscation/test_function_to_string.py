"""
Converting a function to a string answers the source it was written with. The parser records the
span of every function it reads, and the value domain hands that text back for `String(fn)`, for a
concatenation, and for the join an array performs on its elements; the length of one is the length
of that text. A function a transform built instead carries no span and is written back the way the
synthesizer would write it. Retired from `test.lib.scripts.js.test_release_blockers`.
"""
from __future__ import annotations

import inspect
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
    'a function expression written into String': (
        inspect.cleandoc('''
            function f() { return String(function (a) { return a; }); }
            console.log(f());
        '''),
        "console.log('function (a) { return a; }');",
    ),
    'an arrow written into a template': (
        inspect.cleandoc('''
            function f() { return `${(a) => a}`; }
            console.log(f());
        '''),
        "console.log('(a) => a');",
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
#: for each. The text the function was written with is not what such a conversion answers. An
#: assignment that is not a statement of its own is such a route: its value is the function.
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
    inspect.cleandoc('''
        var W;
        function mark(g) { g.toString = function () { return "x"; }; }
        mark(W = function (a) { return a + 1; });
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        var W;
        var g = (W = function (a) { return a + 1; });
        g.toString = function () { return "x"; };
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        var W, g;
        g = W = function (a) { return a + 1; };
        g.toString = function () { return "x"; };
        function f() { return String(W); }
        console.log(f());
    '''):
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


#: Programs that keep a function in an array and give it a conversion of its own through a
#: reference the function itself holds, mapped to what Node prints: its `this` as a method,
#: `arguments.callee`, `new.target`, the `constructor` of an instance of a bound copy or of its
#: prototype, a parameter it is handed to, a name copied from the array, or its own name.
A_FUNCTION_GIVEN_A_CONVERSION_THROUGH_ITS_OWN_REFERENCES = {
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        W.m = function () { this.toString = function () { return "t"; }; };
        g[0].m();
        function f() { return String(W); }
        console.log(f());
    '''):
        't\n',
    inspect.cleandoc('''
        function W(a) { if (a === 1) { arguments.callee.toString = function () { return "c"; }; } return a + 1; }
        var g = [W];
        g[0](1);
        function f() { return String(W); }
        console.log(f());
    '''):
        'c\n',
    inspect.cleandoc('''
        function W(a) { if (new.target) { new.target.toString = function () { return "n"; }; } }
        var g = [W];
        new g[0]();
        function f() { return String(W); }
        console.log(f());
    '''):
        'n\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        var B = W.bind(null);
        (new B()).constructor.toString = function () { return "b"; };
        function f() { return String(W); }
        console.log(f());
    '''):
        'b\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        (function (o) { o.toString = function () { return "o"; }; })(g[0]);
        function f() { return String(W); }
        console.log(f());
    '''):
        'o\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        var V = g[0];
        V.toString = function () { return "c"; };
        function f() { return String(W); }
        console.log(f());
    '''):
        'c\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        W.toString = function () { return "x"; };
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        W[process.argv[9] || "toString"] = function () { return "k"; };
        function f() { return String(W); }
        console.log(f());
    '''):
        'k\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        var src = {};
        src[process.argv[9] || "toString"] = function () { return "s"; };
        Object.assign(W, src);
        function f() { return String(W); }
        console.log(f());
    '''):
        's\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        Object[process.argv[9] || "defineProperty"](W, "toString", { value: function () { return "d"; } });
        function f() { return String(W); }
        console.log(f());
    '''):
        'd\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        W.prototype.constructor.toString = function () { return "c"; };
        function f() { return String(W); }
        console.log(f());
    '''):
        'c\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAFunctionGivenAConversionThroughItsOwnReferencesIsConvertedByIt(TestBase):
    def test_the_deobfuscation_prints_what_the_program_prints(self):
        rows = A_FUNCTION_GIVEN_A_CONVERSION_THROUGH_ITS_OWN_REFERENCES
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


#: Programs that keep a function in an array and give it a `toString`, `valueOf` or
#: `Symbol.toPrimitive` of its own or a new prototype through code that never names it, mapped to
#: what Node prints: a write in any form under a key spelled in any form, an installer however it
#: is reached (an alias, `call`, `apply`, `Reflect`, destructuring, `with`, a fallback), a class
#: static block, and code the program builds at runtime.
A_FUNCTION_GIVEN_A_CONVERSION_BY_AN_INSTALL = {
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        g[0].toString = function () { return "x"; };
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        g[0]["toString"] = function () { return "x"; };
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        g[0]["to" + "String"] = function () { return "x"; };
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        g[0][`toString`] = function () { return "x"; };
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        g[0].valueOf = function () { return "v"; };
        function f() { return "" + W; }
        console.log(f());
    '''):
        'v\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        g[0][Symbol.toPrimitive] = function () { return "p"; };
        function f() { return String(W); }
        console.log(f());
    '''):
        'p\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        g[0].__proto__ = { toString() { return "q"; } };
        function f() { return String(W); }
        console.log(f());
    '''):
        'q\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        Object.setPrototypeOf(g[0], { toString() { return "q"; } });
        function f() { return String(W); }
        console.log(f());
    '''):
        'q\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        Reflect.setPrototypeOf(g[0], { toString() { return "q"; } });
        function f() { return String(W); }
        console.log(f());
    '''):
        'q\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        Object.defineProperty(g[0], "toString", { value: function () { return "d"; } });
        function f() { return String(W); }
        console.log(f());
    '''):
        'd\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        Reflect.defineProperty(g[0], "toString", { value: function () { return "d"; } });
        function f() { return String(W); }
        console.log(f());
    '''):
        'd\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        Object.defineProperties(g[0], { toString: { value: function () { return "d"; } } });
        function f() { return String(W); }
        console.log(f());
    '''):
        'd\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        Object.assign(g[0], { toString() { return "a"; } });
        function f() { return String(W); }
        console.log(f());
    '''):
        'a\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        var mixin = { toString() { return "m"; } };
        Object.assign(g[0], mixin);
        function f() { return String(W); }
        console.log(f());
    '''):
        'm\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        Reflect.set(g[0], "toString", function () { return "r"; });
        function f() { return String(W); }
        console.log(f());
    '''):
        'r\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        g[0].__defineGetter__("toString", function () { return function () { return "g"; }; });
        function f() { return String(W); }
        console.log(f());
    '''):
        'g\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        Object.prototype.__defineGetter__.call(g[0], "toString", function () { return function () { return "g"; }; });
        function f() { return String(W); }
        console.log(f());
    '''):
        'g\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        var dp = Object.defineProperty;
        dp(g[0], "toString", { value: function () { return "d"; } });
        function f() { return String(W); }
        console.log(f());
    '''):
        'd\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        Object.defineProperty.call(null, g[0], "toString", { value: function () { return "d"; } });
        function f() { return String(W); }
        console.log(f());
    '''):
        'd\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        ({ t: g[0].toString } = { t: function () { return "s"; } });
        function f() { return String(W); }
        console.log(f());
    '''):
        's\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        for (g[0].toString of [function () { return "f"; }]) {}
        function f() { return String(W); }
        console.log(f());
    '''):
        'f\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        g[0].toString &&= function () { return "l"; };
        function f() { return String(W); }
        console.log(f());
    '''):
        'l\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        with (g[0]) { toString = function () { return "w"; }; }
        function f() { return String(W); }
        console.log(f());
    '''):
        'w\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        eval('g[0].toString = function () { return "e"; };');
        function f() { return String(W); }
        console.log(f());
    '''):
        'e\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        Function("g", 'g[0].toString = function () { return "F"; };')(g);
        function f() { return String(W); }
        console.log(f());
    '''):
        'F\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        class C { static { g[0].toString = function () { return "s"; }; } }
        function f() { return String(W); }
        console.log(f());
    '''):
        's\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        var R = Reflect;
        R.set(g[0], "toString", function () { return "r"; });
        function f() { return String(W); }
        console.log(f());
    '''):
        'r\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        Object["set" + "PrototypeOf"](g[0], { toString() { return "q"; } });
        function f() { return String(W); }
        console.log(f());
    '''):
        'q\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        var rs = Reflect.set;
        rs(g[0], "toString", function () { return "r"; });
        function f() { return String(W); }
        console.log(f());
    '''):
        'r\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        var sp = Object.setPrototypeOf || function (o, p) { o.__proto__ = p; return o; };
        sp(g[0], { toString() { return "q"; } });
        function f() { return String(W); }
        console.log(f());
    '''):
        'q\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        Object.defineProperty.apply(null, [g[0], "toString", { value: function () { return "d"; } }]);
        function f() { return String(W); }
        console.log(f());
    '''):
        'd\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        var { defineProperty } = Object;
        defineProperty(g[0], "toString", { value: function () { return "d"; } });
        function f() { return String(W); }
        console.log(f());
    '''):
        'd\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        var { setPrototypeOf: sp } = Object;
        sp(g[0], { toString() { return "q"; } });
        function f() { return String(W); }
        console.log(f());
    '''):
        'q\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        with (Object) { defineProperty(g[0], "toString", { value: function () { return "d"; } }); }
        function f() { return String(W); }
        console.log(f());
    '''):
        'd\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        var { defineProperty } = Object;
        var install = [defineProperty][0];
        install(g[0], "toString", { value: function () { return "d"; } });
        function f() { return String(W); }
        console.log(f());
    '''):
        'd\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAFunctionGivenAConversionByAnInstallIsConvertedByIt(TestBase):
    def test_the_deobfuscation_prints_what_the_program_prints(self):
        rows = A_FUNCTION_GIVEN_A_CONVERSION_BY_AN_INSTALL
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_setter_installed_under_tostring_leaves_no_conversion_before_and_after(self):
        source = inspect.cleandoc('''
            function W(a) { return a + 1; }
            var g = [W];
            g[0].__defineSetter__("toString", function () {});
            function f() { return String(W); }
            console.log(f());
        ''')
        self.assertEqual(before_and_after(source), (('', 'TypeError'), ('', 'TypeError')))


#: Programs that give a function kept in an array a conversion of its own under a key the run can
#: read although no write spells it, mapped to what Node prints: a key or a symbol a name holds, a
#: key a helper is called with (also where the helper may be called in other ways), a key a
#: constant object, a constant array, a string table or a decoder holds, and a key computed from
#: the text of another function.
A_FUNCTION_GIVEN_A_CONVERSION_UNDER_A_KEY_THE_RUN_CAN_READ = {
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        var S = Symbol;
        g[0][S.toPrimitive] = function () { return "p"; };
        function f() { return String(W); }
        console.log(f());
    '''):
        'p\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        var k = "toString";
        g[0][k] = function () { return "x"; };
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        var t = Symbol.toPrimitive;
        g[0][t] = function () { return "p"; };
        function f() { return String(W); }
        console.log(f());
    '''):
        'p\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        function def(obj, key, value) { Object.defineProperty(obj, key, { value: value }); return obj; }
        def(g[0], "toString", function () { return "d"; });
        function f() { return String(W); }
        console.log(f());
    '''):
        'd\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        function put(obj, key, value) { obj[key] = value; }
        put(g[0], "toString", function () { return "d"; });
        function f() { return String(W); }
        console.log(f());
    '''):
        'd\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        var { toPrimitive } = Symbol;
        g[0][toPrimitive] = function () { return "p"; };
        function f() { return String(W); }
        console.log(f());
    '''):
        'p\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        var dp = (o, k, d) => Object.defineProperty(o, k, d);
        dp(g[0], "toString", { value: function () { return "d"; } });
        function f() { return String(W); }
        console.log(f());
    '''):
        'd\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        var keys = ["toString", "valueOf"];
        function key(i) { return keys[i]; }
        g[0][key(0)] = function () { return "x"; };
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        g[0][atob("dG9TdHJpbmc=")] = function () { return "x"; };
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        g[0][String.fromCharCode(116, 111, 83, 116, 114, 105, 110, 103)] = function () { return "x"; };
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        g[0]["gnirtSot".split("").reverse().join("")] = function () { return "x"; };
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        var keys = ["toString", "defineProperty"];
        function key(i) { return keys[i]; }
        Object[key(1)](g[0], key(0), { value: function () { return "d"; } });
        function f() { return String(W); }
        console.log(f());
    '''):
        'd\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        var K = { a: "toString" };
        g[0][K.a] = function () { return "x"; };
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        var t = ["valueOf", "toString"];
        function d(i) { i = i - 256; return t[i]; }
        g[0][d(257)] = function () { return "x"; };
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        var _0x3f1a = { "XyZab": "toString", "QwErt": function (a, b) { return a + b; } };
        g[0][_0x3f1a["XyZab"]] = function () { return "x"; };
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        var K = { d: "defineProperty", t: "toString" };
        Object[K.d](g[0], K.t, { value: function () { return "d"; } });
        function f() { return String(W); }
        console.log(f());
    '''):
        'd\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        var K = ["valueOf", "toString"];
        g[0][K[1]] = function () { return "x"; };
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        var K = ["valueOf", "toString"];
        g[0][K[0]] = function () { return "v"; };
        function f() { return "" + W; }
        console.log(f());
    '''):
        'v\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        var K = { s: "setPrototypeOf" };
        Object[K.s](g[0], { toString() { return "q"; } });
        function f() { return String(W); }
        console.log(f());
    '''):
        'q\n',
    inspect.cleandoc('''
        var W = function (a) { return a + 1; };
        var g = [W];
        var K = { a: "toString" };
        g[0][K.a] = function () { return "x"; };
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        function def(o, k, v) { o[k] = v; }
        def(g[0], "toString", function () { return "x"; });
        function probe() { return typeof probe.caller; }
        probe();
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        function def(o, k, v, again) { if (!again) { arguments.callee({}, "valueOf", v, true); } o[k] = v; }
        def(g[0], "toString", function () { return "x"; });
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        function def(o, k, v) { o[k] = v; }
        def(g[0], "toString", function () { return "x"; });
        var keep = [def];
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        function V(b) { return b * 2; }
        function f() {
          var g = [W, V];
          var k = String(W).slice(0, 0) + "toString";
          g[1][k] = function () { return "x"; };
          return String(V);
        }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        function V(b) { return b * 2; }
        var later = [];
        later.push(function () { console.log(String(V)); });
        var g = [W, V];
        var k = String(W).slice(0, 0) + "toString";
        g[1][k] = function () { return "x"; };
        later[0]();
    '''):
        'x\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAFunctionGivenAConversionUnderAKeyTheRunCanReadIsConvertedByIt(TestBase):
    def test_the_deobfuscation_prints_what_the_program_prints(self):
        rows = A_FUNCTION_GIVEN_A_CONVERSION_UNDER_A_KEY_THE_RUN_CAN_READ
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


#: Programs that copy a conversion method onto a function kept in an array from a source that
#: carries one, mapped to what Node prints: a literal spreading a mixin, a mixin built by writes,
#: filled by a function, made by a factory or by a constructor, a prototype, a class instance, the
#: descriptors of an object, a copy loop, a target spread from an array, and a source handed to a
#: helper.
A_FUNCTION_GIVEN_A_CONVERSION_COPIED_FROM_A_SOURCE = {
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        var mixin = { toString() { return "m"; } };
        Object.assign(g[0], { ...mixin });
        function f() { return String(W); }
        console.log(f());
    '''):
        'm\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        var mixin = {};
        mixin.toString = function () { return "m"; };
        Object.assign(g[0], mixin);
        function f() { return String(W); }
        console.log(f());
    '''):
        'm\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        var descs = {};
        descs.toString = { value: function () { return "m"; } };
        Object.defineProperties(g[0], descs);
        function f() { return String(W); }
        console.log(f());
    '''):
        'm\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        var mixin = {};
        function fill(o) { o.toString = function () { return "m"; }; }
        fill(mixin);
        Object.assign(g[0], mixin);
        function f() { return String(W); }
        console.log(f());
    '''):
        'm\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        function mixin() { return { toString() { return "m"; } }; }
        Object.assign(g[0], mixin());
        function f() { return String(W); }
        console.log(f());
    '''):
        'm\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        function descs() { return { "toString": { value: function () { return "m"; } } }; }
        Object.defineProperties(g[0], descs());
        function f() { return String(W); }
        console.log(f());
    '''):
        'm\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        function P() {}
        P.prototype.toString = function () { return "p"; };
        Object.assign(g[0], P.prototype);
        function f() { return String(W); }
        console.log(f());
    '''):
        'p\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        function extend(d, s) { for (var k in s) { d[k] = s[k]; } return d; }
        extend(g[0], { toString: function () { return "e"; } });
        function f() { return String(W); }
        console.log(f());
    '''):
        'e\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        Object.assign(...[g[0], { toString() { return "a"; } }]);
        function f() { return String(W); }
        console.log(f());
    '''):
        'a\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        function Mixin() { this.toString = function () { return "m"; }; }
        Object.assign(g[0], new Mixin());
        function f() { return String(W); }
        console.log(f());
    '''):
        'm\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        Object.defineProperties(g[0], Object.getOwnPropertyDescriptors({ toString() { return "m"; } }));
        function f() { return String(W); }
        console.log(f());
    '''):
        'm\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        var mixin = {};
        var m2 = mixin;
        m2.toString = function () { return "m"; };
        Object.assign(g[0], mixin);
        function f() { return String(W); }
        console.log(f());
    '''):
        'm\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        class Mixin { constructor() { this.toString = function () { return "m"; }; } }
        Object.assign(g[0], new Mixin());
        function f() { return String(W); }
        console.log(f());
    '''):
        'm\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        class Mixin { constructor() { this.valueOf = function () { return "v"; }; } }
        Object.assign(g[0], new Mixin());
        function f() { return "" + W; }
        console.log(f());
    '''):
        'v\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        function mix(o, s) { Object.assign(o, s); }
        mix(g[0], { toString() { return "x"; } });
        function probe() { return typeof probe.caller; }
        probe();
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAFunctionGivenAConversionCopiedFromASourceIsConvertedByIt(TestBase):
    def test_the_deobfuscation_prints_what_the_program_prints(self):
        rows = A_FUNCTION_GIVEN_A_CONVERSION_COPIED_FROM_A_SOURCE
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


#: Programs that give a function a conversion of its own through a value that may hold it, mapped
#: to what Node prints: a callback parameter, a name holding it or another function, a map, a
#: destructured name, a caught value, a closure, the `arguments` object, an object property, a
#: property named `prototype`, a function expression, an arrow or a method in an array, and the
#: parameter of a helper that receives it through a call the text does not show as a call of the
#: helper: `arguments.callee`, `caller`, `call`, a callback, a sequence, an object, a spread, its
#: own name, a tagged template, `new`, `Reflect.apply`, a method on `Object.prototype`.
A_FUNCTION_GIVEN_A_CONVERSION_THROUGH_A_VALUE_THAT_MAY_HOLD_IT = {
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        g.forEach(function (f) { f.toString = function () { return "e"; }; });
        function f() { return String(W); }
        console.log(f());
    '''):
        'e\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        var o = process.argv.length > 99 ? function () {} : g[0];
        o.toString = function () { return "o"; };
        function f() { return String(W); }
        console.log(f());
    '''):
        'o\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        var m = new Map([[1, g[0]]]);
        m.get(1).toString = function () { return "m"; };
        function f() { return String(W); }
        console.log(f());
    '''):
        'm\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        var o = {};
        o = g[0];
        o.toString = function () { return "o"; };
        function f() { return String(W); }
        console.log(f());
    '''):
        'o\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        var o = {};
        [o] = [g[0]];
        o.toString = function () { return "o"; };
        function f() { return String(W); }
        console.log(f());
    '''):
        'o\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        var o = {};
        ({ a: o } = { a: g[0] });
        o.toString = function () { return "o"; };
        function f() { return String(W); }
        console.log(f());
    '''):
        'o\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        try { throw g[0]; } catch (o) { o.toString = function () { return "o"; }; }
        function f() { return String(W); }
        console.log(f());
    '''):
        'o\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        var o = {};
        function put() { o = g[0]; }
        put();
        o.toString = function () { return "o"; };
        function f() { return String(W); }
        console.log(f());
    '''):
        'o\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        function h() { arguments[0].toString = function () { return "a"; }; }
        h(g[0]);
        function f() { return String(W); }
        console.log(f());
    '''):
        'a\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var o = { f: W };
        o.f.toString = function () { return "o"; };
        function f() { return String(W); }
        console.log(f());
    '''):
        'o\n',
    inspect.cleandoc('''
        var W = function (a) { return a + 1; };
        var g = [W];
        g[0].toString = function () { return "x"; };
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        var W = (a) => a + 1;
        var g = [W];
        g[0].toString = function () { return "x"; };
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        var o = { m: function (a) { return a + 1; } };
        var g = [o];
        g[0].m.toString = function () { return "x"; };
        function f() { return String(o.m); }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        function V() {}
        var o = process.argv.length > 99 ? V : W;
        o.toString = function () { return "o"; };
        function f() { return String(W); }
        console.log(f());
    '''):
        'o\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        function X() {}
        X.prototype = g[0];
        X.prototype.toString = function () { return "y"; };
        function f() { return String(W); }
        console.log(f());
    '''):
        'y\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        var o = { prototype: g[0] };
        o.prototype.toString = function () { return "x"; };
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        function setT(o, again) {
          if (!again) { arguments.callee(g[0], true); }
          o.toString = function () { return "x"; };
        }
        setT({});
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        function probe() { probe.caller(g[0], true); }
        function setT(o, again) {
          if (!again) { probe(); }
          o.toString = function () { return "x"; };
        }
        setT({});
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        function setT(o) { o.toString = function () { return "x"; }; }
        setT({});
        setT.call(null, g[0]);
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        function setT(o) { o.toString = function () { return "x"; }; }
        setT({});
        g.forEach(setT);
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        function setT(o) { o.toString = function () { return "x"; }; }
        setT({});
        (0, setT)(g[0]);
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        function setT(o) { o.toString = function () { return "x"; }; }
        setT({});
        var api = { setT: setT };
        api.setT(g[0]);
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        function setT(o) { o.toString = function () { return "x"; }; }
        setT({});
        setT(...g);
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        var setT = function self(o, again) {
          if (!again) { self(g[0], true); }
          o.toString = function () { return "x"; };
        };
        setT({});
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        function setT(parts, o) { o.toString = function () { return "x"; }; }
        setT([], {});
        setT`${g[0]}`;
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        function setT(o) { o.toString = function () { return "x"; }; }
        setT({});
        new setT(g[0]);
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        function setT(o) { o.toString = function () { return "x"; }; }
        setT({});
        Reflect.apply(setT, null, [g[0]]);
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        function setT(o) { o.toString = function () { return "x"; }; }
        setT({});
        Object.prototype.setT = setT;
        g.setT(g[0]);
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAFunctionGivenAConversionThroughAValueThatMayHoldItIsConvertedByIt(TestBase):
    def test_the_deobfuscation_prints_what_the_program_prints(self):
        rows = A_FUNCTION_GIVEN_A_CONVERSION_THROUGH_A_VALUE_THAT_MAY_HOLD_IT
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


#: Programs that run a constructor writing `this.toString` on a function kept in an array, mapped
#: to what Node prints: called on it directly or as a copy, a method, a parent class, the
#: `constructor` of a prototype or of an instance, taken by destructuring, with `Reflect.get`,
#: from a descriptor or under a key a name holds, and through `arguments.callee`, `new.target` or
#: `caller`.
A_FUNCTION_GIVEN_A_CONVERSION_BY_A_CONSTRUCTOR_RUN_ON_IT = {
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        function P() { this.toString = function () { return "t"; }; }
        new P();
        P.call(g[0]);
        function f() { return String(W); }
        console.log(f());
    '''):
        't\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        function A() { return g[0]; }
        class B extends A { constructor() { super(); this.toString = function () { return "t"; }; } }
        new B();
        function f() { return String(W); }
        console.log(f());
    '''):
        't\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        function P() { this.toString = function () { return "t"; }; }
        var Q = P;
        Q.call(g[0]);
        function f() { return String(W); }
        console.log(f());
    '''):
        't\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        var o = { P: function () { this.toString = function () { return "t"; }; } };
        o.P.call(g[0]);
        function f() { return String(W); }
        console.log(f());
    '''):
        't\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        function A() { return g[0]; }
        function F() { var _this = A.call(this) || this; Object.setPrototypeOf(_this, { toString() { return "q"; } }); return _this; }
        new F();
        function f() { return String(W); }
        console.log(f());
    '''):
        'q\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        function P() { this.toString = function () { return "t"; }; }
        new P();
        P.prototype.constructor.call(g[0]);
        function f() { return String(W); }
        console.log(f());
    '''):
        't\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        function P() { this.toString = function () { return "t"; }; }
        new P().constructor.call(g[0]);
        function f() { return String(W); }
        console.log(f());
    '''):
        't\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        function P() { this.toString = function () { return "t"; }; }
        var { constructor: c } = new P();
        c.call(g[0]);
        function f() { return String(W); }
        console.log(f());
    '''):
        't\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        function P() { this.toString = function () { return "t"; }; }
        var c = P.prototype.constructor;
        c.apply(g[0], []);
        function f() { return String(W); }
        console.log(f());
    '''):
        't\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        function P() { this.toString = function () { return "t"; }; if (this instanceof P) { arguments.callee.call(g[0]); } }
        new P();
        function f() { return String(W); }
        console.log(f());
    '''):
        't\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        function P() { this.toString = function () { return "t"; }; if (new.target) { new.target.call(g[0]); } }
        new P();
        function f() { return String(W); }
        console.log(f());
    '''):
        't\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        var done = false;
        function P() { this.toString = function () { return "t"; }; if (!done) { done = true; probe(); } }
        function probe() { probe.caller.call(g[0]); }
        new P();
        function f() { return String(W); }
        console.log(f());
    '''):
        't\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        function P() { this.toString = function () { return "t"; }; }
        new P();
        Object.getOwnPropertyDescriptor(P.prototype, "constructor").value.call(g[0]);
        function f() { return String(W); }
        console.log(f());
    '''):
        't\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        { function P() { this.toString = function () { return "t"; }; } }
        new P();
        P.call(g[0]);
        function f() { return String(W); }
        console.log(f());
    '''):
        't\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        function P() { this.toString = function () { return "t"; }; }
        new P();
        Reflect.get(P.prototype, "constructor").call(g[0]);
        function f() { return String(W); }
        console.log(f());
    '''):
        't\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        function P() { this.toString = function () { return "t"; }; }
        var c = "constructor";
        new P()[c].call(g[0]);
        function f() { return String(W); }
        console.log(f());
    '''):
        't\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAFunctionGivenAConversionByAConstructorRunOnItIsConvertedByIt(TestBase):
    def test_the_deobfuscation_prints_what_the_program_prints(self):
        rows = A_FUNCTION_GIVEN_A_CONVERSION_BY_A_CONSTRUCTOR_RUN_ON_IT
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


#: Programs that give `Function.prototype` or `Object.prototype` a conversion while a function
#: is kept in an array, mapped to what Node prints: through the prototype of the function, an
#: accessor writing `this`, an alias of `Function`, an installer, a constructor reached from the
#: array, a getter or a function returning it.
A_FUNCTION_WHOSE_PROTOTYPES_ARE_GIVEN_A_CONVERSION = {
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        Object.getPrototypeOf(g[0]).toString = function () { return "z"; };
        function f() { return String(W); }
        console.log(f());
    '''):
        'z\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        Object.defineProperty(Object.prototype, "zz", {
            get() { this.toString = function () { return "a"; }; return 1; },
            configurable: true,
        });
        g[0].zz;
        function f() { return String(W); }
        console.log(f());
    '''):
        'a\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        var F = Function;
        F.prototype.toString = function () { return "x"; };
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        Function.prototype.toString = function () { return "x"; };
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        Object.assign(Function.prototype, { toString() { return "x"; } });
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        Reflect.set(Function.prototype, "toString", function () { return "x"; });
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        Reflect.defineProperty(Function.prototype, "toString", { value: function () { return "x"; } });
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        Object.defineProperty(Function.prototype, "toString", { value: function () { return "x"; } });
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        (function () {}).constructor.prototype.toString = function () { return "x"; };
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        Function.prototype[Symbol.toPrimitive] = function () { return "x"; };
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        Object.prototype[Symbol.toPrimitive] = function () { return "x"; };
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var F = [Function][0];
        F.prototype.toString = function () { return "x"; };
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        Object.prototype.valueOf = function () { return "v"; };
        function f() { return "" + W; }
        console.log(f());
    '''):
        'v\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        g[0].constructor.prototype.toString = function () { return "x"; };
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        var C = g[0].constructor;
        C.prototype.toString = function () { return "x"; };
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        var h = { get c() { return g[0].constructor; } };
        h.c.prototype.toString = function () { return "x"; };
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        function ctor(x) { return x.constructor; }
        ctor(g[0]).prototype.toString = function () { return "x"; };
        function f() { return String(W); }
        console.log(f());
    '''):
        'x\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAFunctionWhosePrototypesAreGivenAConversionIsConvertedByIt(TestBase):
    def test_the_deobfuscation_prints_what_the_program_prints(self):
        rows = A_FUNCTION_WHOSE_PROTOTYPES_ARE_GIVEN_A_CONVERSION
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


#: Programs converting a function no code gives a conversion of its own, after handing it to code
#: that could, mapped to what Node prints: the text the function was written with. Keeping the
#: conversion would print the text the deobfuscation wrote instead, so each one is folded.
A_FUNCTION_HANDED_ON_AND_CONVERTED_TO_ITS_WRITTEN_TEXT = {
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        function f() { var g = [W]; return String(g[0]); }
        console.log(f());
    '''):
        'function W(a) { return a + 1; }\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        function get() { return W; }
        function f() { return String(get()); }
        console.log(f());
    '''):
        'function W(a) { return a + 1; }\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        function f() { return String(W || null); }
        console.log(f());
    '''):
        'function W(a) { return a + 1; }\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        console.log([W].length);
        function f() { return String(W); }
        console.log(f());
    '''):
        '1\nfunction W(a) { return a + 1; }\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var B = W.bind(null);
        console.log(B(1));
        function f() { return String(W); }
        console.log(f());
    '''):
        '2\nfunction W(a) { return a + 1; }\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        globalThis[process.argv.length > 99 ? "a" : "b"] = 1;
        function f() { return String(W); }
        console.log(f());
    '''):
        'function W(a) { return a + 1; }\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        for (var k in W) { console.log(k); }
        function f() { return String(W); }
        console.log(f());
    '''):
        'function W(a) { return a + 1; }\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        Promise.resolve(1).then(W);
        function f() { return String(W); }
        console.log(f());
    '''):
        'function W(a) { return a + 1; }\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        module.exports = W;
        function f() { return String(W); }
        console.log(f());
    '''):
        'function W(a) { return a + 1; }\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        console.log(g.length);
        function Foo() {}
        Foo.prototype.toString = function () { return "foo"; };
        console.log(String(new Foo()));
        function f() { return String(W); }
        console.log(f());
    '''):
        '1\nfoo\nfunction W(a) { return a + 1; }\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        console.log(g.length);
        var o = {};
        o.toString = function () { return "o"; };
        console.log(String(o));
        function f() { return String(W); }
        console.log(f());
    '''):
        '1\no\nfunction W(a) { return a + 1; }\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        console.log(g.length);
        class P { toString() { return "p"; } }
        console.log(String(new P()));
        function f() { return String(W); }
        console.log(f());
    '''):
        '1\np\nfunction W(a) { return a + 1; }\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        function setLength(fn, n) { Object.defineProperty(fn, "length", { value: n, configurable: true }); }
        setLength(W, 3);
        console.log(W.length);
        function f() { return String(W); }
        console.log(f());
    '''):
        '3\nfunction W(a) { return a + 1; }\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        console.log(g.length);
        class Tape { constructor() { this.cells = new Uint8Array(4); this.pointer = 0; } set(v) { this.cells[this.pointer] = v; } }
        var t = new Tape();
        t.set(7);
        console.log(t.cells[0]);
        function f() { return String(W); }
        console.log(f());
    '''):
        '1\n7\nfunction W(a) { return a + 1; }\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        console.log(g.length);
        var c = Object.assign({}, { toString() { return "a"; } });
        console.log(String(c));
        function f() { return String(W); }
        console.log(f());
    '''):
        '1\na\nfunction W(a) { return a + 1; }\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        console.log(g.length);
        g.forEach(function (f) { console.log(typeof f); });
        function f() { return String(W); }
        console.log(f());
    '''):
        '1\nfunction\nfunction W(a) { return a + 1; }\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        W.displayName = "w";
        function f() { return String(W); }
        console.log(f());
    '''):
        'function W(a) { return a + 1; }\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        console.log(g.length);
        globalThis.toString = function () { return "g"; };
        function f() { return String(W); }
        console.log(f());
    '''):
        '1\nfunction W(a) { return a + 1; }\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        console.log(g.length);
        var o = {};
        Object.setPrototypeOf(o, { toString() { return "s"; } });
        console.log(String(o));
        function f() { return String(W); }
        console.log(f());
    '''):
        '1\ns\nfunction W(a) { return a + 1; }\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        console.log(g.length);
        var __defProp = Object.defineProperty;
        var api = {};
        __defProp(api, "x", { get: function () { return 1; }, enumerable: true });
        console.log(api.x);
        function f() { return String(W); }
        console.log(f());
    '''):
        '1\n1\nfunction W(a) { return a + 1; }\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        if (typeof register === "function") { register(W); }
        function f() { return String(W); }
        console.log(f());
    '''):
        'function W(a) { return a + 1; }\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        console.log(g.length);
        function V() {}
        V.toString = function () { return "v"; };
        console.log(String(V));
        function f() { return String(W); }
        console.log(f());
    '''):
        '1\nv\nfunction W(a) { return a + 1; }\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        console.log(g.length);
        if (typeof Object.defineProperty === "function" && Object.defineProperty) { console.log("es5"); }
        var o = {};
        if (Object.defineProperty) { Object.defineProperty(o, "x", { value: 1 }); }
        console.log(o.x);
        function f() { return String(W); }
        console.log(f());
    '''):
        '1\nes5\n1\nfunction W(a) { return a + 1; }\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        console.log(g.length);
        function nativeConstruct() {
            if (typeof Reflect === "undefined" || !Reflect.construct) return false;
            if (Reflect.construct.sham) return false;
            if (typeof Proxy === "function") return true;
            try { Boolean.prototype.valueOf.call(Reflect.construct(Boolean, [], function () {})); return true; } catch (e) { return false; }
        }
        console.log(nativeConstruct());
        function f() { return String(W); }
        console.log(f());
    '''):
        '1\ntrue\nfunction W(a) { return a + 1; }\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        console.log(g.length);
        var k = "name";
        var o = {};
        o[k] = 1;
        console.log(o.name);
        function f() { return String(W); }
        console.log(f());
    '''):
        '1\n1\nfunction W(a) { return a + 1; }\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        console.log(g.length);
        function statics() { return { displayName: "w" }; }
        Object.assign(g[0], statics());
        console.log(W.displayName);
        function f() { return String(W); }
        console.log(f());
    '''):
        '1\nw\nfunction W(a) { return a + 1; }\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        console.log(g.length);
        function Point(x) { this.x = x; this.toString = function () { return "P" + this.x; }; }
        var p = new Point(1);
        console.log(p.constructor.name, String(p), p.constructor === Point);
        function f() { return String(W); }
        console.log(f());
    '''):
        '1\nPoint P1 true\nfunction W(a) { return a + 1; }\n',
    inspect.cleandoc('''
        var W = function (a) { return a + 1; };
        function f() { var g = [W]; return String(g[0]); }
        console.log(f());
    '''):
        'function (a) { return a + 1; }\n',
    inspect.cleandoc('''
        var W = (a) => a + 1;
        function f() { var g = [W]; return String(g[0]); }
        console.log(f());
    '''):
        '(a) => a + 1\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        console.log(g.length);
        function V() {}
        var o = V;
        o.toString = function () { return "v"; };
        console.log(String(V));
        function f() { return String(W); }
        console.log(f());
    '''):
        '1\nv\nfunction W(a) { return a + 1; }\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        console.log(g.length);
        function Point(x) { this.x = x; this.toString = function () { return "P" + this.x; }; }
        console.log(String(new Point(1)));
        function f() { return String(W); }
        console.log(f());
    '''):
        '1\nP1\nfunction W(a) { return a + 1; }\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        console.log(g.length);
        function Fail(m) { var _this = Error.call(this, m) || this; Object.setPrototypeOf(_this, Fail.prototype); return _this; }
        Fail.prototype = Object.create(Error.prototype);
        console.log(new Fail("x") instanceof Fail);
        function f() { return String(W); }
        console.log(f());
    '''):
        '1\ntrue\nfunction W(a) { return a + 1; }\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        console.log(g.length);
        function Tape() { this.cells = [0, 0]; this.pointer = 0; this.toString = function () { return "tape"; }; }
        Tape.prototype.set = function (v) { this.cells[this.pointer] = v; };
        var t = new Tape();
        t.set(7);
        console.log(String(t), t.cells[0]);
        function f() { return String(W); }
        console.log(f());
    '''):
        '1\ntape 7\nfunction W(a) { return a + 1; }\n',
    inspect.cleandoc('''
        function W(a) { var b = a; return b + 1; }
        function f() { var g = [W]; return String(g[0]); }
        console.log(f());
    '''):
        'function W(a) { var b = a; return b + 1; }\n',
    inspect.cleandoc('''
        function W(a) { var s = 0; while (true) { switch (s) { case 0: s = 1; break; case 1: return a + 1; } } }
        function f() { var g = [W]; return String(g[0]); }
        console.log(f());
    '''):
        'function W(a) { var s = 0; while (true) { switch (s) { case 0: s = 1; break; case 1: return a + 1; } } }\n',
    inspect.cleandoc('''
        function inner(a) { return a + 1; }
        function W(a) { return inner(a); }
        function f() { var g = [W]; return String(g[0]); }
        console.log(f());
    '''):
        'function W(a) { return inner(a); }\n',
    inspect.cleandoc('''
        var K = 1;
        function W(a) { return a + K; }
        function f() { var g = [W]; return String(g[0]); }
        console.log(f());
    '''):
        'function W(a) { return a + K; }\n',
    inspect.cleandoc('''
        var _s = ["abc", "def"];
        function _d(i) { return _s[i]; }
        function W(a) { return _d(0) + a; }
        function f() { var g = [W]; return String(g[0]); }
        console.log(f());
    '''):
        'function W(a) { return _d(0) + a; }\n',
    inspect.cleandoc('''
        function W() { var a = arguments[0]; return a + 1; }
        function f() { var g = [W]; return String(g[0]); }
        console.log(f());
    '''):
        'function W() { var a = arguments[0]; return a + 1; }\n',
    inspect.cleandoc('''
        function W(a) { if (false) { return 0; } return a + 1; }
        function f() { var g = [W]; return String(g[0]); }
        console.log(f());
    '''):
        'function W(a) { if (false) { return 0; } return a + 1; }\n',
    inspect.cleandoc('''
        function helper(x) { return x * 2; }
        function W(a) { return helper(a) + 1; }
        function f() { var g = [W]; return String(g[0]); }
        console.log(f());
    '''):
        'function W(a) { return helper(a) + 1; }\n',
    inspect.cleandoc('''
        function W(a) { return a + 1; }
        var g = [W];
        function setT(o) { o.toString = function () { return "x"; }; }
        setT({});
        console.log(g.length);
        function f() { return String(W); }
        console.log(f());
    '''):
        '1\nfunction W(a) { return a + 1; }\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAFunctionHandedOnIsConvertedToItsWrittenText(TestBase):
    def test_the_deobfuscation_prints_what_the_program_prints(self):
        rows = A_FUNCTION_HANDED_ON_AND_CONVERTED_TO_ITS_WRITTEN_TEXT
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )
