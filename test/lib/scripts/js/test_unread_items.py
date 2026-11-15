"""
SECURITY: every snippet here is hand-authored and benign. Nothing from `samples` may ever be fed to
this.
"""
from __future__ import annotations

import inspect
import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import deobfuscate_source, node_executable
from test.lib.scripts.js.ledger import before_and_after, well_formed

from refinery.lib.scripts import is_well_formed
from refinery.lib.scripts.js.parser import JsParser


#: Unread text may read anything visible to it, and so may the missing tail of a file that ends
#: inside a construct, so no declaration or store visible to either is dead.
AN_UNREAD_ITEM_IN_EVERY_LIST_POSITION = {
    'x = {a: 1 2, b: 3}; console.log(x.b);': inspect.cleandoc("""
        x = { a: 1 2, b: 3 };
        console.log(x.b);
    """),
    'x = {...a b, c: 1}; console.log(x.c);': inspect.cleandoc("""
        x = { ...a b, c: 1 };
        console.log(x.c);
    """),
    'var {a b} = o; console.log(a);': inspect.cleandoc("""
        var { a b } = o;
        console.log(a);
    """),
    'x = [1 2, 3]; console.log(x[1]);': inspect.cleandoc("""
        x = [1 2, 3];
        console.log(x[1]);
    """),
    'var [a b] = o; console.log(a);': inspect.cleandoc("""
        var [a b] = o;
        console.log(a);
    """),
    'function f(a b) { return a; } console.log(f(1));': inspect.cleandoc("""
        function f(a b) {
          return a;
        }
        console.log(f(1));
    """),
    'var f = (a b) => a; console.log(f(1));': inspect.cleandoc("""
        var f = (a b) => a;
        console.log(f(1));
    """),
    'console.log(f(1 2, 3));': 'console.log(f(1 2, 3));',
    'x = new C(1 2); console.log(x);': inspect.cleandoc("""
        x = new C(1 2);
        console.log(x);
    """),
    'switch (x) { case 1 break; default: g(); }': inspect.cleandoc("""
        switch (x) {
          case 1 break;
          default:
            g();
        }
    """),
    'switch (x) { case 1: f(1 2); break; default: g(); }': inspect.cleandoc("""
        switch (x) {
          case 1:
            f(1 2);
            break;
          default:
            g();
        }
    """),
    'class C { m(a b) {} n() { return 1; } } console.log(new C().n());': inspect.cleandoc("""
        class C {
          m(a b) {}
          n() {
            return 1;
          }
        }
        console.log(new C().n());
    """),
    'class C { x y; n() { return 1; } } console.log(new C().n());': inspect.cleandoc("""
        class C {
          x y;
          n() {
            return 1;
          }
        }
        console.log(new C().n());
    """),
    "import { a, b c } from 'm'; console.log(a);": inspect.cleandoc("""
        import { a, b c } from 'm';
        console.log(a);
    """),
    'var a = 1; export { a, b c };': inspect.cleandoc("""
        var a = 1;
        export { a, b c };
    """),
    "import x from 'm' with { a b }; console.log(x);": inspect.cleandoc("""
        import x from 'm' with { a b };
        console.log(x);
    """),
    'x = `a${1 2}b${3}c`; console.log(x);': inspect.cleandoc("""
        x = `a${1 2}b${3}c`;
        console.log(x);
    """),
    'x = `a${b': 'x = `a${b',
    'function f() { var x = 1; x = y[a b]; return x; } console.log(f());': inspect.cleandoc("""
        function f() {
          var x = 1;
          x = y[a b];
          return x;
        }
        console.log(f());
    """),
    'x = y[a b]; console.log(1);': inspect.cleandoc("""
        x = y[a b];
        console.log(1);
    """),
    'if (a) x = y[a b]; console.log(1);': inspect.cleandoc("""
        if (a) x = y[a b];
        console.log(1);
    """),
    'for (var a b; i < 3; i++) { g(); } h();': inspect.cleandoc("""
        for (var a b; i < 3; i++) { g(); }
        h();
    """),
    'l: x = y[a b]; console.log(1);': inspect.cleandoc("""
        l: x = y[a b];
        console.log(1);
    """),
    'function f() { console.log(1);': inspect.cleandoc("""
        function f() {
          console.log(1);
    """),
    'class C { m() { return 1; }': inspect.cleandoc("""
        class C {
          m() {
            return 1;
          }
    """),
    'switch (x) { case 1: f();': inspect.cleandoc("""
        switch (x) {
          case 1:
            f();
    """),
    'console.log(1); /* tail': inspect.cleandoc("""
        console.log(1);
        /* tail
    """),
    "console.log('abc": "console.log('abc",
    'console.log(`abc': 'console.log(`abc',
    inspect.cleandoc("""
        x = 'abc
        def'; console.log(x);
    """): inspect.cleandoc("""
        x = 'abc
        def'; console.log(x);
    """),
    '}\nconsole.log(1);': '}\nconsole.log(1);',
    '@@@ var x = 1; console.log(x);': inspect.cleandoc("""
        @@@ var x = 1;
        console.log(x);
    """),
    'x = 1e; console.log(x);': inspect.cleandoc("""
        x = 1e;
        console.log(x);
    """),
    'x = a / b => c; console.log(x);': inspect.cleandoc("""
        x = a / b => c;
        console.log(x);
    """),
    '0;--> alert(1)': '0; --> alert(1)',
    'var \\u0069f = 1; console.log(2);': inspect.cleandoc("""
        var \\u0069f = 1;
        console.log(2);
    """),
}


class TestAnUnreadItemInEveryListPositionIsCarriedThroughTheDeobfuscator(TestBase):

    def test_no_file_is_a_program(self):
        rows = AN_UNREAD_ITEM_IN_EVERY_LIST_POSITION
        self.assertEqual(
            {source: is_well_formed(JsParser(source).parse()) for source in rows},
            {source: False for source in rows},
        )

    def test_the_deobfuscator_prints_the_text_where_it_stood(self):
        rows = AN_UNREAD_ITEM_IN_EVERY_LIST_POSITION
        self.assertEqual({source: deobfuscate_source(source) for source in rows}, rows)


A_FILE_THE_PARSER_REFUSED_IN_A_SHAPE_A_PASS_REACHES = (
    'console.log(1 + 1); function f() { g(',
    'function f() { a; ret[urn b; } g();',
    "x = 'abc",
)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAFileTheParserRefusedIsNotAnsweredWithAProgram(TestBase):

    def test_a_file_the_parser_refused_is_refused(self):
        rows = A_FILE_THE_PARSER_REFUSED_IN_A_SHAPE_A_PASS_REACHES
        refused = ('', 'SyntaxError')
        self.assertEqual(
            {source: (well_formed(source), before_and_after(source)) for source in rows},
            {source: (False, (refused, refused)) for source in rows},
        )
