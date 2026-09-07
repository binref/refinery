"""
An item the parser could not read, standing in every list position the grammar has, carried
through the whole deobfuscator. SECURITY: every snippet here is hand-authored and benign, and
nothing is run; the law is what the tool prints for a file it could not read entirely.
"""
from __future__ import annotations

import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import deobfuscate_source, node_executable
from test.lib.scripts.js.ledger import before_and_after, well_formed

from refinery.lib.scripts import is_well_formed
from refinery.lib.scripts.js.parser import JsParser


#: A file holding an unread item in one list position, mapped to what the deobfuscator prints for
#: it. Node refuses every file: the item is text no grammar reads, and it is kept as that text,
#: while everything around it is read, printed, and where a pass reaches it, rewritten. Unread
#: text may read anything visible to it, and so may the missing tail of a file that ends inside a
#: construct, so no declaration or store visible to either is taken for dead.
AN_UNREAD_ITEM_IN_EVERY_LIST_POSITION = {
    'x = {a: 1 2, b: 3}; console.log(x.b);': 'x = { a: 1 2, b: 3 };\nconsole.log(x.b);',
    'x = {...a b, c: 1}; console.log(x.c);': 'x = { ...a b, c: 1 };\nconsole.log(x.c);',
    'var {a b} = o; console.log(a);': 'var { a b } = o;\nconsole.log(a);',
    'x = [1 2, 3]; console.log(x[1]);': 'x = [1 2, 3];\nconsole.log(x[1]);',
    'var [a b] = o; console.log(a);': 'var [a b] = o;\nconsole.log(a);',
    'function f(a b) { return a; } console.log(f(1));': 'function f(a b) {\n  return a;\n}\nconsole.log(f(1));',
    'var f = (a b) => a; console.log(f(1));': 'var f = (a b) => a;\nconsole.log(f(1));',
    'console.log(f(1 2, 3));': 'console.log(f(1 2, 3));',
    'x = new C(1 2); console.log(x);': 'x = new C(1 2);\nconsole.log(x);',
    'switch (x) { case 1 break; default: g(); }': 'switch (x) {\n  case 1 break;\n  default:\n    g();\n}',
    'switch (x) { case 1: f(1 2); break; default: g(); }': (
        'switch (x) {\n  case 1:\n    f(1 2);\n    break;\n  default:\n    g();\n}'
    ),
    'class C { m(a b) {} n() { return 1; } } console.log(new C().n());': (
        'class C {\n  m(a b) {}\n  n() {\n    return 1;\n  }\n}\nconsole.log(new C().n());'
    ),
    'class C { x y; n() { return 1; } } console.log(new C().n());': (
        'class C {\n  x y;\n  n() {\n    return 1;\n  }\n}\nconsole.log(new C().n());'
    ),
    "import { a, b c } from 'm'; console.log(a);": "import { a, b c } from 'm';\nconsole.log(a);",
    'var a = 1; export { a, b c };': 'var a = 1;\nexport { a, b c };',
    "import x from 'm' with { a b }; console.log(x);": "import x from 'm' with { a b };\nconsole.log(x);",
    'x = `a${1 2}b${3}c`; console.log(x);': 'x = `a${1 2}b${3}c`;\nconsole.log(x);',
    'x = `a${b': 'x = `a${b',
    'function f() { var x = 1; x = y[a b]; return x; } console.log(f());': (
        'function f() {\n  var x = 1;\n  x = y[a b];\n  return x;\n}\nconsole.log(f());'
    ),
    'x = y[a b]; console.log(1);': 'x = y[a b];\nconsole.log(1);',
    'if (a) x = y[a b]; console.log(1);': 'if (a) x = y[a b];\nconsole.log(1);',
    'for (var a b; i < 3; i++) { g(); } h();': 'for (var a b; i < 3; i++) { g(); }\nh();',
    'l: x = y[a b]; console.log(1);': 'l: x = y[a b];\nconsole.log(1);',
    'function f() { console.log(1);': 'function f() {\n  console.log(1);',
    'class C { m() { return 1; }': 'class C {\n  m() {\n    return 1;\n  }',
    'switch (x) { case 1: f();': 'switch (x) {\n  case 1:\n    f();',
    'console.log(1); /* tail': 'console.log(1);\n/* tail',
    "console.log('abc": "console.log('abc",
    'console.log(`abc': 'console.log(`abc',
    "x = 'abc\ndef'; console.log(x);": "x = 'abc\ndef'; console.log(x);",
    '}\nconsole.log(1);': '}\nconsole.log(1);',
    '@@@ var x = 1; console.log(x);': '@@@ var x = 1;\nconsole.log(x);',
    'x = 1e; console.log(x);': 'x = 1e;\nconsole.log(x);',
    'x = a / b => c; console.log(x);': 'x = a / b => c;\nconsole.log(x);',
    '0;--> alert(1)': '0; --> alert(1)',
    'var \\u0069f = 1; console.log(2);': 'var \\u0069f = 1;\nconsole.log(2);',
}


class TestAnUnreadItemInEveryListPositionIsCarriedThroughTheDeobfuscator(TestBase):
    """
    Every consumer of the tree — the semantic model, the control-flow graph, the effect model and
    each pass — meets an unread item wherever a list can hold one, and none of them may crash on
    it or read past it: the item is text, the tree is not a program, and what comes back holds the
    text where it stood.
    """

    def test_no_file_is_a_program(self):
        rows = AN_UNREAD_ITEM_IN_EVERY_LIST_POSITION
        self.assertEqual(
            {source: is_well_formed(JsParser(source).parse()) for source in rows},
            {source: False for source in rows},
        )

    def test_the_deobfuscator_prints_the_text_where_it_stood(self):
        rows = AN_UNREAD_ITEM_IN_EVERY_LIST_POSITION
        self.assertEqual({source: deobfuscate_source(source) for source in rows}, rows)


#: Files the parser refuses, each in a shape a pass over the tree could turn into a program: a
#: fold beside a function the file ends inside, a function whose body holds unread text and that
#: nothing before the end of the file calls, and a store whose value is the string the file ends
#: inside. Node refuses all three with a `SyntaxError` and prints nothing.
A_FILE_THE_PARSER_REFUSED_IN_A_SHAPE_A_PASS_REACHES = (
    'console.log(1 + 1); function f() { g(',
    'function f() { a; ret[urn b; } g();',
    "x = 'abc",
)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAFileTheParserRefusedIsNotAnsweredWithAProgram(TestBase):
    """
    A file the parser refuses is kept as the text no engine agreed to read, and the passes run
    over the tree around that text. What they may not do is answer with a program: the text, and
    the missing tail of a file that ends inside a construct, may read anything visible to them, so
    the function holding the text stays, the store the tail may read stays, and what comes back is
    a file Node refuses exactly as it refused the one handed over.
    """

    def test_a_file_the_parser_refused_is_refused(self):
        rows = A_FILE_THE_PARSER_REFUSED_IN_A_SHAPE_A_PASS_REACHES
        refused = ('', 'SyntaxError')
        self.assertEqual(
            {source: (well_formed(source), before_and_after(source)) for source in rows},
            {source: (False, (refused, refused)) for source in rows},
        )
