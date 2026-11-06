from __future__ import annotations

import inspect

from test import TestBase

from refinery.lib.scripts import Node, is_well_formed
from refinery.lib.scripts.js.analysis.model import pattern_identifiers
from refinery.lib.scripts.js.model import (
    JsArrayPattern,
    JsAssignmentPattern,
    JsErrorNode,
    JsIdentifier,
    JsObjectPattern,
    JsProperty,
    JsRestElement,
    JsVariableDeclaration,
)
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer

LET_IS_A_NAME = 'let is a name'
PARSE_ERROR = 'parse error'
NOT_A_BINDING_TARGET = 'not a binding target'

LET_BEFORE_A_BRACKET_ACROSS_A_LINE_BREAK = inspect.cleandoc("""
    let
    [a] = [42];
""")

LET_BEFORE_A_BRACE_ACROSS_A_LINE_BREAK = inspect.cleandoc("""
    let
    {a} = {a: 42};
""")

LET_BEFORE_AN_EQUALS_ACROSS_A_LINE_BREAK = inspect.cleandoc("""
    let
    = 42;
""")

A_LET_LOOP_COUNTER_CAPTURED_BY_A_CLOSURE = inspect.cleandoc("""
    var fns = [];
    for (let i = 0; i < 3; i++) fns.push(function () { return i; });
    log = fns.map(function (f) { return f(); });
""")

A_VAR_LOOP_COUNTER_CAPTURED_BY_A_CLOSURE = inspect.cleandoc("""
    var fns = [];
    for (var i = 0; i < 3; i++) fns.push(function () { return i; });
    log = fns.map(function (f) { return f(); });
""")

THE_NAME_LET_BOUND_BY_VAR_AND_THEN_ASSIGNED = inspect.cleandoc("""
    var let = 42;
    let = 43;
    log.push(let);
""")

A_FUNCTION_NAMED_LET = inspect.cleandoc("""
    function let() { return 'F'; }
    log.push(let());
""")

LET_BEFORE_A_BINDING_NAME = [
    ('let a = 42;', ['let declares a']),
    ('let a;', ['let declares a']),
    ('let a = 1, b = 2;', ['let declares a, b']),
    ('let of = 42;', ['let declares of']),
    ('let async = 42;', ['let declares async']),
    ('let yield = 42;', ['let declares yield']),
]

LET_BEFORE_A_DESTRUCTURING_PATTERN = [
    ('let [a] = [42];', ['let declares a']),
    ('let [, a] = [1, 42];', ['let declares a']),
    ('let [a = 42] = [];', ['let declares a']),
    ('let [a = let] = [];', ['let declares a', LET_IS_A_NAME]),
    ('let [...a] = [42];', ['let declares a']),
    ('let {a} = {a: 42};', ['let declares a']),
    ('let {b: a} = {b: 42};', ['let declares a']),
    ('let {a = 42} = {};', ['let declares a']),
    ('let {a = let} = {};', ['let declares a', LET_IS_A_NAME]),
    ('let {b: a = let} = {};', ['let declares a', LET_IS_A_NAME]),
    ('let {...a} = {b: 42};', ['let declares a']),
    (LET_BEFORE_A_BRACKET_ACROSS_A_LINE_BREAK, ['let declares a']),
    (LET_BEFORE_A_BRACE_ACROSS_A_LINE_BREAK, ['let declares a']),
]

LET_BEFORE_WHAT_CANNOT_BE_BOUND = [
    ('let = 42;', [LET_IS_A_NAME]),
    ('let.x = 42;', [LET_IS_A_NAME]),
    ('let(42);', [LET_IS_A_NAME]),
    ('let;', [LET_IS_A_NAME]),
    ('let++;', [LET_IS_A_NAME]),
    (LET_BEFORE_AN_EQUALS_ACROSS_A_LINE_BREAK, [LET_IS_A_NAME]),
    ("let: log.push('LABEL');", [LET_IS_A_NAME]),
]

LET_WHERE_AN_OPERAND_IS_EXPECTED = [
    ('let a = let;', ['let declares a', LET_IS_A_NAME]),
    ('log.push(typeof let);', [LET_IS_A_NAME]),
    ('var x = let.x; log.push(x);', ['var declares x', LET_IS_A_NAME]),
    ('log.push(let(1));', [LET_IS_A_NAME]),
    ('(let[0]);', [LET_IS_A_NAME]),
    ('(let) = 42;', [LET_IS_A_NAME]),
]

LET_IN_A_FOR_HEADER_THAT_BINDS = [
    ('for (let i = 0; i < 3; i++) log.push(i);', ['let declares i']),
    ('for (let i = 0, j = 1; i < 1; i++) log.push(i, j);', ['let declares i, j']),
    ('for (let x of [42]) log.push(x);', ['let declares x']),
    ('for (let x in {p: 1}) log.push(x);', ['let declares x']),
    ('for (let [a, b] of [[1, 2]]) log.push(a, b);', ['let declares a, b']),
    ('for (let {a} of [{a: 42}]) log.push(a);', ['let declares a']),
    ('for (let of of [42]) log.push(of);', ['let declares of']),
    (A_LET_LOOP_COUNTER_CAPTURED_BY_A_CLOSURE, ['var declares fns', 'let declares i']),
]

LET_IN_A_FOR_HEADER_THAT_BINDS_NOTHING = [
    ('for (let; log.length < 1; ) log.push(let.x);', [LET_IS_A_NAME] * 2),
    ("for (let.x; log.length < 1; ) log.push('B');", [LET_IS_A_NAME]),
    ('for (let = 0; let < 2; let++) log.push(let);', [LET_IS_A_NAME] * 4),
    ('for (let in {p: 1}) log.push(let);', [LET_IS_A_NAME] * 2),
    ('for ((let) of [42]) log.push(let);', [LET_IS_A_NAME] * 2),
    ('for ((let) in {p: 1}) log.push(let);', [LET_IS_A_NAME] * 2),
]

VAR_AND_CONST_ALWAYS_DECLARE = [
    ('var a = 42;', ['var declares a']),
    ('const a = 42;', ['const declares a']),
    ('var [a] = [42];', ['var declares a']),
    ('const [a] = [42];', ['const declares a']),
    ('var {b: a} = {b: 42};', ['var declares a']),
    ('const {b: a} = {b: 42};', ['const declares a']),
    ('for (var x of [42]) log.push(x);', ['var declares x']),
    ('for (const x of [42]) log.push(x);', ['const declares x']),
    ('for (var x in {p: 1}) log.push(x);', ['var declares x']),
    ('if (true) var a = 42;', ['var declares a']),
    (A_VAR_LOOP_COUNTER_CAPTURED_BY_A_CLOSURE, ['var declares fns', 'var declares i']),
]

THE_WORD_LET_OWNED_BY_ANOTHER_BINDER = [
    (THE_NAME_LET_BOUND_BY_VAR_AND_THEN_ASSIGNED, ['var declares let'] + [LET_IS_A_NAME] * 2),
    ('for (var let of [42]) log.push(let);', ['var declares let', LET_IS_A_NAME]),
    (A_FUNCTION_NAMED_LET, [LET_IS_A_NAME] * 2),
]

LET_IN_A_STATEMENT_LIST = [
    ('{ let a = 42; log.push(a); }', ['let declares a']),
    ('{ let\na = 42; log.push(a); }', ['let declares a']),
    ('switch (1) { case 1: let a = 42; }', ['let declares a']),
    ('{ let.x = 42; log.push(let.x); }', [LET_IS_A_NAME] * 2),
]

LET_IN_A_SINGLE_STATEMENT_BODY = [
    ('if (true) let.x = 42;', [LET_IS_A_NAME]),
    ('if (0) let\na = 42;', [LET_IS_A_NAME]),
    ('if (1) {} else let\na = 42;', [LET_IS_A_NAME]),
    ('while (0) let\na = 42;', [LET_IS_A_NAME]),
    ('var let = 9;\ndo let\nwhile (0);\na = 42;', ['var declares let', LET_IS_A_NAME]),
    (
        'var let = 9;\nfor (var i = 0; i < 1; i++) let\na = 42;',
        ['var declares let', 'var declares i', LET_IS_A_NAME],
    ),
    ('var let = 9;\nl: let\na = 42;', ['var declares let', LET_IS_A_NAME]),
    ('var let = 9;\nwith (Math) let\na = 42;', ['var declares let', LET_IS_A_NAME]),
]

A_LET_BINDING_NO_SINGLE_STATEMENT_BODY_TAKES = [
    'if (0) let a = 42;',
    'if (0) let [a] = [42];',
    'if (0) let\n[a] = [42];',
    'if (0) let {a} = {};',
]

A_DECLARATION_NO_SINGLE_STATEMENT_BODY_TAKES = [
    'if (0) const a = 42;',
    'l: const a = 42;',
    'if (0) class C {}',
    'l: class C {}',
]

#: Annex B admits a function as a single statement only as the clause of an `if` or the body of a
#: label, and only a plain function: a generator or an async function is refused there as well.
A_FUNCTION_IN_A_SINGLE_STATEMENT_BODY = {
    'while (0) function f() {}': False,
    'do function f() {} while (0);': False,
    'for (;;) function f() {}': False,
    'for (x in y) function f() {}': False,
    'for (x of y) function f() {}': False,
    'with (o) function f() {}': False,
    'if (0) function* g() {}': False,
    'foo: function* g() {}': False,
    'if (0) async function f() {}': False,
    'foo: async function f() {}': False,
    'if (0) function f() {}': True,
    'if (0) function f() {} else function g() {}': True,
    'foo: function f() {}': True,
}


class TestJsLetDeclarationOrName(TestBase):

    def _binding_names(self, target: Node | None) -> list[str]:
        if target is None:
            return []
        if isinstance(target, JsIdentifier):
            return [target.name]
        if isinstance(target, JsArrayPattern):
            return [name for e in target.elements for name in self._binding_names(e)]
        if isinstance(target, JsObjectPattern):
            return [name for p in target.properties for name in self._binding_names(p)]
        if isinstance(target, JsProperty):
            return self._binding_names(target.value)
        if isinstance(target, JsAssignmentPattern):
            return self._binding_names(target.left)
        if isinstance(target, JsRestElement):
            return self._binding_names(target.argument)
        return [NOT_A_BINDING_TARGET]

    def _let_readings(self, source: str) -> list[str]:
        tree = JsParser(source).parse()
        readings: list[tuple[int, str]] = []
        bound: set[int] = set()
        for node in tree.walk():
            if isinstance(node, JsVariableDeclaration):
                names: list[str] = []
                for declarator in node.declarations:
                    target = declarator.id
                    names.extend(self._binding_names(target))
                    bound.update(id(name) for name in pattern_identifiers(target))
                readings.append((node.offset, F'{node.kind.value} declares {", ".join(names)}'))
            elif isinstance(node, JsErrorNode):
                readings.append((node.offset, PARSE_ERROR))
        for node in tree.walk():
            if isinstance(node, JsIdentifier) and id(node) not in bound:
                if node.name in ('let', 'var', 'const'):
                    readings.append((node.offset, F'{node.name} is a name'))
        return [reading for _, reading in sorted(readings)]

    def test_let_before_a_binding_name_declares_that_name(self):
        for source, expected in LET_BEFORE_A_BINDING_NAME:
            with self.subTest(source=source):
                self.assertEqual(self._let_readings(source), expected)

    def test_let_before_a_pattern_declares_only_the_names_that_pattern_binds(self):
        for source, expected in LET_BEFORE_A_DESTRUCTURING_PATTERN:
            with self.subTest(source=source):
                self.assertEqual(self._let_readings(source), expected)

    def test_let_before_something_that_cannot_be_bound_is_an_ordinary_name(self):
        for source, expected in LET_BEFORE_WHAT_CANNOT_BE_BOUND:
            with self.subTest(source=source):
                self.assertEqual(self._let_readings(source), expected)

    def test_let_where_an_operand_is_expected_is_an_ordinary_name(self):
        for source, expected in LET_WHERE_AN_OPERAND_IS_EXPECTED:
            with self.subTest(source=source):
                self.assertEqual(self._let_readings(source), expected)

    def test_let_in_a_for_header_declares_the_binding_that_follows_it(self):
        for source, expected in LET_IN_A_FOR_HEADER_THAT_BINDS:
            with self.subTest(source=source):
                self.assertEqual(self._let_readings(source), expected)

    def test_let_in_a_for_header_is_an_ordinary_name_when_it_binds_nothing(self):
        for source, expected in LET_IN_A_FOR_HEADER_THAT_BINDS_NOTHING:
            with self.subTest(source=source):
                self.assertEqual(self._let_readings(source), expected)

    def test_var_and_const_declare_whatever_follows_them(self):
        for source, expected in VAR_AND_CONST_ALWAYS_DECLARE:
            with self.subTest(source=source):
                self.assertEqual(self._let_readings(source), expected)

    def test_the_word_let_is_an_ordinary_name_where_another_binder_owns_it(self):
        for source, expected in THE_WORD_LET_OWNED_BY_ANOTHER_BINDER:
            with self.subTest(source=source):
                self.assertEqual(self._let_readings(source), expected)

    def test_a_statement_list_reads_a_let_binding_wherever_the_list_stands(self):
        for source, expected in LET_IN_A_STATEMENT_LIST:
            with self.subTest(source=source):
                self.assertEqual(self._let_readings(source), expected)

    def test_a_single_statement_body_reads_let_as_a_name(self):
        """
        A single-statement body takes no lexical declaration, so `let` there is a name. Where a line
        break follows it, automatic semicolon insertion ends the body at the name, and the
        assignment after it is the next statement.
        """
        for source, expected in LET_IN_A_SINGLE_STATEMENT_BODY:
            with self.subTest(source=source):
                self.assertEqual(self._let_readings(source), expected)

    def test_the_assignment_a_split_body_leaves_is_the_next_statement(self):
        script = JsParser('if (0) let\nx = 1;').parse()
        self.assertEqual(is_well_formed(script), True)
        self.assertEqual(len(script.body), 2)
        self.assertEqual(JsSynthesizer().convert(script.body[1]), 'x = 1;')

    def test_a_let_binding_no_single_statement_body_takes_is_refused(self):
        """
        Without a line break after `let`, nothing ends the body at the name; and an expression
        statement may not open with `let [`, so before a bracket not even a line break does.
        """
        for source in A_LET_BINDING_NO_SINGLE_STATEMENT_BODY_TAKES:
            with self.subTest(source=source):
                self.assertEqual(is_well_formed(JsParser(source).parse()), False)

    def test_a_const_or_a_class_in_a_single_statement_body_is_refused(self):
        for source in A_DECLARATION_NO_SINGLE_STATEMENT_BODY_TAKES:
            with self.subTest(source=source):
                self.assertEqual(is_well_formed(JsParser(source).parse()), False)

    def test_only_an_if_clause_or_a_label_takes_a_plain_function_as_a_single_statement(self):
        self.assertEqual(
            {
                source: is_well_formed(JsParser(source).parse())
                for source in A_FUNCTION_IN_A_SINGLE_STATEMENT_BODY
            },
            A_FUNCTION_IN_A_SINGLE_STATEMENT_BODY,
        )
