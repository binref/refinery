from __future__ import annotations

import inspect

from test import TestBase

from refinery.lib.scripts import Expression
from refinery.lib.scripts.js.model import (
    JsArrayPattern,
    JsArrowFunctionExpression,
    JsAssignmentPattern,
    JsCallExpression,
    JsErrorNode,
    JsExpressionStatement,
    JsIdentifier,
    JsObjectPattern,
    JsParenthesizedExpression,
    JsRestElement,
)
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer

PARSE_ERROR = 'parse error'

PARAMETER_LISTS = [
    ('() => 1', []),
    ('a => a', [(JsIdentifier, 'a')]),
    ('(a) => a', [(JsIdentifier, 'a')]),
    ('(a, b, c) => a', [(JsIdentifier, 'a'), (JsIdentifier, 'b'), (JsIdentifier, 'c')]),
    ('(a = 1) => a', [(JsAssignmentPattern, 'a = 1')]),
    ('([a, b]) => a', [(JsArrayPattern, '[a, b]')]),
    ('({a, b}) => a', [(JsObjectPattern, '{ a, b }')]),
    ('({a: b}) => b', [(JsObjectPattern, '{ a: b }')]),
    ('(...a) => a', [(JsRestElement, '...a')]),
    ('(a, ...b) => b', [(JsIdentifier, 'a'), (JsRestElement, '...b')]),
    ('(a, b, ...c) => c', [(JsIdentifier, 'a'), (JsIdentifier, 'b'), (JsRestElement, '...c')]),
    ('(a, b,) => a', [(JsIdentifier, 'a'), (JsIdentifier, 'b')]),
    ('(a,) => a', [(JsIdentifier, 'a')]),
]

BRACKETED_LISTS_THAT_NO_ARROW_FOLLOWS = [
    ('(a)', '(a)'),
    ('(a, b, c)', '(a, b, c)'),
    ('(a = 1)', '(a = 1)'),
    ('([a, b])', '([a, b])'),
    ('({a, b})', '({ a, b })'),
    ('({a: b})', '({ a: b })'),
]

LISTS_THAT_NO_EXPRESSION_SPELLS = [
    ('()', []),
    ('(...a)', [(JsRestElement, '...a')]),
    ('(a, ...b)', [(JsIdentifier, 'a'), (JsRestElement, '...b')]),
    ('(a, b,)', [(JsIdentifier, 'a'), (JsIdentifier, 'b')]),
]

STATEMENTS_WRITTEN_AFTER_A_LIST_NO_EXPRESSION_SPELLS = [
    ["console.log('kept');"],
    ['x = 1;'],
    ['42;'],
    ["'kept';"],
    ['[1, 2].forEach(g);'],
    ['(1);'],
    ['`kept`;'],
    ['b.c;'],
    ['var v = 3;'],
    [inspect.cleandoc("""
        function g() {
          return 2;
        }
    """)],
    [inspect.cleandoc("""
        class K {
          m() {
            return 1;
          }
        }
    """)],
    [inspect.cleandoc("""
        try {
          p();
        } catch (e) {
          q();
        }
    """)],
    ["console.log('one');", "console.log('two');"],
]
"""
What a file goes on to say after a list no expression spells. Each entry is written exactly as the
printer emits it, so a statement that came back unchanged is one the parser neither dropped nor drew
into the arrow head it was reading when it ran out of source.
"""

BRACKETED_LISTS_AFTER_ASYNC_THAT_NO_ARROW_FOLLOWS = [
    ('async ()', 'async()'),
    ('async (a)', 'async(a)'),
    ('async (a, b, c)', 'async(a, b, c)'),
    ('async (a = 1)', 'async(a = 1)'),
    ('async ([a, b])', 'async([a, b])'),
    ('async ({a, b})', 'async({ a, b })'),
    ('async ({a: b})', 'async({ a: b })'),
    ('async (...a)', 'async(...a)'),
    ('async (a, ...b)', 'async(a, ...b)'),
    ('async (a, b,)', 'async(a, b)'),
]

A_LINE_BREAK_BEFORE_THE_ARROW = [
    ('(a)', ['(a);', (PARSE_ERROR, '=> a')]),
    ('(a, b)', ['(a, b);', (PARSE_ERROR, '=> a')]),
    ('a', ['a;', (PARSE_ERROR, '=> a')]),
]

AN_ARROW_WITH_A_BLOCK_BODY = 'f = a => {}'
AN_ARROW_WITH_A_CONCISE_BODY = 'f = a => b'
A_PARENTHESIZED_EXPRESSION = 'f = (a)'
A_FUNCTION_EXPRESSION = 'f = function () {}'

A_TAIL_AFTER_AN_ARROW_WITH_A_BLOCK_BODY = [
    ('[0]', ['f = a => {};', '[0];']),
    ('(1)', ['f = a => {};', '(1);']),
    ('.b', ['f = a => {};', (PARSE_ERROR, '.b')]),
    ('`t`', ['f = a => {};', '`t`;']),
]
"""
What a tail on the line below a block-bodied arrow is read as. Node accepts the first, second and
fourth of these files and refuses the third with `Unexpected token '.'`; on the same line it
refuses all four, since no tail may follow a block body, and so does the parser, which keeps the
whole line as the text it could not read.
"""

A_TAIL_AFTER_AN_ARROW_WITH_A_CONCISE_BODY = [
    ('[0]', ['f = a => b[0];']),
    ('(1)', ['f = a => b(1);']),
    ('.b', ['f = a => b.b;']),
    ('`t`', ['f = a => b`t`;']),
]

A_TAIL_AFTER_A_PARENTHESIZED_EXPRESSION = [
    ('[0]', ['f = (a)[0];']),
    ('(1)', ['f = (a)(1);']),
    ('.b', ['f = (a).b;']),
    ('`t`', ['f = (a)`t`;']),
]

A_TAIL_AFTER_A_FUNCTION_EXPRESSION = [
    ('[0]', ['f = function() {}[0];']),
    ('(1)', ['f = function() {}(1);']),
    ('.b', ['f = function() {}.b;']),
    ('`t`', ['f = function() {}`t`;']),
]

AN_INCREMENT_AFTER_AN_ASSIGNMENT_TARGET = [
    (AN_ARROW_WITH_A_CONCISE_BODY, ['f = a => b++;']),
    (A_PARENTHESIZED_EXPRESSION, ['f = (a)++;']),
]

AN_INCREMENT_AFTER_WHAT_CANNOT_BE_ASSIGNED_TO = [
    (AN_ARROW_WITH_A_BLOCK_BODY, ['f = a => {}++;']),
    (A_FUNCTION_EXPRESSION, ['f = function() {}++;']),
]

AN_INCREMENT_ON_THE_NEXT_LINE = [
    (AN_ARROW_WITH_A_BLOCK_BODY, ['f = a => {};', '++c;']),
    (AN_ARROW_WITH_A_CONCISE_BODY, ['f = a => b;', '++c;']),
    (A_PARENTHESIZED_EXPRESSION, ['f = (a);', '++c;']),
    (A_FUNCTION_EXPRESSION, ['f = function() {};', '++c;']),
]

AN_ARROW_BEFORE_A_LINE_THAT_BEGINS_WITH_A_BRACKET = inspect.cleandoc("""
    f = a => {}
    [1, 2].forEach(g)
""")

AN_ARROW_BEFORE_A_LINE_THAT_BEGINS_WITH_A_PARENTHESIS = inspect.cleandoc("""
    f = a => {}
    (function () {})()
""")

A_CONCISE_ARROW_BEFORE_A_LINE_THAT_BEGINS_WITH_A_BRACKET = inspect.cleandoc("""
    f = a => b
    [1, 2].forEach(g)
""")

A_CONCISE_ARROW_BEFORE_A_LINE_THAT_BEGINS_WITH_A_PARENTHESIS = inspect.cleandoc("""
    f = a => b
    (function () {})()
""")

TWO_STATEMENTS_AFTER_A_BLOCK_BODY = [
    (
        AN_ARROW_BEFORE_A_LINE_THAT_BEGINS_WITH_A_BRACKET,
        ['f = a => {};', '[1, 2].forEach(g);'],
    ),
    (
        AN_ARROW_BEFORE_A_LINE_THAT_BEGINS_WITH_A_PARENTHESIS,
        ['f = a => {};', '(function() {})();'],
    ),
]

ONE_STATEMENT_AFTER_A_CONCISE_BODY = [
    (
        A_CONCISE_ARROW_BEFORE_A_LINE_THAT_BEGINS_WITH_A_BRACKET,
        ['f = a => b[1, 2].forEach(g);'],
    ),
    (
        A_CONCISE_ARROW_BEFORE_A_LINE_THAT_BEGINS_WITH_A_PARENTHESIS,
        ['f = a => b(function() {})();'],
    ),
]


class TestJsArrowFunction(TestBase):

    def _statements(self, source: str) -> list[str | tuple[str, str]]:
        """
        The statements of the program, each printed back to source, in the order they are written.
        A span the parser could not read is `PARSE_ERROR` paired with the text it holds, which no
        printed statement equals, so a program that lost a statement to a recovery cannot pass for
        one that read it, and a span that swallowed a statement shows which one.
        """
        return [
            (PARSE_ERROR, node.text) if isinstance(node, JsErrorNode) else JsSynthesizer().convert(node)
            for node in JsParser(source).parse().body
        ]

    def _expression(self, source: str) -> Expression:
        script = JsParser(source).parse()
        self.assertEqual(len(script.body), 1)
        statement = script.body[0]
        if not isinstance(statement, JsExpressionStatement):
            return self.fail(F'not a single expression statement: {source}')
        expression = statement.expression
        if expression is None:
            return self.fail(F'the expression statement holds nothing: {source}')
        return expression

    def _arrow(self, source: str) -> JsArrowFunctionExpression:
        expression = self._expression(source)
        if not isinstance(expression, JsArrowFunctionExpression):
            return self.fail(F'not an arrow function: {source}')
        return expression

    def _parameters(self, arrow: JsArrowFunctionExpression) -> list[tuple[type, str]]:
        return [(type(param), JsSynthesizer().convert(param)) for param in arrow.params]

    def _head(self, source: str) -> tuple[bool, list[tuple[type, str]]]:
        arrow = self._arrow(source)
        return arrow.is_async, self._parameters(arrow)

    def _on_both_sides_of_a_line_break(self, head: str, tail: str):
        return self._statements(F'{head} {tail}'), self._statements(F'{head}\n{tail}')

    def test_a_bracketed_list_before_an_arrow_is_the_parameter_list_it_binds(self):
        for source, parameters in PARAMETER_LISTS:
            with self.subTest(source=source):
                self.assertEqual(self._head(source), (False, parameters))

    def test_the_async_spelling_of_a_head_binds_the_same_parameters(self):
        for source, parameters in PARAMETER_LISTS:
            with self.subTest(source=source):
                self.assertEqual(self._head(F'async {source}'), (True, parameters))

    def test_a_bracketed_list_that_no_arrow_follows_is_a_parenthesized_expression(self):
        for source, printed in BRACKETED_LISTS_THAT_NO_ARROW_FOLLOWS:
            with self.subTest(source=source):
                expression = self._expression(source)
                self.assertEqual(
                    (type(expression), JsSynthesizer().convert(expression)),
                    (JsParenthesizedExpression, printed))

    def test_a_list_that_no_expression_spells_is_kept_as_the_text_it_is(self):
        """
        Node rejects each of these four, because the empty list, the rest element and the trailing
        comma are shapes of a parameter list and of nothing else, and no arrow follows to bind
        them. The parser keeps the list as the text it could not read, and writes no arrow the
        file never had.
        """
        for source, _ in LISTS_THAT_NO_EXPRESSION_SPELLS:
            with self.subTest(source=source):
                self.assertEqual(self._statements(source), [(PARSE_ERROR, source)])

    def test_every_statement_written_after_such_a_list_comes_back_as_the_source_wrote_it(self):
        """
        Node rejects every file below, because the list is a parameter list and the body that would
        bind it was never written. The statements that follow are the analyst's file: written on
        the line below the list, each comes back as itself; written on the same line, the first of
        them is inside the text the list's statement runs to, since a statement no grammar reads
        ends where its line does, and every statement after that one comes back as itself.
        """
        for source, _ in LISTS_THAT_NO_EXPRESSION_SPELLS:
            for statements in STATEMENTS_WRITTEN_AFTER_A_LIST_NO_EXPRESSION_SPELLS:
                written = '\n'.join(statements)
                with self.subTest(source=source, written=written, separator='\n'):
                    self.assertEqual(
                        self._statements(F'{source}\n{written}'),
                        [(PARSE_ERROR, source), *statements])
                with self.subTest(source=source, written=written, separator=' '):
                    self.assertEqual(
                        self._statements(F'{source} {written}'),
                        [(PARSE_ERROR, F'{source} {statements[0]}'), *statements[1:]])

    def test_a_bracketed_list_after_async_that_no_arrow_follows_is_a_call_argument_list(self):
        """
        Every one of these ten is a program Node accepts, including the three that no parenthesized
        expression may spell: after `async` the brackets are covered by a call as well as by an
        arrow head, and a call takes an empty list, a spread, and a trailing comma.
        """
        for source, printed in BRACKETED_LISTS_AFTER_ASYNC_THAT_NO_ARROW_FOLLOWS:
            with self.subTest(source=source):
                expression = self._expression(source)
                self.assertEqual(
                    (type(expression), JsSynthesizer().convert(expression)),
                    (JsCallExpression, printed))

    def test_an_arrow_on_the_line_below_its_head_binds_no_parameters(self):
        """
        Node rejects all three: no line break may stand between a parameter list and its arrow.
        What was written is left an expression, and the arrow with the body behind it is one span
        of text the parser could not read.
        """
        for head, expected in A_LINE_BREAK_BEFORE_THE_ARROW:
            with self.subTest(head=head):
                self.assertEqual(self._statements(F'{head}\n=> a'), expected)

    def test_no_tail_attaches_to_an_arrow_whose_body_is_a_block(self):
        for tail, expected in A_TAIL_AFTER_AN_ARROW_WITH_A_BLOCK_BODY:
            with self.subTest(tail=tail):
                self.assertEqual(
                    self._on_both_sides_of_a_line_break(AN_ARROW_WITH_A_BLOCK_BODY, tail),
                    ([(PARSE_ERROR, F'{AN_ARROW_WITH_A_BLOCK_BODY} {tail}')], expected))

    def test_a_tail_after_an_arrow_whose_body_is_an_expression_belongs_to_that_expression(self):
        for tail, expected in A_TAIL_AFTER_AN_ARROW_WITH_A_CONCISE_BODY:
            with self.subTest(tail=tail):
                self.assertEqual(
                    self._on_both_sides_of_a_line_break(AN_ARROW_WITH_A_CONCISE_BODY, tail),
                    (expected, expected))

    def test_a_parenthesized_expression_takes_every_tail_an_arrow_refuses(self):
        for tail, expected in A_TAIL_AFTER_A_PARENTHESIZED_EXPRESSION:
            with self.subTest(tail=tail):
                self.assertEqual(
                    self._on_both_sides_of_a_line_break(A_PARENTHESIZED_EXPRESSION, tail),
                    (expected, expected))

    def test_a_function_expression_takes_every_tail_an_arrow_refuses(self):
        for tail, expected in A_TAIL_AFTER_A_FUNCTION_EXPRESSION:
            with self.subTest(tail=tail):
                self.assertEqual(
                    self._on_both_sides_of_a_line_break(A_FUNCTION_EXPRESSION, tail),
                    (expected, expected))

    def test_an_increment_on_the_same_line_updates_the_expression_before_it(self):
        for head, expected in AN_INCREMENT_AFTER_AN_ASSIGNMENT_TARGET:
            with self.subTest(head=head):
                self.assertEqual(self._statements(F'{head} ++'), expected)

    def test_an_increment_on_the_same_line_joins_even_what_no_program_may_update(self):
        """
        Neither of these is a program Node accepts: an arrow function is no left-hand side
        expression at all, and a function expression is one that may not be assigned to. The parser
        reads no such early error and joins the increment to what precedes it either way, so what
        stands here is the recovery and not a reading.
        """
        for head, expected in AN_INCREMENT_AFTER_WHAT_CANNOT_BE_ASSIGNED_TO:
            with self.subTest(head=head):
                self.assertEqual(self._statements(F'{head} ++'), expected)

    def test_an_increment_below_the_line_it_would_update_begins_a_statement_of_its_own(self):
        for head, expected in AN_INCREMENT_ON_THE_NEXT_LINE:
            with self.subTest(head=head):
                self.assertEqual(self._statements(F'{head}\n++c'), expected)

    def test_a_bracket_below_an_arrow_with_a_block_body_begins_the_second_of_two_statements(self):
        for source, expected in TWO_STATEMENTS_AFTER_A_BLOCK_BODY:
            with self.subTest(source=source):
                self.assertEqual(self._statements(source), expected)

    def test_a_bracket_below_an_arrow_with_an_expression_body_extends_that_expression(self):
        for source, expected in ONE_STATEMENT_AFTER_A_CONCISE_BODY:
            with self.subTest(source=source):
                self.assertEqual(self._statements(source), expected)
