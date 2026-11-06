from __future__ import annotations

from test import TestBase

from refinery.lib.scripts import Expression, Node
from refinery.lib.scripts.js.model import (
    JsExpressionStatement,
    JsStringLiteral,
    JsTaggedTemplateExpression,
    JsTemplateLiteral,
)
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer

ESCAPES = [
    ('`plain text 123`', 'plain text 123'),
    ('``', ''),
    (R'`\b\f\n\r\t\v`', '\b\f\n\r\t\v'),
    (R'`a\0b`', 'a\x00b'),
    (R'`\'\"`', '\'"'),
    (R'`\x41\x7F\xE9`', 'A\x7F\xE9'),
    (R'`\u0041\u00E9\u20AC`', 'A\xE9\u20AC'),
    (R'`\u{41}\u{E9}`', 'A\xE9'),
    (R'`\u{00000041}`', 'A'),
    (R'`\u{1F600}`', '\uD83D\uDE00'),
    (R'`\u{10FFFF}`', '\uDBFF\uDFFF'),
    (R'`\u{D800}`', '\uD800'),
    (R'`\0`', '\x00'),
    (R'`a\`b`', 'a`b'),
    (R'`a\${b}c`', 'a${b}c'),
    (R'`a\$b`', 'a$b'),
    (R'`a\\b`', 'a\\b'),
    (R'`\a\q\{`', 'aq{'),
    ('`a$b$`', 'a$b$'),
    ('`a{b}c`', 'a{b}c'),
]
"""
What each template denotes, measured with Node: the string a tag is handed for the one run of the
literal, which is also the string the literal evaluates to. A string is written here as the code
units Node reports it holding, so a character above the basic plane is the two surrogates that
spell it and the value is as long as `String.prototype.length` says.
"""

LINE_CONTINUATIONS = [
    ('`a\\\nb`', 'ab'),
    ('`a\\\r\nb`', 'ab'),
    ('`a\\\rb`', 'ab'),
]
"""
A backslash at the end of a line, written with each of the three line ending conventions. Node
denotes the two letters with nothing between them in all three.
"""

LINE_TERMINATORS = [
    ('`a\nb\nc`', 'a\nb\nc'),
    ('`a\r\nb\r\nc`', 'a\nb\nc'),
    ('`a\rb\rc`', 'a\nb\nc'),
    ('`a\r\nb\rc\nd`', 'a\nb\nc\nd'),
    ('`a\r\r\nb`', 'a\n\nb'),
    ('`a\u2028b\u2029c`', 'a\u2028b\u2029c'),
]
"""
A template spanning several lines. Node denotes a line feed for every line terminator sequence a
template is written with, and leaves the two separators that are not line breaks standing.
"""

A_STRING_READS_WHAT_A_TEMPLATE_REFUSES = [
    (R"'\01'", R'`\01`', '\x01'),
    (R"'\1'", R'`\1`', '\x01'),
    (R"'\7'", R'`\7`', '\x07'),
    (R"'\07'", R'`\07`', '\x07'),
    (R"'\10'", R'`\10`', '\x08'),
    (R"'\251'", R'`\251`', '\xA9'),
    (R"'\00'", R'`\00`', '\x00'),
    (R"'\08'", R'`\08`', '\x008'),
    (R"'\09'", R'`\09`', '\x009'),
    (R"'\8'", R'`\8`', '8'),
    (R"'\9'", R'`\9`', '9'),
]
"""
An escape written in a string, the same escape written in a template, and the text Node says the
string denotes. These are the spellings at which the two literals part: Node evaluates every string
here and refuses every template, naming the escape in a SyntaxError, so the one denotes text where
the other denotes nothing at all.
"""

AN_ESCAPE_NEITHER_LITERAL_HAS = [
    (R"'\x'", R'`\x`'),
    (R"'\xA'", R'`\xA`'),
    (R"'\xZZ'", R'`\xZZ`'),
    (R"'\u'", R'`\u`'),
    (R"'\u004'", R'`\u004`'),
    (R"'\uZZZZ'", R'`\uZZZZ`'),
    (R"'\u{}'", R'`\u{}`'),
    (R"'\u{110000}'", R'`\u{110000}`'),
    (R"'\u{41'", R'`\u{41`'),
    (R"'\u{ 41}'", R'`\u{ 41}`'),
    (R"'\u{4_1}'", R'`\u{4_1}`'),
    (R"'\u{0x41}'", R'`\u{0x41}`'),
]
"""
An escape neither literal has, in both spellings: a hexadecimal escape short of its digits or
holding a character that is not one, and a braced code point that is empty, out of range,
unterminated, or written with anything besides hexadecimal digits. Node refuses both spellings of
every one of these, so neither literal denotes any text.
"""

REFUSED_BY_THE_LANGUAGE = [
    *(template for _, template, _ in A_STRING_READS_WHAT_A_TEMPLATE_REFUSES),
    *(template for _, template in AN_ESCAPE_NEITHER_LITERAL_HAS),
]
"""
Every template of the two tables above, which Node refuses to evaluate, each with a SyntaxError
naming the escape. A tag reading one of them is handed `undefined` for the run, so no string is what
these denote.
"""

RUNS_THE_LANGUAGE_REFUSES = [
    (R'`\01${1}`', [None, '']),
    (R'`${1}\01`', ['', None]),
    (R'`\8${1}\9`', [None, None]),
    (R'`\0${1}\0`', ['\x00', '\x00']),
]
"""
A template built from more than one run, carrying the refused escape in the first run, in the last,
in both, and in neither. A tag is handed `undefined` for exactly the runs whose escape the grammar
has no rule for and the text for the rest, and Node refuses the untagged literal wherever one such
run is present.
"""

RUNS_AND_HOLES = [
    ('`a${1}b`', ['a', 'b'], ['1']),
    ('`a${1}b${2}c`', ['a', 'b', 'c'], ['1', '2']),
    ('`${1}${2}`', ['', '', ''], ['1', '2']),
    ('`${1}`', ['', ''], ['1']),
    (R'`\t${1}\n${2}\u0041`', ['\t', '\n', 'A'], ['1', '2']),
    ('`a${1 + 2}b`', ['a', 'b'], ['1 + 2']),
    (R'`a\\${1}b`', ['a\\', 'b'], ['1']),
    ('`${"`"}`', ['', ''], ['"`"']),
    ('`${"}"}`', ['', ''], ['"}"']),
]
"""
The runs a template is built from and the expressions between them. Every run is the string Node
hands a tag in that position, and the expressions are given as they are written.
"""

TAGGED = [
    ('tag`a${1}b${2}c`', 'tag', ['a', 'b', 'c'], ['1', '2']),
    (R'String.raw`a\nb`', 'String.raw', ['a\nb'], []),
]
"""
A tag and the literal it reads. The runs are the strings Node hands the tag, which a tag does not
change: what a tag is offered besides them is the spelling, not another value.
"""

SPELLING_AND_VALUE = [
    (R'`a\tb`', 'a\tb', R'a\tb'),
    ('`a\r\nb`', 'a\nb', 'a\r\nb'),
    (R'`\u0041\u0042`', 'AB', R'\u0041\u0042'),
]
"""
A template, the text it denotes, and the text between its backticks. The middle column is measured
with Node; the last is what the source wrote, which is what printing the literal writes again.
"""

NESTED_SIMPLE = '`outer ${`inner ${1}`} end`'
NESTED_ESCAPES = R'`a\t${`b\n${1}c`}d`'
NESTED_LINES = '`a\r\n${`b\rc`}d`'
NESTED_TWICE = '`a${`b${`c`}d`}e`'

SURROGATE_PAIR = R'`\uD83D\uDE00`'
BRACED_ASTRAL = R'`\u{1F600}`'

WRITTEN_BACK = [
    *(source for source, _ in ESCAPES),
    *(source for source, _ in LINE_CONTINUATIONS),
    *(source for source, _ in LINE_TERMINATORS),
    *(source for source, _, _ in RUNS_AND_HOLES),
    *(source for source, _, _, _ in TAGGED),
    *(source for source, _, _ in SPELLING_AND_VALUE),
    *(source for source, _ in RUNS_THE_LANGUAGE_REFUSES),
    *REFUSED_BY_THE_LANGUAGE,
    NESTED_SIMPLE,
    NESTED_ESCAPES,
    NESTED_LINES,
    NESTED_TWICE,
    SURROGATE_PAIR,
]


class TemplateLiteralTest(TestBase):

    def _expression(self, source: str) -> Expression:
        script = JsParser(source).parse()
        if len(script.body) != 1:
            self.fail(F'{source!r} parsed into {len(script.body)} statements')
        statement = script.body[0]
        if not isinstance(statement, JsExpressionStatement):
            self.fail(F'{source!r} parsed into a {type(statement).__name__}')
        expression = statement.expression
        if expression is None:
            self.fail(F'{source!r} parsed into a statement without an expression')
        return expression

    def _template(self, source: str) -> JsTemplateLiteral:
        return self._as_template(self._expression(source))

    def _as_template(self, node: Expression | None) -> JsTemplateLiteral:
        if not isinstance(node, JsTemplateLiteral):
            self.fail(F'expected a template literal, found a {type(node).__name__}')
        return node

    def _tagged(self, source: str) -> JsTaggedTemplateExpression:
        expression = self._expression(source)
        if not isinstance(expression, JsTaggedTemplateExpression):
            self.fail(F'{source!r} parsed into a {type(expression).__name__}')
        return expression

    def _runs(self, template: JsTemplateLiteral) -> list[str | None]:
        return [quasi.value for quasi in template.quasis]

    def _holes(self, template: JsTemplateLiteral) -> list[str]:
        return [self._printed(expression) for expression in template.expressions]

    def _text(self, source: str) -> str | None:
        runs = self._runs(self._template(source))
        if len(runs) != 1:
            self.fail(F'{source!r} is built from {len(runs)} runs')
        return runs[0]

    def _printed(self, node: Node | None) -> str:
        if node is None:
            self.fail('there is no node to print')
        return JsSynthesizer().convert(node)

    def _string_text(self, source: str) -> str | None:
        literal = self._expression(source)
        if not isinstance(literal, JsStringLiteral):
            self.fail(F'{source!r} parsed into a {type(literal).__name__}')
        return literal.value


class TestJsTemplateValue(TemplateLiteralTest):

    def test_escapes_denote_the_text_node_measures(self):
        for source, text in ESCAPES:
            with self.subTest(source=source):
                self.assertEqual(self._text(source), text)

    def test_backslash_at_the_end_of_a_line_joins_the_lines(self):
        for source, text in LINE_CONTINUATIONS:
            with self.subTest(source=source):
                self.assertEqual(self._text(source), text)

    def test_template_spanning_lines_denotes_the_text_node_measures(self):
        for source, text in LINE_TERMINATORS:
            with self.subTest(source=source):
                self.assertEqual(self._text(source), text)

    def test_template_the_language_refuses_denotes_nothing(self):
        for source in REFUSED_BY_THE_LANGUAGE:
            with self.subTest(source=source):
                self.assertEqual(self._runs(self._template(source)), [None])

    def test_astral_character_denotes_one_string_however_it_is_spelled(self):
        self.assertEqual(self._text(SURROGATE_PAIR), self._text(BRACED_ASTRAL))

    def test_a_string_reads_the_escape_that_leaves_a_template_denoting_nothing(self):
        for string, template, text in A_STRING_READS_WHAT_A_TEMPLATE_REFUSES:
            with self.subTest(string=string, template=template):
                self.assertEqual(self._string_text(string), text)
                self.assertEqual(self._runs(self._template(template)), [None])

    def test_an_escape_the_grammar_does_not_have_leaves_neither_literal_denoting_anything(self):
        for string, template in AN_ESCAPE_NEITHER_LITERAL_HAS:
            with self.subTest(string=string, template=template):
                self.assertEqual(self._string_text(string), None)
                self.assertEqual(self._runs(self._template(template)), [None])

    def test_the_run_carrying_the_refused_escape_is_the_only_one_denoting_nothing(self):
        for source, runs in RUNS_THE_LANGUAGE_REFUSES:
            with self.subTest(source=source):
                self.assertEqual(self._runs(self._template(source)), runs)


class TestJsTemplateRuns(TemplateLiteralTest):

    def test_runs_and_holes_interleave(self):
        for source, runs, holes in RUNS_AND_HOLES:
            with self.subTest(source=source):
                template = self._template(source)
                self.assertEqual(self._runs(template), runs)
                self.assertEqual(self._holes(template), holes)
                tails = [quasi.tail for quasi in template.quasis]
                self.assertEqual(tails, [False] * len(holes) + [True])

    def test_tagged_template_reads_the_runs_and_the_holes(self):
        for source, tag, runs, holes in TAGGED:
            with self.subTest(source=source):
                tagged = self._tagged(source)
                template = self._as_template(tagged.quasi)
                self.assertEqual(self._printed(tagged.tag), tag)
                self.assertEqual(self._runs(template), runs)
                self.assertEqual(self._holes(template), holes)

    def test_template_nested_in_a_hole(self):
        outer = self._template(NESTED_SIMPLE)
        self.assertEqual(self._runs(outer), ['outer ', ' end'])
        inner = self._as_template(outer.expressions[0])
        self.assertEqual(self._runs(inner), ['inner ', ''])
        self.assertEqual(self._holes(inner), ['1'])

    def test_template_nested_in_a_hole_carries_its_own_escapes(self):
        outer = self._template(NESTED_ESCAPES)
        self.assertEqual(self._runs(outer), ['a\t', 'd'])
        inner = self._as_template(outer.expressions[0])
        self.assertEqual(self._runs(inner), ['b\n', 'c'])
        self.assertEqual(self._holes(inner), ['1'])

    def test_template_nested_in_a_hole_carries_its_own_line_endings(self):
        outer = self._template(NESTED_LINES)
        self.assertEqual(self._runs(outer), ['a\n', 'd'])
        inner = self._as_template(outer.expressions[0])
        self.assertEqual(self._runs(inner), ['b\nc'])
        self.assertEqual(self._holes(inner), [])

    def test_template_nested_in_a_nested_hole(self):
        outer = self._template(NESTED_TWICE)
        self.assertEqual(self._runs(outer), ['a', 'e'])
        middle = self._as_template(outer.expressions[0])
        self.assertEqual(self._runs(middle), ['b', 'd'])
        inner = self._as_template(middle.expressions[0])
        self.assertEqual(self._runs(inner), ['c'])
        self.assertEqual(self._holes(inner), [])


class TestJsTemplateSpelling(TemplateLiteralTest):

    def test_printing_gives_back_the_source(self):
        for source in WRITTEN_BACK:
            with self.subTest(source=source):
                self.assertEqual(self._printed(self._expression(source)), source)

    def test_run_keeps_the_spelling_beside_the_text_it_denotes(self):
        for source, text, spelling in SPELLING_AND_VALUE:
            with self.subTest(source=source):
                template = self._template(source)
                self.assertEqual(self._runs(template), [text])
                self.assertEqual([quasi.raw for quasi in template.quasis], [spelling])
