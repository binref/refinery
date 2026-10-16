from __future__ import annotations

import itertools

from test import TestBase

from refinery.lib.scripts.js.analysis.model import build_semantic_model
from refinery.lib.scripts.js.deobfuscation.simplify import JsSimplifications
from refinery.lib.scripts.js.deobfuscation.templates import (
    Shuffle,
    Template,
    match,
    matches,
    template_form,
)
from refinery.lib.scripts.js.model import (
    JsFunctionDeclaration,
    JsMemberExpression,
    JsNumericLiteral,
    JsScript,
    JsStringLiteral,
    static_property_key,
)
from refinery.lib.scripts.js.parser import JsParser

INDEX_IN_ALPHABET = Template('function F(s) { return ALPHABET.indexOf(s); }', frozenset({'ALPHABET'}))


def _matches(script: JsScript, template: Template, nodes: dict[int, str] | None = None) -> bool:
    function = script.body[0]
    assert isinstance(function, JsFunctionDeclaration)
    return matches(build_semantic_model(script), function, [template], {}, nodes)


def _alphabet(script: JsScript) -> dict[int, str]:
    return {id(node): 'ALPHABET' for node in script.walk() if isinstance(node, JsStringLiteral)}


def _receiver_of_index_of(script: JsScript) -> dict[int, str]:
    for node in script.walk():
        if isinstance(node, JsMemberExpression) and static_property_key(node) == 'indexOf' and node.object:
            return {id(node.object): 'ALPHABET'}
    raise AssertionError('no call of indexOf')


class TestTemplates(TestBase):

    def test_a_node_standing_for_a_placeholder_matches_whatever_it_spells(self):
        for literal in ('"abc"', '"xyz"', '[1, 2]'):
            script = JsParser(F'function g(t) {{ return {literal}.indexOf(t); }}').parse()
            self.assertTrue(_matches(script, INDEX_IN_ALPHABET, _receiver_of_index_of(script)), literal)

    def test_a_node_standing_for_no_placeholder_is_compared_as_written(self):
        script = JsParser('function g(t) { return "abc".indexOf(t); }').parse()
        self.assertFalse(_matches(script, INDEX_IN_ALPHABET))

    def test_a_node_standing_for_a_placeholder_elsewhere_does_not_match(self):
        script = JsParser('function g(t) { return t.indexOf("abc"); }').parse()
        self.assertFalse(_matches(script, INDEX_IN_ALPHABET, _alphabet(script)))

    def test_a_negative_number_constant_folding_leaves_matches_its_negation(self):
        script = JsParser('function g(t) { return t.indexOf("x") === -1; }').parse()
        JsSimplifications().visit(script)
        self.assertIn(-1, [node.value for node in script.walk() if isinstance(node, JsNumericLiteral)])
        self.assertTrue(_matches(script, Template('function F(s) { return s.indexOf("x") === -1; }')))

    def test_a_negated_zero_does_not_match_zero(self):
        script = JsParser('function g(t) { return t * -0; }').parse()
        self.assertFalse(_matches(script, Template('function F(s) { return s * 0; }')))

    def test_undefined_matches_void_0_where_it_names_the_global_value(self):
        template = Template('function F(s) { return s === undefined; }')
        for source, matched in {
            'function g(t) { return t === void 0; }': True,
            'function g(t) { return t === undefined; }': True,
            'function g(t) { return t === void 1; }': False,
        }.items():
            with self.subTest(source):
                self.assertEqual(_matches(JsParser(source).parse(), template), matched)

    def test_undefined_a_program_declares_is_no_global_value(self):
        script = JsParser('function g(t) { return t === undefined; } var undefined = 5;').parse()
        self.assertFalse(_matches(script, Template('function F(s) { return s === undefined; }')))


SHUFFLED = Template(
    'function F(s, u) { s = s | 0; if (s === 1) { return "a"; } if (u === 2) { return "b"; }'
    ' if (s === u) { return "c"; } }',
    shuffled=Shuffle(1, 1),
)

SHUFFLED_STATEMENTS = {
    1: 'if (t === 1) { return "a"; }',
    2: 'if (w === 2) { return "b"; }',
    3: 'if (t === w) { return "c"; }',
}


REPEATED = Template(
    'function F(s, u) { s = s | 0; if (s === 1) { return "a"; } if (s === 1) { return "a"; }'
    ' if (u === 2) { return "b"; } }',
    shuffled=Shuffle(1, 1),
)


def _fit(body: str, template: Template = SHUFFLED) -> tuple[int, ...] | None:
    script = JsParser(F'function g(t, w) {{ {body} }}').parse()
    function = script.body[0]
    assert isinstance(function, JsFunctionDeclaration)
    found = match(build_semantic_model(script), function, [template], {})
    return None if found is None else found[1]


class TestTemplatesWithShuffledStatements(TestBase):

    def test_every_order_of_every_choice_holding_the_statement_always_written_matches(self):
        for count in range(1, 4):
            for positions in itertools.permutations(SHUFFLED_STATEMENTS, count):
                if 1 not in positions:
                    continue
                body = ' '.join(['t = t | 0;', *(SHUFFLED_STATEMENTS[p] for p in positions)])
                with self.subTest(positions):
                    self.assertEqual(_fit(body), (0, *positions))

    def test_a_choice_without_the_statement_always_written_does_not_match(self):
        self.assertIsNone(_fit(F't = t | 0; {SHUFFLED_STATEMENTS[2]} {SHUFFLED_STATEMENTS[3]}'))

    def test_a_statement_written_twice_does_not_match(self):
        self.assertIsNone(_fit(F't = t | 0; {SHUFFLED_STATEMENTS[1]} {SHUFFLED_STATEMENTS[1]}'))

    def test_a_statement_the_template_lacks_does_not_match(self):
        self.assertIsNone(_fit(F't = t | 0; {SHUFFLED_STATEMENTS[1]} if (t === 4) {{ return "d"; }}'))

    def test_the_statements_before_the_shuffled_ones_keep_their_place(self):
        self.assertIsNone(_fit(F'{SHUFFLED_STATEMENTS[1]} t = t | 0;'))

    def test_a_statement_the_template_holds_twice_matches_as_often_as_it_holds_it(self):
        once = SHUFFLED_STATEMENTS[1]
        other = SHUFFLED_STATEMENTS[2]
        self.assertEqual(_fit(F't = t | 0; {once}', REPEATED), (0, 1))
        self.assertEqual(_fit(F't = t | 0; {other} {once} {once}', REPEATED), (0, 3, 1, 2))
        self.assertIsNone(_fit(F't = t | 0; {once} {once} {once}', REPEATED))

    def test_a_template_whose_shuffled_statement_first_names_a_local_is_refused(self):
        template = Template(
            'function F(s) { var r; s = s | 0; if (s) { r = 1; } if (!s) { r = 2; } }',
            shuffled=Shuffle(1, 1),
        )
        with self.assertRaises(ValueError):
            template_form(template)

    def test_a_template_whose_shuffled_statement_declares_a_name_is_refused(self):
        template = Template(
            'function F(s) { s = s | 0; if (s) { var r = 1; return r; } }',
            shuffled=Shuffle(1, 1),
        )
        with self.assertRaises(ValueError):
            template_form(template)
