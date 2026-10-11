from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.js.analysis.model import build_semantic_model
from refinery.lib.scripts.js.deobfuscation.simplify import JsSimplifications
from refinery.lib.scripts.js.deobfuscation.templates import Template, matches
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
