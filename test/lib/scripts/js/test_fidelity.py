from __future__ import annotations

import ast as pyast
import functools
import glob
import os

from test import TestBase
from test.lib.scripts.js.corpus import SNIPPETS, shapes_the_grammar_forbids

from refinery.lib.scripts import (
    Node,
    canonical,
    child_list_fields,
    is_well_formed,
    owning_field,
    owning_list,
    set_child,
    set_child_list,
)
from refinery.lib.scripts.js import model as jsmodel
from refinery.lib.scripts.js.model import JsBlockStatement, JsParenthesizedExpression
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer

#: A harvested string is taken for JavaScript when it holds one of these. Taking prose for
#: JavaScript costs nothing, because whatever it parses to has to survive the round trip all the
#: same; leaving a program out loses coverage.
HINTS = (';', '{', '(', '=', '[', '`', '"', "'", '.', '/', '+')

MINIMUM_HARVEST = 3000

ADDED_BLOCK = 'a statement that is not a block is printed as one'
ADDED_PAREN = 'a parenthesis the tree does not hold is printed where the program needs one'

#: An entry names a normalization that preserves the program, with the reason it does. A defect not
#: yet fixed is never an entry: writing it down would make the test pass.
KNOWN_VIOLATIONS: dict[str, str] = {
    ADDED_BLOCK:
        'The printer braces every sub-statement body, and a block holding one statement runs that '
        'statement: the slot admits no lexical declaration, so the block scopes nothing, and a '
        'function declaration there is defined as the braced form. The model does not declare the '
        'identification, so `canonical` counts the block as part of the program.',
    ADDED_PAREN:
        'A parenthesis is not part of the program, it is what keeps the text around it readable as '
        'one: `7 .zz` holds no bracket and prints as `(7).zz`. The model does not identify a '
        'parenthesized expression with what it holds, so `canonical` counts each one.',
}


@functools.cache
def _harvested() -> tuple[str, ...]:
    """
    Every string literal holding one of `HINTS` in the test modules of this package, deduplicated,
    leaving out docstrings, the literal parts of f-strings, and this module, whose strings are
    reasons rather than programs.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    seen: set[str] = set()
    result: list[str] = []
    for path in sorted(glob.glob(os.path.join(here, '**', 'test_*.py'), recursive=True)):
        if os.path.abspath(path) == os.path.abspath(__file__):
            continue
        with open(path, 'r', encoding='utf-8') as fd:
            tree = pyast.parse(fd.read(), filename=path)
        prose = {
            id(node.value) for node in pyast.walk(tree)
            if isinstance(node, pyast.Expr)
            and isinstance(node.value, pyast.Constant)
            and isinstance(node.value.value, str)
        }
        fragments = {
            id(part) for node in pyast.walk(tree) if isinstance(node, pyast.JoinedStr)
            for part in pyast.walk(node) if isinstance(part, pyast.Constant)
        }
        for node in pyast.walk(tree):
            if not isinstance(node, pyast.Constant) or not isinstance(node.value, str):
                continue
            if id(node) in prose or id(node) in fragments:
                continue
            text = node.value.strip('\n')
            if not text.strip() or len(text) > 4000 or text in seen:
                continue
            seen.add(text)
            if any(hint in text for hint in HINTS):
                result.append(text)
    return tuple(result)


def _differences(before: Node, after: Node) -> set[str]:
    found: set[str] = set()

    def compare(one: Node, other: Node) -> bool:
        if canonical(one) == canonical(other):
            return False
        if type(one) is not type(other):
            if isinstance(other, JsBlockStatement) and len(other.body) == 1:
                found.add(ADDED_BLOCK)
                compare(one, other.body[0])
                return True
            if isinstance(other, JsParenthesizedExpression) and other.expression is not None:
                found.add(ADDED_PAREN)
                compare(one, other.expression)
                return True
            found.add(F'{type(one).__name__} is printed as {type(other).__name__}')
            return True
        mine, theirs = one.children(), other.children()
        if len(mine) != len(theirs):
            found.add(
                F'{type(one).__name__} holds {len(mine)} children and prints with {len(theirs)}')
            return True
        differed = False
        for child, counterpart in zip(mine, theirs):
            differed = compare(child, counterpart) or differed
        if not differed:
            found.add(F'{type(one).__name__} differs in a value it holds')
        return True

    compare(before, after)
    return found


def _strip_parentheses(root: Node) -> bool:
    changed = False
    for node in list(root.walk()):
        if not isinstance(node, JsParenthesizedExpression) or node.expression is None:
            continue
        inner = node.expression
        if (field := owning_field(node)) is not None:
            holder, name = field
            set_child(holder, name, inner)
        elif (entry := owning_list(node)) is not None:
            holder, name = entry
            set_child_list(holder, name, [
                inner if item is node else item for item in getattr(holder, name)
            ])
        else:
            continue
        changed = True
    return changed


class TestJsFidelity(TestBase):

    @staticmethod
    def _parse(source: str) -> Node:
        return JsParser(source).parse()

    @staticmethod
    def _synth(tree: Node) -> str:
        return JsSynthesizer().convert(tree)

    @staticmethod
    def _spells_a_program(tree: Node) -> bool:
        return is_well_formed(tree) and not shapes_the_grammar_forbids(tree)

    def _corpus(self) -> list[str]:
        return [*SNIPPETS.values(), *_harvested()]

    def _parsed(self, source: str) -> Node | None:
        tree = self._parse(source)
        return tree if self._spells_a_program(tree) else None

    def _unbracketed(self, source: str) -> Node | None:
        tree = self._parsed(source)
        if tree is None:
            return None
        while _strip_parentheses(tree):
            pass
        return tree if self._spells_a_program(tree) else None

    def _round_trip(self, tree: Node) -> tuple[str, set[str]]:
        printed = self._synth(tree)
        return printed, _differences(tree, self._parse(printed))

    def test_the_harvest_still_finds_the_corpus(self):
        self.assertGreater(len(_harvested()), MINIMUM_HARVEST)

    def test_every_node_class_has_a_snippet(self):
        classes = {
            name: value for name, value in vars(jsmodel).items()
            if isinstance(value, type) and issubclass(value, Node) and not name.startswith('_')
        }
        refined = {base.__name__ for value in classes.values() for base in value.__mro__[1:]}
        concrete = {
            name for name, value in classes.items()
            if name not in refined and not value.unparsed
        }
        self.assertEqual(sorted(concrete - set(SNIPPETS)), [])

    def test_every_snippet_parses_to_the_node_class_it_names(self):
        for name, source in SNIPPETS.items():
            with self.subTest(node=name):
                produced = {type(node).__name__ for node in self._parse(source).walk()}
                self.assertIn(name, produced)

    def test_every_snippet_spells_a_program(self):
        skipped = [
            name for name, source in SNIPPETS.items()
            if not self._spells_a_program(self._parse(source))
        ]
        self.assertEqual(skipped, [])

    def test_the_parser_never_builds_a_shape_the_grammar_forbids(self):
        for source in self._corpus():
            with self.subTest(source=source):
                self.assertEqual(shapes_the_grammar_forbids(self._parse(source)), [])

    def test_the_synthesizer_inverts_the_parser(self):
        for source in self._corpus():
            if (tree := self._parsed(source)) is None:
                continue
            with self.subTest(source=source):
                printed, differences = self._round_trip(tree)
                self.assertEqual(
                    sorted(differences - set(KNOWN_VIOLATIONS)), [], F'printed as {printed!r}')

    def test_every_known_violation_is_produced_by_the_corpus(self):
        witnessed: set[str] = set()
        for source in self._corpus():
            if set(KNOWN_VIOLATIONS) <= witnessed:
                break
            for reading in (self._parsed(source), self._unbracketed(source)):
                if reading is not None:
                    witnessed |= self._round_trip(reading)[1]
        self.assertEqual(sorted(set(KNOWN_VIOLATIONS) - witnessed), [])

    def test_the_output_is_stable(self):
        for source in self._corpus():
            if (tree := self._parsed(source)) is None:
                continue
            with self.subTest(source=source):
                once = self._synth(tree)
                self.assertEqual(once, self._synth(self._parse(once)))

    def test_the_synthesizer_inverts_the_parser_at_every_cardinality(self):
        for name, source in SNIPPETS.items():
            for index, field, size in self._truncations(source):
                with self.subTest(node=name, field=field, size=size):
                    tree = self._truncated(source, index, field, size)
                    if not self._spells_a_program(tree):
                        continue
                    printed, differences = self._round_trip(tree)
                    self.assertEqual(
                        sorted(differences - set(KNOWN_VIOLATIONS)), [],
                        F'{field}[:{size}] printed as {printed!r}')

    def test_a_truncation_is_passed_over_only_for_a_shape_the_grammar_forbids(self):
        unspelled = [
            (name, field, size)
            for name, source in SNIPPETS.items()
            for index, field, size in self._truncations(source)
            if not is_well_formed(self._truncated(source, index, field, size))
        ]
        self.assertEqual(unspelled, [])

    def test_the_synthesizer_inverts_the_parser_without_the_original_brackets(self):
        for source in self._corpus():
            if (tree := self._unbracketed(source)) is None:
                continue
            with self.subTest(source=source):
                printed, differences = self._round_trip(tree)
                self.assertEqual(
                    sorted(differences - set(KNOWN_VIOLATIONS)), [], F'printed as {printed!r}')

    def _truncations(self, source: str):
        for index, node in enumerate(self._parse(source).walk_in_order()):
            for field, items in child_list_fields(node):
                for size in range(len(items)):
                    yield index, field, size

    def _truncated(self, source: str, index: int, field: str, size: int) -> Node:
        tree = self._parse(source)
        holder = list(tree.walk_in_order())[index]
        set_child_list(holder, field, getattr(holder, field)[:size])
        return tree


class TestJsSamenessIsBlindToHowAValueIsWritten(TestBase):

    @staticmethod
    def _parse(source: str) -> Node:
        return JsParser(source).parse()

    def test_two_spellings_of_one_value_are_one_program(self):
        for one, other in (
            ('var x = 0xFF;', 'var x = 255;'),
            ('var x = 1e3;', 'var x = 1000;'),
            ("var s = 'a';", 'var s = "a";'),
            ("var s = '\\x61';", "var s = 'a';"),
        ):
            with self.subTest(one=one, other=other):
                self.assertEqual(canonical(self._parse(one)), canonical(self._parse(other)))

    def test_two_values_are_two_programs(self):
        for one, other in (
            ('var x = 255;', 'var x = 256;'),
            ('var x = 255;', 'var x = 255n;'),
            ("var s = 'a';", "var s = 'b';"),
            ('var r = /a/g;', 'var r = /a/i;'),
        ):
            with self.subTest(one=one, other=other):
                self.assertNotEqual(canonical(self._parse(one)), canonical(self._parse(other)))
