"""
An array literal or array pattern has as many positions as it has commas, plus one if an element
stands right before `]`: `[1, 2, ]` has two and `[1, 2, ,]` has three. A hole at the end is spelled
by a comma of its own, which the printer has to keep.

SECURITY: the only text handed to the engine is an array literal of number literals, hand-authored
here. Nothing from `samples` may ever be fed to this.
"""
from __future__ import annotations

import json
import unittest

from typing import NamedTuple

from test import TestBase
from test.lib.scripts.js.analysis.differential import behavior, node_executable

from refinery.lib.scripts.js.model import JsArrayExpression, JsArrayPattern
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer


class Shape(NamedTuple):
    literal: str
    pattern: str
    length: int
    holes: tuple[int, ...]
    printed_literal: str
    printed_pattern: str


SHAPES = (
    Shape('[]', '[]', 0, (), '[]', '[]'),
    Shape('[1, 2, 3]', '[a, b, c]', 3, (), '[1, 2, 3]', '[a, b, c]'),
    Shape('[, 1]', '[, a]', 2, (0,), '[, 1]', '[, a]'),
    Shape('[, , 1]', '[, , a]', 3, (0, 1), '[, , 1]', '[, , a]'),
    Shape('[1, , 2]', '[a, , b]', 3, (1,), '[1, , 2]', '[a, , b]'),
    Shape('[1, , , 2]', '[a, , , b]', 4, (1, 2), '[1, , , 2]', '[a, , , b]'),
    Shape('[1, 2, ,]', '[a, b, ,]', 3, (2,), '[1, 2, ,]', '[a, b, ,]'),
    Shape('[1, 2, ]', '[a, b, ]', 2, (), '[1, 2]', '[a, b]'),
    Shape('[,]', '[,]', 1, (0,), '[,]', '[,]'),
    Shape('[,,,]', '[,,,]', 3, (0, 1, 2), '[, , ,]', '[, , ,]'),
    Shape('[1, , ]', '[a, , ]', 2, (1,), '[1, ,]', '[a, ,]'),
    Shape('[, 1, ,]', '[, a, ,]', 3, (0, 2), '[, 1, ,]', '[, a, ,]'),
)


class Written(NamedTuple):
    source: str
    printed: str
    length: int
    holes: tuple[int, ...]


LITERALS = tuple(
    Written(
        F'x = {shape.literal};',
        F'x = {shape.printed_literal};',
        shape.length,
        shape.holes,
    )
    for shape in SHAPES
)

PATTERNS = tuple(
    Written(
        F'{keyword}{shape.pattern} = source;',
        F'{keyword}{shape.printed_pattern} = source;',
        shape.length,
        shape.holes,
    )
    for shape in SHAPES
    for keyword in ('', 'var ', 'let ')
)


def _bracketed_list(source: str) -> JsArrayExpression | JsArrayPattern:
    return [
        node for node in JsParser(source).parse().walk_in_order()
        if isinstance(node, (JsArrayExpression, JsArrayPattern))
    ][0]


def _holes(source: str) -> tuple[int, ...]:
    return tuple(
        index for index, element in enumerate(_bracketed_list(source).elements) if element is None
    )


def _printed(source: str) -> str:
    return JsSynthesizer().convert(JsParser(source).parse())


def _lengths_according_to_node(literals: tuple[str, ...]) -> list[int]:
    reads = ', '.join(F'{literal}.length' for literal in literals)
    out, error = behavior(F'console.log(JSON.stringify([{reads}]));\n')
    if error is not None:
        raise RuntimeError(F'node refused to measure the corpus: {error}')
    return json.loads(out)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNodeIsTheAuthorityOnHowLongAnArrayIs(TestBase):

    def test_every_recorded_length_is_the_length_node_reports(self):
        self.assertEqual(
            _lengths_according_to_node(tuple(shape.literal for shape in SHAPES)),
            [shape.length for shape in SHAPES],
        )

    def test_printing_an_array_literal_leaves_the_length_node_reports_unchanged(self):
        self.assertEqual(
            _lengths_according_to_node(tuple(shape.printed_literal for shape in SHAPES)),
            [shape.length for shape in SHAPES],
        )


class TestAnArrayLiteralIsAsLongAsItsCommasSpell(TestBase):

    def test_the_parse_holds_one_element_for_every_position_the_commas_spell(self):
        for row in LITERALS:
            with self.subTest(source=row.source):
                array = _bracketed_list(row.source)
                self.assertEqual(
                    (type(array), len(array.elements)), (JsArrayExpression, row.length)
                )

    def test_the_parse_leaves_a_hole_where_no_element_was_written(self):
        for row in LITERALS:
            with self.subTest(source=row.source):
                self.assertEqual(_holes(row.source), row.holes)

    def test_the_printer_gives_a_hole_at_the_end_a_comma_of_its_own(self):
        for row in LITERALS:
            with self.subTest(source=row.source):
                self.assertEqual(_printed(row.source), row.printed)

    def test_parsing_the_print_gives_an_array_of_the_same_length_and_the_same_holes(self):
        for row in LITERALS:
            with self.subTest(source=row.source):
                printed = _printed(row.source)
                self.assertEqual(
                    (len(_bracketed_list(printed).elements), _holes(printed)),
                    (row.length, row.holes),
                )


class TestAPatternPullsOneValueForEveryPositionItsCommasSpell(TestBase):

    def test_the_parse_holds_one_element_for_every_position_the_commas_spell(self):
        for row in PATTERNS:
            with self.subTest(source=row.source):
                pattern = _bracketed_list(row.source)
                self.assertEqual(
                    (type(pattern), len(pattern.elements)), (JsArrayPattern, row.length)
                )

    def test_the_parse_leaves_a_hole_where_a_value_is_pulled_out_and_bound_to_nothing(self):
        for row in PATTERNS:
            with self.subTest(source=row.source):
                self.assertEqual(_holes(row.source), row.holes)

    def test_the_printer_gives_a_hole_at_the_end_a_comma_of_its_own(self):
        for row in PATTERNS:
            with self.subTest(source=row.source):
                self.assertEqual(_printed(row.source), row.printed)

    def test_parsing_the_print_gives_a_pattern_of_the_same_length_and_the_same_holes(self):
        for row in PATTERNS:
            with self.subTest(source=row.source):
                printed = _printed(row.source)
                self.assertEqual(
                    (len(_bracketed_list(printed).elements), _holes(printed)),
                    (row.length, row.holes),
                )
