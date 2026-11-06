from __future__ import annotations

import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import behavior, code_units, node_executable
from test.lib.scripts.js.test_array_holes import SHAPES

from refinery.units.scripting.djs import djs

_DECIDED: dict[str, str] = {
    "[1, 2, 3]['length']"              : '3',
    "[1, 2, 3]['leng' + 'th']"         : '3',
    '([1, 2, 3]).length'               : '3',
    '[1, 2, 3]?.length'                : '3',
    "'abcdef'.split('').length"        : '6',
    "'a-b-c'.split('-').length"        : '3',
    'Object.keys({a: 1, b: 2}).length' : '2',
    '[1, 2, 3].slice(0, 2).length'     : '2',
}

A_COUNT_THE_FOLD_DOES_NOT_REACH: dict[str, str] = {
    '[Math, Date, JSON].length'        : '3',
    '[function () {}, {}].length'      : '2',
    '[{get x() { return 1; }}].length' : '1',
    '[[1, 2], [3]].length'             : '2',
}
"""
A read the literal decides that the fold declines, mapped to the count Node answers it with. Nothing
in any of these elements runs while the array is built — a global value name, a function expression,
an object or an array literal, and a getter that is defined rather than called — so each count is
the number of commas and each read could be replaced by it. No element of any of them is written as
a literal, which is what the fold asks for, so every read is left standing.
`test.lib.scripts.js.test_unfixed_defects` pins what a fold that reached them would answer, and a
row rejoins `_DECIDED` the day it does.
"""

_A_NAME_THAT_IS_NOT_LENGTH: dict[str, str] = {
    'len'     : '[1, 2, 3].len',
    'lengths' : '[1, 2, 3].lengths',
    'Length'  : "[1, 2, 3]['Length']",
    'length ' : "[1, 2, 3]['length ']",
}

_A_SPREAD_IS_NOT_ONE_ELEMENT: dict[str, str] = {
    "[...'abc'].length"           : '3',
    '[...[1, 2]].length'          : '2',
    '[...[]].length'              : '0',
    '[1, ...[2, 3], 4].length'    : '4',
    "[...'abc'.split('')].length" : '3',
}

_BUILDING_THE_ARRAY_DOES_SOMETHING: tuple[tuple[str, tuple[str, str | None]], ...] = (
    (
        "function f() { console.log('ran'); return 1; } console.log([f()].length);",
        ('ran\n1\n', None),
    ),
    (
        'var x = 1; console.log([x++].length, x);',
        ('1 2\n', None),
    ),
    (
        "var o = {get p() { console.log('read'); return 1; }}; console.log([o.p].length);",
        ('read\n1\n', None),
    ),
    (
        "var it = {[Symbol.iterator]: function* () { console.log('iterated'); yield 1; }};"
        ' console.log([[...it]].length);',
        ('iterated\n1\n', None),
    ),
    (
        "console.log([console.log('inside')].length);",
        ('inside\n1\n', None),
    ),
    (
        "function C() { console.log('ctor'); } console.log([new C()].length);",
        ('ctor\n1\n', None),
    ),
    (
        "console.log([decodeURIComponent('%')].length);",
        ('', 'URIError'),
    ),
    (
        "console.log([JSON.parse('{')].length);",
        ('', 'SyntaxError'),
    ),
    (
        'console.log([null.x].length);',
        ('', 'TypeError'),
    ),
    (
        "console.log(['abc'.repeat(-1)].length);",
        ('', 'RangeError'),
    ),
    (
        'console.log([zzz].length);',
        ('', 'ReferenceError'),
    ),
    (
        'console.log([1, zzz, 3].length);',
        ('', 'ReferenceError'),
    ),
    (
        'console.log([q].length); let q = 1;',
        ('', 'ReferenceError'),
    ),
    (
        "try { console.log([zzz].length); } catch (e) { console.log('caught'); }",
        ('caught\n', None),
    ),
    (
        "var o = { valueOf() { console.log('vo'); return 1; } }; console.log([+o].length);",
        ('vo\n1\n', None),
    ),
)

#: Positions in which the access is written to rather than read. Each is spelled exactly as the tool
#: prints it, so that a target the tool leaves alone comes back verbatim.
_WRITE_POSITIONS: dict[str, str] = {
    'assignment'          : 'console.log(TARGET = 9);',
    'compound assignment' : 'console.log(TARGET += 5);',
    'postfix increment'   : 'console.log(TARGET++);',
    'prefix decrement'    : 'console.log(--TARGET);',
    'delete'              : 'console.log(delete TARGET);',
    'strict delete'       : "'use strict';\nconsole.log(delete TARGET);",
    'array pattern'       : 'console.log([TARGET] = [9]);',
    'object pattern'      : 'console.log({ p: TARGET } = { p: 9 });',
    'for-of head'         : 'for (TARGET of [9]) {}\nconsole.log(1);',
    'for-in head'         : 'for (TARGET in { a: 1 }) {}\nconsole.log(1);',
}

_WRITE_POSITIONS_EVALUATED: dict[str, str] = {
    'assignment'          : 'console.log(9);',
    'compound assignment' : 'console.log(8);',
    'postfix increment'   : 'console.log(3);',
    'prefix decrement'    : 'console.log(2);',
    'delete'              : 'console.log(false);',
    'array pattern'       : 'console.log([9]);',
    'object pattern'      : 'console.log({ p: 9 });',
    'for-of head'         : 'console.log(1);',
}

_WRITE_POSITION_ANSWERS: dict[str, tuple[tuple[str, str | None], tuple[str, str | None]]] = {
    'assignment'          : (('9\n', None), ('', 'SyntaxError')),
    'compound assignment' : (('8\n', None), ('', 'SyntaxError')),
    'postfix increment'   : (('3\n', None), ('', 'SyntaxError')),
    'prefix decrement'    : (('2\n', None), ('', 'SyntaxError')),
    'delete'              : (('false\n', None), ('true\n', None)),
    'strict delete'       : (('', 'TypeError'), ('true\n', None)),
    'array pattern'       : (('[ 9 ]\n', None), ('', 'SyntaxError')),
    'object pattern'      : (('{ p: 9 }\n', None), ('', 'SyntaxError')),
    'for-of head'         : (('1\n', None), ('', 'SyntaxError')),
    'for-in head'         : (('', 'RangeError'), ('', 'SyntaxError')),
}

_CALLING_WHAT_THE_COUNT_ANSWERS: dict[str, tuple[str, str]] = {
    '[1, 2, 3].length()'    : ('[1, 2, 3].length()', '[1,2,3].length is not a function'),
    "[1, 2, 3]['length']()" : ('[1, 2, 3].length()', '[1,2,3].length is not a function'),
}

_TARGET = '[1, 2, 3].length'


def _deobfuscated(source: str) -> str:
    return source.encode('utf8') | djs(strict=True) | str


def _fold(expression: str) -> str:
    printed = _deobfuscated(F'console.log({expression});')
    return printed.removeprefix('console.log(').removesuffix(');')


def _in_position(template: str, target: str) -> str:
    return template.replace('TARGET', target)


class TestTheCommasDecideHowLongTheLiteralIs(TestBase):

    def test_every_spelling_of_the_commas_folds_to_the_length_it_spells(self):
        for shape in SHAPES:
            with self.subTest(literal=shape.literal):
                self.assertEqual(_fold(F'{shape.literal}.length'), str(shape.length))

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_reads_the_folded_count_from_the_literal_it_replaced(self):
        reads = [F'{shape.literal}.length' for shape in SHAPES]
        expected = [str(shape.length) for shape in SHAPES]
        self.assertEqual(
            (code_units(reads), code_units([_fold(read) for read in reads])),
            (expected, expected),
        )


class TestALengthReadTheLiteralDecides(TestBase):

    def test_each_read_folds_to_the_count_the_literal_was_written_with(self):
        for expression, folded in _DECIDED.items():
            with self.subTest(expression=expression):
                self.assertEqual(_fold(expression), folded)

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_answers_each_read_with_the_number_it_was_folded_to(self):
        self.assertEqual(code_units(list(_DECIDED)), list(_DECIDED.values()))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestACountTheFoldDoesNotReach(TestBase):

    def test_node_answers_each_read_with_the_count_the_commas_spell(self):
        counts = A_COUNT_THE_FOLD_DOES_NOT_REACH
        self.assertEqual(code_units(list(counts)), list(counts.values()))


class TestAKeyThatIsNotLength(TestBase):

    def test_a_name_that_is_only_close_to_length_folds_to_undefined(self):
        for name, read in _A_NAME_THAT_IS_NOT_LENGTH.items():
            with self.subTest(name=name):
                self.assertEqual(_fold(read), 'void 0')

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_reads_undefined_for_each_of_them(self):
        reads = list(_A_NAME_THAT_IS_NOT_LENGTH.values())
        self.assertEqual(code_units(reads), ['undefined'] * len(reads))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestWhatTheLiteralCannotDecideIsLeftToTheEngine(TestBase):

    def test_node_answers_a_spread_read_the_same_before_and_after(self):
        expressions = list(_A_SPREAD_IS_NOT_ONE_ELEMENT)
        expected = list(_A_SPREAD_IS_NOT_ONE_ELEMENT.values())
        self.assertEqual(
            (
                code_units(expressions),
                code_units([_fold(expression) for expression in expressions]),
            ),
            (expected, expected),
        )

    def test_a_spread_is_as_long_as_the_value_it_spreads_iterates(self):
        source = (
            'function n(x) { return [...x].length; }\n'
            "console.log(n('abc'), n([1]), n(new Set([1, 1])));"
        )
        self.assertEqual(
            (behavior(source), behavior(_deobfuscated(source))),
            (('3 1 1\n', None), ('3 1 1\n', None)),
        )

    def test_a_name_that_is_not_length_is_answered_by_whatever_the_prototype_carries(self):
        for name, read in _A_NAME_THAT_IS_NOT_LENGTH.items():
            source = F"Array.prototype['{name}'] = 99; console.log({read});"
            with self.subTest(name=name):
                self.assertEqual(
                    (behavior(source), behavior(_deobfuscated(source))),
                    (('99\n', None), ('99\n', None)),
                )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNoPrototypeCanShadowTheLengthAnArrayOwns(TestBase):

    def test_a_length_on_the_prototype_does_not_reach_an_array_that_has_its_own(self):
        source = 'Array.prototype.length = 99; console.log([1, 2, 3].length);'
        self.assertEqual(
            (behavior(source), behavior(_deobfuscated(source))),
            (('3\n', None), ('3\n', None)),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestCountingALiteralDoesNotDiscardWhatBuildingItDoes(TestBase):

    def test_node_answers_the_program_the_way_the_row_records(self):
        for source, answer in _BUILDING_THE_ARRAY_DOES_SOMETHING:
            with self.subTest(source=source):
                self.assertEqual(behavior(source), answer)

    def test_the_deobfuscated_program_still_answers_that_way(self):
        for source, answer in _BUILDING_THE_ARRAY_DOES_SOMETHING:
            deobfuscated = _deobfuscated(source)
            with self.subTest(source=source):
                self.assertEqual(
                    behavior(deobfuscated),
                    answer,
                    F'deobfuscation changed observable behavior; result was:\n{deobfuscated}',
                )


class TestALengthAccessThatIsNotARead(TestBase):

    def test_a_write_target_survives_deobfuscation_verbatim_or_evaluated(self):
        for position, template in _WRITE_POSITIONS.items():
            source = _in_position(template, _TARGET)
            evaluated = _WRITE_POSITIONS_EVALUATED.get(position, source)
            with self.subTest(position=position):
                self.assertIn(_deobfuscated(source), (source, evaluated))

    def test_a_read_inside_a_write_target_is_folded(self):
        self.assertIn(
            _deobfuscated('console.log([1, 2, 3].length.x = 5);'),
            ('console.log((3).x = 5);', 'console.log(5);'),
        )


class TestACalleeIsReadForItsReceiverToo(TestBase):

    def test_a_callee_survives_deobfuscation_as_an_access(self):
        for call, (standing, _) in _CALLING_WHAT_THE_COUNT_ANSWERS.items():
            with self.subTest(call=call):
                self.assertEqual(_fold(call), standing)

    def test_a_read_inside_a_callee_is_folded(self):
        self.assertIn(_fold('[1, 2, 3].length.toFixed()'), ('(3).toFixed()', "'3'"))

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_the_type_error_a_called_count_throws_names_the_access(self):
        for call, (_, message) in _CALLING_WHAT_THE_COUNT_ANSWERS.items():
            source = F'try {{ {call}; }} catch (e) {{ console.log(e.message); }}'
            said = (F'{message}\n', None)
            with self.subTest(call=call):
                self.assertEqual((behavior(source), behavior(_deobfuscated(source))), (said, said))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNodeDecidesWhatAWritePositionMayNotBecome(TestBase):

    def test_the_count_in_place_of_the_target_answers_differently_in_every_position(self):
        for position, answers in _WRITE_POSITION_ANSWERS.items():
            template = _WRITE_POSITIONS[position]
            with self.subTest(position=position):
                self.assertEqual(
                    (
                        behavior(_in_position(template, _TARGET)),
                        behavior(_in_position(template, '3')),
                    ),
                    answers,
                )

    def test_a_read_inside_a_write_target_keeps_what_the_program_did(self):
        source = 'console.log([1, 2, 3].length.x = 5);'
        self.assertEqual(
            (behavior(source), behavior(_deobfuscated(source))),
            (('5\n', None), ('5\n', None)),
        )
