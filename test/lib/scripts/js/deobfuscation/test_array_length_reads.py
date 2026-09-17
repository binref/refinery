"""
Reading `length` off an array written as a literal in the file.

An array's `length` is an own data property, so no prototype can shadow it and nothing but the array
itself answers the read. What it answers is the number of positions the literal was written with,
and `[1, , 3]` holds a position no element was written in yet is three long. The count is read off
the way the literal is written, which is the question `test.lib.scripts.js.test_array_holes` states
for every spelling of the commas; that corpus is imported here rather than written out a second
time. An array can also arrive as the result of a call the tool folds — `'abcdef'.split('')` — and
by then it is a literal like any other.

A spread is the one element whose contribution the file does not decide: `[...x]` is as long as
whatever `x` iterates, so a literal holding one is not as long as its commas, and Node is asked
whether what comes back still answers what the file asked.

Building an array is not free either. Only the count survives the fold, so the array and every
element in it is discarded, and a program whose element called something, updated a variable, ran a
getter, resolved a name, converted an operand, or threw has to go on doing that. What the fold asks
before counting is therefore whether every element is written as a literal or is an elision, and
that is narrower than the question of whether anything runs: `A_COUNT_THE_FOLD_DOES_NOT_REACH`
collects reads whose elements do nothing either and which are left standing all the same, and what a
fold reaching them would answer is pinned in `test.lib.scripts.js.test_unfixed_defects`.

An access is finally not always a read. Assigned, updated, deleted, or destructured, `length` names
a location rather than a value, and unlike a string's it is a location a write reaches. What the
fold would leave behind there is not a constant standing in for a target but a different answer, and
Node is asked below for both of them. Called, it names a value and the receiver that value was read
off, and the `TypeError` that follows says which access was not a function.

Node is the authority for every absolute value in this module.
"""
from __future__ import annotations

import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import behavior, code_units, node_executable
from test.lib.scripts.js.test_array_holes import SHAPES

from refinery.units.scripting.js import js

#: Each read the literal decides, mapped to the text the tool folds it to, which is also the number
#: Node answers the read with.
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

#: A name that is close to `length` without being it, mapped to the read that asks for it and to
#: the text that read is left standing as. Where the two differ the key was rewritten as a dot
#: access; the access is still there and still asks the engine, which is what answers it.
_A_NAME_THAT_IS_NOT_LENGTH: dict[str, tuple[str, str]] = {
    'len'     : ('[1, 2, 3].len', '[1, 2, 3].len'),
    'lengths' : ('[1, 2, 3].lengths', '[1, 2, 3].lengths'),
    'Length'  : ("[1, 2, 3]['Length']", '[1, 2, 3].Length'),
    'length ' : ("[1, 2, 3]['length ']", "[1, 2, 3]['length ']"),
}

#: A read over a literal holding a spread, mapped to the count Node answers it with. None of these
#: counts is the number of elements the literal is written with, which is what the fold has to
#: survive: whatever comes back for one of these, the engine still answers it the same.
_A_SPREAD_IS_NOT_ONE_ELEMENT: dict[str, str] = {
    "[...'abc'].length"           : '3',
    '[...[1, 2]].length'          : '2',
    '[...[]].length'              : '0',
    '[1, ...[2, 3], 4].length'    : '4',
    "[...'abc'.split('')].length" : '3',
}

#: A program whose array literal does something observable while it is built, paired with what Node
#: makes of it: the standard output, and the type of an uncaught exception where one ends the run.
#: Calling, updating, reading a getter, iterating, and throwing are such things; so is resolving a
#: name, which throws when no binding answers it, and so is applying an operator to an object, which
#: asks the object for a primitive and runs whatever `valueOf` the file gave it.
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

#: A position in which the access is written to rather than read from, spelled the way the
#: synthesizer spells it so that leaving it alone means handing it back verbatim.
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

#: What Node makes of each write position with the access written out, and what it makes of the same
#: program with the count in its place. Every row differs, which is why the fold may not happen: a
#: count is no target at all in nine of them, and in the tenth `delete` answers about a number what
#: it would not answer about the property.
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

#: A call whose callee is a `length` access, mapped to the text the tool leaves the call as and to
#: the message Node's `TypeError` carries. Where the standing text differs from the call, the
#: synthesizer spelled a computed key as a dot access; the access is still there and still asks the
#: engine. The message names the access that was not a function, so a callee replaced by the count
#: it reads would report about that count and say nothing about the property the file asked for.
_CALLING_WHAT_THE_COUNT_ANSWERS: dict[str, tuple[str, str]] = {
    '[1, 2, 3].length()'    : ('[1, 2, 3].length()', '[1,2,3].length is not a function'),
    "[1, 2, 3]['length']()" : ('[1, 2, 3].length()', '[1,2,3].length is not a function'),
}

_TARGET = '[1, 2, 3].length'


def _deobfuscated(source: str) -> str:
    return source.encode('utf8') | js(strict=True) | str


def _fold(expression: str) -> str:
    """
    The expression `refinery.js` folds *expression* to. It is placed in a `console.log` argument,
    which survives as a side effect, so nothing but the fold decides what comes back.
    """
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

    def test_a_name_that_is_only_close_to_length_is_left_standing(self):
        for name, (read, standing) in _A_NAME_THAT_IS_NOT_LENGTH.items():
            with self.subTest(name=name):
                self.assertEqual(_fold(read), standing)


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
        """
        One text, three counts: `[...x].length` is 3, 1, and 1 for a three-character string, a
        one-element array, and a two-element set holding one distinct value. The deobfuscation is
        asked for all three, because a program that answers them from the one comma its literal is
        written with answers two of them wrongly.
        """
        source = (
            'function n(x) { return [...x].length; }\n'
            "console.log(n('abc'), n([1]), n(new Set([1, 1])));"
        )
        self.assertEqual(
            (behavior(source), behavior(_deobfuscated(source))),
            (('3 1 1\n', None), ('3 1 1\n', None)),
        )

    def test_a_name_that_is_not_length_is_answered_by_whatever_the_prototype_carries(self):
        for name, (read, _) in _A_NAME_THAT_IS_NOT_LENGTH.items():
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

    def test_a_write_target_survives_deobfuscation_verbatim(self):
        for position, template in _WRITE_POSITIONS.items():
            source = _in_position(template, _TARGET)
            with self.subTest(position=position):
                self.assertEqual(_deobfuscated(source), source)

    def test_a_read_inside_a_write_target_is_folded(self):
        self.assertEqual(
            _deobfuscated('console.log([1, 2, 3].length.x = 5);'),
            'console.log((3).x = 5);',
        )


class TestACalleeIsReadForItsReceiverToo(TestBase):

    def test_a_callee_survives_deobfuscation_as_an_access(self):
        for call, (standing, _) in _CALLING_WHAT_THE_COUNT_ANSWERS.items():
            with self.subTest(call=call):
                self.assertEqual(_fold(call), standing)

    def test_a_read_inside_a_callee_is_folded(self):
        self.assertEqual(_fold('[1, 2, 3].length.toFixed()'), '(3).toFixed()')

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
