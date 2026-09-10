"""
The order an object's own properties are visited in, and what a function that walks them folds to.

An object has one order and every walk of it reports that one: `Object.keys`, `Object.values`,
`Object.entries`, and a `for...in` loop all visit the same keys in the same sequence. The keys whose
text is a plain decimal numeral for a position an array could hold come first, in ascending numeric
order, and every other key follows in the order the object first wrote it.

Which keys those are is a question about the text of the key and not about how the file spelled it.
`0x10` written as a number is the key `16` and is one of them, and so is a key a computed slot or a
`JSON.parse` produced, while `01`, `+1`, `-1`, `1.0`, `1e2`, `'0x10'`, and a numeral with a space
beside it are ordinary names and are not. A key already present keeps the place it was first written
in, whatever a later write does to its value.

The upper end of that numeral range is the same bound the second half of this module is about. An
array is the object whose own keys are its positions, and the positions it is defined over end at
`2 ** 32 - 2`: a write above that is an ordinary key that leaves `length` where it was, and a
`length` of `2 ** 32` or more, of a negative number, or of a fraction is refused. A key just past
the end is therefore visited among the names rather than among the numerals, which is what ties the
two halves together.

A program is free to name a position four billion deep, and answering what it does must not mean
building it, so those programs are asked for two things: that an answer arrives at all within a
bound on the time, and that it is the answer Node gives.

Node is the authority for every order and every answer in this module.
"""
from __future__ import annotations

import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import (
    behavior,
    completion_values,
    deobfuscate_within,
    node_executable,
)

from refinery.units.scripting.js import js

#: A literal whose keys are plain names and numerals, mapped to the order they are visited in.
_A_NUMERAL_IS_VISITED_BEFORE_A_NAME: dict[str, str] = {
    '{ b: 1, a: 2, c: 3 }'               : 'b|a|c',
    "{ 2: 'x', 1: 'y', b: 'z', a: 'w' }" : '1|2|b|a',
    '{ 3: 1, 2: 2, 1: 3, 0: 4 }'         : '0|1|2|3',
    '{ 10: 1, 9: 2, 100: 3 }'            : '9|10|100',
    '{ b: 1, 10: 2, 9: 3, a: 4 }'        : '9|10|b|a',
    '{ a: 1, b: 2, a: 3 }'               : 'a|b',
    "{ length: 2, 0: 'a' }"              : '0|length',
    "{ '': 1, a: 2 }"                    : '|a',
}

#: A literal holding a key whose text is a numeral the file did not write out as one, mapped to the
#: order its keys are visited in. A number is spelled by the value it denotes and not by the digits
#: the file used for it, and a computed slot is spelled by the value it evaluates to.
_A_NUMERAL_THE_FILE_SPELLED_ANOTHER_WAY: dict[str, str] = {
    '{ 0x10: 1, 8: 2 }'            : '8|16',
    '{ 1_0: 1, 9: 2 }'             : '9|10',
    '{ 0.5: 1, 2: 2 }'             : '2|0.5',
    '{ 1e21: 1, 2: 2 }'            : '2|1e+21',
    '{ [-0]: 1, b: 2 }'            : '0|b',
    '{ [1 + 1]: 1, b: 2, 1: 3 }'   : '1|2|b',
    "{ ['1' + '0']: 1, 9: 2 }"     : '9|10',
    "{ ['b']: 1, ['1']: 2, a: 3 }" : '1|b|a',
}

#: A literal holding a key that reads as a number without being written as one, mapped to the order
#: its keys are visited in. None of these keys is the text a number is spelled by, so each is an
#: ordinary name that keeps the place it was written in.
_A_KEY_WHOSE_TEXT_IS_NO_NUMERAL: dict[str, str] = {
    "{ '01': 1, '1': 2 }"       : '1|01',
    "{ '00': 1, '0': 2 }"       : '0|00',
    "{ '-1': 1, '1': 2 }"       : '1|-1',
    "{ '-0': 1, '0': 2 }"       : '0|-0',
    "{ '+1': 1, '1': 2 }"       : '1|+1',
    "{ '1.0': 1, '1': 2 }"      : '1|1.0',
    "{ '0.0': 1, '0': 2 }"      : '0|0.0',
    "{ '1e2': 1, 100: 2 }"      : '100|1e2',
    "{ '0x10': 1, 16: 2 }"      : '16|0x10',
    "{ ' 1': 1, '1': 2 }"       : '1| 1',
    "{ '1 ': 1, '1': 2 }"       : '1|1 ',
    "{ 'Infinity': 1, '2': 2 }" : '2|Infinity',
    "{ 'NaN': 1, '2': 2 }"      : '2|NaN',
    "{ 'true': 1, 1: 2 }"       : '1|true',
}

_THE_TOP_OF_THE_RANGE_A_NUMERAL_IS_DRAWN_FROM: dict[str, str] = {
    "{ z: 1, '4294967293': 2 }"                           : '4294967293|z',
    "{ z: 1, '4294967294': 2 }"                           : '4294967294|z',
    "{ z: 1, '4294967295': 2 }"                           : 'z|4294967295',
    "{ z: 1, '4294967296': 2 }"                           : 'z|4294967296',
    "{ z: 1, '9007199254740992': 2 }"                     : 'z|9007199254740992',
    "{ '4294967295': 1, z: 2, '4294967294': 3 }"          : '4294967294|4294967295|z',
    "{ '4294967294': 1, '10': 2, z: 3, '4294967295': 4 }" : '10|4294967294|z|4294967295',
}
"""
A literal whose keys straddle the largest position an array can hold, mapped to the order they are
visited in. Each row writes the numeral after the name `z`, which is the only arrangement that tells
the two groups apart: a numeral that is visited early is one, and one that is left where it was
written is a name like any other. The range ends at `4294967294`, which is `2 ** 32 - 2`, and every
larger numeral is a name — including `4294967295`, which is the largest `length` an array may have
and so is one past the largest position it may hold.
"""

_EVERY_ORDER: dict[str, str] = {
    **_A_NUMERAL_IS_VISITED_BEFORE_A_NAME,
    **_A_NUMERAL_THE_FILE_SPELLED_ANOTHER_WAY,
    **_A_KEY_WHOSE_TEXT_IS_NO_NUMERAL,
    **_THE_TOP_OF_THE_RANGE_A_NUMERAL_IS_DRAWN_FROM,
}

_THE_OBJECT_EVERY_WALK_IS_ASKED_ABOUT = "{ 2: 'x', 1: 'y', b: 'z', a: 'w' }"

#: A body walking `_THE_OBJECT_EVERY_WALK_IS_ASKED_ABOUT`, mapped to what the walk finds. The object
#: is written with its two numerals out of order and after neither of its names, so a walk reporting
#: the order the keys were written would answer every row differently.
_EVERY_WALK_OF_ONE_OBJECT: dict[str, str] = {
    "return Object.keys(OBJECT).join('|');"                            : '1|2|b|a',
    "return Object.values(OBJECT).join('|');"                          : 'y|x|z|w',
    "return Object.entries(OBJECT).join('|');"                         : '1,y|2,x|b,z|a,w',
    "var r = []; for (var k in OBJECT) r.push(k); return r.join('|');" : '1|2|b|a',
}

#: A walk over an object no literal wrote whole, mapped to what the walk finds. Assignments, a
#: shorthand, and `JSON.parse` each make the same keys some other way, and a rewrite of a key that
#: is already there moves its value without moving its place.
_A_WALK_OVER_A_BUILT_OBJECT: dict[str, str] = {
    "var o = {}; o.b = 1; o.a = 2; o[3] = 3; o[2] = 4; return Object.keys(o).join('|');" : '2|3|b|a',
    "var o = {}; o['2'] = 1; o.x = 2; o['1'] = 3; return Object.keys(o).join('|');"      : '1|2|x',
    'return Object.keys(JSON.parse(\'{"b":1,"2":2,"a":3,"1":4}\')).join(\'|\');'         : '1|2|b|a',
    "var b = 1, a = 2; return Object.keys({ b, a }).join('|');"                          : 'b|a',
    "var o = { a: 1, b: 2 }; o.a = 9; return Object.keys(o).join('|');"                  : 'a|b',
    "var o = { a: 1, b: 2 }; o.a = 9; return Object.values(o).join('|');"                : '9|2',
    "return Object.keys({}).length + '|' + Object.values({}).length;"                    : '0|0',
    "var r = []; for (var k in { b: 1, 2: 2, a: 3 }) r.push(k); return r[0];"            : '2',
    "var r = []; for (var k in { 2: 1, b: 2, 1: 3 }) { r.push(k); break; } return r[0];" : '1',
}

#: A walk whose answer is recorded without asking that it be folded, mapped to what Node prints for
#: the program that makes it. Each is a way of reaching an object's own keys that the order rule has
#: to survive whether or not this tool ever computes it: a key removed and written again, an object
#: two others were merged into, an array and a string walked as objects, a key defined by an
#: accessor or a method, and a walk whose body removes a key the walk has not reached yet.
_A_WALK_ANSWERED_THE_SAME_BEFORE_AND_AFTER: dict[str, str] = {
    "var o = { b: 1 }; o.a = 2; delete o.b; o.b = 3; return Object.keys(o).join('|');"   : 'a|b',
    "return Object.keys(Object.assign({ b: 1 }, { a: 2 }, { 1: 3 })).join('|');"         : '1|b|a',
    "return Object.keys({ ...{ b: 1, 2: 2 }, ...{ a: 3, 1: 4 } }).join('|');"            : '1|2|b|a',
    "return Object.keys([7, 8, 9]).join('|');"                                           : '0|1|2',
    "return Object.keys('abc').join('|');"                                               : '0|1|2',
    "return Object.keys({ get g() { return 1; }, a: 1 }).join('|');"                     : 'g|a',
    "return Object.keys({ m() {}, a: 1 }).join('|');"                                    : 'm|a',
    "var r = []; for (var k in 'abc') r.push(k); return r.join('|');"                    : '0|1|2',
    "var o = { a: 1, b: 2 }, r = ''; for (var k in o) { delete o.b; r += k; } return r;" : 'a',
}

#: A program that names a position at or beyond the end of the space an array's positions are drawn
#: from, mapped to what Node makes of it: the standard output, and the type of an uncaught exception
#: where one ends the run. The last position is `4294967294`; a write above it is an ordinary key
#: that leaves `length` alone and is visited among the names, and a `length` that is not a whole
#: number from zero to `4294967295` is refused with a `RangeError` rather than clamped.
_THE_END_OF_THE_INDEX_SPACE: dict[str, tuple[str, str | None]] = {
    'var a = []; a[4294967293] = 1; return a.length;'                                     : ('4294967294\n', None),
    'var a = []; a[4294967294] = 1; return a.length;'                                     : ('4294967295\n', None),
    'var a = []; a[4294967295] = 1; return a.length;'                                     : ('0\n', None),
    'var a = []; a[4294967296] = 1; return a.length;'                                     : ('0\n', None),
    'var a = []; a[-1] = 1; return a.length;'                                             : ('0\n', None),
    "var a = []; a['4294967294'] = 1; return a.length;"                                   : ('4294967295\n', None),
    "var a = []; a['4294967294.0'] = 1; return a.length;"                                 : ('0\n', None),
    'var a = []; a.length = 4294967295; return a.length;'                                 : ('4294967295\n', None),
    'var a = []; a.length = 4294967296; return a.length;'                                 : ('', 'RangeError'),
    'var a = []; a.length = -1; return a.length;'                                         : ('', 'RangeError'),
    'var a = []; a.length = 1.5; return a.length;'                                        : ('', 'RangeError'),
    'return new Array(4294967295).length;'                                                : ('4294967295\n', None),
    'return new Array(4294967296).length;'                                                : ('', 'RangeError'),
    'return new Array(-1).length;'                                                        : ('', 'RangeError'),
    'return Array(4294967294).length;'                                                    : ('4294967294\n', None),
    "var a = []; a[4294967294] = 1; return Object.keys(a).join('|');"                     : ('4294967294\n', None),
    "var a = [1]; a[4294967295] = 2; a.b = 3; a[2] = 4; return Object.keys(a).join('|');" : ('0|2|4294967295|b\n', None),
    'var a = []; a.length = 4294967295; return Object.keys(a).length;'                    : ('0\n', None),
    'var a = []; a[4294967294] = 1; a.length = 0; return a.length;'                       : ('0\n', None),
    "var a = [1, 2]; a.length = 4294967295; return a.length + ':' + a[1];"                : ('4294967295:2\n', None),
}

#: How long a program of `_THE_END_OF_THE_INDEX_SPACE` may take to deobfuscate. Every one of them
#: names a position billions deep, and answering what such a program does by building the array it
#: describes costs an unbounded amount of time and memory rather than a wrong answer.
_SECONDS_A_DEOBFUSCATION_MAY_TAKE = 60.0

_DID_NOT_FINISH = ('', 'the deobfuscation did not finish')


def _walk(body: str) -> str:
    return F'function walk() {{ {body} }}\nconsole.log(walk());'


def _walked(body: str) -> str:
    return _walk(body).encode('utf8') | js() | str


def _keys_of(literal: str) -> str:
    return F"Object.keys({literal}).join('|')"


def _over(body: str) -> str:
    return body.replace('OBJECT', _THE_OBJECT_EVERY_WALK_IS_ASKED_ABOUT)


class TestTheOrderAnObjectVisitsItsOwnPropertiesIn(TestBase):

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_visits_the_keys_of_each_literal_in_the_recorded_order(self):
        self.assertEqual(
            completion_values([_keys_of(literal) for literal in _EVERY_ORDER]),
            [F'"{order}"' for order in _EVERY_ORDER.values()],
        )

    def test_each_literal_folds_to_the_order_its_keys_are_visited_in(self):
        self.assertEqual(
            {literal: _walked(F'return {_keys_of(literal)};') for literal in _EVERY_ORDER},
            {literal: F"console.log('{order}');" for literal, order in _EVERY_ORDER.items()},
        )


class TestEveryWalkOfAnObjectReportsTheOneOrder(TestBase):

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_answers_every_walk_of_the_object_with_the_recorded_text(self):
        self.assertEqual(
            {body: behavior(_walk(_over(body))) for body in _EVERY_WALK_OF_ONE_OBJECT},
            {body: (F'{found}\n', None) for body, found in _EVERY_WALK_OF_ONE_OBJECT.items()},
        )

    def test_every_walk_folds_to_what_it_finds_in_that_order(self):
        self.assertEqual(
            {body: _walked(_over(body)) for body in _EVERY_WALK_OF_ONE_OBJECT},
            {body: F"console.log('{found}');" for body, found in _EVERY_WALK_OF_ONE_OBJECT.items()},
        )


class TestWhatBuiltTheObjectDoesNotDecideTheOrder(TestBase):

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_answers_each_walk_with_the_recorded_text(self):
        rows = _A_WALK_OVER_A_BUILT_OBJECT
        self.assertEqual(
            {body: behavior(_walk(body)) for body in rows},
            {body: (F'{found}\n', None) for body, found in rows.items()},
        )

    def test_each_walk_folds_to_that_text(self):
        rows = _A_WALK_OVER_A_BUILT_OBJECT
        self.assertEqual(
            {body: _walked(body) for body in rows},
            {body: F"console.log('{found}');" for body, found in rows.items()},
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAWalkIsAnsweredTheSameWhetherOrNotItFolds(TestBase):

    def test_node_answers_each_walk_with_the_recorded_text(self):
        rows = _A_WALK_ANSWERED_THE_SAME_BEFORE_AND_AFTER
        self.assertEqual(
            {body: behavior(_walk(body)) for body in rows},
            {body: (F'{found}\n', None) for body, found in rows.items()},
        )

    def test_the_deobfuscated_program_still_answers_that_way(self):
        rows = _A_WALK_ANSWERED_THE_SAME_BEFORE_AND_AFTER
        self.assertEqual(
            {body: behavior(_walked(body)) for body in rows},
            {body: (F'{found}\n', None) for body, found in rows.items()},
        )


#: A question about a position a `delete` emptied, mapped to what Node answers it with. A removed
#: position is no longer one of the array's own keys, so the walk passes over it, the membership
#: test reports it absent, and a search does not find `undefined` there. The same four questions
#: over a position an array grew past were answered wrongly once, and are law in
#: `test.lib.scripts.js.deobfuscation.test_inherited_reads` now; these rows are the half that
#: was always right, and
#: they are what says the two ways of emptying a position are told apart at all.
_A_POSITION_A_DELETE_EMPTIED: dict[str, str] = {
    "var v = [1, 2, 3]; delete v[1]; var r = ''; for (var k in v) r += k; return r;" : '02',
    'var v = [1, 2, 3]; delete v[1]; return 1 in v;'                                 : 'false',
    "var v = [1, 2, 3]; delete v[1]; return Object.keys(v).join('|');"               : '0|2',
    'var v = [1, 2, 3]; delete v[1]; return v.indexOf(undefined);'                   : '-1',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAPositionADeleteEmptiedIsNoLongerAnOwnKey(TestBase):

    def test_node_answers_each_question_the_way_the_row_records(self):
        rows = _A_POSITION_A_DELETE_EMPTIED
        self.assertEqual(
            {body: behavior(_walk(body)) for body in rows},
            {body: (F'{found}\n', None) for body, found in rows.items()},
        )

    def test_the_deobfuscated_program_still_answers_that_way(self):
        rows = _A_POSITION_A_DELETE_EMPTIED
        self.assertEqual(
            {body: behavior(_walked(body)) for body in rows},
            {body: (F'{found}\n', None) for body, found in rows.items()},
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestTheEndOfTheSpaceAnArrayDrawsItsPositionsFrom(TestBase):

    def test_a_position_at_the_end_of_the_space_is_deobfuscated_in_bounded_time(self):
        finished = {
            body: deobfuscate_within(_walk(body), _SECONDS_A_DEOBFUSCATION_MAY_TAKE) is not None
            for body in _THE_END_OF_THE_INDEX_SPACE
        }
        self.assertEqual(finished, {body: True for body in _THE_END_OF_THE_INDEX_SPACE})

    def test_node_answers_each_program_the_way_the_row_records(self):
        self.assertEqual(
            {body: behavior(_walk(body)) for body in _THE_END_OF_THE_INDEX_SPACE},
            dict(_THE_END_OF_THE_INDEX_SPACE),
        )

    def test_the_deobfuscated_program_still_answers_that_way(self):
        answers = {}
        for body in _THE_END_OF_THE_INDEX_SPACE:
            deobfuscated = deobfuscate_within(_walk(body), _SECONDS_A_DEOBFUSCATION_MAY_TAKE)
            answers[body] = _DID_NOT_FINISH if deobfuscated is None else behavior(deobfuscated)
        self.assertEqual(answers, dict(_THE_END_OF_THE_INDEX_SPACE))
