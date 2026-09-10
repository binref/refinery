"""
What a receiver answers for itself, and what belongs to the prototype chain behind it.

A string and an array own the slots `0` through their length less one, an object owns the keys
written into it, and that is the whole of what a receiver decides. Every other name — a method, an
index above the length, a key nobody wrote — is answered by walking the chain, so what the program
did to `String.prototype`, `Array.prototype` or the `Object.prototype` below them decides it. A fold
that answers such a read off the receiver alone hands back a value the engine never produces, and
where the chain holds an accessor it also drops code that was supposed to run.

A position no element was ever written in is the second half of the same fact. An elision, a store
past the end and a `length` moved up all leave the array reaching further than the slots it holds,
and such a position is not one the receiver answers for: `1 in [1, , 3]` is `false` where
`1 in [1, undefined, 3]` is `true`, and `indexOf`, `filter` and a `for...in` walk all pass it by.
That is the one thing a program can say to tell a hole from an element, so a representation holding
the two alike answers every one of those questions for the wrong array.

These were pinned as release blockers and are kept as the regression they retired into. Answering
such a read from the chain rather than from the receiver has a price, since a program the tool
cannot read to the end is a program that may have written the chain, and the last class here pins
what that costs.

SECURITY: every program here is written out by the module itself and Node runs only those. Nothing
from `samples` may ever be handed to the engine.
"""
from __future__ import annotations

import inspect
import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import node_executable
from test.lib.scripts.js.ledger import (
    a_walk_of,
    an_accessor_at,
    before_and_after,
    each_program_still_prints,
    evaluated_in_a_body,
    folded,
    returned_from_a_body,
)


#: A program that installs a property at an index no receiver of the length written holds, and reads
#: that index, mapped to what Node prints for it. A string and an array own the slots `0` through
#: their length less one and nothing above, so every one of these reads is the chain's to answer.
A_READ_OF_AN_INDEX_THE_RECEIVER_DOES_NOT_HOLD = {
    evaluated_in_a_body("'abc'", 'v[5]', "String.prototype[5] = 'X';"): 'X\n',
    evaluated_in_a_body("''", 'v[0]', "String.prototype[0] = 'X';"): 'X\n',
    evaluated_in_a_body("atob('YWJj')", 'v[5]', "String.prototype[5] = 'X';"): 'X\n',
    evaluated_in_a_body('[1, 2]', 'v[5]', "Array.prototype[5] = 'X';"): 'X\n',
    evaluated_in_a_body('[1, 2]', 'v[5]', "Object.prototype[5] = 'X';"): 'X\n',
    evaluated_in_a_body('[1, 2]', 'v[5]', an_accessor_at('Array.prototype', '5')): 'G\n',
    evaluated_in_a_body("'abc'", 'v[5]', an_accessor_at('String.prototype', '5')): 'G\n',
}


#: A program that installs a property at an index no array of the length written holds, and asks
#: whether that index is `in` the array, mapped to what Node prints for it.
A_MEMBERSHIP_TEST_OVER_AN_INDEX_THE_ARRAY_DOES_NOT_HOLD = {
    evaluated_in_a_body('[1, 2]', '5 in v', "Array.prototype[5] = 'X';"): 'true\n',
    evaluated_in_a_body('[1, 2]', "'5' in v", "Array.prototype[5] = 'X';"): 'true\n',
    evaluated_in_a_body('[1, 2]', '5 in v', "Object.prototype[5] = 'X';"): 'true\n',
    evaluated_in_a_body(
        '[1, 2]',
        '5 in v',
        "Object.defineProperty(Array.prototype, '5', {value: 'Q'});",
    ): 'true\n',
}


#: A program that writes one name onto a prototype in the receiver's chain and then asks whether a
#: different name is `in` the receiver, mapped to what Node prints for it. Nothing here installs the
#: name being asked about, so each answer is the one an engine nothing has touched would give.
A_MEMBERSHIP_TEST_FOR_A_KEY_NOBODY_INSTALLED = {
    evaluated_in_a_body('{a: 1}', "'zz' in v", "Object.prototype.qq = 'X';"): 'false\n',
    evaluated_in_a_body('[1, 2]', "'zz' in v", "Object.prototype.qq = 'X';"): 'false\n',
    evaluated_in_a_body('[1, 2]', "'zz' in v", "Array.prototype.qq = 'X';"): 'false\n',
    evaluated_in_a_body(
        '{a: 1}',
        "'zz' in v",
        an_accessor_at('Object.prototype', 'qq'),
    ): 'false\n',
}


#: A program that writes one name onto `Object.prototype` and then asks whether a different name is
#: `in` a receiver that holds nothing beyond what its own declaration writes, mapped to what Node
#: prints for it. A plain function, an empty class and an empty object literal each carry no `zz` of
#: their own, so each of these questions is one the written chain decides.
A_MEMBERSHIP_TEST_OVER_A_RECEIVER_WHOSE_CHAIN_THE_PROGRAM_WROTE = {
    evaluated_in_a_body('g', "'zz' in v", "Object.prototype.qq = 'X'; function g() {}"): 'false\n',
    evaluated_in_a_body('C', "'zz' in v", "Object.prototype.qq = 'X'; class C {}"): 'false\n',
    evaluated_in_a_body('{}', "'zz' in v", "Object.prototype.qq = 'X';"): 'false\n',
}


#: The same three receivers asked the same question in programs that write no prototype at all,
#: mapped to what Node prints for them.
THE_SAME_MEMBERSHIP_TESTS_OVER_A_CHAIN_NOBODY_WROTE = {
    evaluated_in_a_body('g', "'zz' in v", 'function g() {}'): 'false\n',
    evaluated_in_a_body('C', "'zz' in v", 'class C {}'): 'false\n',
    evaluated_in_a_body('{}', "'zz' in v"): 'false\n',
}


#: The same three receivers asked about the one key the program did put on their chain, mapped to
#: what Node prints for it. None of the three carries `qq` itself and all three inherit it.
A_MEMBERSHIP_TEST_FOR_THE_KEY_THE_PROGRAM_PUT_ON_THE_CHAIN = {
    evaluated_in_a_body('g', "'qq' in v", "Object.prototype.qq = 'X'; function g() {}"): 'true\n',
    evaluated_in_a_body('C', "'qq' in v", "Object.prototype.qq = 'X'; class C {}"): 'true\n',
    evaluated_in_a_body('{}', "'qq' in v", "Object.prototype.qq = 'X';"): 'true\n',
}


#: A program that installs a property at the index an elision left empty, and reads it, mapped to
#: what Node prints for it. Each receiver is written with a length the elision counts towards and
#: with no element at that index, so the read finds nothing on the array and walks the chain.
A_READ_OF_A_SLOT_AN_ELISION_LEFT_EMPTY = {
    evaluated_in_a_body('[1, , 3]', 'v[1]', "Array.prototype[1] = 'X';"): 'X\n',
    evaluated_in_a_body('[, 2]', 'v[0]', "Array.prototype[0] = 'X';"): 'X\n',
    evaluated_in_a_body('[1, ,]', 'v[1]', "Array.prototype[1] = 'X';"): 'X\n',
    evaluated_in_a_body('[1, , 3]', 'v[1]', "Object.prototype[1] = 'X';"): 'X\n',
    evaluated_in_a_body(
        '[0, 1, 2, 3, 4, , 6]',
        'v[5]',
        an_accessor_at('Array.prototype', '5'),
    ): 'G\n',
}


#: An array literal written with an elision, and a membership test over the index it left empty,
#: mapped to what Node prints for it in an engine nothing has touched. No prototype is written by
#: any of these: the slot is simply not in the array, which is the whole of what an elision is.
A_MEMBERSHIP_TEST_OVER_A_SLOT_AN_ELISION_LEFT_EMPTY = {
    evaluated_in_a_body('[1, , 3]', '1 in v'): 'false\n',
    evaluated_in_a_body('[, 2]', '0 in v'): 'false\n',
    evaluated_in_a_body('[1, ,]', '1 in v'): 'false\n',
}


#: A program that installs a property on `Object.prototype` and reads it off a variable holding an
#: object literal that does not write it, mapped to what Node prints for it. `Object.prototype`
#: roots the chain of every object, so a key the literal lacks is always the chain's to answer.
A_READ_OF_A_KEY_AN_OBJECT_LITERAL_LACKS = {
    evaluated_in_a_body('{a: 1}', 'v.zz', "Object.prototype.zz = 'X';"): 'X\n',
    evaluated_in_a_body('{a: 1}', "v['zz']", "Object.prototype.zz = 'X';"): 'X\n',
    evaluated_in_a_body('{a: 1}', 'v.length', 'Object.prototype.length = 9;'): '9\n',
    evaluated_in_a_body('{a: 1}', 'v.zz', an_accessor_at('Object.prototype', 'zz')): 'G\n',
}


#: A `for...in` walk over an array holding a position no element was written in, mapped to what Node
#: prints for it. The walk reports the array's own keys, and such a position is not one of them
#: however it came about: written as an elision, passed over by a write beyond the end, or passed
#: over by moving `length` up.
A_FOR_IN_WALK_OVER_AN_ARRAY_HOLDING_A_HOLE = {
    returned_from_a_body(
        "var v = [1, , 3]; var r = ''; for (var k in v) r += k; return r;"
    ): '02\n',
    returned_from_a_body(
        "var v = [1]; v[2] = 3; var r = ''; for (var k in v) r += k; return r;"
    ): '02\n',
    returned_from_a_body(
        "var v = [1]; v.length = 3; var r = ''; for (var k in v) r += k; return r;"
    ): '0\n',
}


#: A membership test over a position an array grew past without writing anything in it, mapped to
#: what Node prints for it. Growth moves how far the array reaches and never says that every
#: position below that was filled.
A_MEMBERSHIP_TEST_OVER_A_SLOT_GROWTH_PASSED_OVER = {
    returned_from_a_body('var v = [1]; v.length = 3; return 1 in v;'): 'false\n',
    returned_from_a_body('var v = [1]; v[2] = 3; return 1 in v;'): 'false\n',
}


#: A search of a grown array for the value a position it passed over would hold if it held one,
#: mapped to what Node prints for it. `indexOf` skips a position the array does not hold, so it
#: reports `-1` where the same search over `[1, undefined, 3]` reports `1`.
A_SEARCH_FOR_UNDEFINED_IN_A_SLOT_GROWTH_PASSED_OVER = {
    returned_from_a_body('var v = [1]; v.length = 3; return v.indexOf(undefined);'): '-1\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnIndexTheReceiverDoesNotHoldIsTheChainsToAnswer(TestBase):
    """
    A string and an array own the slots `0` through their length less one and no others, so an index
    above that is a name the receiver does not carry, no different in that from `zz`: the prototype
    chain answers it, and a program is free to put something there before the read runs.

    The `in` operator asks the same question of the same receiver and has to be answered the same
    way, since comparing the index against the length reports an index the chain holds to be absent.
    """

    def test_a_read_of_an_index_past_the_end_finds_what_the_chain_holds(self):
        """
        Node prints `X` for the five programs of
        `A_READ_OF_AN_INDEX_THE_RECEIVER_DOES_NOT_HOLD` that store a value on a prototype and `G`
        for the two that install an accessor there, the receiver being a string literal, the empty
        string, a string a call produced, or an array literal, and the prototype written being the
        one that owns the receiver's methods or the `Object.prototype` that roots every chain.
        """
        rows = A_READ_OF_AN_INDEX_THE_RECEIVER_DOES_NOT_HOLD
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_membership_of_an_index_past_the_end_finds_what_the_chain_holds(self):
        """
        Node prints `true` for all four programs of
        `A_MEMBERSHIP_TEST_OVER_AN_INDEX_THE_ARRAY_DOES_NOT_HOLD`: `in` asks whether a property is
        reachable at all, which the whole chain answers and not the receiver's own slots.
        """
        rows = A_MEMBERSHIP_TEST_OVER_AN_INDEX_THE_ARRAY_DOES_NOT_HOLD
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnUnansweredMembershipTestIsNotAYes(TestBase):
    """
    `in` reports whether a property is reachable on the receiver or anywhere up its prototype chain.
    Once a program has written to that chain, what it put there is not a thing this tool can
    enumerate, so no name can be shown to be missing any more and the question is left for the
    engine, which is the right answer to one that cannot be answered.

    Taking a failure to prove the key absent for a proof that the key is there would answer `true`
    for every name at once — including all the names the program never installed, which are the
    very names the engine answers `false` for. A single write to one prototype in a receiver's
    chain, under any name at all, would be enough to turn every such test into a `true`.
    """

    def test_a_key_nobody_installed_is_in_nothing(self):
        """
        Node prints `false` for all four programs of
        `A_MEMBERSHIP_TEST_FOR_A_KEY_NOBODY_INSTALLED`: each writes the one name `qq` onto a
        prototype the receiver inherits from and then asks about `zz`, which nothing in the program
        ever defines.
        """
        rows = A_MEMBERSHIP_TEST_FOR_A_KEY_NOBODY_INSTALLED
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_key_nobody_installed_is_in_no_function_class_or_object(self):
        """
        Node prints `false` for all three programs of
        `A_MEMBERSHIP_TEST_OVER_A_RECEIVER_WHOSE_CHAIN_THE_PROGRAM_WROTE`, whose receivers are a
        plain function declaration, an empty class declaration and an empty object literal: the one
        name the program put on `Object.prototype` is `qq`, and `zz` is nowhere in the program.
        """
        rows = A_MEMBERSHIP_TEST_OVER_A_RECEIVER_WHOSE_CHAIN_THE_PROGRAM_WROTE
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_the_same_three_receivers_answer_the_same_way_with_no_prototype_written(self):
        """
        The control for the test above: `THE_SAME_MEMBERSHIP_TESTS_OVER_A_CHAIN_NOBODY_WROTE` asks
        the same three receivers the same question in programs that write no prototype, and Node
        prints `false` for those too. The write is therefore not what makes the answer `false`; it
        only takes away the grounds the tool had for saying so.
        """
        rows = THE_SAME_MEMBERSHIP_TESTS_OVER_A_CHAIN_NOBODY_WROTE
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_the_key_the_program_put_on_the_chain_is_in_all_three_receivers(self):
        """
        Node prints `true` for all three programs of
        `A_MEMBERSHIP_TEST_FOR_THE_KEY_THE_PROGRAM_PUT_ON_THE_CHAIN`. This is the direction a
        receiver read as the whole of itself gets wrong: none of the three carries `qq`, so
        answering off the receiver prints `false` where the program prints `true`.
        """
        rows = A_MEMBERSHIP_TEST_FOR_THE_KEY_THE_PROGRAM_PUT_ON_THE_CHAIN
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnElisionWritesNoSlot(TestBase):
    """
    An elision writes no element: `[1, , 3]` is three long and holds the slots `0` and `2` only,
    which is the whole of what tells it apart from `[1, undefined, 3]`, whose middle slot is present
    and holds `undefined`.

    Two questions part them. Reading the empty slot is the prototype chain's to answer, since the
    array carries nothing there. Asking whether that index is `in` the array is answered `false`,
    and that one is wrong in an engine no program has touched at all.
    """

    def test_a_read_of_a_slot_an_elision_left_empty_finds_what_the_chain_holds(self):
        """
        Node prints `X` for the four programs of `A_READ_OF_A_SLOT_AN_ELISION_LEFT_EMPTY` that store
        a value on a prototype and `G` for the one that installs an accessor there, the elision
        standing first, in the middle, or before the closing bracket.
        """
        rows = A_READ_OF_A_SLOT_AN_ELISION_LEFT_EMPTY
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_slot_an_elision_left_empty_is_in_no_array(self):
        """
        Node prints `false` for all three programs of
        `A_MEMBERSHIP_TEST_OVER_A_SLOT_AN_ELISION_LEFT_EMPTY`, none of which touches a prototype:
        `1 in [1, , 3]` is `false` and `1 in [1, undefined, 3]` is `true`, and that is the one
        expression a program has for telling a hole from an element.
        """
        rows = A_MEMBERSHIP_TEST_OVER_A_SLOT_AN_ELISION_LEFT_EMPTY
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAWalkOfAnArrayVisitsOnlyThePositionsItHolds(TestBase):
    """
    `for...in` visits an object's own keys, and an array's own keys are the positions it holds. A
    position nothing was ever written in is not one of them, so Node prints `02`, `02`, and `0` for
    the three programs of `A_FOR_IN_WALK_OVER_AN_ARRAY_HOLDING_A_HOLE`.

    Taking the walk from the length instead would give `012`, the walk of an array whose every
    position was written, and hand the body an index the array has nothing at — so a body reading
    `v[k]` for each `k` it is given would read a slot the prototype chain owns.

    A walk of an array a `delete` left a hole in is stated as law in
    `test.lib.scripts.js.deobfuscation.test_own_property_order`. The two holes are one hole to an
    engine, and one representation answers both.
    """

    def test_a_position_no_element_was_written_in_is_visited_by_no_walk(self):
        rows = A_FOR_IN_WALK_OVER_AN_ARRAY_HOLDING_A_HOLE
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestGrowingAnArrayWritesNoElement(TestBase):
    """
    Moving `length` up and writing beyond the end both make an array reach further while leaving
    every position passed over empty, which is a hole exactly as an elision is. Node prints `false`
    for both programs of `A_MEMBERSHIP_TEST_OVER_A_SLOT_GROWTH_PASSED_OVER` and `-1` for the one of
    `A_SEARCH_FOR_UNDEFINED_IN_A_SLOT_GROWTH_PASSED_OVER`.

    Recording growth as elements would answer both as though the passed-over position held
    `undefined`: the membership tests would print `true` and the search `1`. The same two questions
    over a hole a `delete` made are answered from the same representation.
    """

    def test_a_position_growth_passed_over_is_in_no_array(self):
        rows = A_MEMBERSHIP_TEST_OVER_A_SLOT_GROWTH_PASSED_OVER
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_search_finds_no_undefined_in_a_position_growth_passed_over(self):
        rows = A_SEARCH_FOR_UNDEFINED_IN_A_SLOT_GROWTH_PASSED_OVER
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAKeyAnObjectLiteralLacksIsTheChainsToAnswer(TestBase):
    """
    `Object.prototype` roots the chain of every object, so a key an object literal does not write is
    never the literal's to answer: whatever the program installed there is what the read finds.
    Reading a variable as though the literal were the whole of it would answer `undefined` for every
    key it lacks but the handful an untouched `Object.prototype` carries, losing a value stored
    under any other name and leaving an accessor stored there unrun.
    """

    def test_a_read_of_a_key_the_literal_lacks_finds_what_the_chain_holds(self):
        """
        Node prints `X`, `X`, `9`, and `G` for the four programs of
        `A_READ_OF_A_KEY_AN_OBJECT_LITERAL_LACKS`, which read the installed key by name, by a string
        key, under the name `length` that no plain object owns, and through an accessor.
        """
        rows = A_READ_OF_A_KEY_AN_OBJECT_LITERAL_LACKS
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


#: A program reading a key its object literal does not hold, behind a call to `eval` whose argument
#: nothing in the program says. What such a call runs is not knowable, `Object.prototype.zz = 'X'`
#: is among the things it may run, and so the read is one the chain may answer.
A_READ_OF_AN_ABSENT_KEY_BEHIND_AN_UNRESOLVABLE_EVAL = evaluated_in_a_body(
    '{a: 1}', 'v.zz', 'eval(payload);'
)


#: The same program with the call to `eval` taken out.
A_READ_OF_AN_ABSENT_KEY_WITH_NOTHING_BEFORE_IT = evaluated_in_a_body('{a: 1}', 'v.zz')


#: A membership test for a name the language does put on the chain, behind the same unresolvable
#: `eval`, asked inside a body where the interpreter answers it and at the top level where
#: `simplify` does. A write to a prototype only ever adds a name, but a `delete` takes one off, so a
#: statement that may have run either is one both sides of the question have to refuse under.
A_MEMBERSHIP_TEST_FOR_AN_INHERITED_KEY_BEHIND_AN_UNRESOLVABLE_EVAL = (
    evaluated_in_a_body('{a: 1}', "'toString' in v", 'eval(payload);'),
    "eval(payload); var o = {}; console.log('toString' in o);",
)


#: The same two questions with the call to `eval` taken out.
A_MEMBERSHIP_TEST_FOR_AN_INHERITED_KEY_WITH_NOTHING_BEFORE_IT = (
    evaluated_in_a_body('{a: 1}', "'toString' in v"),
    "var o = {}; console.log('toString' in o);",
)


#: A `for-in` walk behind the same unresolvable `eval`, and the same walk with it taken out. Such an
#: `eval` may have put an enumerable name on `Object.prototype`, which every plain object inherits.
A_WALK_BEHIND_AN_UNRESOLVABLE_EVAL = a_walk_of('{a: 1, b: 2}', 'eval(payload);')

A_WALK_WITH_NOTHING_BEFORE_IT = a_walk_of('{a: 1, b: 2}')


#: The same program with the call to `eval` replaced by an ordinary call to the same unresolved
#: name. Both calls read a name the program never binds; only one of them can install a property.
A_READ_OF_AN_ABSENT_KEY_BEHIND_AN_ORDINARY_UNRESOLVED_CALL = evaluated_in_a_body(
    '{a: 1}', 'v.zz', 'sink(payload);'
)


class TestAnUnresolvableEvalCostsTheReadsItCouldHaveAnswered(TestBase):
    """
    A key an object literal does not hold is `Object.prototype`'s to answer, and a call to `eval`
    whose argument the tool cannot resolve is a statement that may have written `Object.prototype`.
    The read is therefore left standing, which is a reduction given up in exchange for not printing
    a value the program need not produce.

    The price is pinned in both directions, because an output that merely stands says nothing on its
    own about whether anything was refused. The same read with nothing in front of it folds, so a
    change that stops folding it at all is caught here instead of reading as a refusal; and the same
    read behind an ordinary call to the same unresolved name folds too, so what the refusal answers
    to is the `eval` rather than the name it was handed.
    """

    def test_a_read_of_an_absent_key_is_left_standing_behind_an_unresolvable_eval(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                eval(payload);
                function f() {
                  var v = { a: 1 };
                  return v.zz;
                }
                console.log(f());
                """
            ),
            folded(A_READ_OF_AN_ABSENT_KEY_BEHIND_AN_UNRESOLVABLE_EVAL),
        )

    def test_the_same_read_folds_with_the_eval_taken_out(self):
        self.assertEqual(
            'console.log(void 0);',
            folded(A_READ_OF_AN_ABSENT_KEY_WITH_NOTHING_BEFORE_IT),
        )

    def test_a_membership_test_for_an_inherited_key_is_left_standing_too(self):
        """
        The presence side of the same question. `delete Object.prototype.toString` is a statement
        such an `eval` may have run, so a name every table here lists is no more certain than a name
        none of them lists, and both sides are left standing.
        """
        self.assertEqual(
            [folded(source) for source in
             A_MEMBERSHIP_TEST_FOR_AN_INHERITED_KEY_BEHIND_AN_UNRESOLVABLE_EVAL],
            [
                inspect.cleandoc(
                    """
                    eval(payload);
                    function f() {
                      var v = { a: 1 };
                      return 'toString' in v;
                    }
                    console.log(f());
                    """
                ),
                inspect.cleandoc(
                    """
                    eval(payload);
                    var o = {};
                    console.log('toString' in o);
                    """
                ),
            ],
        )

    def test_the_same_membership_tests_fold_with_the_eval_taken_out(self):
        self.assertEqual(
            [folded(source) for source in
             A_MEMBERSHIP_TEST_FOR_AN_INHERITED_KEY_WITH_NOTHING_BEFORE_IT],
            ['console.log(true);', 'console.log(true);'],
        )

    def test_a_walk_is_left_standing_behind_an_unresolvable_eval(self):
        """
        Such an `eval` may have put an enumerable name on `Object.prototype`, which every plain
        object inherits, so the own names are no longer the whole of what the walk reaches.
        """
        self.assertEqual(
            inspect.cleandoc(
                """
                eval(payload);
                function f() {
                  var t = '';
                  for (var k in { a: 1, b: 2 }) {
                    t += k;
                  }
                  return t;
                }
                console.log(f());
                """
            ),
            folded(A_WALK_BEHIND_AN_UNRESOLVABLE_EVAL),
        )

    def test_the_same_walk_folds_with_the_eval_taken_out(self):
        self.assertEqual("console.log('ab');", folded(A_WALK_WITH_NOTHING_BEFORE_IT))

    def test_the_same_read_folds_behind_an_ordinary_call_to_an_unresolved_name(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                sink(payload);
                console.log(void 0);
                """
            ),
            folded(A_READ_OF_AN_ABSENT_KEY_BEHIND_AN_ORDINARY_UNRESOLVED_CALL),
        )


#: A program that removes a name the language puts on the receiver's prototype chain and then asks
#: whether that name is `in` the receiver, mapped to what Node prints for it. Nothing else touches
#: the chain, so the deletion is the whole of what decides each answer.
A_MEMBERSHIP_TEST_FOR_A_KEY_THE_PROGRAM_DELETED = {
    evaluated_in_a_body(
        '{a: 1}',
        "'toString' in v",
        'delete Object.prototype.toString;',
    ): 'false\n',
    evaluated_in_a_body(
        '{a: 1}',
        "'hasOwnProperty' in v",
        'delete Object.prototype.hasOwnProperty;',
    ): 'false\n',
    evaluated_in_a_body(
        '[1, 2]',
        "'join' in v",
        'delete Array.prototype.join;',
    ): 'false\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAKeyTheProgramDeletedIsInNothing(TestBase):
    """
    A name is reported present on a receiver's prototype chain from a table of what the language
    puts there, with nothing asked about what the program did to that chain. The reasoning is that
    a write to a prototype only ever adds a name, so a name the language already put there is there
    afterwards too — which is true of a write and false of a `delete`.

    Retired from `test.lib.scripts.js.test_release_blockers` and kept as the regression it retired
    into.
    """

    def test_a_key_the_program_deleted_is_in_nothing(self):
        """
        Node prints `false` for all three programs of
        `A_MEMBERSHIP_TEST_FOR_A_KEY_THE_PROGRAM_DELETED`, each of which deletes one name from a
        prototype its receiver inherits from and then asks for that same name, and each
        deobfuscation prints it too.
        """
        rows = A_MEMBERSHIP_TEST_FOR_A_KEY_THE_PROGRAM_DELETED
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


#: Programs writing a name onto `Object.prototype` and then reading that name off an object
#: literal that does not hold it, mapped to what Node prints for each. The four differ in how
#: the write reaches the prototype and in what it puts there: directly, through a name the file
#: bound it to, through `Object.defineProperty`, and as an accessor rather than a value, so that
#: the last of them answers the read by running the program's own code. The last also holds a
#: second key the literal does write, which the flattening keeps and is right to keep.
A_NAMESPACE_KEY_THE_CHAIN_ANSWERS = {
    'Object.prototype.z = 9; var o = {}; console.log(o.z);':
        '9\n',
    'var P = Object.prototype; P.z = 9; var o = {}; console.log(o.z);':
        '9\n',
    "Object.defineProperty(Object.prototype, 'z', {value: 9});"
    ' var o = {}; console.log(o.z);':
        '9\n',
    an_accessor_at('Object.prototype', 'z')
    + ' var o = {}; o.k = 1; console.log(o.k, o.z);':
        '1 G\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestANamespaceKeyTheChainAnswersIsNotAVariable(TestBase):
    """
    An object literal a file only ever reads properties off is flattened into plain variables, one
    per key, and the declaration it was built by is dropped. That is the same program only while a
    key the literal does not hold reads back `undefined`, and a write to `Object.prototype` is what
    makes one read back something else: the flattened variable answers nothing where the property
    answered what the chain holds.

    `refinery.lib.scripts.js.deobfuscation.helpers.property_absent_from_written_chain` is the
    question this is deciding, and the pass now asks it: every key it cannot prove reads `undefined`
    stays on the namespace object. That is the written arm rather than the stricter one, for the
    reason given where it is defined — refusing here costs the pass rather than one fold.

    `test_a_key_the_namespace_holds_is_flattened` is the other side of it: where the literal owns
    the key, the chain never answers and the flattening is right.

    Retired from `test.lib.scripts.js.test_release_blockers` and kept as the regression it retired
    into.
    """

    def test_a_key_the_chain_answers_is_not_flattened(self):
        """
        Node prints `9`, `9`, `9` and `1 G` for the four programs of
        `A_NAMESPACE_KEY_THE_CHAIN_ANSWERS`, each of which reads a key off an object literal that
        does not hold it after putting that key on `Object.prototype`, and each deobfuscation
        prints the same. The accessor row runs the getter, which is what answering the read off the
        receiver would have dropped unrun.
        """
        rows = A_NAMESPACE_KEY_THE_CHAIN_ANSWERS
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_key_the_namespace_holds_is_flattened(self):
        """
        Node prints `1` for a program that writes the same key onto the literal before reading it,
        with the same write to `Object.prototype` standing in front of it. The own property is what
        answers there, so nothing about the chain reaches the read and the flattening keeps it.
        """
        source = 'Object.prototype.z = 9; var o = {}; o.z = 1; console.log(o.z);'
        self.assertEqual(before_and_after(source), (('1\n', None), ('1\n', None)))


#: Programs that remove a name the language puts on a plain object's chain and then ask whether that
#: name is `in` an object literal that never held it, mapped to what Node prints for each. The
#: question is asked at the top level, where `simplify` answers it, rather than inside a body where
#: the interpreter does, so these are the same defect as
#: `A_MEMBERSHIP_TEST_FOR_A_KEY_THE_PROGRAM_DELETED` at the other of the two sites that decide it.
A_TOP_LEVEL_MEMBERSHIP_TEST_FOR_A_KEY_THE_PROGRAM_DELETED = {
    "delete Object.prototype.toString; var o = {}; console.log('toString' in o);":
        'false\n',
    "delete Object.prototype.hasOwnProperty; var o = {}; console.log('hasOwnProperty' in o);":
        'false\n',
}


#: Membership tests whose answer the language alone decides, mapped to the text each comes back as
#: and what Node prints for it. Two ask a chain nothing touched, and two put a write to a prototype
#: no plain object inherits from in front of the same question. All four fold today and a fix has to
#: keep folding them: an entry that only pins a wrong answer is kept green by a pass that stops
#: answering at all.
A_MEMBERSHIP_TEST_THE_CHAIN_STILL_ANSWERS = {
    "var o = {}; console.log('toString' in o);": (
        'console.log(true);',
        'true\n',
    ),
    "var o = {}; console.log('zz' in o);": (
        'console.log(false);',
        'false\n',
    ),
    "delete Array.prototype.join; var o = {}; console.log('toString' in o);": (
        'delete Array.prototype.join;\nconsole.log(true);',
        'true\n',
    ),
    "delete Array.prototype.join; var o = {}; console.log('zz' in o);": (
        'delete Array.prototype.join;\nconsole.log(false);',
        'false\n',
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestATopLevelKeyTheProgramDeletedIsInNothing(TestBase):
    """
    `TestAKeyTheProgramDeletedIsInNothing` at the other site. The two `in` operators are answered by
    different code — a question asked inside a function body is the interpreter's and one asked at
    the top level is `simplify`'s — and each reads the same table of what the language puts on a
    chain without asking the model what the file did to it.

    `refinery.lib.scripts.js.deobfuscation.simplify.JsSimplifications._resolve_in` used to ask
    `read_chain_intact` before answering `False` and not before answering `True`, on the reasoning
    that a name the tables list is there whatever the file wrote. A `delete` is what that reasoning
    did not cover, and both answers now ask.

    Retired from `test.lib.scripts.js.test_release_blockers` and kept as the regression it retired
    into.
    """

    def test_a_key_the_program_deleted_is_in_nothing(self):
        """
        Node prints `false` for both programs of
        `A_TOP_LEVEL_MEMBERSHIP_TEST_FOR_A_KEY_THE_PROGRAM_DELETED`, and each deobfuscation prints
        it too rather than folding the test to the answer it has with nothing deleted.
        """
        rows = A_TOP_LEVEL_MEMBERSHIP_TEST_FOR_A_KEY_THE_PROGRAM_DELETED
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_membership_test_the_chain_answers_is_still_folded(self):
        """
        Node prints `true`, `false`, `true` and `false` for the four programs of
        `A_MEMBERSHIP_TEST_THE_CHAIN_STILL_ANSWERS`, and each deobfuscation comes back with the
        answer folded in place of the test. Writing `Array.prototype` reaches no chain a plain
        object has, so the two rows that do it are answered as if nothing had been written, and the
        `delete` itself stays because it is what puts the file in that state.
        """
        rows = A_MEMBERSHIP_TEST_THE_CHAIN_STILL_ANSWERS
        self.assertEqual(
            {source: (folded(source), before_and_after(source)) for source in rows},
            {
                source: (reduced, ((prints, None), (prints, None)))
                for source, (reduced, prints) in rows.items()
            },
        )


#: Programs that put an enumerable name on `Object.prototype` and then walk a receiver with
#: `for-in`, mapped to what Node prints for each. The four differ in how the write reaches the
#: prototype and in what the walk runs over: directly, through a name the file bound it to, through
#: `Object.defineProperty` asking for an enumerable property, and over an array rather than an
#: object literal. Every plain object and every array inherits from `Object.prototype`, so the added
#: name is reached from all of them.
A_FOR_IN_WALK_REACHING_A_NAME_THE_CHAIN_WAS_GIVEN = {
    a_walk_of('{a: 1}', 'Object.prototype.z = 9;'):
        'az\n',
    a_walk_of('{a: 1}', 'var P = Object.prototype; P.z = 9;'):
        'az\n',
    a_walk_of(
        '{a: 1}',
        'Object.defineProperty(Object.prototype, "z", {value: 9, enumerable: true});',
    ):
        'az\n',
    a_walk_of('[7, 8]', 'Object.prototype.z = 9;'):
        '01z\n',
}


#: Walks whose names the language alone decides, mapped to the text each comes back as and what Node
#: prints for it. Two run over a chain nothing touched and two put a write to `Array.prototype` in
#: front of a walk over an object literal, which inherits from `Object.prototype` and not from that
#: one. All four fold today and a fix has to keep folding them.
A_FOR_IN_WALK_THE_CHAIN_STILL_ANSWERS = {
    a_walk_of('{a: 1, b: 2}'): (
        "console.log('ab');",
        'ab\n',
    ),
    a_walk_of('[7, 8]'): (
        "console.log('01');",
        '01\n',
    ),
    a_walk_of('{a: 1, b: 2}', 'Array.prototype.z = 9;'): (
        "Array.prototype.z = 9;\nconsole.log('ab');",
        'ab\n',
    ),
    a_walk_of('{a: 1, b: 2}', 'delete Array.prototype.join;'): (
        "delete Array.prototype.join;\nconsole.log('ab');",
        'ab\n',
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAForInWalkReachesTheNamesTheChainWasGiven(TestBase):
    """
    A `for-in` walk visits every enumerable name the receiver's whole prototype chain holds, not the
    own properties alone, and a name a file writes onto a prototype with an ordinary assignment is
    enumerable. The interpreter walks the own properties and stops, so a program written to carry a
    name on the chain comes back having visited one name fewer, with nothing to say it did.

    Everything the language itself puts on a chain is non-enumerable, which is why this is only ever
    wrong for a name the file put there — and why the whole question is one about what the
    file did, which the effect model is what knows. The walk is refused where a chain root was
    written.

    Retired from `test.lib.scripts.js.test_release_blockers` and kept as the regression it retired
    into.
    """

    def test_a_name_written_onto_the_chain_is_walked(self):
        """
        Node prints `az`, `az`, `az` and `01z` for the four programs of
        `A_FOR_IN_WALK_REACHING_A_NAME_THE_CHAIN_WAS_GIVEN`, and each deobfuscation prints it too
        rather than the walk with the inherited name missing.
        """
        rows = A_FOR_IN_WALK_REACHING_A_NAME_THE_CHAIN_WAS_GIVEN
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_walk_the_chain_answers_is_still_folded(self):
        """
        Node prints `ab`, `01`, `ab` and `ab` for the four programs of
        `A_FOR_IN_WALK_THE_CHAIN_STILL_ANSWERS`, and each deobfuscation comes back with the names
        folded in place of the loop. An object literal does not inherit from `Array.prototype`, so
        the two rows writing that one are answered as if nothing had been written.
        """
        rows = A_FOR_IN_WALK_THE_CHAIN_STILL_ANSWERS
        self.assertEqual(
            {source: (folded(source), before_and_after(source)) for source in rows},
            {
                source: (reduced, ((prints, None), (prints, None)))
                for source, (reduced, prints) in rows.items()
            },
        )


#: Programs that write a name onto `Object.prototype` without ever spelling `Object`, mapped to what
#: Node prints for each. Every one reaches the same object a literal `Object.prototype` names:
#: as the `__proto__` of an object literal, as what `Object.getPrototypeOf` answers for one, and
#: as the `prototype` of what its `constructor` is. These are the shapes a file uses when it does
#: not want the write found by looking for the name.
A_PROTOTYPE_WRITTEN_WITHOUT_NAMING_ITS_OWNER = {
    '({}).__proto__.z = 9; var o = {}; console.log(o.z);':
        '9\n',
    'Object.getPrototypeOf({}).z = 9; var o = {}; console.log(o.z);':
        '9\n',
    '({}).constructor.prototype.z = 9; var o = {}; console.log(o.z);':
        '9\n',
}


#: Programs whose `__proto__` reaches a prototype other than the one a plain object inherits
#: from, or reaches nothing the file may assume, mapped to what Node prints for each. An array
#: literal's `__proto__` is `Array.prototype`, which a plain object does not inherit from, and a
#: file that binds the name `Object` to something of its own is not writing the intrinsic at all.
A_PROTOTYPE_SPELLING_THAT_NAMES_A_DIFFERENT_OBJECT = {
    '[].__proto__.z = 9; var o = {}; console.log(o.z);':
        'undefined\n',
    '[].__proto__.z = 9; var a = [1]; console.log(a.z);':
        '9\n',
    'var Object = {prototype: {}}; Object.prototype.z = 9; console.log(({}).z);':
        'undefined\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAPrototypeWrittenWithoutNamingItsOwnerIsStillWritten(TestBase):
    """
    A write to a prototype is recorded against the name at the root of the member chain it was
    written through, so a chain rooted in something other than an identifier is recorded against
    nothing and every question about that prototype goes on answering as if the file had left it
    alone. Reaching `Object.prototype` through an object literal is the whole of what a prototype
    pollution gadget does, and all three spellings here are ways of writing it without the name.

    The read was then flattened into a variable that answers `undefined`, so the value the write put
    there was gone from the file as well as from the answer.
    `refinery.lib.scripts.js.deobfuscation.protospelling` writes each spelling out as the name it
    reaches, which is what puts the write in front of every check that was already looking for one.

    Retired from `test.lib.scripts.js.test_release_blockers` and kept as the regression it retired
    into.
    """

    def test_a_prototype_written_through_a_literal_answers_the_read(self):
        """
        Node prints `9` for all three programs of `A_PROTOTYPE_WRITTEN_WITHOUT_NAMING_ITS_OWNER`,
        each of which reaches `Object.prototype` without spelling `Object`, and each deobfuscation
        prints it too.
        """
        rows = A_PROTOTYPE_WRITTEN_WITHOUT_NAMING_ITS_OWNER
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_spelling_that_names_a_different_object_is_read_as_that_object(self):
        """
        Node prints `undefined`, `9` and `undefined` for the three programs of
        `A_PROTOTYPE_SPELLING_THAT_NAMES_A_DIFFERENT_OBJECT`, and each deobfuscation agrees. An
        array literal's `__proto__` is `Array.prototype`, and a file that declares `Object` itself
        names its own object with it.
        """
        rows = A_PROTOTYPE_SPELLING_THAT_NAMES_A_DIFFERENT_OBJECT
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )
