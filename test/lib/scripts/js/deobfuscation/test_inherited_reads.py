"""
What a receiver answers for itself, and what the prototype chain behind it answers: a key it lacks,
an index past its end, and a hole in an array.

SECURITY: every program here is written out by the module itself and Node runs only those. Nothing
from `samples` may ever be handed to the engine.
"""
from __future__ import annotations

import inspect
import unittest

from test import TestBase, opportunity
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


A_READ_OF_AN_INDEX_THE_RECEIVER_DOES_NOT_HOLD = {
    evaluated_in_a_body("'abc'", 'v[5]', "String.prototype[5] = 'X';"): 'X\n',
    evaluated_in_a_body("''", 'v[0]', "String.prototype[0] = 'X';"): 'X\n',
    evaluated_in_a_body("atob('YWJj')", 'v[5]', "String.prototype[5] = 'X';"): 'X\n',
    evaluated_in_a_body('[1, 2]', 'v[5]', "Array.prototype[5] = 'X';"): 'X\n',
    evaluated_in_a_body('[1, 2]', 'v[5]', "Object.prototype[5] = 'X';"): 'X\n',
    evaluated_in_a_body('[1, 2]', 'v[5]', an_accessor_at('Array.prototype', '5')): 'G\n',
    evaluated_in_a_body("'abc'", 'v[5]', an_accessor_at('String.prototype', '5')): 'G\n',
}


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


A_MEMBERSHIP_TEST_OVER_A_RECEIVER_WHOSE_CHAIN_THE_PROGRAM_WROTE = {
    evaluated_in_a_body('g', "'zz' in v", "Object.prototype.qq = 'X'; function g() {}"): 'false\n',
    evaluated_in_a_body('C', "'zz' in v", "Object.prototype.qq = 'X'; class C {}"): 'false\n',
    evaluated_in_a_body('{}', "'zz' in v", "Object.prototype.qq = 'X';"): 'false\n',
}


THE_SAME_MEMBERSHIP_TESTS_OVER_A_CHAIN_NOBODY_WROTE = {
    evaluated_in_a_body('g', "'zz' in v", 'function g() {}'): 'false\n',
    evaluated_in_a_body('C', "'zz' in v", 'class C {}'): 'false\n',
    evaluated_in_a_body('{}', "'zz' in v"): 'false\n',
}


A_MEMBERSHIP_TEST_FOR_THE_KEY_THE_PROGRAM_PUT_ON_THE_CHAIN = {
    evaluated_in_a_body('g', "'qq' in v", "Object.prototype.qq = 'X'; function g() {}"): 'true\n',
    evaluated_in_a_body('C', "'qq' in v", "Object.prototype.qq = 'X'; class C {}"): 'true\n',
    evaluated_in_a_body('{}', "'qq' in v", "Object.prototype.qq = 'X';"): 'true\n',
}


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


A_MEMBERSHIP_TEST_OVER_A_SLOT_AN_ELISION_LEFT_EMPTY = {
    evaluated_in_a_body('[1, , 3]', '1 in v'): 'false\n',
    evaluated_in_a_body('[, 2]', '0 in v'): 'false\n',
    evaluated_in_a_body('[1, ,]', '1 in v'): 'false\n',
}


A_READ_OF_A_KEY_AN_OBJECT_LITERAL_LACKS = {
    evaluated_in_a_body('{a: 1}', 'v.zz', "Object.prototype.zz = 'X';"): 'X\n',
    evaluated_in_a_body('{a: 1}', "v['zz']", "Object.prototype.zz = 'X';"): 'X\n',
    evaluated_in_a_body('{a: 1}', 'v.length', 'Object.prototype.length = 9;'): '9\n',
    evaluated_in_a_body('{a: 1}', 'v.zz', an_accessor_at('Object.prototype', 'zz')): 'G\n',
}


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


A_MEMBERSHIP_TEST_OVER_A_SLOT_GROWTH_PASSED_OVER = {
    returned_from_a_body('var v = [1]; v.length = 3; return 1 in v;'): 'false\n',
    returned_from_a_body('var v = [1]; v[2] = 3; return 1 in v;'): 'false\n',
}


A_SEARCH_FOR_UNDEFINED_IN_A_SLOT_GROWTH_PASSED_OVER = {
    returned_from_a_body('var v = [1]; v.length = 3; return v.indexOf(undefined);'): '-1\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnIndexTheReceiverDoesNotHoldIsTheChainsToAnswer(TestBase):

    def test_a_read_of_an_index_past_the_end_finds_what_the_chain_holds(self):
        rows = A_READ_OF_AN_INDEX_THE_RECEIVER_DOES_NOT_HOLD
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_membership_of_an_index_past_the_end_finds_what_the_chain_holds(self):
        rows = A_MEMBERSHIP_TEST_OVER_AN_INDEX_THE_ARRAY_DOES_NOT_HOLD
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnUnansweredMembershipTestIsNotAYes(TestBase):

    def test_a_key_nobody_installed_is_in_nothing(self):
        rows = A_MEMBERSHIP_TEST_FOR_A_KEY_NOBODY_INSTALLED
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_key_nobody_installed_is_in_no_function_class_or_object(self):
        rows = A_MEMBERSHIP_TEST_OVER_A_RECEIVER_WHOSE_CHAIN_THE_PROGRAM_WROTE
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_the_same_three_receivers_answer_the_same_way_with_no_prototype_written(self):
        rows = THE_SAME_MEMBERSHIP_TESTS_OVER_A_CHAIN_NOBODY_WROTE
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_the_key_the_program_put_on_the_chain_is_in_all_three_receivers(self):
        rows = A_MEMBERSHIP_TEST_FOR_THE_KEY_THE_PROGRAM_PUT_ON_THE_CHAIN
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAnElisionWritesNoSlot(TestBase):

    def test_a_read_of_a_slot_an_elision_left_empty_finds_what_the_chain_holds(self):
        rows = A_READ_OF_A_SLOT_AN_ELISION_LEFT_EMPTY
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_slot_an_elision_left_empty_is_in_no_array(self):
        rows = A_MEMBERSHIP_TEST_OVER_A_SLOT_AN_ELISION_LEFT_EMPTY
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAWalkOfAnArrayVisitsOnlyThePositionsItHolds(TestBase):

    def test_a_position_no_element_was_written_in_is_visited_by_no_walk(self):
        rows = A_FOR_IN_WALK_OVER_AN_ARRAY_HOLDING_A_HOLE
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestGrowingAnArrayWritesNoElement(TestBase):

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

    def test_a_read_of_a_key_the_literal_lacks_finds_what_the_chain_holds(self):
        rows = A_READ_OF_A_KEY_AN_OBJECT_LITERAL_LACKS
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


A_READ_OF_AN_ABSENT_KEY_BEHIND_AN_UNRESOLVABLE_EVAL = evaluated_in_a_body(
    '{a: 1}', 'v.zz', 'eval(payload);'
)


A_READ_OF_AN_ABSENT_KEY_WITH_NOTHING_BEFORE_IT = evaluated_in_a_body('{a: 1}', 'v.zz')


A_MEMBERSHIP_TEST_FOR_AN_INHERITED_KEY_BEHIND_AN_UNRESOLVABLE_EVAL = (
    evaluated_in_a_body('{a: 1}', "'toString' in v", 'eval(payload);'),
    "eval(payload); var o = {}; console.log('toString' in o);",
)


A_MEMBERSHIP_TEST_FOR_AN_INHERITED_KEY_WITH_NOTHING_BEFORE_IT = (
    evaluated_in_a_body('{a: 1}', "'toString' in v"),
    "var o = {}; console.log('toString' in o);",
)


A_WALK_BEHIND_AN_UNRESOLVABLE_EVAL = a_walk_of('{a: 1, b: 2}', 'eval(payload);')

A_WALK_WITH_NOTHING_BEFORE_IT = a_walk_of('{a: 1, b: 2}')


A_READ_OF_AN_ABSENT_KEY_BEHIND_AN_ORDINARY_UNRESOLVED_CALL = evaluated_in_a_body(
    '{a: 1}', 'v.zz', 'sink(payload);'
)


class TestAnUnresolvableEvalCostsTheReadsItCouldHaveAnswered(TestBase):

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

    def test_a_key_the_program_deleted_is_in_nothing(self):
        rows = A_MEMBERSHIP_TEST_FOR_A_KEY_THE_PROGRAM_DELETED
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


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


A_NAMESPACE_KEY_WRITTEN_BEFORE_IT_IS_READ = 'Object.prototype.z = 9; var o = {}; o.z = 1; console.log(o.z);'


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestANamespaceKeyTheChainAnswersIsNotAVariable(TestBase):

    def test_a_key_the_chain_answers_is_not_flattened(self):
        rows = A_NAMESPACE_KEY_THE_CHAIN_ANSWERS
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_key_the_namespace_holds_still_prints_its_own_value(self):
        self.assertEqual(
            before_and_after(A_NAMESPACE_KEY_WRITTEN_BEFORE_IT_IS_READ),
            (('1\n', None), ('1\n', None)),
        )

    @opportunity
    def test_a_key_the_namespace_holds_folds_to_the_value_written_into_it(self):
        self.assertEqual(
            folded(A_NAMESPACE_KEY_WRITTEN_BEFORE_IT_IS_READ),
            inspect.cleandoc(
                """
                Object.prototype.z = 9;
                console.log(1);
                """
            ),
        )


A_TOP_LEVEL_MEMBERSHIP_TEST_FOR_A_KEY_THE_PROGRAM_DELETED = {
    "delete Object.prototype.toString; var o = {}; console.log('toString' in o);":
        'false\n',
    "delete Object.prototype.hasOwnProperty; var o = {}; console.log('hasOwnProperty' in o);":
        'false\n',
}


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

    def test_a_key_the_program_deleted_is_in_nothing(self):
        rows = A_TOP_LEVEL_MEMBERSHIP_TEST_FOR_A_KEY_THE_PROGRAM_DELETED
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_membership_test_the_chain_answers_is_still_folded(self):
        rows = A_MEMBERSHIP_TEST_THE_CHAIN_STILL_ANSWERS
        self.assertEqual(
            {source: (folded(source), before_and_after(source)) for source in rows},
            {
                source: (reduced, ((prints, None), (prints, None)))
                for source, (reduced, prints) in rows.items()
            },
        )


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

    def test_a_name_written_onto_the_chain_is_walked(self):
        rows = A_FOR_IN_WALK_REACHING_A_NAME_THE_CHAIN_WAS_GIVEN
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_walk_the_chain_answers_is_still_folded(self):
        rows = A_FOR_IN_WALK_THE_CHAIN_STILL_ANSWERS
        self.assertEqual(
            {source: (folded(source), before_and_after(source)) for source in rows},
            {
                source: (reduced, ((prints, None), (prints, None)))
                for source, (reduced, prints) in rows.items()
            },
        )


A_PROTOTYPE_WRITTEN_WITHOUT_NAMING_ITS_OWNER = {
    '({}).__proto__.z = 9; var o = {}; console.log(o.z);':
        '9\n',
    'Object.getPrototypeOf({}).z = 9; var o = {}; console.log(o.z);':
        '9\n',
    '({}).constructor.prototype.z = 9; var o = {}; console.log(o.z);':
        '9\n',
}


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

    def test_a_prototype_written_through_a_literal_answers_the_read(self):
        rows = A_PROTOTYPE_WRITTEN_WITHOUT_NAMING_ITS_OWNER
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )

    def test_a_spelling_that_names_a_different_object_is_read_as_that_object(self):
        rows = A_PROTOTYPE_SPELLING_THAT_NAMES_A_DIFFERENT_OBJECT
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )
