from __future__ import annotations

import inspect
import json
import unittest

from typing import NamedTuple

from test.lib.scripts.js.analysis.differential import completion_values, node_executable
from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator


class TestInterpreterValueSemantics(TestJsDeobfuscator):

    def test_add_array_operands_concatenate(self):
        self.assertEqual("var x = '12';", self._fold('[1] + [2]'))

    def test_add_empty_arrays_concatenate(self):
        self.assertEqual("var x = '';", self._fold('[] + []'))

    def test_add_nested_array_operands_concatenate(self):
        self.assertEqual("var x = '1,23';", self._fold('[1, 2] + [3]'))

    def test_add_array_and_number_concatenate(self):
        self.assertEqual("var x = '12';", self._fold('[1] + 2'))

    def test_unary_minus_on_zero_coercion_is_negative_zero(self):
        source = inspect.cleandoc(
            """
            function f() {
                var a = false;
                return -a;
            }
            var x = f();
            """
        )
        self.assertEqual('var x = -0;', self._evaluate(source))

    def test_compound_assignment_reads_target_before_evaluating_rhs(self):
        self.assertEqual(
            'var r = 15;',
            self._evaluate('var r = (function(v) { v += (v = 10); return v; })(5);'))

    def test_add_object_operand_concatenates_object_tag(self):
        self.assertEqual("var x = '[object Object]1';", self._fold('({ a: 1 }) + 1'))

    def test_relational_array_and_string_compare_as_strings(self):
        self.assertEqual('var x = true;', self._fold("[false] <= 'op7'"))

    def test_relational_array_ge_string_compares_as_strings(self):
        self.assertEqual('var x = true;', self._fold("['ef', true] >= 'cd'"))

    def test_compound_add_array_operand_concatenates(self):
        source = inspect.cleandoc(
            """
            function f() {
                var s = [1];
                s += [2];
                return s;
            }
            var x = f();
            """
        )
        self.assertEqual("var x = '12';", self._evaluate(source))

    def test_interleaved_empty_statement_in_function_body(self):
        source = inspect.cleandoc(
            """
            function f() {
                ;
                return 'ab'.charAt(1);
            }
            SINK(f());
            """
        )
        self.assertEqual("SINK('b');", self._evaluate(source))

    def test_consecutive_empty_statements_in_function_body(self):
        source = inspect.cleandoc(
            """
            function f() {
                var a = 'ab';;
                return a.charAt(1);
            }
            SINK(f());
            """
        )
        self.assertEqual("SINK('b');", self._evaluate(source))

    def test_concise_arrow_irreducible_tail_substitutes_whole_expression(self):
        """
        An arrow whose tail expression cannot be reduced folds to that whole tail with the argument
        substituted, exactly as a `return` of the same expression would — never to an inner operand.
        `Array` is unresolved, so the call becomes `!('mn' instanceof Array)`, not the bare `Array`.
        """
        self.assertEqual(
            "SINK(!('mn' instanceof Array));",
            self._evaluate("const f = v => !(v instanceof Array);\nSINK(f('mn'));"),
        )

    def test_strict_equal_distinct_arrays_is_false(self):
        self.assertEqual('var x = false;', self._fold('[1] === [1]'))

    def test_strict_not_equal_distinct_objects_is_true(self):
        self.assertEqual('var x = true;', self._fold('({}) !== ({})'))

    def test_loose_equal_distinct_objects_is_false(self):
        self.assertEqual('var x = false;', self._fold('({}) == ({})'))

    def test_loose_equal_distinct_arrays_is_false(self):
        self.assertEqual('var x = false;', self._fold('[1] == [1]'))

    def test_strict_equal_same_array_reference_is_true(self):
        source = inspect.cleandoc(
            """
            function f() {
                var a = [1];
                return a === a;
            }
            var x = f();
            """
        )
        self.assertEqual('var x = true;', self._evaluate(source))

    def test_includes_uses_reference_equality_for_arrays(self):
        self.assertEqual('var x = false;', self._fold('[[1]].includes([1])'))

    def test_pow_negative_base_fractional_exponent_is_nan(self):
        # Python returns a complex number for (-8) ** 0.5; JavaScript returns NaN.
        self.assertEqual('var x = 0 / 0;', self._fold('(-8) ** 0.5'))

    def test_math_pow_zero_base_negative_exponent_is_infinity(self):
        self.assertEqual('var x = 1e999;', self._fold('Math.pow(0, -1)'))

    def test_pow_negative_base_integer_exponent(self):
        self.assertEqual('var x = -8;', self._fold('(-2) ** 3'))

    def test_pow_overflowing_magnitude_is_infinity(self):
        # JS numbers are doubles, so a result beyond the double range is Infinity, not a Python bignum.
        self.assertEqual('var x = 1e999;', self._fold('2 ** 1024'))

    def test_pow_overflowing_negative_magnitude_is_negative_infinity(self):
        self.assertEqual('var x = -1e999;', self._fold('(-10) ** 999'))

    def test_pow_one_to_infinity_is_nan(self):
        self.assertEqual('var x = 0 / 0;', self._fold('1 ** Infinity'))

    def test_math_pow_one_to_infinity_is_nan(self):
        self.assertEqual('var x = 0 / 0;', self._fold('Math.pow(1, Infinity)'))

    def test_undefined_plus_number_is_nan(self):
        # undefined coerces to NaN, null coerces to 0 — the two must stay distinct.
        self.assertEqual('var x = 0 / 0;', self._fold('undefined + 1'))

    def test_null_plus_number_coerces_to_zero(self):
        self.assertEqual('var x = 1;', self._fold('null + 1'))

    def test_typeof_null_is_object(self):
        self.assertEqual("var x = 'object';", self._fold('typeof null'))

    def test_typeof_builtin_function_folds_to_function(self):
        self.assertEqual("var x = 'function';", self._fold('typeof parseInt'))
        self.assertEqual("var x = 'function';", self._fold('typeof encodeURIComponent'))

    def test_typeof_namespace_object_folds_to_object(self):
        self.assertEqual("var x = 'object';", self._fold('typeof Math'))

    def test_typeof_shadowed_global_in_dead_zone_is_not_folded(self):
        """
        `typeof Math` here reads the local `Math` in its temporal dead zone — a `ReferenceError` at
        runtime, not the global `Math` — so the evaluator must not manufacture `'object'` for it and
        leaves the throwing function unreduced.
        """
        source = inspect.cleandoc(
            """
            function f() {
                var r = typeof Math;
                let Math = 5;
                return r;
            }
            var x = f();
            """
        )
        self.assertEqual(self._run_transformers(source), self._evaluate(source))

    def test_string_of_null_is_null(self):
        self.assertEqual("var x = 'null';", self._fold('String(null)'))

    def test_strict_equal_null_vs_undefined_is_false(self):
        self.assertEqual('var x = false;', self._fold('null === undefined'))

    def test_nullish_coalescing_on_null(self):
        self.assertEqual('var x = 5;', self._fold('null ?? 5'))

    def test_nullish_coalescing_keeps_zero(self):
        self.assertEqual('var x = 0;', self._fold('0 ?? 5'))

    def test_loose_equal_string_and_number(self):
        self.assertEqual('var x = true;', self._fold("'5' == 5"))

    def test_loose_equal_zero_and_false(self):
        self.assertEqual('var x = true;', self._fold('0 == false'))

    def test_loose_equal_null_and_undefined(self):
        self.assertEqual('var x = true;', self._fold('null == undefined'))

    def test_loose_equal_null_and_zero_is_false(self):
        self.assertEqual('var x = false;', self._fold('null == 0'))

    def test_loose_equal_empty_string_and_zero(self):
        self.assertEqual('var x = true;', self._fold("'' == 0"))

    def test_loose_equal_array_and_number(self):
        self.assertEqual('var x = true;', self._fold('[1] == 1'))

    def test_loose_not_equal_numbers(self):
        self.assertEqual('var x = true;', self._fold('1 != 2'))

    def test_array_tostring_renders_null_as_empty(self):
        self.assertEqual("var x = '1,,2';", self._fold('[1, null, 2].toString()'))

    def test_array_join_null_separator(self):
        self.assertEqual("var x = '1null2';", self._fold('[1, 2].join(null)'))

    def test_array_join_undefined_separator_defaults_to_comma(self):
        self.assertEqual("var x = '1,2';", self._fold('[1, 2].join(undefined)'))

    def test_json_parse_null_is_object(self):
        self.assertEqual("var x = 'object';", self._fold("typeof JSON.parse('null')"))

    def test_number_to_string_hex(self):
        self.assertEqual("var x = 'ff';", self._fold('(255).toString(16)'))

    def test_number_to_string_radix_36(self):
        self.assertEqual("var x = 'z';", self._fold('(35).toString(36)'))

    def test_number_to_string_negative_hex(self):
        self.assertEqual("var x = '-ff';", self._fold('(-255).toString(16)'))

    def test_number_to_string_default_radix(self):
        self.assertEqual("var x = '255';", self._fold('(255).toString()'))

    def test_number_to_string_radix_out_of_range_throws(self):
        source = inspect.cleandoc(
            """
            function f() {
                try {
                    return (5).toString(40);
                } catch (e) {
                    return e.name;
                }
            }
            var x = f();
            """
        )
        self.assertEqual("var x = 'RangeError';", self._evaluate(source))

    def test_number_string_small_magnitude_exponential(self):
        self.assertEqual("var x = '1e-7';", self._fold('String(1e-7)'))

    def test_number_string_large_magnitude_exponential(self):
        self.assertEqual("var x = '1e+21';", self._fold('String(1e21)'))

    def test_number_string_exponent_has_no_leading_zero(self):
        self.assertEqual("var x = '1e-8';", self._fold('String(1e-8)'))

    def test_number_of_signed_hex_is_nan(self):
        self.assertEqual('var x = 0 / 0;', self._fold("Number('-0x1F')"))

    def test_var_redeclaration_without_initializer_preserves_binding(self):
        # A bare `var k;` is a no-op when `k` is already bound; it must not reset the parameter.
        source = inspect.cleandoc(
            """
            function f(k) {
                var k;
                return k;
            }
            var x = f('KEY');
            """
        )
        self.assertEqual("var x = 'KEY';", self._evaluate(source))

    def test_division_by_negative_zero_is_negative_infinity(self):
        self.assertEqual('var x = -1e999;', self._fold('1 / -0'))

    def test_division_of_negative_by_negative_zero_is_positive_infinity(self):
        self.assertEqual('var x = 1e999;', self._fold('-1 / -0'))

    def test_math_round_negative_zero_observable_through_division(self):
        self.assertEqual('var x = -1e999;', self._fold('1 / Math.round(-0.4)'))

    def test_math_round_largest_value_below_half_rounds_down(self):
        self.assertEqual('var x = 0;', self._fold('Math.round(0.49999999999999994)'))

    def test_math_max_selects_positive_over_negative_zero(self):
        self.assertEqual('var x = 1e999;', self._fold('1 / Math.max(-0, 0)'))

    def test_math_min_selects_negative_over_positive_zero(self):
        self.assertEqual('var x = -1e999;', self._fold('1 / Math.min(-0, 0)'))

    def test_math_max_keeps_negative_zero_when_all_operands_negative_zero(self):
        self.assertEqual('var x = -1e999;', self._fold('1 / Math.max(-0, -0)'))

    def test_math_abs_of_no_argument_is_nan(self):
        self.assertEqual('var x = 0 / 0;', self._fold('Math.abs()'))

    def test_math_sqrt_of_no_argument_is_nan(self):
        self.assertEqual('var x = 0 / 0;', self._fold('Math.sqrt()'))

    def test_math_sign_of_no_argument_is_nan(self):
        self.assertEqual('var x = 0 / 0;', self._fold('Math.sign()'))

    def test_math_floor_of_no_argument_is_nan(self):
        self.assertEqual('var x = 0 / 0;', self._fold('Math.floor()'))

    def test_math_log_of_no_argument_is_nan(self):
        self.assertEqual('var x = 0 / 0;', self._fold('Math.log()'))


class TestInterpreterMethodValueSemantics(TestJsDeobfuscator):
    """
    Reading a method off a value yields the method itself, not the result of calling it, and not
    `undefined`. Node decides these: `typeof 'abc'.charAt` is `'function'`, `'abc'.length()` is a
    `TypeError` because `length` is a number rather than a callable, and `typeof 'abc'.normalize` is
    `'function'` even though this package does not implement `normalize`. There is no value domain here
    for a function — a JS function has an observable identity, `name`, and source text — so the only
    correct answers are the true one or a refusal to fold. Each case asserts the fold declines rather
    than guessing.
    """

    def _declines(self, expression: str):
        """
        Assert that the interpreter leaves a function returning *expression* entirely unfolded.
        """
        source = F'function f() {{\n  return {expression};\n}}\nvar x = f();'
        self.assertEqual(source, self._evaluate(source))

    def test_string_method_read_is_not_invoked(self):
        self._declines("typeof 'abc'.charAt")

    def test_string_transform_method_read_is_not_invoked(self):
        self._declines("typeof 'abc'.toUpperCase")

    def test_string_split_read_is_not_invoked(self):
        self._declines("typeof 'abc'.split")

    def test_unimplemented_string_method_read_is_not_absent(self):
        """
        `normalize` is a real `String.prototype` method this package does not model. Membership in the
        language and evaluability by this interpreter are different questions, so an unmodeled method
        must not read as `undefined` — that would make `typeof` answer `'undefined'` where Node says
        `'function'`.
        """
        self._declines("typeof 'abc'.normalize")

    def test_unimplemented_array_method_read_is_not_absent(self):
        self._declines('typeof [1, 2].sort')

    def test_inherited_object_method_read_is_not_absent(self):
        self._declines("typeof 'abc'.hasOwnProperty")

    def test_array_hof_read_is_not_absent(self):
        self._declines('typeof [1, 2].map')

    def test_constructor_read_is_not_absent(self):
        """
        `constructor` is the entry point of the `[].constructor.constructor('...')()` reflection chain,
        so answering `undefined` for it would erase a capability rather than resolve it.
        """
        self._declines('typeof [1, 2].constructor')

    def test_object_prototype_read_on_plain_object_is_not_absent(self):
        self._declines('typeof ({ a: 1 }).toString')

    def test_absent_member_still_reads_as_undefined(self):
        """
        The companion negative case: a name that is on no prototype really is `undefined`, and must keep
        folding, so refusing method reads does not degrade into refusing every miss.
        """
        source = inspect.cleandoc(
            """
            function f() {
                return typeof 'abc'.nosuchmember;
            }
            var x = f();
            """
        )
        self.assertEqual("var x = 'undefined';", self._evaluate(source))

    def test_buffer_member_is_never_provably_absent(self):
        """
        A Buffer's surface is over a hundred methods and varies between Node versions, so it cannot be
        enumerated here. Nothing can be proven absent on one, and a read must decline rather than answer
        `undefined` — `Buffer.prototype.readUInt8` is a function.
        """
        source = inspect.cleandoc(
            """
            function f() {
              var b = Buffer.from('aa', 'hex');
              return typeof b.readUInt8;
            }
            var x = f();
            """
        )
        self.assertEqual(source, self._evaluate(source))

    def test_buffer_length_still_folds(self):
        """
        `length` is a data property on a Buffer as much as on an array, so refusing to enumerate the
        Buffer method surface must not also block reading its length.
        """
        source = inspect.cleandoc(
            """
            function f() {
                var b = Buffer.from('aabb', 'hex');
                return b.length;
            }
            var x = f();
            """
        )
        self.assertEqual('var x = 2;', self._evaluate(source))

    def test_string_length_is_not_callable(self):
        """
        `length` is a number, so calling it throws. The interpreter must not treat the call as a second
        application of a registry entry and fold it to the string's length.
        """
        self._declines("'hello'.length()")

    def test_array_length_is_not_callable(self):
        self._declines('[1, 2].length()')

    def test_length_read_still_folds(self):
        """
        The companion positive case: `length` is a genuine data property, so the read form must keep
        folding even though the call form now throws.
        """
        source = inspect.cleandoc(
            """
            function f() {
                return 'abc'.charAt(0).length;
            }
            var x = f();
            """
        )
        self.assertEqual('var x = 1;', self._evaluate(source))

    def test_non_canonical_index_key_is_undefined(self):
        """
        A property key is an array index only in its canonical decimal spelling, so `'+1'` is an
        ordinary property name and reads as `undefined`. Python's `int` accepts `'+1'`, which would
        otherwise invent the element at index 1.
        """
        source = inspect.cleandoc(
            """
            function f() {
                return typeof 'abc'['+1'];
            }
            var x = f();
            """
        )
        self.assertEqual("var x = 'undefined';", self._evaluate(source))

    def test_canonical_index_key_still_folds(self):
        source = inspect.cleandoc(
            """
            function f() {
                return 'abc'['1'];
            }
            var x = f();
            """
        )
        self.assertEqual("var x = 'b';", self._evaluate(source))

    def test_astral_split_by_code_unit(self):
        """
        `String.prototype.split('')` splits by UTF-16 code unit, so an astral character becomes its two
        surrogate halves: Node yields 3 elements for a smiley followed by `x`, where splitting by Unicode
        code point would yield 2.
        """
        source = inspect.cleandoc(
            """
            function f() {
                return '\U0001F600x'.split('').length;
            }
            var x = f();
            """
        )
        self.assertEqual('var x = 3;', self._evaluate(source))


class TestInterpreterInOperator(TestJsDeobfuscator):
    """
    The `in` operator asks whether a property exists anywhere on the prototype chain, so it shares the
    membership question with a property read. Node decides: `'sort' in [1,2]` is `true` even though this
    package does not implement `sort`, and `'+1' in [1,2]` is `false` because a non-canonical key is an
    ordinary property name rather than an index.
    """

    def _in(self, expression: str, expected: str):
        source = F'function f() {{\n  return {expression};\n}}\nvar x = f();'
        self.assertEqual(F'var x = {expected};', self._evaluate(source))

    def test_data_property_is_present(self):
        self._in("'length' in [1, 2]", 'true')

    def test_implemented_method_is_present(self):
        self._in("'join' in [1, 2]", 'true')

    def test_unimplemented_method_is_present(self):
        self._in("'sort' in [1, 2]", 'true')

    def test_inherited_object_method_is_present(self):
        self._in("'hasOwnProperty' in [1, 2]", 'true')

    def test_absent_name_is_missing(self):
        self._in("'nosuch' in [1, 2]", 'false')

    def test_index_in_range_is_present(self):
        self._in("'0' in [1, 2]", 'true')

    def test_index_out_of_range_is_missing(self):
        self._in("'2' in [1, 2]", 'false')

    def test_non_canonical_index_is_missing(self):
        self._in("'+1' in [1, 2]", 'false')

    def test_leading_zero_index_is_missing(self):
        self._in("'01' in [1, 2]", 'false')

    def test_own_property_of_object_is_present(self):
        self._in("'a' in { a: 1 }", 'true')

    def test_inherited_property_of_object_is_present(self):
        self._in("'toString' in { a: 1 }", 'true')

    def test_absent_property_of_object_is_missing(self):
        self._in("'nosuch' in { a: 1 }", 'false')


class TestInterpreterProtoKeySemantics(TestJsDeobfuscator):
    """
    A `__proto__` key is the one property name whose plain spelling does not create an own property.
    Node decides: `Object.keys({__proto__: {x: 1}})` is empty and the object inherits `x`, whereas
    `Object.keys({['__proto__']: {x: 1}})` has one entry and inherits nothing. The interpreter models an
    object as a dict of own data properties and has no representation for an installed prototype, so a
    literal or an assignment that installs one must decline rather than record an ordinary key — that
    would invent an own property and hide the inherited ones.
    """

    def _declines(self, body: str):
        source = F'function f() {{\n{body}\n}}\nvar x = f();'
        self.assertEqual(source, self._evaluate(source))

    def _folds(self, body: str, expected: str):
        source = F'function f() {{\n{body}\n}}\nvar x = f();'
        self.assertEqual(F'var x = {expected};', self._evaluate(source))

    def test_bare_proto_literal_declines(self):
        self._declines('  return Object.keys({ __proto__: { x: 1 } }).length;')

    def test_quoted_proto_literal_declines(self):
        self._declines("  return Object.keys({ '__proto__': { x: 1 } }).length;")

    def test_bare_proto_literal_with_primitive_declines(self):
        self._declines('  return Object.keys({ __proto__: 1 }).length;')

    def test_bare_proto_literal_with_null_declines(self):
        """
        `{__proto__: null}` installs a null prototype, which changes the object's whole member surface
        rather than adding a property, so it is no more representable than any other prototype.
        """
        self._declines('  return Object.keys({ __proto__: null }).length;')

    def test_inherited_member_read_through_proto_literal_declines(self):
        self._declines('  var o = { __proto__: { x: 1 } };\n  return o.x;')

    def test_proto_key_alongside_other_keys_declines(self):
        self._declines('  return Object.keys({ a: 1, __proto__: { x: 1 } }).length;')

    def test_computed_proto_literal_folds(self):
        """
        The computed form creates an ordinary own property for every value type, so it is representable
        and must keep folding — otherwise the fix would trade one wrong answer for a lost one.
        """
        self._folds("  return Object.keys({ ['__proto__']: { x: 1 } }).length;", '1')

    def test_computed_proto_literal_is_not_inherited(self):
        self._folds("  var o = { ['__proto__']: { x: 1 } };\n  return o.x === undefined;", 'true')

    def test_shorthand_proto_is_an_ordinary_property(self):
        """
        A shorthand `{__proto__}` defines an ordinary own property; only the `key: value` data form
        installs a prototype.
        """
        self._folds('  var __proto__ = 7;\n  return Object.keys({ __proto__ }).length;', '1')

    def test_proto_assignment_to_plain_object_declines(self):
        self._declines("  var o = {};\n  o['__proto__'] = { x: 1 };\n  return o.x;")

    def test_proto_dot_assignment_to_plain_object_declines(self):
        self._declines('  var o = {};\n  o.__proto__ = { x: 1 };\n  return o.x;')

    def test_proto_assignment_over_own_proto_property_folds(self):
        """
        An own `__proto__` data property shadows the inherited accessor, so a later write lands in the
        data slot instead of installing a prototype. This is the one assignment form that is precise.
        """
        self._folds(
            "  var o = { ['__proto__']: 1 };\n"
            "  o['__proto__'] = 2;\n"
            "  return o['__proto__'];",
            '2',
        )

    def test_ordinary_assignment_still_folds(self):
        self._folds("  var o = {};\n  o['a'] = 1;\n  return o['a'];", '1')

    def test_json_parsed_proto_key_is_an_own_property(self):
        """
        `JSON.parse` creates a genuine own `__proto__` property, which is representable, so the round
        trip through the interpreter and back into source must preserve it.
        """
        self._folds(
            '  return Object.keys(JSON.parse(\'{"__proto__":{"x":1}}\')).length;',
            '1',
        )

    def test_ordinary_prototype_member_name_as_key_folds(self):
        self._folds('  return Object.keys({ constructor: 1 }).length;', '1')


class TestInterpreterThrowSemantics(TestJsDeobfuscator):

    def test_unsupported_expression_in_try_does_not_run_catch(self):
        # `new Date()` does not throw in JS, so the catch must not run; the interpreter cannot evaluate
        # it, so it leaves the call untouched rather than wrongly folding to the catch value 'B'.
        source = inspect.cleandoc(
            """
            function f() {
              try {
                var y = new Date();
                return 'A';
              } catch (e) {
                return 'B';
              }
            }
            var r = f();
            """
        )
        self.assertEqual(source, self._evaluate(source))

    def test_null_property_access_throws_caught(self):
        source = inspect.cleandoc(
            """
            function f() {
                try {
                    return null.x;
                } catch (e) {
                    return 'caught';
                }
            }
            var r = f();
            """
        )
        self.assertEqual("var r = 'caught';", self._evaluate(source))

    def test_for_of_null_throws_caught(self):
        source = inspect.cleandoc(
            """
            function f() {
                try {
                    for (const x of null) {}
                    return 'no';
                } catch (e) {
                    return 'caught';
                }
            }
            var r = f();
            """
        )
        self.assertEqual("var r = 'caught';", self._evaluate(source))

    def test_range_error_name_available_in_catch(self):
        source = inspect.cleandoc(
            """
            function f() {
                try {
                    return 'x'.repeat(-1);
                } catch (e) {
                    return e.name;
                }
            }
            var r = f();
            """
        )
        self.assertEqual("var r = 'RangeError';", self._evaluate(source))

    def test_array_length_range_error_is_catchable(self):
        source = inspect.cleandoc(
            """
            function f() {
                var a = [1, 2, 3];
                try {
                    a['length'] = NaN;
                    return 'no throw';
                } catch (e) {
                    return e.name + ': ' + e.message;
                }
            }
            var r = f();
            """
        )
        self.assertEqual("var r = 'RangeError: Invalid array length';", self._evaluate(source))

    def test_uncaught_runtime_throw_is_not_folded(self):
        source = inspect.cleandoc(
            """
            function f() {
              return null.x;
            }
            var r = f();
            """
        )
        self.assertEqual(source, self._evaluate(source))

    def test_optional_member_on_null_is_undefined(self):
        self.assertEqual('var x = void 0;', self._fold('null?.b'))

    def test_optional_call_on_null_is_undefined(self):
        self.assertEqual('var x = void 0;', self._fold('null?.b()'))

    def test_finally_runs_on_propagating_runtime_throw(self):
        source = inspect.cleandoc(
            """
            function f() {
                var log = '';
                try {
                    try {
                        null.x;
                    } finally {
                        log = 'fin';
                    }
                } catch (e) {
                    return log;
                }
            }
            var r = f();
            """
        )
        self.assertEqual("var r = 'fin';", self._evaluate(source))


class TestInterpreterCompoundAssignment(TestJsDeobfuscator):
    """
    Compound assignment and update expressions, across every operator the parser can emit and every target
    form it accepts. The interpreter used to answer these from three hand-rolled operator tables that
    disagreed with each other and with `_eval_binary`: a plain identifier target supported ten operators, a
    member target only four, and an update expression refused a member target outright. Worse, the identifier
    table reached `math.fmod` directly, so `Infinity %= 5` raised an uncaught `ValueError` out of the unit.

    Every expected value here is what Node prints for the same program.
    """

    def _target(self, body: str) -> str:
        return self._evaluate(F'function f() {{ {body} }}\nvar r = f();')

    def test_modulo_assign_infinite_dividend_is_nan(self):
        """
        `Infinity % 5` is `NaN`. Computing it with `math.fmod` raises `ValueError: math domain error`, which
        is not an `InterpreterError` and so escaped every refusal path and crashed the unit. The canonical
        operator table has always answered this correctly; the compound path simply did not consult it.
        """
        self.assertEqual('var r = 0 / 0;', self._target('var t = Infinity; t %= 5; return t;'))

    def test_modulo_assign_infinite_divisor_keeps_dividend(self):
        self.assertEqual('var r = 5;', self._target('var t = 5; t %= Infinity; return t;'))

    def test_modulo_assign_by_zero_is_nan(self):
        """
        A zero divisor is not an error in JavaScript. Refusing here contradicted `t = t % 0`, which folds.
        """
        self.assertEqual('var r = 0 / 0;', self._target('var t = 5; t %= 0; return t;'))

    def test_divide_assign_by_zero_is_infinity(self):
        self.assertEqual('var r = 1e999;', self._target('var t = 5; t /= 0; return t;'))

    def test_divide_assign_by_negative_zero_is_negative_infinity(self):
        self.assertEqual('var r = -1e999;', self._target('var t = 5; t /= -0; return t;'))

    def test_multiply_assign_preserves_negative_zero(self):
        """
        `0 * -5` is `-0`, which the synthesizer prints distinctly from `0`. Plain multiplication in Python
        does not preserve the sign.
        """
        self.assertEqual('var r = -0;', self._target('var t = 0; t *= -5; return t;'))

    def test_exponent_assign(self):
        self.assertEqual('var r = 1024;', self._target('var t = 2; t **= 10; return t;'))

    def test_unsigned_shift_assign_on_negative(self):
        self.assertEqual('var r = 15;', self._target('var t = -1; t >>>= 28; return t;'))

    def test_logical_or_assign_replaces_falsy(self):
        self.assertEqual('var r = 7;', self._target('var t = 0; t ||= 7; return t;'))

    def test_logical_and_assign_replaces_truthy(self):
        self.assertEqual('var r = 7;', self._target('var t = 3; t &&= 7; return t;'))

    def test_nullish_assign_replaces_undefined(self):
        self.assertEqual('var r = 7;', self._target('var t; t ??= 7; return t;'))

    def test_nullish_assign_keeps_zero(self):
        """
        `??=` tests for nullish, not falsy, so a zero is kept where `||=` would replace it.
        """
        self.assertEqual('var r = 0;', self._target('var t = 0; t ??= 7; return t;'))

    def test_logical_assign_does_not_evaluate_right_side_when_short_circuiting(self):
        """
        The right operand of a logical assignment runs only when the existing value does not already decide
        the result. Here the operand would increment `n`, so a folded `n` of `0` proves it never ran.
        """
        self.assertEqual('var r = 0;', self._target('var n = 0; var t = 3; t ||= (n += 1); return n;'))

    def test_logical_assign_evaluates_right_side_when_not_short_circuiting(self):
        """
        The companion case, without which the test above would pass on an implementation that never
        evaluates the right operand at all.
        """
        self.assertEqual('var r = 1;', self._target('var n = 0; var t = 0; t ||= (n += 1); return n;'))

    def test_logical_assign_on_member_does_not_write_when_short_circuiting(self):
        """
        A short-circuiting logical assignment performs no write at all — observable in JavaScript through a
        setter or a frozen object. Reading the member back proves the original value survived untouched.
        """
        self.assertEqual('var r = 7;', self._target('var o = { k: 7 }; o.k ||= 9; return o.k;'))

    def test_logical_assign_on_length_does_not_relength_when_short_circuiting(self):
        """
        The store a short-circuit skips is observable even where the value would be unchanged, because
        `length` is not an ordinary slot: assigning to it resizes the array. `a.length ||= 9` on a nonempty
        array short-circuits, so the array keeps its three elements; a redundant store of the old length
        would be invisible here, but the same store computed from a stale value would truncate.
        """
        self.assertEqual(
            "var r = '1,2,3|3';",
            self._target('var a = [1, 2, 3]; a.length ||= 9; return a[0] + "," + a[1] + "," + a[2] + "|" + a.length;'))

    def test_logical_assign_on_length_writes_when_not_short_circuiting(self):
        """
        The companion: a nonempty array has a truthy `length`, so `&&=` does not short-circuit and
        the store runs, truncating the array to the two elements it now reaches. The operator is
        `&&=` rather than `||=` because the only `||=` that reaches its store on a `length` raises
        it, and a position raising it passes over is one the array does not hold rather than one
        holding `undefined`.
        """
        self.assertEqual(
            "var r = '1,2|2';",
            self._target(
                'var a = [1, 2, 3]; a.length &&= 2;'
                ' return a[0] + "," + a[1] + "|" + a.length;'
            ),
        )

    def test_bitwise_assign_on_array_element(self):
        self.assertEqual('var r = 18;', self._target('var a = [17]; a[0] ^= 3; return a[0];'))

    def test_bitwise_assign_on_computed_element(self):
        self.assertEqual('var r = 18;', self._target('var a = [17]; var i = 0; a[i] ^= 3; return a[i];'))

    def test_bitwise_assign_on_object_property(self):
        self.assertEqual('var r = 18;', self._target('var o = { k: 17 }; o.k ^= 3; return o.k;'))

    def test_shift_assign_on_array_element(self):
        self.assertEqual('var r = 136;', self._target('var a = [17]; a[0] <<= 3; return a[0];'))

    def test_divide_assign_on_array_element(self):
        self.assertEqual('var r = 8.5;', self._target('var a = [17]; a[0] /= 2; return a[0];'))

    def test_exponent_assign_on_object_property(self):
        self.assertEqual('var r = 4913;', self._target('var o = { k: 17 }; o.k **= 3; return o.k;'))

    def test_increment_on_array_element(self):
        self.assertEqual('var r = 18;', self._target('var a = [17]; a[0]++; return a[0];'))

    def test_prefix_increment_on_array_element_yields_new_value(self):
        self.assertEqual('var r = 18;', self._target('var a = [17]; return ++a[0];'))

    def test_postfix_increment_on_array_element_yields_old_value(self):
        self.assertEqual('var r = 17;', self._target('var a = [17]; return a[0]++;'))

    def test_decrement_on_object_property(self):
        self.assertEqual('var r = 16;', self._target('var o = { k: 17 }; o.k--; return o.k;'))

    def test_increment_on_computed_element_evaluates_index_once(self):
        """
        `a[i++]++` reads the index expression once, so `i` advances by one rather than two. The returned
        value encodes both the element and the counter, so a double evaluation cannot hide behind either.
        """
        source = 'var a = [17, 20]; var i = 0; a[i++]++; return a[0] * 100 + i;'
        self.assertEqual('var r = 1801;', self._target(source))

    def test_compound_assign_on_computed_element_evaluates_index_once(self):
        source = 'var a = [10, 20]; var i = 0; a[i++] += 1; return a[0] * 100 + i;'
        self.assertEqual('var r = 1101;', self._target(source))

    def test_length_compound_assign_truncates(self):
        self.assertEqual(
            'var r = 3;',
            self._target('var a = [1, 2, 3, 4, 5]; a.length -= 2; return a.length;'))

    def test_length_decrement_truncates(self):
        self.assertEqual(
            'var r = 2;',
            self._target('var a = [1, 2, 3]; a.length--; return a.length;'))

    def test_length_compound_assign_to_fraction_is_refused(self):
        """
        `a.length /= 2` on three elements asks for a length of `1.5`, which JavaScript answers with a
        `RangeError`. The fold must not invent a value for it.
        """
        source = inspect.cleandoc(
            """
            function f() {
              var a = [1, 2, 3];
              a.length /= 2;
              return a.length;
            }
            var r = f();
            """
        )
        self.assertEqual(source, self._evaluate(source))

    def test_length_compound_assign_below_zero_is_refused(self):
        source = inspect.cleandoc(
            """
            function f() {
              var a = [1];
              a.length -= 5;
              return a.length;
            }
            var r = f();
            """
        )
        self.assertEqual(source, self._evaluate(source))


class TestInterpreterNumericCoercion(TestJsDeobfuscator):
    """
    ToNumber and `parseInt` over strings, in the places where Python's own number parser and the
    language disagree about what a string names. Every expected value is what Node prints for the
    same expression.
    """

    def test_a_string_that_names_negative_zero_coerces_to_negative_zero(self):
        self.assertEqual('var x = -0;', self._fold("Number('-0')"))
        self.assertEqual('var x = -0;', self._fold("+'-0'"))
        self.assertEqual('var x = -0;', self._fold("parseInt('-0')"))
        self.assertEqual('var x = -1e999;', self._fold("1 / Number('-0')"))

    def test_non_ascii_decimal_digits_coerce_to_nan(self):
        self.assertEqual('var x = 0 / 0;', self._fold(R"Number('\u0661\u0662\u0663')"))
        self.assertEqual('var x = 0 / 0;', self._fold(R"Number('\uFF11\uFF12\uFF13')"))
        self.assertEqual('var x = 0 / 0;', self._fold(R"Number('\u0967\u0968\u0969')"))
        self.assertEqual('var x = 0 / 0;', self._fold(R"+'\u0661\u0662\u0663'"))

    def test_padding_python_strips_and_javascript_does_not_coerces_to_nan(self):
        self.assertEqual('var x = 0 / 0;', self._fold(R"Number('\u001C5')"))
        self.assertEqual('var x = 0 / 0;', self._fold(R"Number('\u001D5')"))
        self.assertEqual('var x = 0 / 0;', self._fold(R"Number('\u001E5')"))
        self.assertEqual('var x = 0 / 0;', self._fold(R"Number('\u001F5')"))
        self.assertEqual('var x = 0 / 0;', self._fold(R"+'\u001C5'"))
        self.assertEqual('var x = 0 / 0;', self._fold(R"parseInt('\u001C5')"))

    def test_the_byte_order_mark_pads_a_number_the_way_a_space_does(self):
        self.assertEqual('var x = 5;', self._fold(R"Number('\uFEFF5')"))
        self.assertEqual('var x = 5;', self._fold(R"Number('5\uFEFF')"))
        self.assertEqual('var x = 5;', self._fold(R"+'\uFEFF5'"))
        self.assertEqual('var x = 5;', self._fold(R"parseInt('\uFEFF5')"))

    def test_parse_int_reads_its_radix_through_the_signed_32_bit_wrap(self):
        """
        The radix is coerced with ToInt32, which wraps rather than saturates: `2**32 + 16` is base
        sixteen, `2**32` is the language's unsupplied radix and therefore ten, and a negative value
        lands on the same base its wrap names. Truncating instead names a radix outside 2 to 36,
        which is `NaN` for every string.
        """
        self.assertEqual('var x = 16;', self._fold("parseInt('10', 2 ** 32 + 16)"))
        self.assertEqual('var x = 10;', self._fold("parseInt('10', 2 ** 32)"))
        self.assertEqual('var x = 255;', self._fold("parseInt('ff', -(2 ** 32) + 16)"))


class TestAstralStringCodePointIterationAndCodeUnitIndexing(TestJsDeobfuscator):
    """
    A JavaScript string is stored as UTF-16 code units but iterated as Unicode code points, so a
    character above the basic multilingual plane is one element to `Array.from` and to `for ... of`,
    and two code units to `length`, an index, `charCodeAt`, and `String.fromCharCode`. Node:
    `Array.from('\U0001F600').length` is `1`, `'\U0001F600'.length` is `2`, and the two units are
    `55357` and `56832`.
    """

    def test_array_from_sees_one_element(self):
        self.assertEqual('var x = 1;', self._fold("Array.from('\U0001F600').length"))

    def test_for_of_iterates_once(self):
        source = inspect.cleandoc(
            """
            function f() {
                var n = 0;
                for (const c of '\U0001F600') n = n + 1;
                return n;
            }
            var x = f();
            """
        )
        self.assertEqual('var x = 1;', self._evaluate(source))

    def test_the_iterated_element_is_the_whole_character(self):
        self.assertEqual(
            'var x = true;',
            self._fold("Array.from('\U0001F600')[0] === '\U0001F600'"),
        )

    def test_length_counts_two_code_units(self):
        self.assertEqual('var x = 2;', self._fold("'\U0001F600'.length"))

    def test_char_code_at_reads_the_high_surrogate(self):
        self.assertEqual('var x = 55357;', self._fold("'\U0001F600'.charCodeAt(0)"))

    def test_char_code_at_reads_the_low_surrogate(self):
        self.assertEqual('var x = 56832;', self._fold("'\U0001F600'.charCodeAt(1)"))

    def test_indexing_splits_into_the_two_code_units(self):
        self.assertEqual(
            'var x = true;',
            self._fold("('\U0001F600'[0] + '\U0001F600'[1]) === '\U0001F600'"),
        )

    def test_from_char_code_rebuilds_the_character_from_its_code_units(self):
        self.assertEqual(
            'var x = true;',
            self._fold(
                "String.fromCharCode('\U0001F600'.charCodeAt(0), '\U0001F600'.charCodeAt(1)) "
                "=== '\U0001F600'"
            ),
        )

_SWITCH_DEFAULT_LAST = inspect.cleandoc("""
    function f(x) {
      var log = '';
      switch (x) {
        case 1: log += 'A'; break;
        case 2: log += 'B'; break;
        default: log += 'D';
      }
      return log;
    }
""")

_SWITCH_DEFAULT_ABSENT = inspect.cleandoc("""
    function f(x) {
      var log = '';
      switch (x) {
        case 1: log += 'A'; break;
        case 2: log += 'B'; break;
      }
      return log;
    }
""")

_SWITCH_DEFAULT_FIRST = inspect.cleandoc("""
    function f(x) {
      var log = '';
      switch (x) {
        default: log += 'D'; break;
        case 1: log += 'A'; break;
        case 2: log += 'B'; break;
      }
      return log;
    }
""")

_SWITCH_DEFAULT_FIRST_OPEN = inspect.cleandoc("""
    function f(x) {
      var log = '';
      switch (x) {
        default: log += 'D';
        case 1: log += 'A'; break;
        case 2: log += 'B'; break;
      }
      return log;
    }
""")

_SWITCH_DEFAULT_BETWEEN = inspect.cleandoc("""
    function f(x) {
      var log = '';
      switch (x) {
        case (log += 'a', 1): log += 'A';
        case (log += 'b', 2): log += 'B'; break;
        default: log += 'D'; break;
        case (log += 'c', 3): log += 'C'; break;
      }
      return log;
    }
""")

_SWITCH_DEFAULT_BETWEEN_OPEN = inspect.cleandoc("""
    function f(x) {
      var log = '';
      switch (x) {
        case 1: log += 'A';
        default: log += 'D';
        case 2: log += 'B';
      }
      return log;
    }
""")

_SWITCH_DEFAULT_WITHOUT_A_BODY = inspect.cleandoc("""
    function f(x) {
      var log = '';
      switch (x) {
        case 1: log += 'A'; break;
        default:
        case 2: log += 'B'; break;
        case 3: log += 'C'; break;
      }
      return log;
    }
""")

_SWITCH_DEFAULT_ALONE = inspect.cleandoc("""
    function f(x) {
      var log = '';
      switch (x) {
        default: log += 'D';
      }
      return log;
    }
""")

_SWITCH_WITHOUT_CLAUSES = inspect.cleandoc("""
    function f(x) {
      var log = '';
      switch (x) {
      }
      return log;
    }
""")

_SWITCH_TRACED_TESTS = inspect.cleandoc("""
    function f(x) {
      var log = '';
      switch (x) {
        case (log += 'a', 1): log += 'A'; break;
        case (log += 'b', 2): log += 'B'; break;
        case (log += 'c', 3): log += 'C'; break;
      }
      return log;
    }
""")

_SWITCH_TRACED_BEHIND_DEFAULT = inspect.cleandoc("""
    function f(x) {
      var log = '';
      switch (x) {
        default: log += 'D'; break;
        case (log += 'a', 1): log += 'A'; break;
        case (log += 'b', 2): log += 'B'; break;
      }
      return log;
    }
""")

_SWITCH_TRACED_DISCRIMINANT = inspect.cleandoc("""
    function f(x) {
      var log = '';
      switch (log += 'x', x) {
        case (log += 'a', 1): log += 'A'; break;
        case (log += 'b', 2): log += 'B'; break;
      }
      return log;
    }
""")

_SWITCH_THROWING_LAST_TEST = inspect.cleandoc("""
    function f(x) {
      try {
        switch (x) {
          case 1: return 'A';
          case null.missing: return 'B';
        }
      } catch (e) {
        return e.name;
      }
      return 'Z';
    }
""")

_SWITCH_THROWING_TEST_BEHIND_DEFAULT = inspect.cleandoc("""
    function f(x) {
      try {
        switch (x) {
          case 1: return 'A';
          default: return 'D';
          case null.missing: return 'B';
        }
      } catch (e) {
        return e.name;
      }
    }
""")

_SWITCH_THROWING_DISCRIMINANT = inspect.cleandoc("""
    function f(x) {
      var log = '';
      try {
        switch (null.missing) {
          case (log += 'a', 1): log += 'A'; break;
          default: log += 'D';
        }
      } catch (e) {
        log += e.name;
      }
      return log;
    }
""")

_SWITCH_OVER_EVERY_KIND_OF_CASE = inspect.cleandoc("""
    function f(x) {
      var log = '';
      switch (x) {
        case 1: log += 'n'; break;
        case '1': log += 's'; break;
        case true: log += 'b'; break;
        case null: log += 'z'; break;
        case undefined: log += 'u'; break;
        case NaN: log += 'q'; break;
        case 0: log += 'o'; break;
        default: log += 'D';
      }
      return log;
    }
""")

_SWITCH_OVER_AN_OBJECT = inspect.cleandoc("""
    function f() {
      var log = '';
      var o = { valueOf: function () { return 1; } };
      var p = { valueOf: function () { return 1; } };
      switch (o) {
        case 1: log += 'v'; break;
        case p: log += 'P'; break;
        case o: log += 'O'; break;
        default: log += 'D';
      }
      return log;
    }
""")

_SWITCH_WITH_EQUAL_TESTS = inspect.cleandoc("""
    function f(x) {
      var log = '';
      switch (x) {
        case 1: log += 'A'; break;
        case 1: log += 'B'; break;
        default: log += 'D';
      }
      return log;
    }
""")

_SWITCH_WITHOUT_CLAUSE_BODIES = inspect.cleandoc("""
    function f(x) {
      var log = '';
      switch (x) {
        case 1:
        case 2:
        case 3: log += 'L'; break;
        default: log += 'D';
      }
      return log;
    }
""")

_SWITCH_WITHOUT_BREAKS = inspect.cleandoc("""
    function f(x) {
      var log = '';
      switch (x) {
        case 1: log += 'A';
        case 2: log += 'B';
        case 3: log += 'C';
      }
      return log;
    }
""")

_SWITCH_WITH_RETURNS = inspect.cleandoc("""
    function f(x) {
      switch (x) {
        case 1: return 'A';
        case 2: return 'B';
      }
      return 'Z';
    }
""")

_SWITCH_INSIDE_A_LOOP = inspect.cleandoc("""
    function f() {
      var log = '';
      for (var i = 0; i < 3; i++) {
        switch (i) {
          case 1: log += 'A'; break;
          default: log += 'd';
        }
        log += i;
      }
      return log;
    }
""")

_SWITCH_WITH_A_CONTINUE = inspect.cleandoc("""
    function f() {
      var log = '';
      for (var i = 0; i < 3; i++) {
        switch (i) {
          case 1: continue;
          default: log += 'd';
        }
        log += i;
      }
      return log;
    }
""")

_SWITCH_INSIDE_A_CLAUSE = inspect.cleandoc("""
    function f(x) {
      var log = '';
      switch (x) {
        case 1:
          switch (x) {
            case 1: log += 'i'; break;
          }
          log += 'A';
        case 2: log += 'B'; break;
        default: log += 'D';
      }
      return log;
    }
""")

_SWITCH_WITH_A_STATEMENT_BEHIND_IT = inspect.cleandoc("""
    function f(x) {
      var log = '';
      switch (x) {
        case 1: log += 'A'; break;
        default: log += 'D';
      }
      log += '!';
      return log;
    }
""")

_SWITCH_DECLARING_IN_A_CLAUSE = inspect.cleandoc("""
    function f(x) {
      var log = '';
      switch (x) {
        case 1: var v = 'v'; let l = 'l'; log += v + l;
        case 2: log += typeof v;
      }
      return log;
    }
""")

_SWITCH_WITH_TESTS_THAT_WRITE = inspect.cleandoc("""
    function f(x) {
      var log = '';
      var k = 0;
      switch (x) {
        case (k = 1, x = 99, 0): log += 'A'; break;
        case k: log += 'B'; break;
        case 99: log += 'C'; break;
        default: log += 'D';
      }
      return log;
    }
""")

_SWITCH_WITH_COMPUTED_TESTS = inspect.cleandoc("""
    function f(x) {
      var bump = function (v) { return v + 1; };
      switch (x) {
        case bump(0): return 'A';
        case bump(1): return 'B';
        default: return 'D';
      }
    }
""")

_SWITCH_OVER_STRINGS = inspect.cleandoc("""
    function f(x) {
      switch (x) {
        case 'a': return 'alpha';
        case 'b': return 'beta';
        default: return 'other';
      }
    }
""")

_SWITCH_THROWING_IN_A_CLAUSE_BODY = inspect.cleandoc("""
    function f(x) {
      try {
        switch (x) {
          case 1: throw 'boom';
          default: return 'D';
        }
      } catch (e) {
        return e;
      }
    }
""")

_SWITCH_WITH_TWO_DEFAULTS = inspect.cleandoc("""
    function f(x) {
      var log = '';
      switch (x) {
        default:
          log += 'D';
        case 1:
          log += 'A';
          break;
        default:
          log += 'E';
      }
      return log;
    }
""")

_EVERY_KIND_OF_DISCRIMINANT = {
    '1'      : 'n',
    "'1'"    : 's',
    'true'   : 'b',
    'null'   : 'z',
    'void 0' : 'u',
    ''       : 'u',
    '0 / 0'  : 'D',
    '-0'     : 'o',
    'false'  : 'D',
    "'0'"    : 'D',
    '[]'     : 'D',
}


class _SwitchProbe(NamedTuple):
    """
    One way of writing a `switch`, and the string the function hands back for each discriminant it
    is asked about, spelled the way that discriminant is written as an argument to `f`.
    """
    source: str
    answers: dict[str, str]


class _SwitchRun(NamedTuple):
    """
    One of those switches asked about one of those discriminants.
    """
    label: str
    source: str
    argument: str
    result: str


_SWITCH_PROBES: dict[str, _SwitchProbe] = {
    'default_written_last': _SwitchProbe(
        _SWITCH_DEFAULT_LAST, {'1': 'A', '2': 'B', '9': 'D'}
    ),
    'no_default_at_all': _SwitchProbe(
        _SWITCH_DEFAULT_ABSENT, {'1': 'A', '9': ''}
    ),
    'default_written_first': _SwitchProbe(
        _SWITCH_DEFAULT_FIRST, {'2': 'B', '9': 'D'}
    ),
    'default_written_first_without_a_break': _SwitchProbe(
        _SWITCH_DEFAULT_FIRST_OPEN, {'2': 'B', '9': 'DA'}
    ),
    'default_written_between_the_cases': _SwitchProbe(
        _SWITCH_DEFAULT_BETWEEN,
        {'1': 'aAB', '2': 'abB', '3': 'abcC', '9': 'abcD', '0 / 0': 'abcD'},
    ),
    'default_written_between_cases_without_breaks': _SwitchProbe(
        _SWITCH_DEFAULT_BETWEEN_OPEN, {'1': 'ADB', '2': 'B', '9': 'DB'}
    ),
    'default_written_without_a_body': _SwitchProbe(
        _SWITCH_DEFAULT_WITHOUT_A_BODY, {'1': 'A', '3': 'C', '9': 'B'}
    ),
    'default_is_the_only_clause': _SwitchProbe(
        _SWITCH_DEFAULT_ALONE, {'1': 'D'}
    ),
    'no_clauses_at_all': _SwitchProbe(
        _SWITCH_WITHOUT_CLAUSES, {'1': ''}
    ),
    'tests_that_record_being_evaluated': _SwitchProbe(
        _SWITCH_TRACED_TESTS, {'1': 'aA', '2': 'abB', '9': 'abc'}
    ),
    'tests_recorded_behind_a_leading_default': _SwitchProbe(
        _SWITCH_TRACED_BEHIND_DEFAULT, {'2': 'abB', '9': 'abD'}
    ),
    'a_discriminant_that_records_being_evaluated': _SwitchProbe(
        _SWITCH_TRACED_DISCRIMINANT, {'2': 'xabB', '9': 'xab'}
    ),
    'a_throwing_test_written_last': _SwitchProbe(
        _SWITCH_THROWING_LAST_TEST, {'1': 'A', '2': 'TypeError', '9': 'TypeError'}
    ),
    'a_throwing_test_written_behind_the_default': _SwitchProbe(
        _SWITCH_THROWING_TEST_BEHIND_DEFAULT, {'1': 'A', '9': 'TypeError'}
    ),
    'a_throwing_discriminant': _SwitchProbe(
        _SWITCH_THROWING_DISCRIMINANT, {'1': 'TypeError'}
    ),
    'a_case_for_every_kind_of_value': _SwitchProbe(
        _SWITCH_OVER_EVERY_KIND_OF_CASE, _EVERY_KIND_OF_DISCRIMINANT
    ),
    'an_object_discriminant': _SwitchProbe(
        _SWITCH_OVER_AN_OBJECT, {'': 'O'}
    ),
    'two_cases_with_the_same_test': _SwitchProbe(
        _SWITCH_WITH_EQUAL_TESTS, {'1': 'A'}
    ),
    'cases_written_without_bodies': _SwitchProbe(
        _SWITCH_WITHOUT_CLAUSE_BODIES, {'1': 'L', '2': 'L', '3': 'L', '9': 'D'}
    ),
    'cases_written_without_breaks': _SwitchProbe(
        _SWITCH_WITHOUT_BREAKS, {'1': 'ABC', '3': 'C', '9': ''}
    ),
    'cases_that_return': _SwitchProbe(
        _SWITCH_WITH_RETURNS, {'2': 'B', '3': 'Z'}
    ),
    'a_switch_inside_a_loop': _SwitchProbe(
        _SWITCH_INSIDE_A_LOOP, {'': 'd0A1d2'}
    ),
    'a_continue_inside_a_clause': _SwitchProbe(
        _SWITCH_WITH_A_CONTINUE, {'': 'd0d2'}
    ),
    'a_switch_inside_a_clause': _SwitchProbe(
        _SWITCH_INSIDE_A_CLAUSE, {'1': 'iAB'}
    ),
    'a_statement_written_behind_the_switch': _SwitchProbe(
        _SWITCH_WITH_A_STATEMENT_BEHIND_IT, {'1': 'A!', '9': 'D!'}
    ),
    'declarations_written_inside_a_clause': _SwitchProbe(
        _SWITCH_DECLARING_IN_A_CLAUSE, {'1': 'vlstring', '2': 'undefined'}
    ),
    'tests_that_write_what_a_later_test_reads': _SwitchProbe(
        _SWITCH_WITH_TESTS_THAT_WRITE, {'1': 'B', '9': 'D'}
    ),
    'tests_that_are_computed': _SwitchProbe(
        _SWITCH_WITH_COMPUTED_TESTS, {'1': 'A', '2': 'B', '9': 'D'}
    ),
    'a_dispatch_over_strings': _SwitchProbe(
        _SWITCH_OVER_STRINGS, {"'a'": 'alpha', "'b'": 'beta', "'z'": 'other'}
    ),
    'a_throw_inside_a_clause_body': _SwitchProbe(
        _SWITCH_THROWING_IN_A_CLAUSE_BODY, {'1': 'boom', '9': 'D'}
    ),
}


def _switch_runs() -> list[_SwitchRun]:
    return [
        _SwitchRun(F'{name}({argument})', probe.source, argument, result)
        for name, probe in _SWITCH_PROBES.items()
        for argument, result in probe.answers.items()
    ]


class TestInterpreterSwitchStatement(TestJsDeobfuscator):
    """
    A `switch` selects one clause and then runs it and every clause written behind it, until a
    `break`, a `continue`, a `return`, or the end of the switch. Which clause it selects follows
    three rules: a clause is selected when its test is strictly equal to the discriminant; the tests
    are evaluated in the order they are written and the search stops at the first match; and
    `default` is selected only once every test has missed, wherever the `default` is written, so a
    clause written behind it is still asked before it is taken.

    Each program below is one reading of those rules, and Node decides every answer. The
    discriminant is the argument `f` is called with, and the string `f` hands back names what
    happened: where a program records its own run, a lowercase letter is written by a clause test
    being evaluated and an uppercase letter by a clause body being run, so `abcD` is a switch that
    asked three tests, matched none of them, and then ran its `default`.
    """

    def test_switch_folds_to_what_the_clauses_it_runs_produce(self):
        for run in _switch_runs():
            with self.subTest(run.label):
                self.assertEqual(
                    F"var x = '{run.result}';",
                    self._evaluate(F'{run.source}\nvar x = f({run.argument});'),
                )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_produces_every_pinned_switch_result(self):
        """
        `completion_values` names a string value by its JSON spelling, which is what `json.dumps`
        writes, so each comparison is between the value Node computed and the value pinned above.
        """
        runs = _switch_runs()
        values = completion_values([F'{run.source}\nf({run.argument});' for run in runs])
        self.assertEqual(
            {run.label: json.dumps(run.result) for run in runs},
            dict(zip([run.label for run in runs], values)),
        )

    def test_a_switch_with_two_default_clauses_folds_to_nothing(self):
        """
        A second `default` clause is an early error, so the program never runs at all and there is
        no value for the call to be folded to.
        """
        source = F'{_SWITCH_WITH_TWO_DEFAULTS}\nvar x = f(9);'
        self.assertEqual(source, self._evaluate(source))

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_refuses_a_switch_with_two_default_clauses(self):
        self.assertEqual(
            ['throw SyntaxError'],
            completion_values([F'{_SWITCH_WITH_TWO_DEFAULTS}\nf(9);']),
        )


class TestAStringDenotingNothingIsIrreducible(TestJsDeobfuscator):
    """
    A string written with a `\\x` or `\\u` escape naming no character denotes nothing, so the
    interpreter has no value to reduce it to: it refuses the fold that reads one and leaves the
    expression as it was written. Reading it as a value would hand the operation `undefined` — the
    interpreter reads `None` as that — and collapse `['\\xZZ'].join('')` to the empty string. A
    well-formed operation beside it still folds, so the refusal costs no genuine reduction. The
    backslash is spelled with `chr(92)` so nothing between the source and the parser reads it as an
    escape of its own.
    """

    def test_a_join_reading_a_string_that_denotes_nothing_is_left_standing(self):
        source = inspect.cleandoc(
            F"""
            function f() {{
              return ["a", "{chr(92)}xZZ"].join("-");
            }}
            var x = f();
            """
        )
        self.assertEqual(source, self._evaluate(source))

    def test_a_well_formed_join_beside_it_still_folds(self):
        self.assertEqual("var x = 'a-b';", self._fold('["a", "b"].join("-")'))
