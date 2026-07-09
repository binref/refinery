from __future__ import annotations

import inspect

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

    def test_strict_equal_distinct_arrays_is_false(self):
        self.assertEqual('var x = false;', self._fold('[1] === [1]'))

    def test_strict_not_equal_distinct_objects_is_true(self):
        self.assertEqual('var x = true;', self._fold('({}) !== ({})'))

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
        self.assertEqual('var x = NaN;', self._fold('(-8) ** 0.5'))

    def test_math_pow_zero_base_negative_exponent_is_infinity(self):
        self.assertEqual('var x = Infinity;', self._fold('Math.pow(0, -1)'))

    def test_pow_negative_base_integer_exponent(self):
        self.assertEqual('var x = -8;', self._fold('(-2) ** 3'))

    def test_pow_overflowing_magnitude_is_infinity(self):
        # JS numbers are doubles, so a result beyond the double range is Infinity, not a Python bignum.
        self.assertEqual('var x = Infinity;', self._fold('2 ** 1024'))

    def test_pow_overflowing_negative_magnitude_is_negative_infinity(self):
        self.assertEqual('var x = -Infinity;', self._fold('(-10) ** 999'))

    def test_pow_one_to_infinity_is_nan(self):
        self.assertEqual('var x = NaN;', self._fold('1 ** Infinity'))

    def test_math_pow_one_to_infinity_is_nan(self):
        self.assertEqual('var x = NaN;', self._fold('Math.pow(1, Infinity)'))

    def test_undefined_plus_number_is_nan(self):
        # undefined coerces to NaN, null coerces to 0 — the two must stay distinct.
        self.assertEqual('var x = NaN;', self._fold('undefined + 1'))

    def test_null_plus_number_coerces_to_zero(self):
        self.assertEqual('var x = 1;', self._fold('null + 1'))

    def test_typeof_null_is_object(self):
        self.assertEqual("var x = 'object';", self._fold('typeof null'))

    def test_typeof_builtin_function_folds_to_function(self):
        self.assertEqual("var x = 'function';", self._fold('typeof parseInt'))
        self.assertEqual("var x = 'function';", self._fold('typeof encodeURIComponent'))

    def test_typeof_namespace_object_folds_to_object(self):
        self.assertEqual("var x = 'object';", self._fold('typeof Math'))

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
        self.assertEqual('var x = NaN;', self._fold("Number('-0x1F')"))

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
        self.assertEqual('var x = -Infinity;', self._fold('1 / -0'))

    def test_division_of_negative_by_negative_zero_is_positive_infinity(self):
        self.assertEqual('var x = Infinity;', self._fold('-1 / -0'))

    def test_math_round_negative_zero_observable_through_division(self):
        self.assertEqual('var x = -Infinity;', self._fold('1 / Math.round(-0.4)'))

    def test_math_round_largest_value_below_half_rounds_down(self):
        self.assertEqual('var x = 0;', self._fold('Math.round(0.49999999999999994)'))

    def test_math_max_selects_positive_over_negative_zero(self):
        self.assertEqual('var x = Infinity;', self._fold('1 / Math.max(-0, 0)'))

    def test_math_min_selects_negative_over_positive_zero(self):
        self.assertEqual('var x = -Infinity;', self._fold('1 / Math.min(-0, 0)'))

    def test_math_max_keeps_negative_zero_when_all_operands_negative_zero(self):
        self.assertEqual('var x = -Infinity;', self._fold('1 / Math.max(-0, -0)'))

    def test_math_abs_of_no_argument_is_nan(self):
        self.assertEqual('var x = NaN;', self._fold('Math.abs()'))

    def test_math_sqrt_of_no_argument_is_nan(self):
        self.assertEqual('var x = NaN;', self._fold('Math.sqrt()'))

    def test_math_sign_of_no_argument_is_nan(self):
        self.assertEqual('var x = NaN;', self._fold('Math.sign()'))

    def test_math_floor_of_no_argument_is_nan(self):
        self.assertEqual('var x = NaN;', self._fold('Math.floor()'))

    def test_math_log_of_no_argument_is_nan(self):
        self.assertEqual('var x = NaN;', self._fold('Math.log()'))


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
