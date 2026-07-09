from __future__ import annotations

import inspect

from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator


class TestBasicSimplifications(TestJsDeobfuscator):

    def test_string_concat_simple(self):
        self.assertEqual("'ab';", self._simplify("'a' + 'b';"))

    def test_string_concat_nested(self):
        self.assertEqual("'abc';", self._simplify("'a' + 'b' + 'c';"))

    def test_arithmetic_add(self):
        self.assertEqual('5;', self._simplify('2 + 3;'))

    def test_arithmetic_multiply(self):
        self.assertEqual('20;', self._simplify('10 * 2;'))

    def test_arithmetic_subtract(self):
        self.assertEqual('7;', self._simplify('10 - 3;'))

    def test_arithmetic_power(self):
        self.assertEqual('8;', self._simplify('2 ** 3;'))

    def test_arithmetic_modulo(self):
        self.assertEqual('1;', self._simplify('10 % 3;'))

    def test_arithmetic_bitwise_or(self):
        self.assertEqual('7;', self._simplify('5 | 3;'))

    def test_arithmetic_bitwise_and(self):
        self.assertEqual('1;', self._simplify('5 & 3;'))

    def test_arithmetic_bitwise_xor(self):
        self.assertEqual('6;', self._simplify('5 ^ 3;'))

    def test_arithmetic_left_shift(self):
        self.assertEqual('8;', self._simplify('1 << 3;'))

    def test_arithmetic_right_shift(self):
        self.assertEqual('2;', self._simplify('8 >> 2;'))

    def test_arithmetic_unsigned_right_shift(self):
        self.assertEqual('4294967295;', self._simplify('(-1) >>> 0;'))

    def test_arithmetic_division_by_zero_unchanged(self):
        self.assertEqual('1 / 0;', self._simplify('1 / 0;'))

    def test_tuple_all_literals(self):
        self.assertEqual("'c';", self._simplify("'a', 'b', 'c';"))

    def test_tuple_side_effect_free(self):
        self.assertEqual("'c';", self._simplify("'a', x, 'c';"))

    def test_tuple_with_side_effect(self):
        self.assertEqual("f(), 'c';", self._simplify("'a', f(), 'c';"))

    def test_array_indexing(self):
        self.assertEqual('"b";', self._simplify('["a", "b", "c"][1];'))

    def test_array_indexing_first(self):
        self.assertEqual('"x";', self._simplify('["x", "y"][0];'))

    def test_bracket_to_dot(self):
        self.assertEqual('obj.prop;', self._simplify('obj["prop"];'))

    def test_bracket_non_identifier_unchanged(self):
        self.assertEqual('obj["a-b"];', self._simplify('obj["a-b"];'))

    def test_bracket_reserved_word_unchanged(self):
        self.assertEqual('obj["class"];', self._simplify('obj["class"];'))

    def test_computed_property_key_to_identifier(self):
        self.assertEqual('({ a: 1 });', self._simplify('({ ["a"]: 1 });'))

    def test_computed_getter_key_to_identifier(self):
        self.assertEqual('({ get a() {} });', self._simplify('({ get ["a"]() {} });'))

    def test_computed_setter_key_to_identifier(self):
        self.assertEqual('({ set a(v) {} });', self._simplify('({ set ["a"](v) {} });'))

    def test_computed_accessor_proto_key_to_identifier(self):
        self.assertEqual('({ get __proto__() {} });', self._simplify('({ get ["__proto__"]() {} });'))

    def test_computed_property_non_identifier_unchanged(self):
        self.assertEqual('({ ["a-b"]: 1 });', self._simplify('({ ["a-b"]: 1 });'))

    def test_computed_property_proto_unchanged(self):
        self.assertEqual('({ ["__proto__"]: 1 });', self._simplify('({ ["__proto__"]: 1 });'))

    def test_computed_property_reserved_key_to_identifier(self):
        self.assertEqual('({ class: 1 });', self._simplify('({ ["class"]: 1 });'))

    def test_computed_method_reserved_key_to_identifier(self):
        self.assertEqual('({ return() {} });', self._simplify('({ ["return"]() {} });'))

    def test_paren_unwrap_string(self):
        self.assertEqual('"hello";', self._simplify('("hello");'))

    def test_paren_unwrap_number(self):
        self.assertEqual('42;', self._simplify('(42);'))

    def test_unary_not_zero(self):
        self.assertEqual('true;', self._simplify('!0;'))

    def test_unary_not_one(self):
        self.assertEqual('false;', self._simplify('!1;'))

    def test_typeof_string(self):
        self.assertEqual("'string';", self._simplify('typeof "x";'))

    def test_typeof_number(self):
        self.assertEqual("'number';", self._simplify('typeof 42;'))

    def test_typeof_boolean(self):
        self.assertEqual("'boolean';", self._simplify('typeof true;'))

    def test_unary_negate(self):
        self.assertEqual('-5;', self._simplify('-(5);'))

    def test_unary_plus(self):
        self.assertEqual('5;', self._simplify('+(5);'))

    def test_non_constant_unchanged(self):
        self.assertEqual('a + b;', self._simplify('a + b;'))

    def test_non_constant_member_unchanged(self):
        self.assertEqual('a[b];', self._simplify('a[b];'))

    def test_combined_deobfuscation(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var x = 'hello';
                var y = 1;
                """
            ),
            self._simplify('var x = "hel" + "lo"; var y = [1, 2, 3][0];'),
        )

    def test_unescape_hex_space(self):
        self.assertEqual("'hello world';", self._simplify("'hello\\x20world';"))

    def test_unescape_hex_mixed(self):
        self.assertEqual("'AB\\nC';", self._simplify("'A\\x42\\x0a\\x43';"))

    def test_unescape_unicode_short(self):
        self.assertEqual("'Hi';", self._simplify("'\\u0048\\u0069';"))

    def test_unescape_unicode_full(self):
        self.assertEqual("'Hello';", self._simplify("'\\u0048\\u0065\\u006c\\u006c\\u006f';"))

    def test_unescape_unicode_non_ascii(self):
        self.assertEqual("'你好';", self._simplify("'\\u4f60\\u597d';"))

    def test_unescape_preserves_quote(self):
        self.assertEqual("'don\\'t';", self._simplify("'don\\x27t';"))

    def test_unescape_preserves_backslash(self):
        self.assertEqual("'back\\\\slash';", self._simplify("'back\\x5cslash';"))

    def test_split_pipe_to_array(self):
        self.assertEqual("['a', 'b', 'c'];", self._simplify("'a|b|c'['split']('|');"))

    def test_split_dash_separator(self):
        self.assertEqual("['x', 'y'];", self._simplify("'x-y'['split']('-');"))

    def test_split_dot_notation(self):
        self.assertEqual("['a', 'b'];", self._simplify("'a|b'.split('|');"))

    def test_string_slice(self):
        self.assertEqual("'el';", self._simplify("'hello'.slice(1, 3);"))

    def test_string_char_at(self):
        self.assertEqual("'h';", self._simplify("'hello'.charAt(0);"))

    def test_string_to_lower_case(self):
        self.assertEqual("'hello';", self._simplify("'HELLO'.toLowerCase();"))

    def test_string_repeat(self):
        self.assertEqual("'abcabc';", self._simplify("'abc'.repeat(2);"))

    def test_string_replace(self):
        self.assertEqual(
            "'hello there';", self._simplify("'hello world'.replace('world', 'there');"),
        )

    def test_string_substring(self):
        self.assertEqual("'ell';", self._simplify("'hello'.substring(1, 4);"))

    def test_array_index_of(self):
        self.assertEqual("1;", self._simplify("['a', 'b', 'c'].indexOf('b');"))

    def test_array_slice(self):
        self.assertEqual("['b', 'c'];", self._simplify("['a', 'b', 'c'].slice(1);"))

    def test_atob(self):
        self.assertEqual("'Hello';", self._simplify("atob('SGVsbG8=');"))

    def test_btoa(self):
        self.assertEqual("'SGVsbG8=';", self._simplify("btoa('Hello');"))

    def test_unescape(self):
        self.assertEqual("'Hello';", self._simplify("unescape('%48%65%6C%6C%6F');"))

    def test_number_conversion(self):
        self.assertEqual("42;", self._simplify("Number('42');"))

    def test_json_parse_string(self):
        self.assertEqual("'hello';", self._simplify("JSON.parse('\"hello\"');"))

    def test_json_parse_array(self):
        self.assertEqual("[1, 2, 3];", self._simplify("JSON.parse('[1, 2, 3]');"))

    def test_json_parse_object(self):
        self.assertEqual("({ 'a': 1 });", self._simplify("JSON.parse('{\"a\": 1}');"))

    def test_no_fold_variable_receiver(self):
        self.assertEqual("x.slice(1);", self._simplify("x.slice(1);"))

    def test_no_fold_variable_arg(self):
        self.assertEqual("atob(x);", self._simplify("atob(x);"))

    def test_no_fold_unknown_method(self):
        self.assertEqual("'hello'.unknownMethod();", self._simplify("'hello'.unknownMethod();"))

    def test_no_fold_length_as_callable(self):
        self.assertEqual("'hello'.length();", self._simplify("'hello'.length();"))

    def test_no_fold_void_with_side_effect(self):
        self.assertEqual("atob(void f());", self._simplify("atob(void f());"))

    def test_array_index_of_boolean_strict(self):
        self.assertEqual("-1;", self._simplify("[1, 2].indexOf(true);"))

    def test_array_includes_boolean_strict(self):
        self.assertEqual("false;", self._simplify("[1].includes(true);"))

    def test_string_replace_dollar_match(self):
        self.assertEqual("'[a]bc';", self._simplify("'abc'.replace('a', '[$&]');"))

    def test_string_replace_dollar_escape(self):
        self.assertEqual("'$bc';", self._simplify("'abc'.replace('a', '$$');"))

    def test_math_max_with_nan_string(self):
        self.assertEqual("NaN;", self._simplify("Math.max(5, 'abc');"))

    def test_number_empty_array(self):
        self.assertEqual("0;", self._simplify("Number([]);"))

    def test_number_single_element_array(self):
        self.assertEqual("5;", self._simplify("Number([5]);"))

    def test_number_underscore_string_is_nan(self):
        self.assertEqual("NaN;", self._simplify("Number('1_000');"))

    def test_no_fold_json_parse_infinity(self):
        self.assertEqual("JSON.parse('Infinity');", self._simplify("JSON.parse('Infinity');"))


class TestDeadCodeElimination(TestJsDeobfuscator):

    def test_ternary_true(self):
        self.assertEqual(
            "var x = 'a';",
            self._simplify("var x = true ? 'a' : 'b';"),
        )

    def test_ternary_false(self):
        self.assertEqual(
            "var x = 'b';",
            self._simplify("var x = false ? 'a' : 'b';"),
        )


class TestExtendedOperatorFolding(TestJsDeobfuscator):

    def test_strict_equality_true(self):
        self.assertEqual('true;', self._simplify("'abc' === 'abc';"))

    def test_strict_equality_false(self):
        self.assertEqual('false;', self._simplify("'abc' === 'xyz';"))

    def test_strict_inequality(self):
        self.assertEqual('true;', self._simplify("'abc' !== 'xyz';"))

    def test_number_strict_equality(self):
        self.assertEqual('true;', self._simplify('42 === 42;'))

    def test_less_than_numbers(self):
        self.assertEqual('true;', self._simplify('3 < 5;'))

    def test_greater_equal_numbers(self):
        self.assertEqual('true;', self._simplify('5 >= 5;'))

    def test_less_than_strings(self):
        self.assertEqual('true;', self._simplify("'abc' < 'abd';"))

    def test_greater_than_numbers_false(self):
        self.assertEqual('false;', self._simplify('3 > 5;'))

    def test_less_equal_numbers(self):
        self.assertEqual('false;', self._simplify('7 <= 3;'))

    def test_loose_equality_same_type(self):
        self.assertEqual('true;', self._simplify('42 == 42;'))

    def test_loose_inequality_same_type(self):
        self.assertEqual('true;', self._simplify("'a' != 'b';"))

    def test_null_equality(self):
        self.assertEqual('true;', self._simplify('null == null;'))

    def test_logical_and_truthy_left(self):
        self.assertEqual("'world';", self._simplify("'hello' && 'world';"))

    def test_logical_and_falsy_left(self):
        self.assertEqual('0;', self._simplify("0 && 'world';"))

    def test_logical_or_truthy_left(self):
        self.assertEqual("'hello';", self._simplify("'hello' || 'world';"))

    def test_logical_or_falsy_left(self):
        self.assertEqual("'fallback';", self._simplify("'' || 'fallback';"))

    def test_nullish_coalescing_null(self):
        self.assertEqual("'default';", self._simplify("null ?? 'default';"))

    def test_nullish_coalescing_value(self):
        self.assertEqual('42;', self._simplify("42 ?? 'default';"))

    def test_bitwise_not_zero(self):
        self.assertEqual('-1;', self._simplify('~0;'))

    def test_bitwise_not_negative_one(self):
        self.assertEqual('0;', self._simplify('~(-1);'))

    def test_logical_not_true(self):
        self.assertEqual('false;', self._simplify('!true;'))

    def test_logical_not_false(self):
        self.assertEqual('true;', self._simplify('!false;'))

    def test_logical_not_null(self):
        self.assertEqual('true;', self._simplify('!null;'))

    def test_logical_not_empty_string(self):
        self.assertEqual('true;', self._simplify("!'';"))

    def test_logical_not_nonempty_string(self):
        self.assertEqual('false;', self._simplify("!'hello';"))

    def test_logical_not_undefined(self):
        self.assertEqual('true;', self._simplify('!undefined;'))

    def test_logical_not_empty_array(self):
        self.assertEqual('false;', self._simplify('![];'))

    def test_double_bang_array(self):
        self.assertEqual('true;', self._simplify('!![];'))

    def test_parseint_fold(self):
        self.assertEqual('3379;', self._simplify("parseInt('3379kkQfix');"))

    def test_parseint_no_leading_digits(self):
        self.assertEqual("parseInt('abc');", self._simplify("parseInt('abc');"))

    def test_parseint_hex_radix_folded(self):
        self.assertEqual('255;', self._simplify("parseInt('0xFF', 16);"))

    def test_parseint_binary_radix(self):
        self.assertEqual('2;', self._simplify("parseInt('10', 2);"))

    def test_parseint_unknown_radix_preserved(self):
        self.assertEqual("parseInt('ff', radix);", self._simplify("parseInt('ff', radix);"))

    def test_from_char_code_direct(self):
        self.assertEqual("'GET';", self._simplify('String.fromCharCode(71, 69, 84);'))

    def test_iife_inline_comparison(self):
        self.assertEqual(
            'false;',
            self._deobfuscate("(function(a, b) { return a === b; })('x', 'y');"),
        )

    def test_iife_inline_nested(self):
        source = (
            "if ((function(a, b) { return a !== b; })('VpDUG', 'ULVFR'))"
            " { live(); } else { dead(); }"
        )
        self.assertEqual('live();', self._deobfuscate(source))

    def test_iife_inline_member_access_arg(self):
        source = "var r = (function(a, b) { return a < b; })(x, y.length);"
        self.assertEqual('var r = x < y.length;', self._simplify(source))

    def test_iife_inline_computed_member_arg(self):
        source = "var r = (function(a, b) { return a <= b; })(arr[0], x);"
        self.assertEqual('var r = arr[0] <= x;', self._simplify(source))

    def test_iife_inline_leaves_param_named_property_key(self):
        source = 'var r = (function(a, b) { return b.a; })(1, obj);'
        self.assertEqual('var r = obj.a;', self._simplify(source))

    def test_iife_inline_substitutes_computed_property(self):
        source = 'var r = (function(a, b) { return b[a]; })(0, arr);'
        self.assertEqual('var r = arr[0];', self._simplify(source))

    def test_iife_returning_shadowing_function_keeps_inner_parameter(self):
        source = 'var r = (function(a) { return function(a) { return a; }; })(5);'
        self.assertEqual('var r = function(a) {\n  return a;\n};', self._simplify(source))

    def test_iife_inlines_bare_parameter_return(self):
        source = 'var r = (function(a) { return a; })(7);'
        self.assertEqual('var r = 7;', self._simplify(source))

    def test_iife_object_shorthand_substitutes_value_not_property_name(self):
        source = 'var r = (function(a) { return {a}; })(7);'
        self.assertEqual('var r = { a: 7 };', self._simplify(source))

    def test_iife_object_shorthand_substitutes_value_with_nested_scope(self):
        source = 'var r = (function(a) { return [{a}, function() { return a; }]; })(7);'
        self.assertEqual(
            'var r = [{ a: 7 }, function() {\n  return 7;\n}];', self._simplify(source))

    def test_iife_not_inlined_when_parameter_is_assigned(self):
        self.assertEqual(
            '(function(v) {\n  return v = 1;\n})(2);',
            self._simplify('(function (v) { return (v = 1); })(2);'))

    def test_iife_not_inlined_when_parameter_is_compound_assigned(self):
        self.assertEqual(
            '(function(v) {\n  return v += 1;\n})(2);',
            self._simplify('(function (v) { return (v += 1); })(2);'))

    def test_iife_inlined_when_parameter_only_read(self):
        self.assertEqual('2 + 1;', self._simplify('(function (v) { return (v + 1); })(2);'))

    def test_iife_preserves_conditional_effectful_arg(self):
        source = inspect.cleandoc(
            """
            var r = (function(a, b) {
              return a || b;
            })(x, y.z);
            """
        )
        self.assertEqual(source, self._simplify(source))

    def test_iife_preserves_reordered_effectful_args(self):
        source = inspect.cleandoc(
            """
            var r = (function(a, b) {
              return b + a;
            })(x.y, z.w);
            """
        )
        self.assertEqual(source, self._simplify(source))

    def test_pure_call_argument_used_twice_not_duplicated(self):
        """
        `x` is used twice, so substituting would duplicate the argument. Only a simple literal or
        identifier may be duplicated; a call (or a fresh array/object) could split one value into
        distinct copies — flipping an identity comparison — so the IIFE is left intact even though `p`
        here is pure.
        """
        source = inspect.cleandoc(
            """
            function p() {
              return 1;
            }
            var r = (function(x) {
              return x + x;
            })(p());
            """
        )
        self.assertEqual(source, self._simplify(source))

    def test_iife_does_not_duplicate_array_argument_used_twice(self):
        """
        `a` is used twice and the argument `[1]` is a fresh array, so substituting it would compare two
        distinct arrays (`[1] === [1]` is false) instead of one array with itself; the IIFE is left
        intact.
        """
        source = inspect.cleandoc(
            """
            var r = (function(a) {
              return a === a;
            })([1]);
            """
        )
        self.assertEqual(source, self._simplify(source))

    def test_nullish_coalescing_undefined(self):
        self.assertEqual("'default';", self._simplify("undefined ?? 'default';"))

    def test_logical_and_undefined(self):
        self.assertEqual('undefined;', self._simplify("undefined && 'world';"))

    def test_logical_or_undefined(self):
        self.assertEqual("'fallback';", self._simplify("undefined || 'fallback';"))


class TestDeadCodeLiteralConditions(TestJsDeobfuscator):

    def test_ternary_zero(self):
        self.assertEqual("var x = 'b';", self._simplify("var x = 0 ? 'a' : 'b';"))

    def test_ternary_nonempty_string(self):
        self.assertEqual("var x = 'a';", self._simplify("var x = 'yes' ? 'a' : 'b';"))

    def test_ternary_undefined(self):
        self.assertEqual("var x = 'b';", self._simplify("var x = undefined ? 'a' : 'b';"))


class TestRegressionBugs(TestJsDeobfuscator):

    def test_bitwise_ops_use_signed_32bit(self):
        cases = [
            ('0xFFFFFFFF | 0', '-1'),
            ('0x80000000 | 0', '-2147483648'),
            ('0x80000000 ^ 0', '-2147483648'),
            ('       1 << 31', '-2147483648'),
        ]
        for expr, expected in cases:
            source = F'var x = {expr};'
            self.assertEqual(
                self._simplify(source),
                F'var x = {expected};',
                F'{expr} should fold to {expected}',
            )

    def test_modulo_uses_truncated_remainder(self):
        self.assertEqual('var x = -1;', self._simplify('var x = (-7) % 3;'))

    def test_split_empty_separator(self):
        self.assertEqual(
            self._simplify('var x = "hello".split("");'),
            "var x = ['h', 'e', 'l', 'l', 'o'];",
        )

    def test_void_0_not_replaced_with_undefined(self):
        source = inspect.cleandoc(
            """
            function f(undefined) {
              return void 0 === undefined;
            }
            """
        )
        self.assertEqual(source, self._simplify(source))

    def test_split_empty_sep_emoticon(self):
        self.assertEqual(
            self._simplify("var x = '\U0001f600'.split('');"),
            "var x = ['\\uD83D', '\\uDE00'];",
        )

    def test_negative_zero_literal(self):
        self.assertEqual('var x = -0;', self._simplify('var x = -(0);'))

    def test_zero_times_negative_is_negative_zero(self):
        self.assertEqual('-0;', self._simplify('0 * -5;'))

    def test_negative_times_zero_is_negative_zero(self):
        self.assertEqual('-0;', self._simplify('-3 * 0;'))

    def test_like_signed_zero_product_is_positive_zero(self):
        self.assertEqual('0;', self._simplify('-0 * -5;'))

    def test_positive_zero_product_is_unsigned(self):
        self.assertEqual('0;', self._simplify('0 * 5;'))


class TestParenthesizedExpressionStripping(TestJsDeobfuscator):

    def test_iife_parens_preserved(self):
        source = inspect.cleandoc(
            """
            (function() {
              var x = 1;
              console.log(x);
            })();
            """
        )
        self.assertEqual(source, self._simplify(source))

    def test_bare_identifier_parens_stripped(self):
        self.assertEqual('var x = y;', self._simplify('var x = (y);'))


class TestParenthesisPreservation(TestJsDeobfuscator):

    def test_paren_preserved_when_inner_has_lower_precedence(self):
        self.assertEqual('var x = (a | b) & c;', self._simplify('var x = (a | b) & c;'))

    def test_paren_preserved_when_inner_is_ternary_inside_binop(self):
        self.assertEqual(
            'var x = (a ? b : c) + d;',
            self._simplify('var x = (a ? b : c) + d;'),
        )

    def test_paren_dropped_when_inner_has_higher_precedence(self):
        self.assertEqual('var x = a + b * c;', self._simplify('var x = a + (b * c);'))

    def test_paren_dropped_around_primary(self):
        self.assertEqual('var x = a + b;', self._simplify('var x = (a) + (b);'))

    def test_paren_preserved_for_right_side_of_same_precedence(self):
        self.assertEqual('var x = a - (b - c);', self._simplify('var x = a - (b - c);'))

    def test_paren_dropped_for_left_side_of_same_precedence(self):
        self.assertEqual('var x = a - b - c;', self._simplify('var x = (a - b) - c;'))

    def test_paren_preserved_for_conditional_as_ternary_test(self):
        self.assertEqual(
            'var x = (a ? b : c) ? d : e;',
            self._simplify('var x = (a ? b : c) ? d : e;'),
        )

    def test_paren_preserved_for_assignment_as_ternary_test(self):
        self.assertEqual(
            'var x = (a = b) ? c : d;',
            self._simplify('var x = (a = b) ? c : d;'),
        )

    def test_paren_preserved_for_numeric_literal_member_object(self):
        self.assertEqual(
            'var x = (5).toString();',
            self._simplify('var x = (5).toString();'),
        )

    def test_paren_dropped_for_numeric_literal_computed_member(self):
        self.assertEqual('var x = 5[k];', self._simplify('var x = (5)[k];'))

    def test_paren_preserved_for_nested_negation(self):
        self.assertEqual('var x = -(-a);', self._simplify('var x = -(-a);'))

    def test_paren_preserved_for_nested_unary_plus(self):
        self.assertEqual('var x = +(+a);', self._simplify('var x = +(+a);'))

    def test_paren_dropped_for_double_logical_not(self):
        self.assertEqual('var x = !!a;', self._simplify('var x = !(!a);'))

    def test_paren_preserved_for_unary_base_of_exponentiation(self):
        self.assertEqual('var x = (-a) ** b;', self._simplify('var x = (-a) ** b;'))

    def test_paren_preserved_for_call_as_new_callee(self):
        self.assertEqual('var x = new (f())();', self._simplify('var x = new (f())();'))

    def test_paren_preserved_for_logical_as_new_callee(self):
        self.assertEqual('var x = new (a || b)();', self._simplify('var x = new (a || b)();'))

    def test_paren_preserved_for_call_in_new_callee_spine(self):
        self.assertEqual('var x = new (a().b)();', self._simplify('var x = new (a().b)();'))

    def test_paren_dropped_for_member_chain_new_callee(self):
        self.assertEqual('var x = new a.b.c();', self._simplify('var x = new (a.b.c)();'))

    def test_paren_preserved_for_operator_tag_of_tagged_template(self):
        self.assertEqual('var r = (a + b)`x`;', self._simplify('var r = (a + b)`x`;'))

    def test_paren_dropped_for_member_tag_of_tagged_template(self):
        self.assertEqual('var r = a.b`x`;', self._simplify('var r = (a.b)`x`;'))

    def test_paren_preserved_for_operator_class_super(self):
        self.assertEqual(
            'var C = class extends (a + b) {};',
            self._simplify('var C = class extends (a + b) {};'),
        )

    def test_paren_dropped_for_member_class_super(self):
        self.assertEqual(
            'var C = class extends a.b {};',
            self._simplify('var C = class extends (a.b) {};'),
        )

    def test_paren_preserved_for_nullish_under_logical_or(self):
        self.assertEqual('var x = (a ?? b) || c;', self._simplify('var x = (a ?? b) || c;'))

    def test_paren_preserved_for_logical_or_under_nullish(self):
        self.assertEqual('var x = (a || b) ?? c;', self._simplify('var x = (a || b) ?? c;'))

    def test_paren_preserved_for_logical_and_under_nullish(self):
        self.assertEqual('var x = a ?? (b && c);', self._simplify('var x = a ?? (b && c);'))

    def test_paren_dropped_for_nullish_chain(self):
        self.assertEqual('var x = a ?? b ?? c;', self._simplify('var x = (a ?? b) ?? c;'))

    def test_paren_preserved_for_optional_chain_member_object(self):
        self.assertEqual('var x = (a?.b).c;', self._simplify('var x = (a?.b).c;'))

    def test_paren_preserved_for_optional_chain_call_callee(self):
        self.assertEqual('var x = (a?.b)();', self._simplify('var x = (a?.b)();'))

    def test_paren_preserved_for_optional_chain_new_callee(self):
        self.assertEqual('new (a?.b)();', self._simplify('new (a?.b)();'))

    def test_paren_dropped_for_plain_member_chain(self):
        self.assertEqual('var x = a.b.c;', self._simplify('var x = (a.b).c;'))

    def test_paren_preserved_for_prefix_update_as_exponent_left_operand(self):
        self.assertEqual('var x = (++a) ** 2;', self._simplify('var x = (++a) ** 2;'))

    def test_paren_preserved_for_await_as_exponent_left_operand(self):
        source = 'async function f() {\n  var x = (await a) ** 2;\n}'
        self.assertEqual(source, self._simplify(source))

    def test_paren_preserved_for_destructuring_assignment_statement(self):
        self.assertEqual('({ a } = obj);', self._simplify('({ a } = obj);'))

    def test_paren_preserved_for_prefix_update_in_member_object(self):
        self.assertEqual('(++a).foo;', self._simplify('(++a).foo;'))

    def test_paren_preserved_for_postfix_update_in_member_object(self):
        self.assertEqual('(a++).foo;', self._simplify('(a++).foo;'))

    def test_paren_preserved_for_postfix_update_as_call_callee(self):
        self.assertEqual('(a++)();', self._simplify('(a++)();'))

    def test_paren_preserved_for_optional_tagged_template_as_member_object(self):
        self.assertEqual('var x = (a?.b`s`).c;', self._simplify('var x = (a?.b`s`).c;'))

    def test_paren_preserved_for_optional_chain_as_tagged_template_tag(self):
        self.assertEqual('var x = (a?.b)`s`;', self._simplify('var x = (a?.b)`s`;'))

    def test_paren_dropped_for_plain_tagged_template_as_member_object(self):
        self.assertEqual('var x = a.b`s`.c;', self._simplify('var x = (a.b`s`).c;'))

    def test_paren_preserved_for_sequence_in_conditional_consequent(self):
        self.assertEqual(
            'var x = a ? (f(), g()) : d;',
            self._simplify('var x = a ? (f(), g()) : d;'),
        )

    def test_paren_preserved_for_arrow_in_binary_left(self):
        self.assertEqual('var x = (() => y) + b;', self._simplify('var x = (() => y) + b;'))

    def test_paren_preserved_for_assignment_in_binary_right(self):
        self.assertEqual('var x = a + (b = c);', self._simplify('var x = a + (b = c);'))

    def test_paren_preserved_for_same_precedence_right_subtraction(self):
        self.assertEqual('var x = a - (b - c);', self._simplify('var x = a - (b - c);'))

    def test_paren_dropped_for_same_precedence_left_subtraction(self):
        self.assertEqual('var x = a - b - c;', self._simplify('var x = (a - b) - c;'))

    def test_paren_preserved_for_destructuring_assignment_arrow_body(self):
        self.assertEqual('var f = () => ({ a } = obj);', self._simplify('var f = () => ({ a } = obj);'))


class TestGlobalAliasStripping(TestJsDeobfuscator):

    def test_free_name_alias_member_not_stripped(self):
        """
        `X` is free — a bare read would throw where `globalThis.X` yields `undefined` — so the alias
        member is preserved rather than collapsed into a `ReferenceError`.
        """
        self.assertEqual('y = globalThis.X;', self._simplify('y = globalThis.X;'))

    def test_guaranteed_global_alias_member_stripped(self):
        self.assertEqual('y = String;', self._simplify('y = globalThis.String;'))

    def test_implicit_global_alias_member_stripped_after_dominating_write(self):
        source = inspect.cleandoc(
            """
            X = 5;
            y = globalThis.X;
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                X = 5;
                y = X;
                """
            ),
            self._simplify(source),
        )

    def test_implicit_global_alias_member_not_stripped_before_its_write(self):
        """
        `globalThis.X` is read before the write that makes `X` an implicit global, so a bare read there
        would throw where the member read is `undefined`; the alias member is preserved.
        """
        source = inspect.cleandoc(
            """
            f(globalThis.X);
            X = 5;
            """
        )
        self.assertEqual(source, self._simplify(source))

    def test_global_alias_preserved_when_locally_shadowed(self):
        source = inspect.cleandoc(
            """
            var X = 1;
            y = globalThis.X;
            """
        )
        self.assertEqual(source, self._simplify(source))

    def test_host_global_alias_member_not_stripped(self):
        """
        `console` exists in every mainstream host but is not spec-mandated, so the analyzer cannot prove
        a bare read resolves; the alias member is conservatively preserved.
        """
        self.assertEqual('y = window.console;', self._simplify('y = window.console;'))

    def test_global_alias_preserved_when_shadowed_by_param(self):
        source = inspect.cleandoc(
            """
            function f(X) {
              return globalThis.X;
            }
            """
        )
        self.assertEqual(source, self._simplify(source))

    def test_global_alias_preserved_when_shadowed_by_catch_param(self):
        source = inspect.cleandoc(
            """
            try {
              f();
            } catch (X) {
              y = globalThis.X;
            }
            """
        )
        self.assertEqual(source, self._simplify(source))

    def test_global_alias_preserved_when_shadowed_by_destructuring(self):
        source = inspect.cleandoc(
            """
            var { X } = obj;
            y = globalThis.X;
            """
        )
        self.assertEqual(source, self._simplify(source))

    def test_global_alias_preserved_when_shadowed_by_class(self):
        source = inspect.cleandoc(
            """
            class X {}
            y = globalThis.X;
            """
        )
        self.assertEqual(source, self._simplify(source))

    def test_shadowed_base_via_param_not_stripped(self):
        """
        The base `self` is a parameter, not the global object, so `self.foo` reads that argument's
        property; stripping to bare `foo` would read a different (global) name.
        """
        source = inspect.cleandoc(
            """
            function f(self) {
              return self.foo;
            }
            """
        )
        self.assertEqual(source, self._simplify(source))

    def test_shadowed_base_via_var_not_stripped(self):
        source = inspect.cleandoc(
            """
            var self = obj;
            y = self.foo;
            """
        )
        self.assertEqual(source, self._simplify(source))

    def test_const_aliased_base_not_stripped(self):
        """
        A base reached only through a `const` alias of the global object is conservatively preserved:
        proving the alias equals the global is a value-provenance question this syntactic collapse no
        longer attempts.
        """
        source = inspect.cleandoc(
            """
            const w = window;
            y = w.foo;
            """
        )
        self.assertEqual(source, self._simplify(source))

    def test_free_name_alias_member_in_argument_not_stripped(self):
        self.assertEqual('f(globalThis.X);', self._simplify('f(globalThis.X);'))

    def test_global_alias_not_stripped_from_call_callee(self):
        """
        Stripping `window` from the callee of `window.foo()` would call `foo` with no receiver instead
        of with `window` as `this`, so the alias is kept in callee position even though it is stripped
        from a value position.
        """
        self.assertEqual('window.foo();', self._simplify('window.foo();'))

    def test_alias_eval_callee_not_de_indirected(self):
        """
        `window.eval(code)` is an indirect eval evaluated in the global scope; stripping the alias to
        `eval(code)` would make it a direct eval evaluated in the caller's scope, so the alias is kept.
        """
        self.assertEqual("window.eval('x');", self._simplify("window.eval('x');"))


class TestCalleeSequencePreserved(TestJsDeobfuscator):

    def test_sequence_folded_in_statement_position(self):
        self.assertEqual('x;', self._simplify('(0, x);'))

    def test_sequence_callee_not_collapsed_for_indirect_eval(self):
        """
        `(0, eval)(code)` is an indirect eval evaluated in the global scope; collapsing the callee
        sequence to `eval(code)` would make it a direct eval evaluated in the caller's scope, so the
        sequence is kept.
        """
        self.assertEqual("(0, eval)('x');", self._simplify("(0, eval)('x');"))

    def test_sequence_callee_not_collapsed_for_method_receiver(self):
        """
        `(0, o.m)()` invokes `o.m` with no receiver; collapsing the callee sequence to `o.m()` would
        bind `this` to `o`, so the sequence is kept.
        """
        self.assertEqual('(0, o.m)();', self._simplify('(0, o.m)();'))

    def test_sequence_callee_collapsed_for_plain_identifier(self):
        """
        `(0, f)(x)` invokes the plain identifier `f` with no receiver, exactly as `f(x)` does — only a
        member or `eval` callee, whose reference form the sequence protects, must be kept — so the
        indirect-call idiom collapses.
        """
        self.assertEqual('f(x);', self._simplify('(0, f)(x);'))
