from __future__ import annotations

import inspect
import unittest

from test.lib.scripts.js.analysis.differential import behavior, node_executable
from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator

from refinery.lib.scripts.js.analysis.environment import HostEnvironment
from refinery.lib.scripts.js.deobfuscation.simplify import JsSimplifications
from refinery.lib.scripts.js.options import DeobfuscationOptions
from refinery.units.scripting.js import js

_ASTRAL = chr(0x1F600)

_SPANNING = F"'a{_ASTRAL}b'"
"""
A JavaScript string literal whose middle character is above the basic multilingual plane. It is
four code units long and JavaScript indexes it as `a`, a high surrogate, a low surrogate, `b`,
while Python sees three code points, so every offset past the middle character differs by one.
"""


def _folded_value(expression: str) -> str:
    """
    The text `refinery.js` prints for *expression* once it has folded it. The expression is placed
    in the argument of a `console.log` call, which survives because it is a side effect, so nothing
    but the fold decides what comes back.
    """
    printed = F'console.log({expression});'.encode('utf8') | js() | str
    return printed.removeprefix('console.log(').removesuffix(');')


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

    def test_string_of_negative_infinity(self):
        self.assertEqual(
            "console.log('-Infinity');", self._simplify('console.log(String(-Infinity));'))

    def test_arithmetic_division_by_zero(self):
        self.assertEqual('1e999;', self._simplify('1 / 0;'))

    def test_arithmetic_zero_divided_by_zero_unchanged(self):
        self.assertEqual('0 / 0;', self._simplify('0 / 0;'))

    def test_tuple_all_literals(self):
        self.assertEqual("'c';", self._simplify("'a', 'b', 'c';"))

    def test_tuple_side_effect_free(self):
        """
        A resolved read cannot throw and carries no other effect, so the middle operand is dropped;
        a free `x` would throw a `ReferenceError` and is kept by
        `TestASequenceOperandThatMayThrowIsKept`.
        """
        self.assertEqual("var x = 0;\n'c';", self._simplify("var x = 0;\n'a', x, 'c';"))

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
        self.assertEqual("0 / 0;", self._simplify("Math.max(5, 'abc');"))

    def test_number_empty_array(self):
        self.assertEqual("0;", self._simplify("Number([]);"))

    def test_number_single_element_array(self):
        self.assertEqual("5;", self._simplify("Number([5]);"))

    def test_number_underscore_string_is_nan(self):
        self.assertEqual("0 / 0;", self._simplify("Number('1_000');"))

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

    def test_parseint_no_leading_digits_folds_to_the_not_a_number_it_names(self):
        """
        Node prints `NaN` for `parseInt('abc')`: a string whose first character is not a digit of
        the radix names no number, which is a result the language settles as fully as any other.
        """
        self.assertEqual('0 / 0;', self._simplify("parseInt('abc');"))

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

    def test_iife_inline_member_arg_landing_as_callee_is_neutralized(self):
        source = (
            'var o = { f: function () { return this === o; } };'
            ' console.log(function (a) { return a; }(o.f)());'
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                var o = { f: function() {
                  return this === o;
                } };
                console.log((0, o.f)());
                """
            ),
            self._simplify(source),
        )

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

    def test_implicit_global_alias_member_stripped_inside_a_function_called_after_the_write(self):
        """
        The read stands in a body no statement order relates to the write, but every call of `f` runs
        after it, so the definite-assignment model carries the fact through the call site into the
        body and the alias member collapses there too.
        """
        source = inspect.cleandoc(
            """
            X = 5;
            function f() {
              return globalThis.X;
            }
            console.log(f());
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                X = 5;
                function f() {
                  return X;
                }
                console.log(f());
                """
            ),
            self._simplify(source),
        )

    def test_implicit_global_alias_member_stripped_after_a_member_spelled_write(self):
        """
        `globalThis.X = 5` creates the property in either mode, so the later read collapses; the
        write itself keeps its member spelling, being a write and not a read.
        """
        source = inspect.cleandoc(
            """
            globalThis.X = 5;
            y = globalThis.X;
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                globalThis.X = 5;
                y = X;
                """
            ),
            self._simplify(source),
        )

    def test_implicit_global_alias_member_not_stripped_where_a_delete_addresses_the_name(self):
        """
        A `delete` anywhere in the program can unbind the name between the write and the read, so no
        fact about it may be trusted; both spellings of the delete refuse the collapse.
        """
        for spelling in ['delete globalThis.X;', 'delete X;']:
            source = F'X = 5;\n{spelling}\ny = globalThis.X;'
            with self.subTest(spelling=spelling):
                self.assertEqual(source, self._simplify(source))

    def test_implicit_global_alias_member_not_stripped_where_a_computed_delete_hides_its_base(self):
        """
        `someObj` is a name nothing pins, so it may hold the global object and the delete may unbind
        `X` with a key no scan reads; the collapse fails closed. The control allocates the base in
        the file, which provably is not the global object, so the same delete forgets nothing.
        """
        source = inspect.cleandoc(
            """
            X = 5;
            delete someObj[k];
            y = globalThis.X;
            """
        )
        self.assertEqual(source, self._simplify(source))
        control = inspect.cleandoc(
            """
            var o = {};
            X = 5;
            delete o[k];
            y = globalThis.X;
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                var o = {};
                X = 5;
                delete o[k];
                y = X;
                """
            ),
            self._simplify(control),
        )

    def test_implicit_global_alias_member_stripped_after_a_destructuring_write(self):
        """
        A destructuring assignment that completes normally has assigned every target it holds, so
        the later read collapses exactly as it does behind a plain store.
        """
        source = inspect.cleandoc(
            """
            [X] = [5];
            y = globalThis.X;
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                [X] = [5];
                y = X;
                """
            ),
            self._simplify(source),
        )

    def test_implicit_global_alias_member_not_stripped_inside_a_host_entrypoint(self):
        """
        With `f` declared a host entrypoint, the host calls it from outside the file, so the guarded
        in-file call does not bound when the body runs and the member read must keep answering
        `undefined` there.
        """
        source = inspect.cleandoc(
            """
            var c = 0;
            function f() {
              return globalThis.X;
            }
            if (c) {
              X = 1;
              console.log(f());
            }
            """
        )
        self.assertEqual(
            source,
            self._run_transformer(
                source, JsSimplifications, options=DeobfuscationOptions(entrypoints=('f',))),
        )

    def test_implicit_global_alias_member_not_stripped_where_the_global_object_is_handed_out(self):
        """
        The body `d` runs deletes the property the read would find, and the file names that body
        only through the object it hands over, so the write vouches for nothing after the call.
        """
        source = inspect.cleandoc(
            """
            function d(o) {
              delete o.X;
            }
            X = 5;
            d(globalThis);
            y = globalThis.X;
            """
        )
        self.assertEqual(source, self._simplify(source))

    def test_implicit_global_alias_member_not_stripped_where_the_write_is_strict(self):
        """
        In strict code an assignment to an undeclared name throws instead of creating the property,
        so the write establishes nothing and the alias member is preserved.
        """
        source = inspect.cleandoc(
            """
            function s() {
              'use strict';
              X = 5;
            }
            s();
            y = globalThis.X;
            """
        )
        self.assertEqual(source, self._simplify(source))

    def test_implicit_global_alias_member_not_stripped_under_a_reflection_surface(self):
        """
        A direct `eval` between the write and the read can unbind the name with code no scan reads,
        so a reflection-reachable binding is never vouched for.
        """
        source = inspect.cleandoc(
            """
            X = 5;
            eval(c);
            y = globalThis.X;
            """
        )
        self.assertEqual(source, self._simplify(source))

    def test_implicit_global_alias_member_not_stripped_after_another_realms_write(self):
        """
        `top` and `frames` name another document's global object, so a write through either creates
        no property a bare name in this file reads.
        """
        for alias in ['top', 'frames']:
            source = F'{alias}.X = 5;\ny = globalThis.X;'
            with self.subTest(alias=alias):
                self.assertEqual(source, self._simplify(source))

    def test_implicit_global_alias_member_not_stripped_after_a_conditional_write(self):
        """
        The write completes only on the branch its guard takes, so no fact holds at the read.
        """
        source = inspect.cleandoc(
            """
            cond && (X = 5);
            y = globalThis.X;
            """
        )
        self.assertEqual(source, self._simplify(source))

    def test_implicit_global_alias_member_not_stripped_after_a_write_an_empty_finally_returns_past(
        self
    ):
        """
        `w()` returns without writing whenever `cond` is falsy, so the read may find no property and
        the member spelling is what keeps it answering `undefined` instead of throwing.
        """
        source = inspect.cleandoc(
            """
            function w() {
              if (cond) {
                X = 5;
                return;
              }
              try {
                g();
              } finally {}
            }
            w();
            y = globalThis.X;
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

    def test_global_object_existence_guard_folded(self):
        self.assertEqual('var g = globalThis;', self._simplify('var g = globalThis || {};'))

    def test_intrinsic_existence_guard_folded(self):
        self.assertEqual('var s = String;', self._simplify('var s = String || String;'))

    def test_host_alias_existence_guard_not_folded(self):
        self.assertEqual('var g = window || {};', self._simplify('var g = window || {};'))

    def test_falsy_global_existence_guard_answers_from_the_value_not_the_existence(self):
        """
        `NaN` exists, so the existence shortcut that folds `String || String` to its left operand would
        answer `NaN` here. `NaN` is also falsy, so the operator answers `5`.
        """
        self.assertEqual('var s = 5;', self._simplify('var s = NaN || 5;'))

    def test_local_global_object_alias_member_stripped(self):
        source = inspect.cleandoc(
            """
            var g = globalThis || {};
            var s = g.String;
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                var g = globalThis;
                var s = String;
                """
            ),
            self._simplify(source),
        )

    def test_local_global_object_alias_member_before_establishment_not_stripped(self):
        source = inspect.cleandoc(
            """
            var s = g.String;
            var g = globalThis || {};
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                var s = g.String;
                var g = globalThis;
                """
            ),
            self._simplify(source),
        )

    def test_in_operator_folds_absent_key_for_established_empty_object(self):
        source = inspect.cleandoc(
            """
            var obj = {};
            var a = 'x' in obj;
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                var obj = {};
                var a = false;
                """
            ),
            self._simplify(source),
        )

    def test_in_operator_folds_present_key_for_store_before_read(self):
        source = inspect.cleandoc(
            """
            var obj = {};
            obj.x = 1;
            var a = 'x' in obj;
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                var obj = {};
                obj.x = 1;
                var a = true;
                """
            ),
            self._simplify(source),
        )

    def test_in_operator_not_folded_before_object_initializer_runs(self):
        """
        At the `in`, `obj` is still its hoisted `undefined`, so `'x' in obj` throws a `TypeError` at
        runtime rather than reading an empty object. Folding it to `false` would delete that throw, so the
        establishment gate must decline until the declarator runs.
        """
        source = inspect.cleandoc(
            """
            var a = 'x' in obj;
            var obj = {};
            """
        )
        self.assertEqual(source, self._simplify(source))

    def test_in_operator_not_folded_for_store_after_read(self):
        """
        The `obj.x = 1` store runs after the read, so the property is absent when `'x' in obj` evaluates;
        the store cannot make the key present at the read and must not fold the membership to `true`.
        """
        source = inspect.cleandoc(
            """
            var obj = {};
            var a = 'x' in obj;
            obj.x = 1;
            """
        )
        self.assertEqual(source, self._simplify(source))

    def test_in_operator_not_folded_when_key_deleted_before_read(self):
        """
        The property is stored then deleted before the read, so it is absent when `'x' in obj` evaluates;
        a store the membership check trusts must not be one a `delete` can remove first.
        """
        source = inspect.cleandoc(
            """
            var obj = {};
            obj.x = 1;
            delete obj.x;
            var a = 'x' in obj;
            """
        )
        self.assertEqual(source, self._simplify(source))

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


class TestMembershipOverAWrittenPrototypeChain(TestJsDeobfuscator):
    """
    `in` asks whether a key is reachable on the receiver or anywhere up its prototype chain, so a
    receiver whose own keys the pass can read whole decides the question only while the chain behind
    it is one the program has not written. Each test below is that pair: the same receiver and the
    same key, folded where nothing wrote the chain and left standing where something did.
    """

    def test_absent_key_over_a_function_folds_only_while_its_chain_is_untouched(self):
        untouched = inspect.cleandoc(
            """
            function g() {}
            var a = 'zz' in g;
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                function g() {}
                var a = false;
                """
            ),
            self._simplify(untouched),
        )
        written = inspect.cleandoc(
            """
            Object.prototype.qq = 'X';
            function g() {}
            var a = 'zz' in g;
            """
        )
        self.assertEqual(written, self._simplify(written))

    def test_absent_key_over_a_class_folds_only_while_its_chain_is_untouched(self):
        untouched = inspect.cleandoc(
            """
            class C {}
            var a = 'zz' in C;
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                class C {}
                var a = false;
                """
            ),
            self._simplify(untouched),
        )
        written = inspect.cleandoc(
            """
            Object.prototype.qq = 'X';
            class C {}
            var a = 'zz' in C;
            """
        )
        self.assertEqual(written, self._simplify(written))

    def test_absent_key_over_an_object_literal_folds_only_while_its_chain_is_untouched(self):
        untouched = inspect.cleandoc(
            """
            var obj = {};
            var a = 'zz' in obj;
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                var obj = {};
                var a = false;
                """
            ),
            self._simplify(untouched),
        )
        written = inspect.cleandoc(
            """
            Object.prototype.qq = 'X';
            var obj = {};
            var a = 'zz' in obj;
            """
        )
        self.assertEqual(written, self._simplify(written))

    def test_absent_key_over_an_object_literal_folds_past_a_write_to_another_chain(self):
        """
        `Array.prototype` is not on a plain object's chain, so a write to it cannot answer `'zz' in
        obj` and cannot be a reason to decline. Refusing here would make any prototype write
        anywhere in the file the end of this fold rather than a write to the chain that decides it.
        """
        source = inspect.cleandoc(
            """
            Array.prototype.qq = 'X';
            var obj = {};
            var a = 'zz' in obj;
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                Array.prototype.qq = 'X';
                var obj = {};
                var a = false;
                """
            ),
            self._simplify(source),
        )


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
        self.assertEqual('f(x);', self._simplify('(0, f)(x);'))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestASequenceOperandThatMayThrowIsKept(TestJsDeobfuscator):
    """
    Every operand of a sequence is evaluated in order and every one but the last has its value
    discarded, but discarding the value is not licence to skip the evaluation: a bare read of a
    name no binding resolves throws a `ReferenceError` before the operands behind it, so dropping
    it lets a program that ended there run on.
    """

    def test_a_throwing_operand_is_kept_at_the_head_of_a_statement(self):
        """
        Node refuses `missing, console.log(1);` with a `ReferenceError` and prints nothing; the
        simplification has to throw the same way rather than come back printing `1`.
        """
        self.assertEqual(
            behavior(self._simplify('missing, console.log(1);')),
            ('', 'ReferenceError'),
        )

    def test_a_throwing_operand_is_kept_inside_a_call_argument(self):
        self.assertEqual(
            behavior(self._simplify('console.log((missing, 1));')),
            ('', 'ReferenceError'),
        )

    def test_a_resolved_operand_is_still_dropped(self):
        """
        A read that resolves cannot throw and carries no other effect, so the operand is dropped
        and the sequence collapses to the value the last operand decides.
        """
        self.assertEqual(
            'var x = 1;\nconsole.log(1);',
            self._simplify('var x = 1;\nx, console.log(1);'),
        )


class TestAnAllocationDiscardedForItsShapeKeepsWhatBuildingItThrows(TestJsDeobfuscator):
    """
    The type and the truthiness of an object are read from the way it is written, without the
    object, which is discarded along with every element in it. Discarding it is licence only where
    building it does nothing observable and cannot throw: a name no binding resolves throws a
    `ReferenceError` as its element is evaluated, so an allocation holding one is left standing where
    its shape would otherwise have answered. `TestASequenceOperandThatMayThrowIsKept` keeps the same
    throw one indirection out, at the operand of a sequence.
    """

    def test_a_typeof_over_a_throwing_allocation_is_left_standing(self):
        self.assertEqual(
            'console.log(typeof [zzz]);', self._simplify('console.log(typeof [zzz]);'))
        self.assertEqual(
            'console.log(!{ p: zzz });', self._simplify('console.log(!{p: zzz});'))

    def test_a_branch_a_throwing_allocation_picks_keeps_the_allocation(self):
        """
        The fold answers the branch from the object's truthiness and drops the test, so the throw the
        test raised is kept in front of the branch as a sequence: `({ p: zzz }, 1)` evaluates the
        object and throws before it reaches `1`, exactly as `{p: zzz} ? 1 : 2` does.
        """
        self.assertEqual(
            'console.log(({ p: zzz }, 1));', self._simplify('console.log({p: zzz} ? 1 : 2);'))
        self.assertEqual(
            'console.log(([zzz], 1));', self._simplify('console.log([zzz] ? 1 : 2);'))

    def test_an_allocation_nothing_in_which_throws_is_still_discarded_for_its_shape(self):
        """
        The control: a literal, a global value name, a function expression, and a resolved local each
        build without throwing, so the object is discarded and its shape answers. A refusal reached
        for every allocation rather than only a throwing one would fold none of these.
        """
        self.assertEqual("console.log('object');", self._simplify('console.log(typeof {p: 1});'))
        self.assertEqual('console.log(false);', self._simplify('console.log(!{p: 1});'))
        self.assertEqual(
            "console.log('object');", self._simplify('console.log(typeof [undefined, NaN]);'))
        self.assertEqual(
            "console.log('object');", self._simplify('console.log(typeof [function () {}]);'))
        self.assertEqual(
            "var a = 1, b = 2;\nconsole.log('object');",
            self._simplify('var a = 1, b = 2;\nconsole.log(typeof [a, b]);'))

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_refuses_each_throwing_allocation_before_and_after(self):
        for source in [
            'console.log(typeof [zzz]);',
            'console.log(!{p: zzz});',
            'console.log({p: zzz} ? 1 : 2);',
            'console.log([zzz] ? 1 : 2);',
        ]:
            with self.subTest(source=source):
                self.assertEqual(
                    (behavior(source), behavior(self._simplify(source))),
                    (('', 'ReferenceError'), ('', 'ReferenceError')),
                )


class TestConcatReassociation(TestJsDeobfuscator):
    """
    A `+` chain whose left end is not a literal still has adjacent literals in it, and splitting a
    string across such a chain is a common concealment. Because `+` is left-associative, `x + 'a' + 'b'`
    nests as `(x + 'a') + 'b'`, so no single node has two literal operands and pairwise folding alone
    never touches it.
    """

    def test_literal_tail_merged_after_identifier(self):
        self.assertEqual(
            "f(x + '/Finder.app');",
            self._simplify("f(x + '/Fi' + 'nde' + 'r.ap' + 'p');"),
        )

    def test_literal_run_merged_between_identifiers(self):
        self.assertEqual(
            "f('p' + x + 'ab' + y + 'cd');",
            self._simplify("f('p' + x + 'a' + 'b' + y + 'c' + 'd');"),
        )

    def test_empty_string_joins_dropped(self):
        self.assertEqual(
            "f(x + 'ab');",
            self._simplify("f(x + 'a' + '' + 'b');"),
        )

    def test_call_result_receiver_merged(self):
        self.assertEqual(
            "f(g() + 'ab');",
            self._simplify("f(g() + 'a' + 'b');"),
        )

    def test_number_appended_to_string_merged(self):
        self.assertEqual(
            "f(x + 'a1');",
            self._simplify("f(x + 'a' + 1);"),
        )

    def test_numeric_pair_not_merged(self):
        """
        `x + 1 + 2` adds when `x` is numeric and concatenates when `x` is a string, so the pair cannot
        be reduced without knowing `x`: merging to `x + 3` gives `10` where `7` gives `712`, and merging
        to `x + '12'` breaks the numeric case instead.
        """
        self.assertEqual('f(x + 1 + 2);', self._simplify('f(x + 1 + 2);'))

    def test_number_before_string_not_merged(self):
        """
        In `x + 1 + 'b'` the `1` binds to `x` first, so it is `8b` for `x = 7` — merging the trailing
        pair into `'1b'` would yield `71b`.
        """
        self.assertEqual("f(x + 1 + 'b');", self._simplify("f(x + 1 + 'b');"))

    def test_leading_literal_pair_still_folded_wholly(self):
        self.assertEqual("f('ab' + x);", self._simplify("f('a' + 'b' + x);"))

    def test_parenthesized_right_operand_not_reassociated(self):
        """
        `x + ('a' + 'b')` already groups the literals, and the inner fold handles it; the outer node
        must not then merge `'ab'` into a left operand it does not have.
        """
        self.assertEqual("f(x + 'ab');", self._simplify("f(x + ('a' + 'b'));"))

    def test_subtraction_not_reassociated(self):
        self.assertEqual("f(x - 'a' - 'b');", self._simplify("f(x - 'a' - 'b');"))

    def test_multiplication_inner_not_reassociated(self):
        """
        Only a `+` may absorb the literal on its left. For `x = 4`, `x * '1' + '2'` multiplies and then
        concatenates, giving `'42'`; merging the literals across the `*` would compute `4 * '12'` and give
        `48`. A subtraction chain alone does not witness this — it is `NaN` either way.
        """
        self.assertEqual("f(x * '1' + '2');", self._simplify("f(x * '1' + '2');"))

    def test_array_tail_not_merged(self):
        """
        An array converts through `Array.prototype.join`, which a program can replace, so its string form
        is not a property of the syntax: after `Array.prototype.join = ...`, `x + 'a' + [1, 2]` is not
        `x + 'a1,2'`. Primitives have no such hook and are merged.
        """
        self.assertEqual("f(x + 'a' + [1, 2]);", self._simplify("f(x + 'a' + [1, 2]);"))

    def test_imprecise_integer_tail_merged_as_the_double_it_denotes(self):
        """
        A JS number is a double, so `9007199254740993` denotes `9007199254740992` and Node agrees that
        `'a' + 9007199254740993` is `'a9007199254740992'`. The literal is a primitive like any other and
        merges; what it must never contribute is the digit string it was written with.
        """
        self.assertEqual(
            "f(x + 'a9007199254740992');",
            self._simplify("f(x + 'a' + 9007199254740993);"),
        )

    def test_representable_integer_tail_merged(self):
        self.assertEqual(
            "f(x + 'a9007199254740992');",
            self._simplify("f(x + 'a' + 9007199254740992);"),
        )

    def test_template_literal_not_merged(self):
        self.assertEqual("f(x + `a` + 'b');", self._simplify("f(x + `a` + 'b');"))


class TestGlobalValueNameOperands(TestJsDeobfuscator):
    """
    `undefined`, `NaN` and `Infinity` name values that the tool already reads through a call, and it
    already spells them back as `void 0`, `0 / 0` and `1e999`. An operand written with one of the
    names is therefore as constant as one written with those expressions, but an arithmetic or a
    concatenation reading it is left standing. Node says what each expression here denotes.
    """

    def test_the_same_operands_spelled_without_a_name_are_folded(self):
        self.assertEqual('1e999;', self._simplify('1e999 + 1;'))
        self.assertEqual('0;', self._simplify('1 / 1e999;'))
        self.assertEqual("f(x + 'aundefined');", self._simplify("f(x + 'a' + void 0);"))
        self.assertEqual("f(x + 'aNaN');", self._simplify("f(x + 'a' + (0 / 0));"))

    @unittest.expectedFailure
    def test_arithmetic_reading_a_global_value_name_is_folded(self):
        """
        Node: `Infinity` and `0`.
        """
        self.assertEqual('1e999;', self._simplify('Infinity + 1;'))
        self.assertEqual('0;', self._simplify('1 / Infinity;'))

    @unittest.expectedFailure
    def test_a_global_value_name_concatenated_onto_a_string_is_merged(self):
        """
        Node: `aundefined`, `aNaN` and `aInfinity`.
        """
        self.assertEqual("f(x + 'aundefined');", self._simplify("f(x + 'a' + undefined);"))
        self.assertEqual("f(x + 'aNaN');", self._simplify("f(x + 'a' + NaN);"))
        self.assertEqual("f(x + 'aInfinity');", self._simplify("f(x + 'a' + Infinity);"))


class TestTypeofAGuaranteedGlobalIsFolded(TestJsDeobfuscator):
    """
    `typeof` of a name the specification mandates on the global object is host-independent — the name
    resolves in every host to a value of a fixed type — so it folds to a constant string. Node says
    what `typeof` answers for each below. A host-conditional alias (`window`) and a name a conformant
    host may withhold (`SharedArrayBuffer`) are left standing, since their `typeof` is `'undefined'`
    where the name is absent; a name the program reassigns or shadows is left standing too, since the
    value it now holds may be of another type.
    """

    def test_a_pristine_guaranteed_global_folds_to_its_type_string(self):
        """
        Node: `object`, `function`, `object`, `object`, `function`, `undefined`.
        """
        self.assertEqual("'object';", self._simplify('typeof globalThis;'))
        self.assertEqual("'function';", self._simplify('typeof Object;'))
        self.assertEqual("'object';", self._simplify('typeof Math;'))
        self.assertEqual("'object';", self._simplify('typeof JSON;'))
        self.assertEqual("'function';", self._simplify('typeof Array;'))
        self.assertEqual("'undefined';", self._simplify('typeof undefined;'))

    def test_a_host_conditional_or_withheld_name_is_left_standing(self):
        for name in ('window', 'self', 'global', 'top', 'frames', 'SharedArrayBuffer', 'Atomics'):
            with self.subTest(name=name):
                self.assertEqual(F'typeof {name};', self._simplify(F'typeof {name};'))

    def test_a_host_conditional_typeof_folds_under_a_pin(self):
        """
        Pinning the host settles a host-conditional `typeof` the same way the interpreter's fold does,
        so a top-level guard folds too: `-e node` proves `Buffer` present (`'function'`) and `window`
        absent (`'undefined'`); `-e browser` proves the reverse.
        """
        pinned = DeobfuscationOptions(environment=HostEnvironment.node)
        self.assertEqual("'function';", self._run_transformer('typeof Buffer;', JsSimplifications, pinned))
        self.assertEqual("'undefined';", self._run_transformer('typeof window;', JsSimplifications, pinned))
        browser = DeobfuscationOptions(environment=HostEnvironment.browser)
        self.assertEqual("'undefined';", self._run_transformer('typeof Buffer;', JsSimplifications, browser))
        self.assertEqual("'object';", self._run_transformer('typeof window;', JsSimplifications, browser))

    def test_a_reassigned_or_shadowed_global_is_left_standing(self):
        """
        Node: after `Object = 5`, `typeof Object` is `number`, not `function`, and a parameter named
        `Object` holds whatever the caller passed.
        """
        self.assertEqual('Object = 5;\ntypeof Object;', self._simplify('Object = 5;\ntypeof Object;'))
        self.assertEqual(
            'function f(Object) {\n  return typeof Object;\n}',
            self._simplify('function f(Object) { return typeof Object; }'),
        )


class TestStringMethodsIndexInUtf16CodeUnits(TestJsDeobfuscator):
    """
    A `String.prototype` method that takes or returns an index or a length counts in UTF-16 code
    units, so over `_SPANNING` every offset past the middle character is one greater than the count
    of Python code points. Each call here is folded, so the offset the method read is written into
    the deobfuscated file as a constant, where nothing recalls what the source said.
    """

    def test_char_at_returns_one_code_unit(self):
        """
        Node answers with the high surrogate 0xD83D at index 1 and the low surrogate 0xDE00 at
        index 2. `charAt` names a single code unit, so it can never answer with a whole character
        that spans two of them, and it can never run out of string before index 3.
        """
        self.assertEqual(
            (
                _folded_value(F'{_SPANNING}.charAt(1)'),
                _folded_value(F'{_SPANNING}.charAt(2)'),
            ),
            (R"'\uD83D'", R"'\uDE00'"),
        )

    def test_at_indexes_code_units_from_either_end(self):
        """
        Node answers with the high surrogate 0xD83D at index 1 and the low surrogate 0xDE00 at
        index -2. A negative index counts back from a length that is also measured in code units,
        so the two ends of the string have to agree about where the middle character sits.
        """
        self.assertEqual(
            (
                _folded_value(F'{_SPANNING}.at(1)'),
                _folded_value(F'{_SPANNING}.at(-2)'),
            ),
            (R"'\uD83D'", R"'\uDE00'"),
        )

    def test_substring_cuts_between_code_units(self):
        """
        Node answers with the high surrogate 0xD83D for `substring(1, 2)` and with the low
        surrogate 0xDE00 followed by `b` for `substring(2)`.
        """
        self.assertEqual(
            (
                _folded_value(F'{_SPANNING}.substring(1, 2)'),
                _folded_value(F'{_SPANNING}.substring(2)'),
            ),
            (R"'\uD83D'", R"'\uDE00b'"),
        )

    def test_index_of_reports_a_code_unit_offset(self):
        """
        Node answers `3` for both, since `b` follows two surrogates. The returned offset is what a
        caller feeds back into an index, so reporting it one short misplaces every later cut, and
        searching from position 3 must still find the character that sits there.
        """
        self.assertEqual(
            (
                _folded_value(F"{_SPANNING}.indexOf('b')"),
                _folded_value(F"{_SPANNING}.indexOf('b', 3)"),
            ),
            ('3', '3'),
        )

    def test_last_index_of_reports_a_code_unit_offset(self):
        """
        Node answers `3`, the same offset the forward search reports for the only `b` in the
        string.
        """
        self.assertEqual(_folded_value(F"{_SPANNING}.lastIndexOf('b')"), '3')

    def test_includes_takes_a_code_unit_position(self):
        """
        Node answers `true`: the search starts at code unit 3, which is where `b` is. A position
        measured in code points starts the search past the end of the string and finds nothing.
        """
        self.assertEqual(_folded_value(F"{_SPANNING}.includes('b', 3)"), 'true')

    def test_starts_with_takes_a_code_unit_position(self):
        """
        Node answers `true`, because the string does start with `b` when read from code unit 3.
        """
        self.assertEqual(_folded_value(F"{_SPANNING}.startsWith('b', 3)"), 'true')

    def test_ends_with_takes_a_code_unit_end_position(self):
        """
        Node answers `true`: the first three code units end with the two that spell the astral
        character. An end position read as a code point cuts one unit short of it.
        """
        self.assertEqual(
            _folded_value(F"{_SPANNING}.endsWith('{_ASTRAL}', 3)"),
            'true',
        )

    def test_slice_cuts_between_code_units(self):
        """
        Node answers with the astral character for `slice(1, 3)` and with the low surrogate 0xDE00
        followed by `b` for both `slice(2)` and `slice(-2)`. A cut may fall between the two halves
        of a character, and a slice that starts on the second half begins with a lone surrogate.
        """
        self.assertEqual(
            (
                _folded_value(F'{_SPANNING}.slice(1, 3)'),
                _folded_value(F'{_SPANNING}.slice(2)'),
                _folded_value(F'{_SPANNING}.slice(-2)'),
            ),
            (F"'{_ASTRAL}'", R"'\uDE00b'", R"'\uDE00b'"),
        )

    def test_substr_counts_its_length_in_code_units(self):
        """
        Node answers with the astral character for `substr(1, 2)` and with the low surrogate 0xDE00
        for `substr(2, 1)`. The second argument is a count of code units and not of characters, so
        two of them are what it takes to name the middle character.
        """
        self.assertEqual(
            (
                _folded_value(F'{_SPANNING}.substr(1, 2)'),
                _folded_value(F'{_SPANNING}.substr(2, 1)'),
            ),
            (F"'{_ASTRAL}'", R"'\uDE00'"),
        )

    def test_pad_start_measures_the_target_length_in_code_units(self):
        """
        Node answers with two dashes before the string. The target length is compared against a
        length of four, so exactly two units are wanted; counting the astral character once asks
        for one dash too many and changes what the padded string says.
        """
        self.assertEqual(
            _folded_value(F"{_SPANNING}.padStart(6, '-')"),
            F"'--a{_ASTRAL}b'",
        )

    def test_pad_end_measures_the_target_length_in_code_units(self):
        """
        Node answers with two dashes after the string, for the reason `padStart` gets two before
        it.
        """
        self.assertEqual(
            _folded_value(F"{_SPANNING}.padEnd(6, '-')"),
            F"'a{_ASTRAL}b--'",
        )
