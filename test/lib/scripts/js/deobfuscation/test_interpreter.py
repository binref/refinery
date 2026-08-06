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
