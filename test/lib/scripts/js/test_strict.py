from __future__ import annotations

from test import TestBase

from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.strict import StrictViolation, collect_strict_violations


class TestJsStrict(TestBase):

    def _violations(self, source: str, *, strict: bool = False) -> list[StrictViolation]:
        return collect_strict_violations(JsParser(source).parse(), strict=strict)

    def test_octal_literal_flagged_in_strict(self):
        for source in ['010', '0755', '017', '00', '08', '09', '019', '08.5']:
            with self.subTest(source=source):
                self.assertEqual(
                    self._violations(source, strict=True),
                    [StrictViolation(0, 'octal-literal')])

    def test_octal_literal_not_flagged_when_sloppy(self):
        for source in ['010', '0755', '08', '019']:
            with self.subTest(source=source):
                self.assertEqual(self._violations(source, strict=False), [])

    def test_octal_literal_negatives(self):
        for source in ['0x10', '0o10', '0b10', '0.5', '0', '10', '0e5', '0n', '1n']:
            with self.subTest(source=source):
                self.assertEqual(self._violations(source, strict=True), [])

    def test_octal_string_escape_flagged_in_strict(self):
        sources = [r"'\1'", r"'\7'", r"'\07'", r"'\101'", r"'\00'", r"'\08'", r"'\09'", r"'\8'", r"'\9'"]
        for source in sources:
            with self.subTest(source=source):
                self.assertEqual(
                    self._violations(source, strict=True),
                    [StrictViolation(0, 'octal-escape')])

    def test_octal_string_escape_negatives(self):
        for source in [r"'\0'", r"'\n'", r"'\x41'", r"'A'", r"'\\1'", r"'\0a'"]:
            with self.subTest(source=source):
                self.assertEqual(self._violations(source, strict=True), [])

    def test_with_statement(self):
        self.assertEqual(
            self._violations('with ({}) {}', strict=True),
            [StrictViolation(0, 'with-statement')])
        self.assertEqual(self._violations('with ({}) {}', strict=False), [])

    def test_delete_of_reference_flagged(self):
        for source in ['delete x', 'delete (x)', 'delete ((x))']:
            with self.subTest(source=source):
                self.assertEqual(
                    self._violations(source, strict=True),
                    [StrictViolation(0, 'delete-of-reference')])

    def test_delete_negatives(self):
        for source in ['delete o.a', 'delete o[0]', 'delete 1']:
            with self.subTest(source=source):
                self.assertEqual(self._violations(source, strict=True), [])

    def test_function_in_if_clause(self):
        source = 'if (x) function f() {}'
        self.assertEqual(
            self._violations(source, strict=True),
            [StrictViolation(source.index('function'), 'function-in-statement')])

    def test_function_in_else_clause(self):
        source = 'if (x) 1; else function g() {}'
        self.assertEqual(
            self._violations(source, strict=True),
            [StrictViolation(source.index('function'), 'function-in-statement')])

    def test_function_as_label_body(self):
        source = 'lbl: function h() {}'
        self.assertEqual(
            self._violations(source, strict=True),
            [StrictViolation(source.index('function'), 'function-in-statement')])

    def test_function_in_block_not_flagged(self):
        self.assertEqual(self._violations('if (x) { function f() {} }', strict=True), [])
        self.assertEqual(self._violations('function f() {}', strict=True), [])

    def test_for_in_var_initializer(self):
        source = 'for (var i = 0 in {}) {}'
        self.assertEqual(
            self._violations(source, strict=True),
            [StrictViolation(source.index('var'), 'for-in-var-init')])

    def test_for_in_negatives(self):
        for source in ['for (var j in {}) {}', 'for (let k in {}) {}', 'for (m in {}) {}']:
            with self.subTest(source=source):
                self.assertEqual(self._violations(source, strict=True), [])

    def test_directive_prologue_activates_strict(self):
        source = '"use strict"; with ({}) {}'
        self.assertEqual(
            self._violations(source, strict=False),
            [StrictViolation(source.index('with'), 'with-statement')])

    def test_escaped_directive_does_not_activate_strict(self):
        source = '"use\\u0020strict"; with ({}) {}'
        self.assertEqual(self._violations(source, strict=False), [])

    def test_strict_function_body_flags_nested_octal(self):
        source = 'function f() { "use strict"; return 010; }'
        self.assertEqual(
            self._violations(source, strict=False),
            [StrictViolation(source.index('010'), 'octal-literal')])

    def test_class_body_is_always_strict(self):
        source = 'class C { m() { return 010; } }'
        self.assertEqual(
            self._violations(source, strict=False),
            [StrictViolation(source.index('010'), 'octal-literal')])

    def test_sloppy_function_body_flags_nothing(self):
        self.assertEqual(self._violations('function f() { return 010; }', strict=False), [])

    def test_multiple_violations_sorted_by_offset(self):
        source = '010; with ({}) {}'
        self.assertEqual(
            self._violations(source, strict=True),
            [
                StrictViolation(0, 'octal-literal'),
                StrictViolation(source.index('with'), 'with-statement'),
            ])

    RESERVED = [
        'implements', 'interface', 'let', 'package', 'private', 'protected', 'public', 'static', 'yield',
    ]

    def test_reserved_word_as_binding(self):
        for word in self.RESERVED:
            source = F'var {word} = 1'
            with self.subTest(word=word):
                self.assertEqual(
                    self._violations(source, strict=True),
                    [StrictViolation(source.index(word), 'reserved-word', word)])

    def test_reserved_word_as_reference(self):
        for word in self.RESERVED:
            source = F'typeof {word}'
            with self.subTest(word=word):
                self.assertEqual(
                    self._violations(source, strict=True),
                    [StrictViolation(source.index(word), 'reserved-word', word)])

    def test_reserved_word_as_label(self):
        self.assertEqual(
            self._violations('yield: ;', strict=True),
            [StrictViolation(0, 'reserved-word', 'yield')])

    def test_reserved_word_in_property_position_clean(self):
        for source in ['({let: 1})', '({}).public', 'o.yield', 'o.static = 1']:
            with self.subTest(source=source):
                self.assertEqual(self._violations(source, strict=True), [])

    def test_eval_arguments_as_binding_or_target(self):
        cases = [
            ('var eval = 1', 'eval'),
            ('eval = 1', 'eval'),
            ('eval += 1', 'eval'),
            ('++arguments', 'arguments'),
            ('(function (eval) {})', 'eval'),
            ('(function arguments() {})', 'arguments'),
            ('try {} catch (eval) {}', 'eval'),
            ('for (arguments in {}) {}', 'arguments'),
        ]
        for source, name in cases:
            with self.subTest(source=source):
                self.assertEqual(
                    self._violations(source, strict=True),
                    [StrictViolation(source.index(name), 'eval-arguments-target', name)])

    def test_eval_arguments_as_reference_clean(self):
        for source in ['typeof eval', '({eval: 1})', '({}).arguments', 'eval()', 'arguments[0]']:
            with self.subTest(source=source):
                self.assertEqual(self._violations(source, strict=True), [])

    def test_eval_in_binding_pattern(self):
        cases = [
            ('(function ({eval}) {})', 'eval'),
            ('(function ([arguments]) {})', 'arguments'),
            ('(function ({a: {b: eval}}) {})', 'eval'),
        ]
        for source, name in cases:
            with self.subTest(source=source):
                self.assertEqual(
                    self._violations(source, strict=True),
                    [StrictViolation(source.index(name), 'eval-arguments-target', name)])

    def test_duplicate_parameter(self):
        source = '(function (q, q) {})'
        self.assertEqual(
            self._violations(source, strict=True),
            [StrictViolation(source.rindex('q'), 'duplicate-parameter', 'q')])

    def test_distinct_parameters_clean(self):
        self.assertEqual(self._violations('(function (a, b, c) {})', strict=True), [])

    def test_default_value_is_a_reference(self):
        self.assertEqual(self._violations('(function (a = eval) {})', strict=True), [])
        source = '(function (a = implements) {})'
        self.assertEqual(
            self._violations(source, strict=True),
            [StrictViolation(source.index('implements'), 'reserved-word', 'implements')])

    def test_computed_key_is_a_reference(self):
        self.assertEqual(self._violations('({[eval]: 1})', strict=True), [])
        source = '({[yield]: 1})'
        self.assertEqual(
            self._violations(source, strict=True),
            [StrictViolation(source.index('yield'), 'reserved-word', 'yield')])

    def test_name_rules_clean_when_sloppy(self):
        for source in ['var eval = 1', 'yield: ;', '(function (q, q) {})', 'typeof implements']:
            with self.subTest(source=source):
                self.assertEqual(self._violations(source, strict=False), [])

    def test_reserved_binding_in_strict_function_body(self):
        source = 'function outer() { "use strict"; var yield = 1; }'
        self.assertEqual(
            self._violations(source, strict=False),
            [StrictViolation(source.index('yield'), 'reserved-word', 'yield')])

    def test_reserved_binding_in_class_method(self):
        source = 'class C { m() { var package = 1; } }'
        self.assertEqual(
            self._violations(source, strict=False),
            [StrictViolation(source.index('package'), 'reserved-word', 'package')])
