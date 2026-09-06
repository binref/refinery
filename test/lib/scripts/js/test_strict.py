from __future__ import annotations

import inspect
import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import behavior, node_executable
from test.lib.scripts.js.ledger import a_program, well_formed

from refinery.lib.scripts import Statement, set_body
from refinery.lib.scripts.js.model import JsBlockStatement, JsScript
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.strict import (
    StrictViolation,
    collect_strict_violations,
    keeping_directives,
)
from refinery.lib.scripts.js.synth import JsSynthesizer


class TestJsStrict(TestBase):

    def _violations(
        self, source: str, *, strict: bool = False, module: bool = False,
    ) -> list[StrictViolation]:
        return collect_strict_violations(JsParser(source).parse(), strict=strict, module=module)

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

    def test_await_bound_in_module_flagged(self):
        cases = [
            'var await = 1',
            '(function (await) {})',
            'function f(){ function g(await){} }',
            'var f = (await) => 1;',
            'try {} catch (await) {}',
            'await = 1',
        ]
        for source in cases:
            with self.subTest(source=source):
                self.assertEqual(
                    self._violations(source, strict=True, module=True),
                    [StrictViolation(source.index('await'), 'await-in-module', 'await')])

    def test_await_bound_is_a_module_rule_not_a_strict_one(self):
        for source in ['var await = 1', '(function (await) {})', 'try {} catch (await) {}']:
            with self.subTest(source=source):
                self.assertEqual(self._violations(source, strict=True, module=False), [])

    def test_await_referred_to_in_module_flagged(self):
        rows = {
            'typeof await'                   : [7],
            'f(await)'                       : [2],
            'function g() { return await; }' : [22],
            'var o = { await };'             : [10],
            'await: for (;;) break await;'   : [0, 22],
        }
        for source, offsets in rows.items():
            with self.subTest(source=source):
                self.assertEqual(
                    self._violations(source, strict=True, module=True),
                    [StrictViolation(offset, 'await-in-module', 'await') for offset in offsets],
                )

    def test_await_as_a_property_name_in_module_clean(self):
        for source in ['({await: 1})', 'o.await', 'x.await = 1', 'class C { await() {} }']:
            with self.subTest(source=source):
                self.assertEqual(self._violations(source, strict=True, module=True), [])

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

    def test_duplicate_parameter_of_a_method_flagged_when_sloppy(self):
        source = 'var o = { m(a, a) {} };'
        self.assertEqual(
            self._violations(source, strict=False),
            [StrictViolation(source.rindex('a'), 'duplicate-parameter', 'a')])

    def test_duplicate_parameter_of_an_arrow_flagged_when_sloppy(self):
        source = 'var f = (a, a) => {};'
        self.assertEqual(
            self._violations(source, strict=False),
            [StrictViolation(source.rindex('a'), 'duplicate-parameter', 'a')])

    def test_duplicate_parameter_of_a_property_value_is_a_sloppy_program(self):
        source = 'var o = { m: function (a, a) {} };'
        self.assertEqual(self._violations(source, strict=False), [])
        self.assertEqual(
            self._violations(source, strict=True),
            [StrictViolation(source.rindex('a'), 'duplicate-parameter', 'a')])

    def test_duplicate_parameter_in_a_list_that_is_not_simple_flagged_when_sloppy(self):
        source = 'function f(a, ...a) {}'
        self.assertEqual(
            self._violations(source, strict=False),
            [StrictViolation(source.rindex('a'), 'duplicate-parameter', 'a')])

    def test_use_strict_under_a_parameter_list_that_is_not_simple(self):
        source = "function f(a = 1) { 'use strict'; }"
        self.assertEqual(
            self._violations(source, strict=False),
            [StrictViolation(0, 'use-strict-with-non-simple-parameters')])

    def test_use_strict_under_a_non_simple_list_is_flagged_in_either_mode(self):
        source = "var f = function ({a}) { 'use strict'; };"
        expected = [StrictViolation(
            source.index('function'), 'use-strict-with-non-simple-parameters')]
        self.assertEqual(self._violations(source, strict=False), expected)
        self.assertEqual(self._violations(source, strict=True), expected)

    def test_use_strict_negatives(self):
        sources = [
            "function f(a, b) { 'use strict'; }",
            "function f(a = 1) { ('use strict'); }",
            "function f(a = 1) { 0; 'use strict'; }",
            "var f = (a = 1) => 'use strict';",
        ]
        for source in sources:
            with self.subTest(source=source):
                self.assertEqual(self._violations(source, strict=True), [])

    def test_getter_with_a_parameter(self):
        for source in ['var o = { get g(a) {} };', 'class C { get g(...a) {} }']:
            with self.subTest(source=source):
                self.assertEqual(
                    self._violations(source, strict=False),
                    [StrictViolation(source.index('('), 'accessor-arity')])

    def test_setter_without_exactly_one_parameter(self):
        sources = [
            'var o = { set s() {} };',
            'var o = { set s(a, b) {} };',
            'var o = { set s(...a) {} };',
        ]
        for source in sources:
            with self.subTest(source=source):
                self.assertEqual(
                    self._violations(source, strict=False),
                    [StrictViolation(source.index('('), 'accessor-arity')])

    def test_accessor_arity_negatives(self):
        sources = [
            'var o = { get g() {} };',
            'var o = { set s(v) {} };',
            'var o = { set s(v = 1) {} };',
            'var o = { set s([v]) {} };',
            'var o = { get(a, b) {} };',
            'var o = { get: function (a, b) {} };',
        ]
        for source in sources:
            with self.subTest(source=source):
                self.assertEqual(self._violations(source, strict=True), [])

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


#: A file that spells syntax only module code may hold, together with a construct strict code
#: refuses. Nothing in any of them declares a mode, so the `import` or `export` — or the
#: `import.meta` — is the whole of what makes each a file no engine reads.
A_STRICT_ERROR_UNDER_MODULE_SYNTAX = [
    'export const a = 1;\nwith ({}) {}',
    "import 'fs';\nvar q = 010;",
    'export default 1;\nvar eval = 1;',
    'var q = import.meta;\ndelete q;',
    "export * from 'fs';\nfunction f(q, q) {}",
]

#: The same five files with the module syntax taken out of them, which leaves five sloppy scripts
#: every engine reads and nothing is reported about.
THE_SAME_FILES_WITHOUT_THE_MODULE_SYNTAX = [
    'with ({}) {}',
    'var q = 010;',
    'var eval = 1;',
    'var q = 1;\ndelete q;',
    'function f(q, q) {}',
]


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNodeRefusesAStrictErrorInAFileThatSpellsModuleSyntax(TestBase):

    def test_node_refuses_every_one_of_them_as_a_module(self):
        self.assertEqual(
            [behavior(source, module=True) for source in A_STRICT_ERROR_UNDER_MODULE_SYNTAX],
            [('', 'SyntaxError')] * len(A_STRICT_ERROR_UNDER_MODULE_SYNTAX),
        )

    def test_node_reads_every_one_of_them_with_the_module_syntax_taken_out(self):
        self.assertEqual(
            [behavior(source) for source in THE_SAME_FILES_WITHOUT_THE_MODULE_SYNTAX],
            [('', None)] * len(THE_SAME_FILES_WITHOUT_THE_MODULE_SYNTAX),
        )


class TestTheCollectorReadsModuleCodeAsStrictCode(TestBase):
    """
    Module code is strict code with nothing saying so, so a file whose text spells module-only
    syntax is one the collector reports a strict error in without any seed being given for it. Which
    files those are is `refinery.lib.scripts.js.strict.names_module_syntax`, recorded on the tree by
    the parser; the seed a caller passes is the mode of a *destination* and says nothing about the
    file in hand.
    """

    @staticmethod
    def _violations(source: str) -> list[StrictViolation]:
        return collect_strict_violations(JsParser(source).parse(), strict=False)

    def test_a_with_statement_beside_an_export(self):
        source = A_STRICT_ERROR_UNDER_MODULE_SYNTAX[0]
        self.assertEqual(
            self._violations(source),
            [StrictViolation(source.index('with'), 'with-statement')])

    def test_an_octal_literal_beside_an_import(self):
        source = A_STRICT_ERROR_UNDER_MODULE_SYNTAX[1]
        self.assertEqual(
            self._violations(source),
            [StrictViolation(source.index('010'), 'octal-literal')])

    def test_a_binding_named_eval_beside_a_default_export(self):
        source = A_STRICT_ERROR_UNDER_MODULE_SYNTAX[2]
        self.assertEqual(
            self._violations(source),
            [StrictViolation(source.index('eval'), 'eval-arguments-target', 'eval')])

    def test_a_delete_of_a_name_beside_an_import_meta(self):
        source = A_STRICT_ERROR_UNDER_MODULE_SYNTAX[3]
        self.assertEqual(
            self._violations(source),
            [StrictViolation(source.index('delete'), 'delete-of-reference')])

    def test_a_repeated_parameter_name_beside_a_star_export(self):
        source = A_STRICT_ERROR_UNDER_MODULE_SYNTAX[4]
        self.assertEqual(
            self._violations(source),
            [StrictViolation(source.rindex('q'), 'duplicate-parameter', 'q')])

    def test_the_parser_reads_each_of_those_files_as_module_code(self):
        self.assertEqual(
            [JsParser(source).parse().module for source in A_STRICT_ERROR_UNDER_MODULE_SYNTAX],
            [True] * len(A_STRICT_ERROR_UNDER_MODULE_SYNTAX),
        )

    def test_nothing_is_reported_once_the_module_syntax_is_taken_out(self):
        self.assertEqual(
            [self._violations(source) for source in THE_SAME_FILES_WITHOUT_THE_MODULE_SYNTAX],
            [[]] * len(THE_SAME_FILES_WITHOUT_THE_MODULE_SYNTAX),
        )


class TestKeepingTheDirectiveAcrossAWholeBodyReplacement(TestBase):
    """
    Installing a new statement list as a body's whole content drops the Use Strict Directive without
    removing anything, which is why `refinery.lib.scripts.js.strict.keeping_directives` restores it.
    A pass that rebuilds a body out of copies of its own statements has already kept it, by value
    rather than by identity, and carrying the original as well would write the directive twice.
    """

    SOURCE = "function f() { 'use strict'; log(1); log(2); }"

    STRICT_AGAIN = inspect.cleandoc(
        """
        function f() {
          'use strict';
          log(1);
          log(2);
        }
        """
    )

    def _body(self, ast: JsScript) -> JsBlockStatement:
        return next(node for node in ast.walk() if isinstance(node, JsBlockStatement))

    def _installed(self, replacement) -> str:
        ast = JsParser(self.SOURCE).parse()
        host = self._body(ast)
        set_body(host, keeping_directives(host, replacement(host)))
        return JsSynthesizer().convert(ast)

    def _a_copy_of_the_prologue(self):
        """
        The directive statement of a second parse of the same source: a statement the source wrote
        as a directive and that is not the one the host holds, which is what a pass handing back
        clones of a body's own statements installs.
        """
        return self._body(JsParser(self.SOURCE).parse()).body[0]

    def test_a_replacement_that_dropped_the_directive_gets_it_back(self):
        self.assertEqual(self.STRICT_AGAIN, self._installed(lambda host: list(host.body[1:])))

    def test_a_replacement_holding_the_hosts_own_directive_keeps_exactly_one(self):
        self.assertEqual(self.STRICT_AGAIN, self._installed(lambda host: list(host.body)))

    def test_a_replacement_holding_a_copy_of_the_directive_keeps_exactly_one(self):
        self.assertEqual(
            self.STRICT_AGAIN,
            self._installed(lambda host: [self._a_copy_of_the_prologue(), *host.body[1:]]),
        )

    def test_a_replacement_that_reordered_the_body_keeps_the_directive_at_its_head(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                function f() {
                  'use strict';
                  log(2);
                  log(1);
                }
                """
            ),
            self._installed(lambda host: [host.body[0], host.body[2], host.body[1]]),
        )


#: A permutation of a three-statement body whose first statement is the Use Strict Directive,
#: written as the indices the replacement takes from that body. None of them opens with the
#: directive, which is the case a pass that reorders statements hands over, and the last one
#: drops a statement as well.
AN_ORDER_THAT_LEAVES_THE_DIRECTIVE_OFF_THE_HEAD = [
    (1, 0, 2),
    (1, 2, 0),
    (2, 0, 1),
    (2, 1, 0),
    (2, 0),
]


class TestAReplacementHoldingTheDirectiveBehindAnotherStatement(TestBase):
    """
    A directive is what a body opens with, so a pass that reorders statements hands back a list
    where the host's own directive statement declares nothing, and the list installed as the body
    has to open with it again. Moving it there is the only way: a tree holds a node in one place, so
    a list naming the same statement at two indices leaves one node with one parent standing at
    both, and every map keyed by identity over the tree then reads it as two.
    """

    SOURCE = "function f() { 'use strict'; log(1); log(2); }"

    def _replacement_and_result(
        self,
        order: tuple[int, ...],
    ) -> tuple[list[Statement], list[Statement], list[Statement]]:
        ast = JsParser(self.SOURCE).parse()
        host = next(node for node in ast.walk() if isinstance(node, JsBlockStatement))
        written = list(host.body)
        replacement = [written[index] for index in order]
        return written, replacement, keeping_directives(host, replacement)

    def _where_the_directive_stands(self, order: tuple[int, ...]) -> list[int]:
        written, _, kept = self._replacement_and_result(order)
        return [index for index, member in enumerate(kept) if member is written[0]]

    def _times_each_statement_is_named(self, order: tuple[int, ...]) -> list[int]:
        _, replacement, kept = self._replacement_and_result(order)
        return [
            sum(1 for member in kept if member is statement)
            for statement in replacement
        ]

    def _the_statements_beside_the_directive(self, order: tuple[int, ...]) -> list[int]:
        written, _, kept = self._replacement_and_result(order)
        return [
            index
            for member in kept
            for index, statement in enumerate(written)
            if statement is member and index != 0
        ]

    def test_the_directive_stands_once_and_at_the_head(self):
        orders = AN_ORDER_THAT_LEAVES_THE_DIRECTIVE_OFF_THE_HEAD
        self.assertEqual(
            {order: self._where_the_directive_stands(order) for order in orders},
            {order: [0] for order in orders},
        )

    def test_every_statement_the_replacement_named_is_named_exactly_once(self):
        orders = AN_ORDER_THAT_LEAVES_THE_DIRECTIVE_OFF_THE_HEAD
        self.assertEqual(
            {order: self._times_each_statement_is_named(order) for order in orders},
            {order: [1] * len(order) for order in orders},
        )

    def test_the_statements_beside_it_keep_the_order_the_replacement_gave_them(self):
        orders = AN_ORDER_THAT_LEAVES_THE_DIRECTIVE_OFF_THE_HEAD
        self.assertEqual(
            {order: self._the_statements_beside_the_directive(order) for order in orders},
            {order: [index for index in order if index != 0] for order in orders},
        )


#: A function declaration written as the whole of an `if` clause, in each of the modes. Annex B.3.4
#: admits one in sloppy code, reading it as a block holding it; strict code has no such rule and
#: the grammar refuses a declaration where it requires a statement.
A_FUNCTION_DECLARATION_AS_AN_IF_CLAUSE = {
    'sloppy': a_program("""
        if (1) function W() { return 1; }
        console.log(W());
        """),
    'strict': a_program("""
        'use strict';
        if (1) function W() { return 1; }
        console.log(W());
        """),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestNodeReadsAClausePositionDeclarationOnlyWhereAnnexBSaysSo(TestBase):

    def test_node_runs_the_sloppy_file_and_refuses_the_strict_one(self):
        self.assertEqual(
            {mode: behavior(source) for mode, source in A_FUNCTION_DECLARATION_AS_AN_IF_CLAUSE.items()},
            {'sloppy': ('1\n', None), 'strict': ('', 'SyntaxError')},
        )


class TestTheVerdictReadsTheFileUnderItsOwnModeAndGoal(TestBase):
    """
    `refinery.lib.scripts.is_well_formed` asks the root of a file for its early errors, and a
    script's root answers with what `collect_strict_violations` reports under the mode the file
    declares and the goal its syntax spells. So a clause-position declaration is a program only
    below no directive, a strict error beside module syntax makes a file no program, and the same
    text with the module syntax taken out is one.
    """

    def test_a_clause_position_declaration_is_refused_in_strict_code_only(self):
        self.assertEqual(
            {
                mode: well_formed(source)
                for mode, source in A_FUNCTION_DECLARATION_AS_AN_IF_CLAUSE.items()
            },
            {'sloppy': True, 'strict': False},
        )

    def test_a_strict_error_beside_module_syntax_is_no_program(self):
        rows = A_STRICT_ERROR_UNDER_MODULE_SYNTAX
        self.assertEqual(
            {source: well_formed(source) for source in rows},
            {source: False for source in rows},
        )

    def test_the_same_files_without_the_module_syntax_are_programs(self):
        rows = THE_SAME_FILES_WITHOUT_THE_MODULE_SYNTAX
        self.assertEqual(
            {source: well_formed(source) for source in rows},
            {source: True for source in rows},
        )
