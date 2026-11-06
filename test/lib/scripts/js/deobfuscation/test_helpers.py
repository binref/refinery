from __future__ import annotations

import inspect
import struct
import unittest

from test.lib.scripts.js.analysis.differential import behavior, node_executable
from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator
from test.lib.scripts.js.ledger import printed

from refinery.lib.scripts import Transformer
from refinery.lib.scripts.js.analysis.model import build_semantic_model, is_use_position
from refinery.lib.scripts.js.deobfuscation.helpers import (
    Landing,
    binding_has_references,
    declares_a_watched_name,
    extract_literal_value,
    insert_after_prologue,
    make_numeric_literal,
    make_string_literal,
    substitute_params,
    substitute_use_position,
    value_landing,
    value_to_node,
)
from refinery.lib.scripts.js.lexer import decode_js_string_body
from refinery.lib.scripts.js.model import (
    Expression,
    JsBlockStatement,
    JsExportSpecifier,
    JsExpressionStatement,
    JsFunctionDeclaration,
    JsIdentifier,
    JsObjectExpression,
    JsProperty,
    JsReturnStatement,
    JsStaticBlock,
    JsStringLiteral,
    JsVariableDeclaration,
    JsVariableDeclarator,
    JsVarKind,
)
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer, escape_js_string
from refinery.lib.scripts.js.values import JS_NULL, JsBuffer


class TestDeobfuscationHelpers(TestJsDeobfuscator):

    def test_make_string_literal_escapes_control_chars(self):
        self.assertEqual(make_string_literal('a\nb').raw, "'a\\nb'")
        self.assertEqual(make_string_literal('x\ry').raw, "'x\\ry'")
        self.assertEqual(make_string_literal('p\tq').raw, "'p\\tq'")
        self.assertEqual(make_string_literal('m\0n').raw, "'m\\0n'")

    def test_binding_has_references_ignores_shadowing_param(self):
        source = inspect.cleandoc(
            """
            var table = pool;
            function uses(table) { return table.length; }
            """
        )
        model = build_semantic_model(JsParser(source).parse())
        binding = model.lookup('table', model.root_scope)
        self.assertFalse(binding_has_references(model, binding))

    def test_binding_has_references_counts_genuine_use(self):
        source = inspect.cleandoc(
            """
            var table = pool;
            log(table.length);
            """
        )
        model = build_semantic_model(JsParser(source).parse())
        binding = model.lookup('table', model.root_scope)
        self.assertTrue(binding_has_references(model, binding))


class TestValueToNode(TestJsDeobfuscator):

    def _render(self, value: object) -> str | None:
        node = value_to_node(value)
        if node is None:
            return None
        return JsSynthesizer().convert(node)

    def test_renders_primitives(self):
        self.assertEqual("'abc'", self._render('abc'))
        self.assertEqual('42', self._render(42))
        self.assertEqual('-42', self._render(-42))
        self.assertEqual('1.5', self._render(1.5))
        self.assertEqual('true', self._render(True))
        self.assertEqual('false', self._render(False))
        self.assertEqual('null', self._render(JS_NULL))
        self.assertEqual('void 0', self._render(None))

    def test_renders_special_numbers(self):
        self.assertEqual('0 / 0', self._render(float('nan')))
        self.assertEqual('1e999', self._render(float('inf')))
        self.assertEqual('-1e999', self._render(float('-inf')))
        self.assertEqual('-0', self._render(-0.0))

    def test_renders_containers(self):
        self.assertEqual('[]', self._render([]))
        self.assertEqual('[1, 2]', self._render([1, 2]))
        self.assertEqual('[1, void 0]', self._render([1, None]))
        self.assertEqual('{}', self._render({}))
        self.assertEqual("{ 'a': 1 }", self._render({'a': 1}))

    def test_renders_proto_key_as_computed(self):
        """
        A bare or quoted `__proto__` key sets the prototype of the object; only the computed key
        `['__proto__']` makes an own property.
        """
        self.assertEqual("{ ['__proto__']: 1 }", self._render({'__proto__': 1}))

    def test_renders_nested_proto_key_as_computed(self):
        self.assertEqual(
            "{ 'a': { ['__proto__']: 1 } }",
            self._render({'a': {'__proto__': 1}}),
        )

    def test_renders_ordinary_prototype_member_names_plainly(self):
        self.assertEqual("{ 'constructor': 1 }", self._render({'constructor': 1}))
        self.assertEqual("{ 'toString': 1 }", self._render({'toString': 1}))
        self.assertEqual("{ 'hasOwnProperty': 1 }", self._render({'hasOwnProperty': 1}))

    def test_refuses_buffer(self):
        self.assertIsNone(value_to_node(JsBuffer([65, 66])))
        self.assertIsNone(value_to_node(JsBuffer([])))

    def test_refuses_buffer_nested_in_container(self):
        self.assertIsNone(value_to_node([JsBuffer([65])]))
        self.assertIsNone(value_to_node({'b': JsBuffer([65])}))
        self.assertIsNone(value_to_node([[JsBuffer([65])]]))

    def test_refuses_non_string_key(self):
        self.assertIsNone(value_to_node({1: 'x'}))

    def test_refuses_unrepresentable_value(self):
        self.assertIsNone(value_to_node(object()))


JS_NUMBERS = [
    0.0,
    -0.0,
    1.0,
    -1.0,
    42.0,
    -42.0,
    0.1,
    0.30000000000000004,
    -1.5,
    4.35,
    0.3333333333333333,
    9007199254740992.0,
    9007199254740994.0,
    1152921504606846976.0,
    1e16,
    1.2345678901234568e17,
    1e20,
    9.999999999999999e20,
    1e21,
    -1e21,
    1.2345678901234568e29,
    1e-6,
    1e-7,
    1.5e-7,
    2.220446049250313e-16,
    2.2250738585072014e-308,
    1e-323,
    5e-324,
    -5e-324,
    1.7976931348623157e308,
    float('inf'),
    float('-inf'),
]
"""
A sample of the JavaScript Number domain, weighted towards the members whose spelling is least
obvious: the two zeros, which nothing but their sign tells apart; the integers past 2^53, where a
double has fewer digits than its exact value; both boundaries where the language switches between
positional and exponential notation, and the one where Python switches at a different magnitude; the
smallest subnormals; and the infinities, which no arithmetic but a decimal literal reaches by
rounding.
"""

NUMBER_BITS_IN_NODE = inspect.cleandoc("""
    const view = new DataView(new ArrayBuffer(8));
    function bits(x) {
      view.setFloat64(0, x);
      return view.getBigUint64(0).toString(16).padStart(16, '0');
    }
""")


class TestNumericLiteralRoundTrip(TestJsDeobfuscator):

    def _bits(self, value: float) -> str:
        return struct.pack('>d', value).hex()

    def _spelling(self, value: int | float) -> str:
        node = make_numeric_literal(value)
        if node is None:
            self.fail(F'{value!r} was refused a spelling')
        return JsSynthesizer().convert(node)

    def _spellings(self) -> list[tuple[float, str]]:
        return [(value, self._spelling(value)) for value in JS_NUMBERS]

    def _node_reads(self, expressions: list[str]) -> list[str]:
        script = [NUMBER_BITS_IN_NODE]
        script.extend(F'console.log(bits({expression}));' for expression in expressions)
        output, error = behavior('\n'.join(script))
        self.assertIsNone(error, 'node.js refused the spellings')
        lines = output.split()
        self.assertEqual(len(expressions), len(lines))
        return lines

    def _reader_reads(self, text: str) -> str:
        script = JsParser(F'{text};').parse()
        statement = script.body[0]
        if not isinstance(statement, JsExpressionStatement) or statement.expression is None:
            self.fail(F'{text!r} did not parse as a single expression')
        recognized, value = extract_literal_value(statement.expression)
        if not recognized or not isinstance(value, float):
            return F'refused: {value!r}'
        return self._bits(value)

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_every_spelling_denotes_the_number_it_was_asked_to_spell(self):
        spelled = self._spellings()
        reads = self._node_reads([F'({text})' for _, text in spelled])
        self.assertEqual(
            {text: self._bits(value) for value, text in spelled},
            {text: read for (_, text), read in zip(spelled, reads)},
        )

    def test_every_spelling_reads_back_as_the_number_it_was_asked_to_spell(self):
        spelled = self._spellings()
        self.assertEqual(
            {text: self._bits(value) for value, text in spelled},
            {text: self._reader_reads(text) for _, text in spelled},
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_every_spelling_denotes_the_same_number_where_the_value_names_are_rebound(self):
        spelled = self._spellings()
        reads = self._node_reads([
            F'(function (NaN, Infinity, undefined) {{ return ({text}); }})(1, 2, 3)'
            for _, text in spelled
        ])
        self.assertEqual(
            {text: self._bits(value) for value, text in spelled},
            {text: read for (_, text), read in zip(spelled, reads)},
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_an_integer_is_spelled_as_the_number_its_own_digits_denote(self):
        integers = [
            2 ** 53 + 1,
            2 ** 60,
            -(2 ** 60),
            10 ** 400,
            -(10 ** 400),
        ]
        digits = self._node_reads([F'({integer})' for integer in integers])
        spellings = self._node_reads([F'({self._spelling(integer)})' for integer in integers])
        self.assertEqual(
            {str(integer): read for integer, read in zip(integers, digits)},
            {str(integer): read for integer, read in zip(integers, spellings)},
        )

    def test_the_one_number_with_no_literal_is_refused(self):
        self.assertIsNone(make_numeric_literal(float('nan')))


class TestNulFollowedByDigitSurvivesPrinting(TestJsDeobfuscator):
    """
    The compact NUL escape followed by a digit from 0 to 7 is read as one legacy octal escape, a
    different character, and followed by an 8 or a 9 it is an escape strict code refuses.
    """

    def _printed_then_read(self, value: str) -> str:
        printed = JsSynthesizer().convert(make_string_literal(value))
        reparsed = JsParser(printed).parse()
        statement = reparsed.body[0]
        if not isinstance(statement, JsExpressionStatement):
            self.fail(F'{printed!r} did not parse as an expression statement')
        literal = statement.expression
        if not isinstance(literal, JsStringLiteral):
            self.fail(F'{printed!r} did not parse as a string literal')
        if literal.value is None:
            self.fail(F'{printed!r} did not denote a string')
        return literal.value

    def test_nul_before_seven_reads_back_as_a_nul_and_a_seven(self):
        value = '\x00' + '7'
        self.assertEqual(value, self._printed_then_read(value))

    def test_nul_before_zero_reads_back_as_a_nul_and_a_zero(self):
        value = '\x00' + '0'
        self.assertEqual(value, self._printed_then_read(value))

    def test_nul_before_a_letter_reads_back_as_a_nul_and_the_letter(self):
        value = '\x00' + 'a'
        self.assertEqual(value, self._printed_then_read(value))

    def test_nul_before_a_letter_keeps_the_compact_escape(self):
        self.assertEqual("'\\0a'", make_string_literal('\x00' + 'a').raw)


class TestEscapeAndDecodeInvertOnNulFollowedByDigit(TestJsDeobfuscator):

    def _round_trip(self, value: str) -> str:
        decoded = decode_js_string_body(escape_js_string(value))
        if decoded is None:
            self.fail(F'the escaping of {value!r} did not denote a string')
        return decoded

    def test_every_digit_after_a_nul_is_recovered(self):
        values = [F'\x00{digit}' for digit in '0123456789']
        self.assertEqual(
            {value: value for value in values},
            {value: self._round_trip(value) for value in values},
        )

    def test_a_letter_after_a_nul_is_recovered(self):
        value = '\x00' + 'a'
        self.assertEqual(value, self._round_trip(value))


class TestHoistingBehindADirectivePrologue(TestJsDeobfuscator):

    @staticmethod
    def _hoisted_into(source: str, host: type) -> str:
        ast = JsParser(source).parse()
        node = next(n for n in ast.walk() if isinstance(n, host))
        insert_after_prologue(node, [JsVariableDeclaration(
            kind=JsVarKind.VAR,
            declarations=[JsVariableDeclarator(id=JsIdentifier(name='hoisted'))],
        )])
        return JsSynthesizer().convert(ast)

    def test_a_declaration_hoisted_into_a_class_static_block_lands_in_it(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                class C {
                  static {
                    var hoisted;
                    log(1);
                  }
                }
                """
            ),
            self._hoisted_into('class C { static { log(1); } }', JsStaticBlock),
        )

    def test_it_lands_behind_the_static_blocks_directive_prologue(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                class C {
                  static {
                    'use strict';
                    var hoisted;
                    log(1);
                  }
                }
                """
            ),
            self._hoisted_into("class C { static { 'use strict'; log(1); } }", JsStaticBlock),
        )

    def test_it_lands_behind_a_function_bodys_directive_prologue(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                function f() {
                  'use strict';
                  var hoisted;
                  log(1);
                }
                """
            ),
            self._hoisted_into("function f() { 'use strict'; log(1); }", JsBlockStatement),
        )


A_NAME_NO_VALUE_MAY_BE_PUT_IN_THE_PLACE_OF = (
    'console.log(q.zz);',
    'console.log({ zz: 1 });',
    'class C { zz(){} }',
    'class C { zz = 1; }',
    "import d from 'm' with { zz: 'json' };",
    'zz: while (0) break zz;',
    'zz: while (0) continue zz;',
    "export * as zz from 'm';",
    "import { zz as q } from 'm';",
    "import zz from 'm';",
    "import * as zz from 'm';",
    'var q = 1; export { q as zz };',
    "export { zz } from 'm';",
)

THE_KINDS_OF_POSITION_THAT_CORPUS_REACHES = [
    'JsBreakStatement',
    'JsContinueStatement',
    'JsExportAllDeclaration',
    'JsExportSpecifier',
    'JsImportAttribute',
    'JsImportDefaultSpecifier',
    'JsImportNamespaceSpecifier',
    'JsImportSpecifier',
    'JsLabeledStatement',
    'JsMemberExpression',
    'JsMethodDefinition',
    'JsProperty',
    'JsPropertyDefinition',
]

#: Neither shorthand has a written-out form that means the same: `__proto__: __proto__` sets the
#: prototype of the object where the shorthand `{ __proto__ }` makes an own property, and `{ [zz] }`
#: is no valid source.
A_SHORTHAND_READ_BUT_NOT_WRITTEN_OUT = (
    'var __proto__ = 1; console.log({ __proto__ });',
    'console.log({ [zz] });',
)

AN_EXPORT_LIST_READ_BUT_NEVER_TAKING_THE_VALUE = (
    'var zz = 1; export { zz };',
    'var zz = 1; export { zz as q };',
)

A_NAME_A_VALUE_STANDS_IN_THE_PLACE_OF = {
    'console.log(zz);': 'console.log(5);',
    'var q = {}; console.log(q[zz]);': 'var q = {};\nconsole.log(q[5]);',
    'console.log({ zz });': 'console.log({ zz: 5 });',
    'console.log({ q: zz });': 'console.log({ q: 5 });',
    'zz.p = 1;': '(5).p = 1;',
}


class TestTheOneGateEverySubstitutionGoesThrough(TestJsDeobfuscator):

    @staticmethod
    def _identifiers(source: str) -> list[JsIdentifier]:
        """
        Every identifier of *source* once, in walk order; a walk visits the one node of a shorthand
        property like `{ q }` twice.
        """
        found: dict[int, JsIdentifier] = {}
        for node in JsParser(source).parse().walk():
            if isinstance(node, JsIdentifier):
                found.setdefault(id(node), node)
        return list(found.values())

    def _substituted(self, source: str, index: int) -> tuple[bool, str]:
        tree = JsParser(source).parse()
        found: dict[int, JsIdentifier] = {}
        for node in tree.walk():
            if isinstance(node, JsIdentifier):
                found.setdefault(id(node), node)
        answer = substitute_use_position(list(found.values())[index], make_numeric_literal(5))
        return answer, JsSynthesizer().convert(tree)

    def _substituted_by_name(self, source: str, name: str) -> tuple[bool, str]:
        indices = [
            index for index, node in enumerate(self._identifiers(source)) if node.name == name
        ]
        self.assertEqual(len(indices), 1, source)
        return self._substituted(source, indices[0])

    def _substituted_shorthand(self, source: str) -> tuple[bool, bool, str]:
        tree = JsParser(source).parse()
        shorthand = [
            node for node in tree.walk()
            if isinstance(node, JsProperty) and node.shorthand
        ][0]
        node = shorthand.value
        assert isinstance(node, JsIdentifier)
        answer = substitute_use_position(node, make_numeric_literal(5))
        return is_use_position(node), answer, JsSynthesizer().convert(tree)

    def _refused_positions(self) -> dict[tuple[str, int], str]:
        return {
            (source, index): type(node.parent).__name__
            for source in A_NAME_NO_VALUE_MAY_BE_PUT_IN_THE_PLACE_OF
            for index, node in enumerate(self._identifiers(source))
            if not is_use_position(node)
        }

    def test_the_corpus_reaches_every_kind_of_position_no_value_may_stand_in(self):
        self.assertEqual(
            sorted(set(self._refused_positions().values())),
            THE_KINDS_OF_POSITION_THAT_CORPUS_REACHES,
        )

    def test_a_position_the_model_says_reads_nothing_is_refused_and_nothing_moves(self):
        rows = self._refused_positions()
        self.assertEqual(
            {key: self._substituted(*key) for key in rows},
            {(source, index): (False, printed(source)) for source, index in rows},
        )

    def test_a_shorthand_the_gate_may_not_write_out_is_refused_although_it_is_read(self):
        rows = A_SHORTHAND_READ_BUT_NOT_WRITTEN_OUT
        self.assertEqual(
            {source: self._substituted_shorthand(source) for source in rows},
            {source: (True, False, printed(source)) for source in rows},
        )

    def _substituted_export_local(self, source: str) -> tuple[bool, bool, str]:
        tree = JsParser(source).parse()
        specifier = [
            node for node in tree.walk()
            if isinstance(node, JsExportSpecifier)
        ][0]
        node = specifier.local
        assert isinstance(node, JsIdentifier)
        answer = substitute_use_position(node, make_numeric_literal(5))
        return is_use_position(node), answer, JsSynthesizer().convert(tree)

    def test_an_export_list_is_refused_although_it_is_read(self):
        rows = AN_EXPORT_LIST_READ_BUT_NEVER_TAKING_THE_VALUE
        self.assertEqual(
            {source: self._substituted_export_local(source) for source in rows},
            {source: (True, False, printed(source)) for source in rows},
        )

    def test_a_position_that_reads_a_value_takes_the_replacement(self):
        rows = A_NAME_A_VALUE_STANDS_IN_THE_PLACE_OF
        self.assertEqual(
            {source: self._substituted_by_name(source, 'zz') for source in rows},
            {source: (True, printed(expected)) for source, expected in rows.items()},
        )

    def test_a_shorthand_whose_halves_are_two_nodes_is_written_out_once(self):
        source = 'function f(a) { return { a }; }'
        function = [
            node for node in JsParser(source).parse().walk()
            if isinstance(node, JsFunctionDeclaration)
        ][0]
        literal = [
            node for node in function.walk() if isinstance(node, JsObjectExpression)
        ][0]
        substituted = substitute_params(
            literal,
            function.params,
            [make_numeric_literal(5)],
            Transformer(),
        )
        self.assertEqual(JsSynthesizer().convert(substituted), '{ a: 5 }')


class TestASubstitutedCalleeKeepsTheCallTheNameMade(TestJsDeobfuscator):

    @staticmethod
    def _substituting_the_callee_of(source: str, replacement: str, **kwargs) -> str:
        ast = JsParser(source).parse()
        callee = next(n for n in ast.walk() if isinstance(n, JsIdentifier) and n.name == 'f')
        statement = JsParser(F'{replacement};').parse().body[0]
        assert isinstance(statement, JsExpressionStatement) and statement.expression is not None
        substitute_use_position(callee, statement.expression, **kwargs)
        return JsSynthesizer().convert(ast)

    def test_a_member_written_for_a_callee_is_called_behind_a_sequence(self):
        self.assertEqual("(0, ns.f)('x');", self._substituting_the_callee_of("f('x');", 'ns.f'))

    def test_the_name_eval_written_for_a_callee_is_called_behind_a_sequence(self):
        self.assertEqual("(0, eval)('x');", self._substituting_the_callee_of("f('x');", 'eval'))

    def test_a_member_written_as_the_spelling_of_the_reference_keeps_its_receiver(self):
        self.assertEqual(
            "ns.f('x');",
            self._substituting_the_callee_of("f('x');", 'ns.f', as_spelled=True),
        )

    def test_a_member_written_for_a_read_stands_bare(self):
        self.assertEqual('typeof ns.f;', self._substituting_the_callee_of('typeof f;', 'ns.f'))


_BS = chr(92)
A_STRING_AND_THE_VALUE_IT_HOLDS = {
    F'"{_BS}xZZ"': (False, None),
    F'"{_BS}u123"': (False, None),
    F'"{_BS}x"': (False, None),
    '"ab"': (True, 'ab'),
    F'"a{_BS}tb"': (True, 'a\tb'),
    "''": (True, ''),
}


class TestExtractLiteralValueRefusesAStringDenotingNothing(TestJsDeobfuscator):

    @staticmethod
    def _expression(source: str) -> Expression:
        statement = JsParser(source + ';').parse().body[0]
        assert isinstance(statement, JsExpressionStatement) and statement.expression is not None
        return statement.expression

    def test_a_string_holds_its_value_only_where_it_denotes_one(self):
        self.assertEqual(
            {source: extract_literal_value(self._expression(source))
             for source in A_STRING_AND_THE_VALUE_IT_HOLDS},
            A_STRING_AND_THE_VALUE_IT_HOLDS,
        )


class TestWhereAValueLands(TestJsDeobfuscator):

    @staticmethod
    def _landing(source: str) -> Landing | None:
        value = next(
            node for node in JsParser(source).parse().walk()
            if isinstance(node, JsIdentifier) and node.name == 'VALUE'
        )
        return value_landing(value)

    def _assert_lands(self, landing: Landing, sources: tuple[str, ...]):
        for source in sources:
            with self.subTest(source=source):
                self.assertEqual(self._landing(source), landing)

    def test_a_value_a_binding_receives(self):
        self._assert_lands(Landing.BINDING, (
            'var x = VALUE;',
            'x = VALUE;',
            '[x] = VALUE;',
            'var {x} = VALUE;',
            'var x = (VALUE);',
            'var x = y || VALUE;',
            'var x = c ? 1 : VALUE;',
            'var x = (0, VALUE);',
            'x ||= VALUE;',
        ))

    def test_a_value_a_member_receives(self):
        self._assert_lands(Landing.PROPERTY, (
            'o.p = VALUE;',
            'x = o.p = VALUE;',
            'x += (o.p = VALUE, 1);',
            'globalThis.q = VALUE;',
            'arguments[0] = VALUE;',
        ))

    def test_a_value_a_member_access_is_made_on(self):
        self._assert_lands(Landing.MEMBER, (
            'var x = VALUE.prototype;',
            'var x = VALUE.a.b;',
            'VALUE.prototype.k = 1;',
            'f(VALUE.k);',
            'VALUE[k]("code");',
            '(y || VALUE).C;',
            'delete VALUE.k;',
            'VALUE.__defineGetter__("k", f);',
        ))

    def test_a_value_that_names_the_property_an_access_or_an_install_reaches(self):
        self._assert_lands(Landing.KEY, (
            'var x = o[VALUE];',
            'globalThis[VALUE] = 1;',
            'Object[VALUE](o, "k", d);',
            'Object.defineProperty(o, VALUE, d);',
            'o.__defineGetter__(VALUE, f);',
        ))

    def test_a_value_a_descriptor_is_installed_on(self):
        self._assert_lands(Landing.INSTALL, (
            'Object.defineProperty(VALUE, "k", d);',
            'Object.defineProperties(VALUE, d);',
            'Reflect.defineProperty(VALUE, "k", d);',
        ))

    def test_a_value_handed_to_a_call(self):
        self._assert_lands(Landing.ARGUMENT, (
            'f(VALUE);',
            'f(1, VALUE);',
            'new F(VALUE);',
            'f(...VALUE);',
            'Object.defineProperties(o, VALUE);',
            'Object.defineProperty(o, "k", VALUE);',
        ))

    def test_a_value_a_call_invokes(self):
        self._assert_lands(Landing.CALLEE, (
            'VALUE("code");',
            '(0, VALUE)("code");',
            'new VALUE();',
        ))

    def test_a_value_no_position_reads(self):
        self._assert_lands(Landing.ELSEWHERE, (
            'x = VALUE == 1;',
            'x = {k: VALUE};',
            'x = [VALUE];',
            'x = [...VALUE];',
            'var x = VALUE ? 1 : 2;',
            'var x = (VALUE, 1);',
            'typeof VALUE;',
            'VALUE;',
            'function f() { return VALUE; }',
            'var x = o.VALUE;',
        ))

    def test_a_value_reaching_the_root_it_is_followed_to_lands_nowhere_yet(self):
        script = JsParser('function f(p, q) { return c ? p : (q, p).k; }').parse()
        function = script.body[0]
        assert isinstance(function, JsFunctionDeclaration) and function.body is not None
        statement = function.body.body[0]
        assert isinstance(statement, JsReturnStatement) and statement.argument is not None
        expression = statement.argument
        names = [node for node in expression.walk() if isinstance(node, JsIdentifier)]
        answered = next(node for node in names if node.name == 'p' and node.parent is expression)
        read = next(node for node in names if node.name == 'p' and node.parent is not expression)
        self.assertIsNone(value_landing(answered, expression))
        self.assertEqual(value_landing(read, expression), Landing.MEMBER)
        self.assertEqual(value_landing(expression), Landing.ELSEWHERE)


class TestCodeThatDeclaresANameTheIntrinsicWriteScanWatches(TestJsDeobfuscator):

    @staticmethod
    def _declares(source: str) -> bool:
        return declares_a_watched_name(JsParser(source).parse().body)

    def test_a_declaration_or_an_assignment_of_the_name(self):
        for source in (
            'var Object;',
            'let {Math} = o;',
            'function Object() {}',
            'function f(Math) {}',
            'var f = function (a, [Object]) {};',
            'var f = (Math) => 1;',
            'class Object {}',
            'try {} catch (Math) {}',
            'Object = 1;',
            'Object++;',
            '[Math] = o;',
            'for (Object in o);',
        ):
            with self.subTest(source=source):
                self.assertTrue(self._declares(source))

    def test_a_read_of_the_name_or_a_name_it_does_not_watch(self):
        for source in (
            'Object.keys(o);',
            'Object.prototype.p = 1;',
            'var o = {Object: 1};',
            'o.Object = 1;',
            'var window = this;',
            'var globalThis = 1;',
            'var local = Object;',
            'function f(a) { return Math; }',
        ):
            with self.subTest(source=source):
                self.assertFalse(self._declares(source))
