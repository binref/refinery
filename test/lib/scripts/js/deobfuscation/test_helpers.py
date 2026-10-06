from __future__ import annotations

import inspect
import struct
import unittest

from test.lib.scripts.js.analysis.differential import behavior, node_executable
from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator
from test.lib.scripts.js.ledger import printed

from refinery.lib.scripts.js.analysis.model import build_semantic_model, is_use_position
from refinery.lib.scripts.js.deobfuscation.helpers import (
    JS_NULL,
    JsBuffer,
    binding_has_references,
    declares_a_watched_name,
    escape_js_string,
    extract_literal_value,
    insert_after_prologue,
    lands_in_binding,
    make_numeric_literal,
    make_string_literal,
    substitute_params,
    substitute_use_position,
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
    JsStaticBlock,
    JsStringLiteral,
    JsVariableDeclaration,
    JsVariableDeclarator,
    JsVarKind,
)
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer


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
    """
    `value_to_node` renders an interpreter value back into source. Every value it accepts must denote
    exactly the same thing once re-parsed, so these tests pin the rendered text for the cases where a
    plausible-looking rendering would mean something else, and pin refusal for the values that have no
    faithful literal form at all.
    """

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
        A `__proto__` entry in the value is an own data property. Only the computed key form creates
        one; the bare and quoted forms install a prototype and leave no own property behind.
        """
        self.assertEqual("{ ['__proto__']: 1 }", self._render({'__proto__': 1}))

    def test_renders_nested_proto_key_as_computed(self):
        self.assertEqual(
            "{ 'a': { ['__proto__']: 1 } }",
            self._render({'a': {'__proto__': 1}}),
        )

    def test_renders_ordinary_prototype_member_names_plainly(self):
        """
        Only `__proto__` is special. The other inherited member names are ordinary own properties when
        written as plain keys, so forcing them computed would be needless noise.
        """
        self.assertEqual("{ 'constructor': 1 }", self._render({'constructor': 1}))
        self.assertEqual("{ 'toString': 1 }", self._render({'toString': 1}))
        self.assertEqual("{ 'hasOwnProperty': 1 }", self._render({'hasOwnProperty': 1}))

    def test_refuses_buffer(self):
        """
        A Buffer has no literal form. Rendering its bytes as an array would produce a value of a
        different type, silently dropping `Buffer.isBuffer` and `.toString('hex')`.
        """
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
    """
    `make_numeric_literal` writes a Number as source text and `extract_literal_value` reads source
    text back into a value; the module declares the two inverses of each other. Whether they are is
    decided by what the text means, and neither of them may answer that: every spelling below goes
    to Node, which reports the 64 bits of the Number it read, and through `JsParser`, so that the
    reader is handed the tree the text really produces rather than the one the writer built.
    """

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
        """
        The 64 bits of the Number Node reads from each of *expressions*, as hexadecimal. A bit
        pattern is the whole Number and nothing besides it, which is what makes it the thing to
        compare: it separates the two zeros, and it is not a printed form, so no spelling is ever
        measured against a reading of itself.
        """
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
        """
        `NaN`, `Infinity` and `undefined` are ordinary identifiers that any scope may bind to
        something else, so a spelling that reached a Number through one of those names would mean
        whatever the scope supplies. A literal denotes its value in every scope, which is what this
        asks of each spelling by reading it inside a function that binds all three to other numbers.
        """
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
        """
        A Python integer is not a Number, and what it names is what its digits round to: past 2^53 a
        different integer, and past the double range an infinity. Those digits are themselves a
        JavaScript numeric literal, so what Node reads from them is what the spelling has to agree
        with, without a Python-side Number entering the comparison at all.
        """
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
        """
        Every other Number has a literal that denotes it, the infinities included. NaN has none, so
        the writer answers nothing rather than a spelling that would mean something else.
        """
        self.assertIsNone(make_numeric_literal(float('nan')))


class TestNulFollowedByDigitSurvivesPrinting(TestJsDeobfuscator):
    """
    A NUL immediately before an ASCII digit is the one place the compact NUL escape cannot be used:
    before a 0 through 7 it joins the digit into a single legacy octal escape, a different character
    (Node reads a NUL written before a 7 that way as the one character U+0007), and before an 8 or 9
    it is an escape strict code refuses. Printing the value must keep the NUL and the digit apart,
    while a NUL that no digit follows keeps the compact escape it had.
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
    """
    Escaping a value into a literal body and decoding a literal body are inverse operations, so a
    string put through both comes back unchanged. The case a naive escape would corrupt is a NUL
    immediately before a digit, where the compact NUL escape would merge with the digit into one
    character; every ASCII digit is checked here, the 8 and 9 that form no octal escape included.
    """

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
    """
    `insert_after_prologue` puts statements at the head of a host's body, behind whatever Directive
    Prologue the body opens with. Which nodes are prologue hosts is
    `refinery.lib.scripts.js.strict.is_prologue_host`, and a class static block is one of them: it
    holds a statement list of its own that a prologue can open, whatever a prologue there decides.

    A hoist that lands nowhere is worse than one that is declined. The caller has already rewritten
    the references the hoisted declaration is supposed to bind, so a silent no-op leaves those
    references bound to nothing.
    """

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


#: A program naming something in a position no value may be put in. Between them the thirteen reach
#: every such position the language has: the member after a dot, a key of an object literal, the
#: name of a class method and of a class field, the key of an import attribute, a label and the two
#: jumps to one, the name a module is re-exported under, both halves of an import specifier, the
#: local of a default and of a namespace import, the name a binding is exported under, and the
#: local of an export list carrying a `from` clause. The local of a sourceless list is the one
#: specifier position missing here: it reads, and
#: `AN_EXPORT_LIST_READ_BUT_NEVER_TAKING_THE_VALUE` holds it.
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

#: The parent node classes the corpus above stands under, which is what says the law over it is
#: quantified over every kind of position rather than over whichever ones a program happened to
#: hold.
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

#: A shorthand property whose one identifier is read and which is still not written out. `{ x }` is
#: `{ x: x }` for every name but `__proto__`, which written with the colon sets the object's
#: prototype and gives it no property of that name at all; and a shorthand carrying a computed key
#: is a shape no source spells, so there is no one program that writing it out could be said to
#: mean.
A_SHORTHAND_READ_BUT_NOT_WRITTEN_OUT = (
    'var __proto__ = 1; console.log({ __proto__ });',
    'console.log({ [zz] });',
)

#: A module whose export list is the only reader of the name `zz`. The local half of a sourceless
#: list stands where `is_use_position` says a value is read, and there is still no program that a
#: value put there could mean: a list exports bindings and never values, and `export { 5 };` is a
#: module no engine links.
AN_EXPORT_LIST_READ_BUT_NEVER_TAKING_THE_VALUE = (
    'var zz = 1; export { zz };',
    'var zz = 1; export { zz as q };',
)

#: A program naming something a value may stand in the place of, mapped to the program that stands
#: once it does. The shorthand is the one written out rather than replaced, since its one identifier
#: is the key as much as it is the read and only the read may move.
A_NAME_A_VALUE_STANDS_IN_THE_PLACE_OF = {
    'console.log(zz);': 'console.log(5);',
    'var q = {}; console.log(q[zz]);': 'var q = {};\nconsole.log(q[5]);',
    'console.log({ zz });': 'console.log({ zz: 5 });',
    'console.log({ q: zz });': 'console.log({ q: 5 });',
    'zz.p = 1;': '(5).p = 1;',
}


class TestTheOneGateEverySubstitutionGoesThrough(TestJsDeobfuscator):
    """
    `refinery.lib.scripts.js.deobfuscation.helpers.substitute_use_position` is where every pass puts
    a substitution, and what it decides is whether the position reads a value at all.
    `refinery.lib.scripts.js.analysis.model.is_use_position` is the statement of that, and the gate
    refuses everything it refuses: text standing in one of those positions names a property, a label
    or a module binding, and a value put there is not a rename but a different program — `o.5`,
    `{ -2: 1 }`, `5: while (0) break 5;`, `import { 5 } from 'm'`.

    Whether a name in a use position is a *reference* is the caller's question and not this one: a
    name bound by a destructuring pattern is written like a read and no syntactic test tells the two
    apart, so a declarator id is answered here exactly as a read of it would be.

    The answer is what a caller announcing a change reads, so a declined substitution has to leave
    the tree it was handed: a pass that reports a change it did not make reports one every round,
    and the fixpoint it sits in never arrives.
    """

    @staticmethod
    def _identifiers(source: str) -> list[JsIdentifier]:
        """
        Every identifier of *source*, once each and in the order a walk reaches them. A shorthand
        property is one node filling two slots of its parent and a walk arrives at it through both,
        so counting nodes rather than visits is what keeps `{ q }` from reading as two identifiers.
        """
        found: dict[int, JsIdentifier] = {}
        for node in JsParser(source).parse().walk():
            if isinstance(node, JsIdentifier):
                found.setdefault(id(node), node)
        return list(found.values())

    def _substituted(self, source: str, index: int) -> tuple[bool, str]:
        """
        What the gate answers for the identifier standing at *index* in *source*, and the program
        that stands afterwards. The source is parsed afresh for every question, since the gate
        rewrites the tree it is given and a second question asked of that tree is a question about
        some other program.
        """
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
        """
        Whether the value half of the one shorthand property of *source* reads a value, what the
        gate answers for it, and the program that stands afterwards.
        """
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
        """
        Every identifier of `A_NAME_NO_VALUE_MAY_BE_PUT_IN_THE_PLACE_OF` that `is_use_position`
        refuses, handed to the gate one at a time: the answer is `False` and the program that stands
        afterwards is the one that stood before.
        """
        rows = self._refused_positions()
        self.assertEqual(
            {key: self._substituted(*key) for key in rows},
            {(source, index): (False, printed(source)) for source, index in rows},
        )

    def test_a_shorthand_the_gate_may_not_write_out_is_refused_although_it_is_read(self):
        """
        The two shorthand properties of `A_SHORTHAND_READ_BUT_NOT_WRITTEN_OUT` stand where
        `is_use_position` says a value is read, and the gate declines both, leaving each program as
        it found it.
        """
        rows = A_SHORTHAND_READ_BUT_NOT_WRITTEN_OUT
        self.assertEqual(
            {source: self._substituted_shorthand(source) for source in rows},
            {source: (True, False, printed(source)) for source in rows},
        )

    def _substituted_export_local(self, source: str) -> tuple[bool, bool, str]:
        """
        Whether the local half of the one export specifier of *source* reads a value, what the gate
        answers for it, and the program that stands afterwards.
        """
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
        """
        The export lists of `AN_EXPORT_LIST_READ_BUT_NEVER_TAKING_THE_VALUE` stand where
        `is_use_position` says a value is read, and the gate declines both, leaving each program as
        it found it.
        """
        rows = AN_EXPORT_LIST_READ_BUT_NEVER_TAKING_THE_VALUE
        self.assertEqual(
            {source: self._substituted_export_local(source) for source in rows},
            {source: (True, False, printed(source)) for source in rows},
        )

    def test_a_position_that_reads_a_value_takes_the_replacement(self):
        """
        Each program of `A_NAME_A_VALUE_STANDS_IN_THE_PLACE_OF` with the numeral `5` put where `zz`
        stood, the gate answering `True` for every one of them.
        """
        rows = A_NAME_A_VALUE_STANDS_IN_THE_PLACE_OF
        self.assertEqual(
            {source: self._substituted_by_name(source, 'zz') for source in rows},
            {source: (True, printed(expected)) for source, expected in rows.items()},
        )

    def test_a_shorthand_whose_halves_are_two_nodes_is_written_out_once(self):
        """
        A parse builds one node for both halves of `{ a }` and a clone builds two, so a caller
        walking a cloned tree offers the gate the key and the value separately and in whichever
        order it reaches them. `substitute_params` is such a caller: inlining `5` for `a` writes the
        property out once, and the numeral lands in the half that reads it.
        """
        source = 'function f(a) { return { a }; }'
        function = [
            node for node in JsParser(source).parse().walk()
            if isinstance(node, JsFunctionDeclaration)
        ][0]
        literal = [
            node for node in function.walk() if isinstance(node, JsObjectExpression)
        ][0]
        substituted = substitute_params(literal, function.params, [make_numeric_literal(5)])
        self.assertEqual(JsSynthesizer().convert(substituted), '{ a: 5 }')


class TestASubstitutedCalleeKeepsTheCallTheNameMade(TestJsDeobfuscator):
    """
    A name standing as a callee invoked its value with no receiver and no direct-eval effect, so a
    value put in its place whose own spelling as a callee means more — a member access binds
    `this` to its object, a bare `eval` runs its text in the caller's scope — is called behind
    `(0, ...)` instead. A caller that re-spells the reference itself asks for the form it wrote with
    `as_spelled=True`: the flattening recovery qualifies a name to the namespaced home it was
    recovered from, and the member call is the call the input made there.
    """

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


#: A string written with a `\x` or `\u` escape naming no character, whose `value` is `None`, and a
#: well-formed string beside it. The backslash is spelled with `chr(92)` so that no tool between the
#: source and the parser reads it as an escape of its own.
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
    """
    A string written with a `\\x` or `\\u` escape naming no character denotes nothing, so it holds
    no value to extract. Reporting `(True, None)` for it would hand the caller the value `undefined`
    — the interpreter and `value_to_node` both read `None` as that — folding a run the file could
    never have carried into a value it never named. A well-formed string beside it is read as the
    text it denotes, so the refusal costs no genuine literal its value.
    """

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


class TestWhereAValueLandsInABinding(TestJsDeobfuscator):

    @staticmethod
    def _lands(source: str) -> bool:
        value = next(
            node for node in JsParser(source).parse().walk()
            if isinstance(node, JsIdentifier) and node.name == 'VALUE'
        )
        return lands_in_binding(value)

    def test_a_value_a_binding_receives(self):
        for source in (
            'var x = VALUE;',
            'x = VALUE;',
            '[x] = VALUE;',
            'var {x} = VALUE;',
            'var x = (VALUE);',
            'var x = y || VALUE;',
            'var x = c ? 1 : VALUE;',
            'var x = (0, VALUE);',
            'var x = VALUE.prototype;',
            'var x = VALUE.a.b;',
            'x = o.p = VALUE;',
        ):
            with self.subTest(source=source):
                self.assertTrue(self._lands(source))

    def test_a_value_no_binding_receives(self):
        for source in (
            'f(VALUE);',
            'o.p = VALUE;',
            'x = VALUE == 1;',
            'x = {k: VALUE};',
            'x = [VALUE];',
            'var x = c[VALUE];',
            'var x = VALUE ? 1 : 2;',
            'var x = (VALUE, 1);',
            'var x = VALUE();',
            'x += (o.p = VALUE, 1);',
        ):
            with self.subTest(source=source):
                self.assertFalse(self._lands(source))


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
