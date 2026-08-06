from __future__ import annotations

import inspect

from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator

from refinery.lib.scripts.js.analysis.model import build_semantic_model
from refinery.lib.scripts.js.deobfuscation.helpers import (
    JS_NULL,
    JsBuffer,
    binding_has_references,
    make_string_literal,
    value_to_node,
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
        self.assertEqual('NaN', self._render(float('nan')))
        self.assertEqual('Infinity', self._render(float('inf')))
        self.assertEqual('-Infinity', self._render(float('-inf')))
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
