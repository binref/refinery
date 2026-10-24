from __future__ import annotations

from test import TestBase

from refinery.lib.scripts import _clone_node
from refinery.lib.scripts.js.analysis.cache import ModelCache
from refinery.lib.scripts.js.deobfuscation.admission import CallAdmission
from refinery.lib.scripts.js.model import (
    FUNCTION_NODES,
    JsCallExpression,
    JsIdentifier,
)
from refinery.lib.scripts.js.parser import JsParser


class TestCallAdmission(TestBase):

    @staticmethod
    def _admission(source: str, name: str) -> tuple[CallAdmission, JsCallExpression]:
        script = JsParser(source).parse()
        call = next(
            node for node in script.walk_in_order()
            if isinstance(node, JsCallExpression)
            and isinstance(node.callee, JsIdentifier)
            and node.callee.name == name
        )
        return CallAdmission(ModelCache(script), script), call

    def test_a_call_of_a_function_computing_from_its_arguments_is_admitted(self):
        admission, call = self._admission('function add(a, b) { return a + b; } SINK(add(1, 2));', 'add')
        callee = admission.callee(call)
        self.assertIsInstance(callee, FUNCTION_NODES)
        self.assertEqual(admission.interpreter_at(call).execute(callee, [1.0, 2.0]), 3.0)

    def test_a_call_of_a_function_writing_a_global_is_refused(self):
        admission, call = self._admission('function f(a) { g = a; return a; } SINK(f(1));', 'f')
        self.assertIsNone(admission.callee(call))

    def test_a_call_after_its_function_is_assigned_is_admitted(self):
        admission, call = self._admission('var f = function (a) { return a; }; SINK(f(1));', 'f')
        self.assertIsNotNone(admission.callee(call))

    def test_a_call_before_its_function_is_assigned_is_refused(self):
        admission, call = self._admission('SINK(f(1)); var f = function (a) { return a; };', 'f')
        self.assertIsNone(admission.callee(call))

    def test_a_call_of_a_function_reading_a_table_nothing_changes_is_admitted(self):
        admission, call = self._admission(
            'var T = [1, 2]; function g(i) { return T[i]; } SINK(g(0));', 'g')
        self.assertIsNotNone(admission.callee(call))

    def test_a_call_of_a_function_reading_a_table_the_program_changes_is_refused(self):
        admission, call = self._admission(
            'var T = [1, 2]; function g(i) { return T[i]; } T.push(3); SINK(g(0));', 'g')
        self.assertIsNone(admission.callee(call))

    def test_trust_is_answered_at_a_call_in_the_tree(self):
        admission, call = self._admission('function add(a, b) { return a + b; } SINK(add(1, 2));', 'add')
        self.assertIsNotNone(admission.trust_at(call))

    def test_no_trust_question_is_answered_about_a_copy_outside_the_tree(self):
        admission, call = self._admission('function add(a, b) { return a + b; } SINK(add(1, 2));', 'add')
        self.assertIsNone(admission.trust_at(_clone_node(call)))
