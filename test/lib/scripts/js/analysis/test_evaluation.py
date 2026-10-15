from __future__ import annotations

import dataclasses

from test import TestBase

from refinery.lib.scripts import Node, child_fields
from refinery.lib.scripts.js import model
from refinery.lib.scripts.js.analysis.evaluation import (
    PART_EVALUATION,
    evaluated_whenever_completed,
    evaluated_with,
)
from refinery.lib.scripts.js.model import JsIdentifier, JsScript
from refinery.lib.scripts.js.parser import JsParser


def _node_types() -> list[type[Node]]:
    return [
        value for value in vars(model).values()
        if isinstance(value, type)
        and issubclass(value, Node)
        and dataclasses.is_dataclass(value)
        and value.__module__ == model.__name__
    ]


class TestEveryPartIsListed(TestBase):

    def test_every_child_field_of_every_node_type_has_a_row(self):
        missing = [
            F'{node_type.__name__}.{name}'
            for node_type in _node_types()
            for name in child_fields(node_type)
            if (node_type, name) not in PART_EVALUATION
        ]
        self.assertEqual(missing, [])

    def test_every_row_names_a_child_field(self):
        stale = [
            F'{node_type.__name__}.{name}'
            for node_type, name in PART_EVALUATION
            if name not in child_fields(node_type)
        ]
        self.assertEqual(stale, [])


class TestWhenAPartOfAStatementRuns(TestBase):

    @staticmethod
    def _evaluated(source: str, name: str = 'c') -> bool:
        script = JsParser(source).parse()
        assert isinstance(script, JsScript)
        statement = script.body[-1]
        node = next(
            node for node in statement.walk()
            if isinstance(node, JsIdentifier) and node.name == name
        )
        return evaluated_whenever_completed(node, statement)

    def test_the_left_operand_of_and_runs(self):
        self.assertTrue(self._evaluated('(c = 1) && x;'))

    def test_the_right_operand_of_and_may_not_run(self):
        self.assertFalse(self._evaluated('x && (c = 1);'))

    def test_the_test_of_a_conditional_runs(self):
        self.assertTrue(self._evaluated('(c = 1) ? a : b;'))

    def test_an_arm_of_a_conditional_may_not_run(self):
        self.assertFalse(self._evaluated('x ? (c = 1) : 0;'))
        self.assertFalse(self._evaluated('x ? 0 : (c = 1);'))

    def test_the_value_of_a_logical_assignment_may_not_run(self):
        self.assertFalse(self._evaluated('y ||= (c = 1);'))
        self.assertFalse(self._evaluated('y &&= (c = 1);'))
        self.assertFalse(self._evaluated('y ??= (c = 1);'))

    def test_the_value_of_an_arithmetic_assignment_runs(self):
        self.assertTrue(self._evaluated('y += (c = 1);'))

    def test_an_argument_of_an_optional_call_may_not_run(self):
        self.assertFalse(self._evaluated('o?.f(c = 1);'))
        self.assertFalse(self._evaluated('o?.p.f(c = 1);'))

    def test_an_argument_of_a_call_runs(self):
        self.assertTrue(self._evaluated('o.f(c = 1);'))

    def test_a_key_past_an_optional_link_may_not_run(self):
        self.assertFalse(self._evaluated('o?.p[c = 1];'))

    def test_a_destructuring_default_may_not_run(self):
        self.assertFalse(self._evaluated('var { a = (c = 1) } = o;'))
        self.assertFalse(self._evaluated('({ a: b = (c = 1) } = o);'))
        self.assertFalse(self._evaluated('[b = (c = 1)] = o;'))

    def test_a_later_case_test_may_not_run(self):
        self.assertFalse(self._evaluated('switch (x) { case 0: break; case (c = 1): break; }'))

    def test_a_function_body_runs_later(self):
        self.assertFalse(self._evaluated('function f() { c = 1; }'))
        self.assertFalse(self._evaluated('var f = () => (c = 1);'))

    def test_a_field_initializer_runs_later(self):
        self.assertFalse(self._evaluated('class A { v = (c = 1); }'))

    def test_an_initializer_of_a_declaration_runs(self):
        self.assertTrue(self._evaluated('var a = [o.f(c = 1)], b = 2;'))


class TestWhetherAPartRunsWithItsStatement(TestBase):

    @staticmethod
    def _with(source: str) -> bool:
        script = JsParser(source).parse()
        assert isinstance(script, JsScript)
        statement = script.body[-1]
        node = next(
            node for node in statement.walk()
            if isinstance(node, JsIdentifier) and node.name == 'c'
        )
        return evaluated_with(node, statement)

    def test_a_part_run_on_some_runs_runs_with_its_statement(self):
        self.assertTrue(self._with('x && c();'))
        self.assertTrue(self._with('x ? c() : 0;'))

    def test_a_computed_key_of_a_class_runs_with_its_statement(self):
        self.assertTrue(self._with('class A { [c()]() {} }'))

    def test_a_field_initializer_runs_at_a_time_of_its_own(self):
        self.assertFalse(self._with('class A { v = c(); }'))
        self.assertFalse(self._with('class A { v = x && c(); }'))
