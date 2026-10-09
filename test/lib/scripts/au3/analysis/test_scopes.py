"""
Which storage a write or a read targets, per the scope model: the script level always the global,
a function's parameters and dominating declarations the local, and everything else nothing at
all — and which storage an occurrence may reach, the branch-created local among them. Every
expectation below restates a rule the AutoIt3 documentation states, so a failure is
either a parsing defect or a rule the model misapplies — the unseen `#include` a bare write
cannot decide is the reason the third answer exists.
"""
from __future__ import annotations

import inspect

from test import TestBase

from refinery.lib.scripts.au3 import ast
from refinery.lib.scripts.au3.analysis.scopes import Binding, build_scope_model
from refinery.lib.scripts.au3.model import Au3Assignment, Au3Variable
from refinery.lib.scripts.au3.parser import Au3Parser


class TestAu3ScopeModel(TestBase):

    def _binding(self, source: str, name: str) -> Binding:
        root = Au3Parser(inspect.cleandoc(source)).parse()
        model = build_scope_model(root)
        function = model.functions['f']
        for node in ast.scope_nodes(function.body):
            if not isinstance(node, Au3Assignment):
                continue
            variable = ast.store_target_variable(node.target)
            statement = ast.owning_statement(node)
            if variable is not None and variable.name == name and statement is not None:
                return model.binding(function, statement, name)
        self.fail('the source holds no assignment of that name')

    def test_a_parameter_write_targets_the_local(self):
        self.assertEqual(
            self._binding(
                '''
                Func f($p)
                    $p = 5
                EndFunc
                ''',
                'p',
            ),
            Binding.LOCAL)

    def test_a_bare_write_after_a_dominating_local_targets_the_local(self):
        self.assertEqual(
            self._binding(
                '''
                Func f()
                    Local $x
                    $x = 5
                EndFunc
                ''',
                'x',
            ),
            Binding.LOCAL)

    def test_a_bare_write_before_the_declaration_proves_nothing(self):
        self.assertEqual(
            self._binding(
                '''
                Func f()
                    $x = 5
                    Local $x
                EndFunc
                ''',
                'x',
            ),
            Binding.NONE)

    def test_a_dim_declaration_dominates_nothing(self):
        self.assertEqual(
            self._binding(
                '''
                Func f()
                    Dim $x
                    $x = 5
                EndFunc
                ''',
                'x',
            ),
            Binding.NONE)

    def test_a_static_declaration_dominates_the_local(self):
        self.assertEqual(
            self._binding(
                '''
                Func f()
                    Static $x
                    $x = 5
                EndFunc
                ''',
                'x',
            ),
            Binding.LOCAL)

    def test_a_function_scope_const_declaration_dominates_the_local(self):
        self.assertEqual(
            self._binding(
                '''
                Func f()
                    Const $x = 1
                    $x = 5
                EndFunc
                ''',
                'x',
            ),
            Binding.LOCAL)

    def test_a_local_enum_declaration_dominates_the_local(self):
        self.assertEqual(
            self._binding(
                '''
                Func f()
                    Local Enum $e
                    $e = 5
                EndFunc
                ''',
                'e',
            ),
            Binding.LOCAL)

    def test_a_bare_enum_declaration_dominates_the_local(self):
        """
        An `Enum` no `Global` keyword leads declares its entries into the scope it stands in, so
        inside a function they are constants of the function's local storage.
        """
        self.assertEqual(
            self._binding(
                '''
                Func f()
                    Enum $e = 1, $d
                    $d = 5
                EndFunc
                ''',
                'd',
            ),
            Binding.LOCAL)

    def test_a_global_enum_declaration_in_the_function_claims_the_global(self):
        self.assertEqual(
            self._binding(
                '''
                Func f()
                    Global Enum $e = 1
                    $e = 5
                EndFunc
                ''',
                'e',
            ),
            Binding.NONE)

    def test_a_global_declaration_in_the_function_claims_the_global(self):
        self.assertEqual(
            self._binding(
                '''
                Func f()
                    Local $x
                    $x = 5
                    Global $x
                EndFunc
                ''',
                'x',
            ),
            Binding.NONE)

    def test_a_declaration_inside_control_flow_dominates_nothing(self):
        self.assertEqual(
            self._binding(
                '''
                Func f()
                    If True Then
                        Local $x
                    EndIf
                    $x = 5
                EndFunc
                ''',
                'x',
            ),
            Binding.NONE)

    def test_a_write_inside_control_flow_under_a_dominating_declaration(self):
        self.assertEqual(
            self._binding(
                '''
                Func f()
                    Local $x
                    If True Then
                        $x = 5
                    EndIf
                EndFunc
                ''',
                'x',
            ),
            Binding.LOCAL)

    def test_a_write_inside_a_for_body_targets_the_loop_variable(self):
        self.assertEqual(
            self._binding(
                '''
                Func f()
                    For $i = 1 To 3
                        $i = 5
                    Next
                EndFunc
                ''',
                'i',
            ),
            Binding.LOCAL)

    def test_a_write_after_a_for_targets_the_loop_variable(self):
        """
        The loop creates its variable before its first test, a zero trip included (probe4 31),
        so the local exists for every write after the loop statement.
        """
        self.assertEqual(
            self._binding(
                '''
                Func f()
                    For $i = 1 To 0
                    Next
                    $i = 5
                EndFunc
                ''',
                'i',
            ),
            Binding.LOCAL)

    def test_a_write_before_a_for_proves_nothing(self):
        self.assertEqual(
            self._binding(
                '''
                Func f()
                    $i = 5
                    For $i = 1 To 3
                    Next
                EndFunc
                ''',
                'i',
            ),
            Binding.NONE)

    def test_a_for_inside_control_flow_claims_nothing(self):
        self.assertEqual(
            self._binding(
                '''
                Func f()
                    If True Then
                        For $i = 1 To 3
                        Next
                    EndIf
                    $i = 5
                EndFunc
                ''',
                'i',
            ),
            Binding.NONE)

    def test_the_script_level_always_answers_global(self):
        root = Au3Parser('Local $x = 1\n$x = 2\n').parse()
        model = build_scope_model(root)
        for node in ast.scope_nodes(root.body):
            if (
                isinstance(node, Au3Variable)
                and node.name == 'x'
                and ast.is_write_occurrence(node)
            ):
                statement = ast.owning_statement(node)
                assert statement is not None
                self.assertEqual(model.binding(None, statement, 'x'), Binding.GLOBAL)
                return
        self.fail('the source holds no write')


class TestAu3ReadBinding(TestBase):
    """
    Which storage a read targets: the same dominating-declaration rule a write follows, with the
    global on the other side — a read before a same-named `Local` sees the global, a read after it
    the local (probe4 22-23). Every expectation restates a rule the AutoIt3 documentation states.
    """

    def _read_binding(self, source: str, name: str, occurrence: int = 0) -> Binding:
        root = Au3Parser(inspect.cleandoc(source)).parse()
        model = build_scope_model(root)
        function = model.functions['f']
        seen = 0
        for node in ast.scope_nodes(function.body):
            if not isinstance(node, Au3Variable) or node.name != name:
                continue
            if ast.is_write_occurrence(node):
                continue
            if seen < occurrence:
                seen += 1
                continue
            return model.read_binding(function, node, name)
        self.fail('the source holds no read of that name')

    def test_a_parameter_read_targets_the_local(self):
        self.assertEqual(
            self._read_binding(
                '''
                Func f($p)
                    $x = $p
                EndFunc
                ''',
                'p',
            ),
            Binding.LOCAL)

    def test_a_read_before_a_dominating_local_targets_the_global(self):
        self.assertEqual(
            self._read_binding(
                '''
                Func f()
                    $y = $x
                    Local $x = 1
                    $y = $x
                EndFunc
                ''',
                'x',
            ),
            Binding.GLOBAL)

    def test_a_read_after_a_dominating_local_targets_the_local(self):
        self.assertEqual(
            self._read_binding(
                '''
                Func f()
                    $y = $x
                    Local $x = 1
                    $y = $x
                EndFunc
                ''',
                'x',
                occurrence=1,
            ),
            Binding.LOCAL)

    def test_a_read_in_a_function_declaring_the_global_targets_the_global(self):
        self.assertEqual(
            self._read_binding(
                '''
                Func f()
                    $y = $x
                    Global $x
                EndFunc
                ''',
                'x',
            ),
            Binding.GLOBAL)

    def test_a_read_after_a_dim_targets_the_global(self):
        """
        A `Dim` forces no storage, so the function created no local the read could see.
        """
        self.assertEqual(
            self._read_binding(
                '''
                Func f()
                    Dim $x
                    $y = $x
                EndFunc
                ''',
                'x',
            ),
            Binding.GLOBAL)

    def test_the_script_level_always_answers_global(self):
        root = Au3Parser('Global $x = 1\nMsgBox(0, 0, $x)\n').parse()
        model = build_scope_model(root)
        for node in ast.scope_nodes(root.body):
            if isinstance(node, Au3Variable) and node.name == 'x':
                self.assertEqual(model.read_binding(None, node, 'x'), Binding.GLOBAL)
                return
        self.fail('the source holds no read')


class TestAu3MayBindLocal(TestBase):
    """
    Whether an occurrence may reach a local of its function: a local created inside a branch is
    live from the moment the branch runs it, so an occurrence after it in the same statement or
    in a later one may reach it, while an occurrence every declaration trails may not. Every
    expectation below restates that rule.
    """

    def _may_bind_local(self, source: str, name: str, occurrence: int = 0) -> bool:
        root = Au3Parser(inspect.cleandoc(source)).parse()
        model = build_scope_model(root)
        function = model.functions['f']
        seen = 0
        for node in ast.scope_nodes(function.body):
            if not isinstance(node, Au3Variable) or node.name != name:
                continue
            if ast.is_write_occurrence(node):
                continue
            if seen < occurrence:
                seen += 1
                continue
            return model.may_bind_local(function, node, name)
        self.fail('the source holds no read of that name')

    def test_a_read_after_a_dominating_local_may_bind_it(self):
        self.assertTrue(self._may_bind_local(
            '''
            Func f()
                Local $x = 1
                $y = $x
            EndFunc
            ''',
            'x',
        ))

    def test_a_read_in_the_branch_that_declares_the_local_may_bind_it(self):
        self.assertTrue(self._may_bind_local(
            '''
            Func f($c)
                If $c Then
                    Local $x = 1
                    $y = $x
                EndIf
            EndFunc
            ''',
            'x',
        ))

    def test_a_read_after_the_branch_that_declares_the_local_may_bind_it(self):
        self.assertTrue(self._may_bind_local(
            '''
            Func f($c)
                If $c Then
                    Local $x = 1
                EndIf
                $y = $x
            EndFunc
            ''',
            'x',
        ))

    def test_a_read_earlier_in_the_loop_that_declares_the_local_may_bind_it(self):
        """
        A loop's second iteration reads what an earlier iteration's declaration created.
        """
        self.assertTrue(self._may_bind_local(
            '''
            Func f($n)
                While $n > 0
                    $y = $x
                    Local $x = 7
                Wend
            EndFunc
            ''',
            'x',
        ))

    def test_a_read_before_every_declaration_may_not_bind_it(self):
        self.assertFalse(self._may_bind_local(
            '''
            Func f($c)
                $y = $x
                If $c Then
                    Local $x = 1
                EndIf
            EndFunc
            ''',
            'x',
        ))

    def test_a_read_of_a_name_the_function_declares_global_may_not_bind_a_local(self):
        self.assertFalse(self._may_bind_local(
            '''
            Func f()
                $y = $x
                Global $x
            EndFunc
            ''',
            'x',
        ))
