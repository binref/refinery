from __future__ import annotations

from inspect import cleandoc

from test import TestBase

from refinery.lib.scripts import Node
from refinery.lib.scripts.ps1.analysis.cache import Ps1ModelCache
from refinery.lib.scripts.ps1.analysis.dispatch import Ps1ErrorKind
from refinery.lib.scripts.ps1.analysis.raising import Ps1RaiseModel
from refinery.lib.scripts.ps1.model import (
    Ps1CommandInvocation,
    Ps1ExpressionStatement,
    Ps1FunctionDefinition,
    Ps1Script,
    Ps1Variable,
)
from refinery.lib.scripts.ps1.parser import Ps1Parser


def _model(source: str) -> tuple[Ps1Script, Ps1RaiseModel]:
    tree = Ps1Parser(cleandoc(source)).parse()
    return tree, Ps1ModelCache(tree).raises(True)


def _last_read(tree: Ps1Script, name: str) -> Ps1Variable:
    return [node for node in tree.walk_in_order() if isinstance(node, Ps1Variable) and node.name == name][-1]


def _statement(tree: Ps1Script, index: int) -> Node:
    statement = tree.body[index]
    assert isinstance(statement, Ps1ExpressionStatement)
    assert statement.expression is not None
    return statement.expression


class TestPs1APlainStoreFailsOnlyWhereTheNameIsConstrained(TestBase):
    """
    Storing into a plain local fails where something gave the variable a type, an attribute or
    options, and for the variables the engine owns; every other store of a value that cannot fail
    cannot fail either.
    """

    def _store_cannot_fail(self, source: str) -> bool:
        tree, model = _model(source)
        store = _statement(tree, len(tree.body) - 1)
        return model.cannot_fault(store, store)

    def test_a_store_of_a_constant_into_a_plain_local_cannot_fail(self):
        self.assertTrue(self._store_cannot_fail("$x = 'a'"))

    def test_a_store_into_a_name_the_script_constrains_may_fail(self):
        for constraint in (
            '[int]$x = 1',
            'function f { param([int]$x) }',
            'New-Variable x 1 -Option ReadOnly',
            "$o = @{ Name = 'x'; Value = 1; Option = 'ReadOnly' }; New-Variable @o",
            '$v = Get-Variable x',
            "$PSDefaultParameterValues['New-Variable:Option'] = 'ReadOnly'",
            'Set-Variable $args[0] 1',
        ):
            with self.subTest(constraint=constraint):
                self.assertFalse(self._store_cannot_fail(F"{constraint}\n$x = 'a'"))

    def test_a_store_into_a_variable_the_engine_owns_may_fail(self):
        for name in ('VerbosePreference', 'MaximumHistoryCount', 'true'):
            with self.subTest(name=name):
                self.assertFalse(self._store_cannot_fail(F"${name} = 'a'"))

    def test_a_store_of_a_value_that_may_fail_may_fail(self):
        self.assertFalse(self._store_cannot_fail('$x = [int]$args[0]'))


class TestPs1AReadUnderStrictModeIsClearedByAStoreThatCertainlyCompleted(TestBase):
    """
    Under strict mode a read of an unset variable fails, so a read is cleared only where a store to
    it completed on every run that reaches it, and nothing may have removed the variable since.
    """

    def _read_cannot_fail(self, source: str) -> bool:
        tree, model = _model(F'Set-StrictMode -Version 1\n{cleandoc(source)}\n$null = $v')
        read = _last_read(tree, 'v')
        return model.cannot_fault(read, tree.body[-1])

    def test_a_read_after_a_store_cannot_fail(self):
        self.assertTrue(self._read_cannot_fail('$v = 1'))

    def test_a_read_after_a_store_in_one_branch_may_fail(self):
        self.assertFalse(self._read_cannot_fail('if ($args[0]) { $v = 1 }'))

    def test_a_read_after_a_store_that_may_fail_inside_a_try_may_fail(self):
        self.assertFalse(self._read_cannot_fail('try { $v = [int]$args[0] } catch { }'))

    def test_a_read_after_a_store_in_a_loop_that_may_not_run_may_fail(self):
        self.assertFalse(self._read_cannot_fail('foreach ($i in $args) { $v = 1 }'))

    def test_a_read_after_a_removal_may_fail(self):
        self.assertFalse(self._read_cannot_fail('$v = 1\nRemove-Variable v'))

    def test_a_read_in_end_after_a_store_in_process_may_fail(self):
        tree, model = _model("""
            Set-StrictMode -Version 1
            function f { process { $v = 1 } end { $null = $v } }
            @() | f
        """)
        read = _last_read(tree, 'v')
        self.assertFalse(model.cannot_fault(read, read))


class TestPs1ABodyBindsWithoutFaultOnlyWhereItsParametersCannotFail(TestBase):

    def _binds(self, source: str) -> bool:
        tree, model = _model(source)
        definition = next(node for node in tree.walk() if isinstance(node, Ps1FunctionDefinition))
        assert definition.body is not None
        return model.binds_without_fault(definition.body)

    def test_a_body_without_parameters_binds_without_fault(self):
        self.assertTrue(self._binds('function f { 1 }'))

    def test_a_plain_default_binds_without_fault(self):
        self.assertTrue(self._binds("function f { param($a = 'x') }"))

    def test_a_typed_default_that_converts_binds_without_fault(self):
        self.assertTrue(self._binds("function f { param([int]$a = '42') }"))

    def test_a_parameter_that_may_fail_to_bind_may_fail(self):
        for parameters in (
            "[int]$a = 'abc'",
            '$a = $(throw)',
            '[Parameter(Mandatory)] $a',
            '[int]$a',
            '[ValidateNotNull()] $a = 1',
        ):
            with self.subTest(parameters=parameters):
                self.assertFalse(self._binds(F'function f {{ param({parameters}) }}'))

    def test_a_body_with_dynamic_parameters_may_fail(self):
        self.assertFalse(self._binds('function f { dynamicparam { } end { } }'))


class TestPs1ACallRaisesWhatItsBodyHandsBack(TestBase):

    def _call_kinds(self, source: str) -> Ps1ErrorKind:
        tree, model = _model(source)
        return model.kinds(tree.body[-1])

    def test_a_call_of_a_body_that_cannot_fail_raises_nothing(self):
        self.assertEqual(self._call_kinds("function f { 'a' }\nf"), Ps1ErrorKind.NONE)

    def test_a_call_of_a_body_that_throws_hands_back_the_throw(self):
        self.assertIn(Ps1ErrorKind.THROWN, self._call_kinds("function f { throw 'x' }\nf"))

    def test_a_call_standing_before_the_definition_may_fail_to_find_it(self):
        tree, model = _model("f\nfunction f { 'a' }")
        self.assertIn(Ps1ErrorKind.STATEMENT, model.kinds(tree.body[0]))

    def test_a_call_of_a_body_that_runs_itself_hands_back_every_kind(self):
        kinds = self._call_kinds("function f { f }\nf")
        self.assertEqual(kinds & (Ps1ErrorKind.THROWN | Ps1ErrorKind.MARKED), Ps1ErrorKind.THROWN | Ps1ErrorKind.MARKED)

    def test_a_call_handed_an_argument_may_fail_to_bind_it(self):
        tree, model = _model("function f { 'a' }\nf -Bogus 1")
        call = next(node for node in tree.body[-1].walk() if isinstance(node, Ps1CommandInvocation))
        self.assertFalse(model.raises_only_what_its_bodies_hand_back(call))
