from __future__ import annotations

import functools

from test import TestBase, fastest_processor_time, processor_time_ratio

from refinery.lib.scripts.ps1 import data
from refinery.lib.scripts.ps1.analysis.arguments import (
    RECEIVER,
    _floored,
    _floored_keepers,
    keeps_nothing,
)
from refinery.lib.scripts.ps1.analysis.model import (
    Ps1OccurrenceRole,
    ScopeKind,
    build_semantic_model,
    changes_the_object_it_names,
    declares_binding,
    is_mutated_in_place,
    is_substitutable_position,
    is_write_occurrence,
    observes_previous_value,
    occurrence_role,
    replaces_value,
)
from refinery.lib.scripts.ps1.model import Ps1AssignmentExpression, Ps1ScopeModifier, Ps1Variable
from refinery.lib.scripts.ps1.parser import Ps1Parser


class TestPs1SemanticModel(TestBase):

    @staticmethod
    def _model(source: str):
        return build_semantic_model(Ps1Parser(source).parse())

    @staticmethod
    def _assignment_value(ast, target_name: str):
        for node in ast.walk():
            if isinstance(node, Ps1AssignmentExpression) and isinstance(node.target, Ps1Variable):
                if node.target.name.lower() == target_name:
                    return node.value
        raise AssertionError(F'no assignment to ${target_name}')

    def _script_binding(self, source: str, name: str):
        model = self._model(source)
        return model, model.script_scope.bindings.get(name)

    def test_script_root_is_a_script_scope(self):
        model = self._model("$a = 1\nWrite-Host $a")
        self.assertIs(model.script_scope.kind, ScopeKind.SCRIPT)

    def test_if_and_loop_bodies_introduce_no_scope(self):
        model = self._model("$a = 1\nif ($a) { $b = 2 }\nwhile ($a) { $c = 3 }")
        self.assertEqual(model.script_scope.children, [])
        self.assertIn('b', model.script_scope.bindings)
        self.assertIn('c', model.script_scope.bindings)

    def test_function_body_is_a_function_scope(self):
        model = self._model("function f { $x = 1 }")
        self.assertEqual(len(model.script_scope.children), 1)
        self.assertIs(model.script_scope.children[0].kind, ScopeKind.FUNCTION)

    def test_bare_scriptblock_is_a_scriptblock_scope(self):
        model = self._model("$cb = { $x = 1 }")
        self.assertEqual(len(model.script_scope.children), 1)
        self.assertIs(model.script_scope.children[0].kind, ScopeKind.SCRIPTBLOCK)

    def test_unread_variable_is_dead(self):
        _, binding = self._script_binding("$x = 'hi'\nWrite-Host done", 'x')
        self.assertIsNotNone(binding)
        assert binding is not None
        self.assertTrue(binding.is_dead)

    def test_read_variable_is_live(self):
        _, binding = self._script_binding("$x = 'hi'\nWrite-Host $x", 'x')
        assert binding is not None
        self.assertFalse(binding.is_dead)

    def test_read_inside_function_keeps_outer_binding_live(self):
        _, binding = self._script_binding(
            "$x = 'payload'\nfunction Run { iex $x }\nRun", 'x')
        assert binding is not None
        self.assertFalse(binding.is_dead)

    def test_qualified_read_keeps_binding_live(self):
        _, binding = self._script_binding(
            "$x = 'keepme'\nfunction f { Write-Host $script:x }\nf", 'x')
        assert binding is not None
        self.assertFalse(binding.is_dead)

    def test_local_qualified_read_resolves_in_the_scope_of_the_reference(self):
        model = self._model('function f { $y = 1; Write-Host $local:y }')
        binding = model.script_scope.children[0].bindings['y']
        self.assertFalse(binding.is_dead)

    def test_class_property_declaration_is_not_a_read(self):
        model = self._model('$x = 1\nclass C { [int]$x }')
        self.assertTrue(model.script_scope.bindings['x'].is_dead)

    def test_scriptblock_assignment_is_write_local(self):
        model = self._model("$inner = 1\n$cb = { $inner = 99 }\nWrite-Host $inner")
        outer = model.script_scope.bindings['inner']
        block_scope = model.script_scope.children[0]
        self.assertIn('inner', block_scope.bindings)
        self.assertIsNot(outer, block_scope.bindings['inner'])
        self.assertEqual(len(outer.writes), 1)

    def test_reads_in_scope_sees_read_nested_in_scriptblock(self):
        ast = Ps1Parser("$x = 1\n$arr = @( { Write-Host $x } )").parse()
        model = build_semantic_model(ast)
        value = self._assignment_value(ast, 'arr')
        self.assertIn('x', model.reads_in_scope(value, model.script_scope))

    def test_reads_in_scope_sees_compound_assignment_target(self):
        ast = Ps1Parser("$x = 1\n$a = ($x += 1)").parse()
        model = build_semantic_model(ast)
        value = self._assignment_value(ast, 'a')
        self.assertIn('x', model.reads_in_scope(value, model.script_scope))

    def test_reads_in_scope_ignores_write_only_scriptblock(self):
        ast = Ps1Parser("$inner = 1\n$cb = { $inner = 99 }").parse()
        model = build_semantic_model(ast)
        value = self._assignment_value(ast, 'cb')
        self.assertNotIn('inner', model.reads_in_scope(value, model.script_scope))

    def test_environment_variable_is_a_distinct_binding(self):
        model = self._model("$env:X = 'v'\n$X = 1\nWrite-Host $X")
        self.assertIn('env:x', model.script_scope.bindings)
        self.assertIn('x', model.script_scope.bindings)
        self.assertTrue(model.script_scope.bindings['env:x'].is_dead)
        self.assertFalse(model.script_scope.bindings['x'].is_dead)

    def test_scope_of_maps_nested_node_to_its_scriptblock(self):
        model = self._model("function f { $x = 1 }")
        function_scope = model.script_scope.children[0]
        inner = next(
            n for n in model.root.walk()
            if isinstance(n, Ps1Variable) and n.name.lower() == 'x')
        self.assertIs(model.scope_of(inner), function_scope)


class TestPs1WriteOccurrenceKinds(TestBase):

    @staticmethod
    def _write(source: str, name: str = 'x') -> Ps1Variable:
        for node in Ps1Parser(source).parse().walk():
            if isinstance(node, Ps1Variable) and node.name.lower() == name:
                if is_write_occurrence(node):
                    return node
        raise AssertionError(F'no write of ${name}')

    def test_a_plain_assignment_replaces_without_observing(self):
        write = self._write("$x = 'a'")
        self.assertTrue(replaces_value(write))
        self.assertFalse(observes_previous_value(write))

    def test_a_compound_assignment_observes_the_previous_value(self):
        for source in ("$x += 'a'", '$x -= 1', '$x *= 2', '$x /= 2', '$x %= 2'):
            with self.subTest(source):
                write = self._write(source)
                self.assertFalse(replaces_value(write))
                self.assertTrue(observes_previous_value(write))

    def test_an_increment_observes_the_previous_value(self):
        for source in ('$x++', '$x--'):
            with self.subTest(source):
                self.assertTrue(observes_previous_value(self._write(source)))

    def test_a_value_handed_in_from_outside_observes_nothing(self):
        for source in ('foreach ($x in 1, 2) { }', 'function f { param($x) }'):
            with self.subTest(source):
                write = self._write(source)
                self.assertFalse(replaces_value(write))
                self.assertFalse(observes_previous_value(write))

    @staticmethod
    def _read(source: str, name: str = 'x') -> Ps1Variable:
        for node in Ps1Parser(source).parse().walk():
            if isinstance(node, Ps1Variable) and node.name.lower() == name:
                if not is_write_occurrence(node):
                    return node
        raise AssertionError(F'no read of ${name}')

    def test_an_assignment_through_a_part_of_a_variable_mutates_it_in_place(self):
        for source in (
            "$x[0] = 'z'",
            '$x.Length = 5',
            "$x[0][1] = 'z'",
            '$x.A.B = 5',
            "($x)[0] = 'z'",
            "([array]$x)[0] = 'z'",
            "$x[0], $x[1] = 'p', 'q'",
            "$x[0] += 'z'",
        ):
            with self.subTest(source):
                self.assertTrue(is_mutated_in_place(self._write(source)))

    def test_a_variable_an_assignment_does_not_store_through_is_not_mutated_in_place(self):
        for source in (
            'Write-Host $x[0]',
            'Write-Host $x.Length',
            "$a[$x] = 'z'",
            "$a[0] = $x",
        ):
            with self.subTest(source):
                self.assertFalse(is_mutated_in_place(self._read(source)))

    def test_a_variable_an_assignment_replaces_outright_is_not_mutated_in_place(self):
        for source in ("$x = 'a'", "$x, $y = 'p', 'q'", "[string]$x = 'a'"):
            with self.subTest(source):
                self.assertFalse(is_mutated_in_place(self._write(source)))


class TestPs1OccurrenceRoles(TestBase):

    @staticmethod
    def _occurrence(source: str, name: str = 'x', index: int = 0) -> Ps1Variable:
        found = [
            node for node in Ps1Parser(source).parse().walk()
            if isinstance(node, Ps1Variable) and node.name.lower() == name
        ]
        if len(found) <= index:
            raise AssertionError(F'no occurrence {index} of ${name} in {source!r}')
        return found[index]

    def _role(self, source: str, name: str = 'x', index: int = 0) -> Ps1OccurrenceRole:
        return occurrence_role(self._occurrence(source, name, index))

    def test_a_store_into_a_member_the_source_does_not_name_stores_through_the_name(self):
        for source in ('$x.$m = 5', '$x.$m++', '$x.SyncRoot = 5'):
            with self.subTest(source):
                self.assertIs(self._role(source), Ps1OccurrenceRole.WRITE_THROUGH)

    def test_a_store_through_a_member_that_may_be_an_entry_reaches_past_the_object(self):
        for source in ('$x.$m[0] = 9', '$x.SyncRoot[0] = 9', '$x.$($m)[0]++'):
            with self.subTest(source):
                self.assertIs(self._role(source), Ps1OccurrenceRole.WRITE_THROUGH)
                self.assertFalse(changes_the_object_it_names(self._occurrence(source)))

    def test_an_occurrence_that_only_observes_the_value_is_a_read(self):
        for source in ('Write-Host $x', '$y = $x + 1', 'Write-Host $x[0]', 'Get-Item @x'):
            with self.subTest(source):
                self.assertIs(self._role(source), Ps1OccurrenceRole.READ)

    def test_an_occurrence_handed_a_value_from_outside_replaces_it(self):
        for source in (
            "$x = 'a'",
            "[string]$x = 'a'",
            "$x, $y = 'p', 'q'",
            'foreach ($x in 1, 2) { }',
            'function f { param($x) }',
        ):
            with self.subTest(source):
                self.assertIs(self._role(source), Ps1OccurrenceRole.WRITE_REPLACING)

    def test_an_occurrence_that_reads_what_it_writes_observes_the_previous_value(self):
        for source in ("$x += 'a'", '$x -= 1', '$x++', '$x--'):
            with self.subTest(source):
                self.assertIs(self._role(source), Ps1OccurrenceRole.WRITE_OBSERVING)

    def test_a_reference_the_callee_may_store_through_observes_the_previous_value(self):
        for source in (
            "[void][int]::TryParse('7', [ref]$x)",
            "[void][int]::TryParse('7', ([ref]$x))",
            "[void][int]::TryParse('7', [management.automation.psreference]$x)",
        ):
            with self.subTest(source):
                self.assertIs(self._role(source), Ps1OccurrenceRole.WRITE_OBSERVING)

    def test_an_occurrence_an_assignment_stores_through_keeps_its_own_value(self):
        for source in ("$x[0] = 'z'", '$x.Length = 5', "$x[0][1] = 'z'", "$x[0] += 'z'"):
            with self.subTest(source):
                self.assertIs(self._role(source), Ps1OccurrenceRole.WRITE_THROUGH)

    def test_an_occurrence_an_increment_stores_through_keeps_its_own_value(self):
        for source in ('$x[0]++', '$x[0]--', '++$x[0]', '$x.P[1]++'):
            with self.subTest(source):
                self.assertIs(self._role(source), Ps1OccurrenceRole.WRITE_THROUGH)

    def test_a_class_property_declaration_references_no_variable(self):
        self.assertIs(
            self._role('class C { [int]$x }'), Ps1OccurrenceRole.NOT_A_REFERENCE)

    def test_a_plain_read_is_the_only_position_a_value_may_be_installed_in(self):
        self.assertTrue(is_substitutable_position(self._occurrence('Write-Host $x')))
        for source in (
            "$x = 'a'",
            "$x[0] = 'z'",
            "[void][int]::TryParse('7', [ref]$x)",
            "$x += 'a'",
        ):
            with self.subTest(source):
                self.assertFalse(is_substitutable_position(self._occurrence(source)))

    def test_a_splatted_read_is_not_a_position_a_value_may_be_installed_in(self):
        splatted = self._occurrence('Get-Item @x')
        self.assertIs(occurrence_role(splatted), Ps1OccurrenceRole.READ)
        self.assertFalse(is_substitutable_position(splatted))

    def test_every_write_but_a_reference_brings_the_binding_into_existence(self):
        for source in ("$x = 'a'", "$x += 'a'", '$x++', 'foreach ($x in 1, 2) { }'):
            with self.subTest(source):
                self.assertTrue(declares_binding(self._occurrence(source)))
        for source in ("[void][int]::TryParse('7', [ref]$x)", 'Write-Host $x', "$x[0] = 'z'"):
            with self.subTest(source):
                self.assertFalse(declares_binding(self._occurrence(source)))


class TestPs1ReferenceAttribution(TestBase):

    @staticmethod
    def _model(source: str):
        return build_semantic_model(Ps1Parser(source).parse())

    def test_a_reference_is_a_write_of_the_binding_and_not_a_read(self):
        model = self._model("$n = 0\n[void][int]::TryParse('7', [ref]$n)")
        binding = model.script_scope.bindings['n']
        self.assertEqual(len(binding.writes), 2)
        self.assertEqual(len(binding.reads), 0)

    def test_a_reference_keeps_the_binding_alive_although_nothing_reads_it(self):
        model = self._model("$n = 0\n[void][int]::TryParse('7', [ref]$n)")
        binding = model.script_scope.bindings['n']
        self.assertEqual(len(binding.uses), 1)
        self.assertFalse(binding.is_dead)

    def test_a_reference_inside_a_body_declares_nothing_there(self):
        model = self._model("$n = 0\nfunction f { [void][int]::TryParse('7', [ref]$n) }")
        function_scope = model.script_scope.children[0]
        self.assertIs(function_scope.kind, ScopeKind.FUNCTION)
        self.assertNotIn('n', function_scope.bindings)
        self.assertEqual(len(model.script_scope.bindings['n'].writes), 2)

    def test_a_binding_whose_only_use_is_a_compound_assignment_is_not_dead(self):
        model = self._model("$x = 'a'\n$x += 'b'")
        binding = model.script_scope.bindings['x']
        self.assertEqual(len(binding.reads), 0)
        self.assertEqual(len(binding.uses), 1)
        self.assertFalse(binding.is_dead)


class TestPs1StoreThroughAttribution(TestBase):

    @staticmethod
    def _model(source: str):
        return build_semantic_model(Ps1Parser(source).parse())

    def test_a_store_through_is_a_write_of_the_binding_and_not_a_read(self):
        model = self._model("$x = @('a', 'b')\n$x[0] = 'z'")
        binding = model.script_scope.bindings['x']
        self.assertEqual(len(binding.writes), 2)
        self.assertEqual(len(binding.reads), 0)

    def test_a_store_through_observes_the_value_it_reaches_into(self):
        binding = self._model("$x = @('a', 'b')\n$x[0] = 'z'").script_scope.bindings['x']
        self.assertEqual(len(binding.uses), 1)
        self.assertFalse(binding.is_dead)

    def test_a_store_through_inside_a_body_is_a_write_of_the_enclosing_binding(self):
        model = self._model("$x = @('a', 'b')\nfunction f { $x[0] = 'z' }")
        function_scope = model.script_scope.children[0]
        self.assertEqual(function_scope.bindings, {})
        self.assertEqual(len(model.script_scope.bindings['x'].writes), 2)

    def test_a_store_through_declares_nothing_where_no_scope_binds_the_name(self):
        stored = self._model("function f { $x[0] = 'z' }")
        self.assertEqual(stored.script_scope.bindings, {})
        self.assertEqual(stored.script_scope.children[0].bindings, {})
        assigned = self._model("function f { $x = 'z' }")
        self.assertEqual(list(assigned.script_scope.children[0].bindings), ['x'])

    def test_a_scope_qualified_store_through_and_reference_are_writes(self):
        stored = self._model("$x = @('a', 'b')\n$script:x[0] = 9")
        self.assertEqual(len(stored.script_scope.bindings['x'].writes), 2)
        referenced = self._model("$x = 0\n[void][int]::TryParse('7', [ref]$script:x)")
        self.assertEqual(len(referenced.script_scope.bindings['x'].writes), 2)


class TestPs1AQualifiedReadIsFiledOnTheBindingItsScopeHolds(TestBase):

    @staticmethod
    def _qualified_read(source: str, scope: Ps1ScopeModifier):
        tree = Ps1Parser(source).parse()
        model = build_semantic_model(tree)
        for node in tree.walk():
            if isinstance(node, Ps1Variable) and node.scope is scope:
                return model, node
        raise AssertionError(F'no {scope.value}-qualified read in {source!r}')

    def test_a_local_or_private_read_in_a_trap_body_names_no_binding(self):
        # A `trap` body is a scope of its own: such a read names no variable of the scope around it.
        for scope in (Ps1ScopeModifier.LOCAL, Ps1ScopeModifier.PRIVATE):
            source = F"$x = 'a'; if (1) {{ trap {{ ${scope.value}:x; continue }}; throw 'e' }}"
            with self.subTest(source):
                model, read = self._qualified_read(source, scope)
                self.assertIsNone(model.binding_of(read))

    def test_a_script_read_in_a_trap_body_names_the_script_binding(self):
        model, read = self._qualified_read(
            "$x = 'a'; if (1) { trap { $script:x; continue }; throw 'e' }",
            Ps1ScopeModifier.SCRIPT,
        )
        self.assertIs(model.binding_of(read), model.script_scope.bindings['x'])

    def test_the_dead_store_read_set_holds_a_qualified_read(self):
        tree = Ps1Parser("$x = 'a'; Write-Host $script:x").parse()
        model = build_semantic_model(tree)
        self.assertEqual(model.reads_in_scope(tree.body[1], model.script_scope), {'x'})


class TestPs1NamedReferenceAttribution(TestBase):

    @staticmethod
    def _model(source: str):
        return build_semantic_model(Ps1Parser(source).parse())

    def test_a_named_write_creates_the_binding_when_nothing_else_mentions_it(self):
        model = self._model('Get-Process -OutVariable p')
        binding = model.script_scope.bindings['p']
        self.assertEqual(len(binding.writes), 1)
        self.assertFalse(binding.is_read)

    def test_a_named_write_lands_on_the_binding_the_assignments_use(self):
        model = self._model("$x = 'calc'\nGet-Process -OutVariable x")
        binding = model.script_scope.bindings['x']
        self.assertEqual(len(binding.writes), 2)

    def test_a_named_read_is_a_use_that_keeps_the_binding_alive(self):
        model = self._model("$a = 'x'\nGet-Variable a")
        binding = model.script_scope.bindings['a']
        self.assertEqual(len(binding.reads), 1)
        self.assertFalse(binding.is_dead)

    def test_an_appending_out_variable_observes_the_previous_value(self):
        model = self._model("$a = 'x'\nGet-Process -OutVariable +a")
        binding = model.script_scope.bindings['a']
        self.assertEqual(len(binding.uses), 1)
        self.assertFalse(binding.is_dead)

    def test_a_bare_named_write_in_a_body_binds_that_body_and_not_the_script(self):
        model = self._model("$d = 'OUTER'\nfunction f { Set-Variable d 'INNER' }")
        function_scope = model.script_scope.children[0]
        self.assertIn('d', function_scope.bindings)
        self.assertEqual(len(function_scope.bindings['d'].writes), 1)
        self.assertEqual(len(model.script_scope.bindings['d'].writes), 1)

    def test_a_globally_scoped_named_write_binds_the_script_scope(self):
        model = self._model("function f { Set-Variable d 'V' -Scope Global }")
        self.assertIn('d', model.script_scope.bindings)
        self.assertNotIn('d', model.script_scope.children[0].bindings)

    def test_an_environment_item_write_binds_the_key_the_variable_reads_under(self):
        model = self._model("Set-Item Env:ComSpec 'evil'\nWrite-Host $env:ComSpec")
        binding = model.script_scope.bindings['env:comspec']
        self.assertEqual(len(binding.writes), 1)
        self.assertEqual(len(binding.reads), 1)

    def test_an_unbinding_replaces_the_value_rather_than_observing_it(self):
        model = self._model("$a = 'x'\nRemove-Variable a")
        roles = [write.role for write in model.script_scope.bindings['a'].writes]
        self.assertIn(Ps1OccurrenceRole.WRITE_REPLACING, roles)
        self.assertNotIn(Ps1OccurrenceRole.READ, roles)
        self.assertNotIn(Ps1OccurrenceRole.WRITE_OBSERVING, roles)

    def test_a_computed_name_this_cannot_place_puts_the_scope_it_writes_in_doubt(self):
        model = self._model("$x = 'a'\nSet-Variable $n 'b' -Scope Global")
        self.assertTrue(model.script_scope.writes_unreadable_names)
        model = self._model("$x = 'a'\nSet-Variable $n 'b'")
        self.assertFalse(model.script_scope.writes_unreadable_names)

    def test_a_literal_named_write_leaves_the_scope_out_of_doubt(self):
        model = self._model("$x = 'a'\nSet-Variable y 'b'")
        self.assertFalse(model.script_scope.writes_unreadable_names)

    def test_a_scope_the_lexical_chain_cannot_name_puts_the_script_in_doubt(self):
        model = self._model("function f { Set-Variable x 'b' -Scope 1 }")
        self.assertTrue(model.script_scope.writes_unreadable_names)

    def test_a_named_session_state_call_is_filed_on_the_binding_it_names(self):
        model = self._model(
            "$x = 'a'\n"
            "Write-Output $ExecutionContext.SessionState.PSVariable.GetValue('x')\n"
            "$ExecutionContext.SessionState.PSVariable.Set('x', 'b')")
        binding = model.script_scope.bindings['x']
        self.assertEqual(len(binding.reads), 1)
        self.assertEqual(len(binding.writes), 2)

    def test_a_listing_of_every_variable_reads_names_nobody_can_read(self):
        for source in ('$v = Get-Variable', "$p = $ExecutionContext.SessionState.PSVariable"):
            with self.subTest(source):
                self.assertTrue(self._model(source).reads_unreadable_names)
        self.assertFalse(
            self._model("$n = (Get-Variable '*mdr*').Name").reads_unreadable_names)

    def test_a_variable_handed_out_is_recorded_by_its_name(self):
        self.assertEqual(
            self._model("$b = 'a'\n$v = Get-Variable b").variables_handed_out, {'b'})
        self.assertEqual(
            self._model("$b = 'a'\n$v = (Get-Variable b).Value").variables_handed_out, set())

    def test_a_variable_of_any_name_handed_out_puts_the_script_in_doubt(self):
        self.assertTrue(self._model('$v = Get-Variable').script_scope.writes_unreadable_names)

    def test_the_session_state_handed_out_puts_every_scope_in_doubt(self):
        model = self._model(
            '$ss = $ExecutionContext.SessionState\n'
            "$sb = { $y = 'abc'; $ss.PSVariable.Set('y', 'def'); Write-Output $y }")
        self.assertTrue(all(scope.writes_unreadable_names for scope in model.scopes()))

    def test_a_name_the_session_state_reads_is_in_the_read_set_of_the_statement(self):
        source = "$b = 'a'\nWrite-Output $ExecutionContext.SessionState.PSVariable.GetValue('b')"
        model = self._model(source)
        statement = model.root.body[1]
        self.assertIn('b', model.reads_in_scope(statement, model.script_scope))
        self.assertIn('b', model.variables_in_scope(statement, model.script_scope))


class TestPs1AConversionBetweenTwoNamesIsAnAliasThisCannotBeSureOf(TestBase):

    _HANDED_OVER = ('$y = $x', '$y = ($x)')

    _CONVERTED = (
        '$y = [array]$x',
        '$y = $x -as [array]',
        '[array]$y = $x',
        '[int[]]$y = $x',
        '$y = [int[]]$x',
    )

    @staticmethod
    def _shared(definition: str, store: str, name: str, value: str = '$args[0]'):
        source = F'$x = {value}\n{definition}\n{store}'
        model = build_semantic_model(Ps1Parser(source).parse())
        return [
            write for write in model.script_scope.bindings[name].writes if write.may_define
        ]

    def test_a_store_through_either_name_is_filed_against_the_other(self):
        for definition in (*self._HANDED_OVER, *self._CONVERTED):
            for store, name in (('$y[0] = 9', 'x'), ('$x[0] = 9', 'y')):
                with self.subTest(F'{definition}; {store}'):
                    self.assertEqual(len(self._shared(definition, store, name)), 1)

    def test_a_definition_that_hands_the_object_over_is_a_link_this_is_sure_of(self):
        for definition in self._HANDED_OVER:
            with self.subTest(definition):
                shared, = self._shared(definition, '$y[0] = 9', 'x')
                self.assertEqual([link.certain for link in shared.shared_through], [True])

    def test_a_definition_with_a_conversion_on_either_side_is_a_link_this_is_not_sure_of(self):
        for definition in self._CONVERTED:
            with self.subTest(definition):
                shared, = self._shared(definition, '$y[0] = 9', 'x')
                self.assertEqual([link.certain for link in shared.shared_through], [False])

    def test_a_definition_that_certainly_copies_is_no_link_at_all(self):
        for store, name in (('$y[0] = 9', 'x'), ('$x[0] = 9', 'y')):
            with self.subTest(store):
                self.assertEqual(self._shared('$y = $($x)', store, name, '1, 2, 3'), [])


class TestPs1EveryOccurrenceRoleAnswersUnlikeEveryOther(TestBase):

    def test_no_two_roles_carry_the_same_four_answers(self):
        answers = {
            (role.stores, role.observes, role.substitutable, role.through)
            for role in Ps1OccurrenceRole
        }
        self.assertEqual(len(answers), len(Ps1OccurrenceRole.__members__))


class TestPs1ACallThatFillsAnArgumentWritesTheNameThatFilledIt(TestBase):

    @staticmethod
    def _occurrence(source: str, name: str = 'x') -> Ps1Variable:
        found = [
            node for node in Ps1Parser(source).parse().walk()
            if isinstance(node, Ps1Variable) and node.name.lower() == name
        ]
        if not found:
            raise AssertionError(F'no occurrence of ${name} in {source!r}')
        return found[0]

    def test_a_filled_buffer_is_a_store_through_the_name_that_hands_it_over(self):
        for source in (
            '[Buffer]::BlockCopy($s, 0, $x, 0, 3)',
            '[Buffer]::SetByte($x, 0, 9)',
            '$stream.Read($x, 0, 3)',
            '$random.NextBytes($x)',
            '$arrayList.CopyTo($x)',
            '$transform.TransformBlock($s, 0, 3, $x, 0)',
            '[Text.Encoding]::ASCII.GetBytes($c, 0, 2, $x, 0)',
        ):
            with self.subTest(source):
                occurrence = self._occurrence(source)
                self.assertIs(occurrence_role(occurrence), Ps1OccurrenceRole.WRITE_THROUGH)
                self.assertFalse(is_substitutable_position(occurrence))

    def test_a_slot_the_same_call_only_reads_is_a_position_a_value_may_stand_in(self):
        for source in (
            '[Buffer]::BlockCopy($x, 0, $d, 0, 3)',
            '$arrayList.CopyTo($d, 0, $x, 3)',
            '[Text.Encoding]::ASCII.GetBytes($x)',
            '[Text.Encoding]::ASCII.GetString($x)',
        ):
            with self.subTest(source):
                occurrence = self._occurrence(source)
                self.assertIs(occurrence_role(occurrence), Ps1OccurrenceRole.READ)
                self.assertTrue(is_substitutable_position(occurrence))

    def test_a_call_whose_member_cannot_be_named_is_a_store_through_every_slot(self):
        for source in ('[Array]::$m($x)', '$obj.$m($x)'):
            with self.subTest(source):
                self.assertIs(
                    occurrence_role(self._occurrence(source)), Ps1OccurrenceRole.WRITE_THROUGH)

    def test_a_conversion_between_the_name_and_a_written_slot_does_not_free_the_name(self):
        for source in (
            '[Array]::Reverse([int[]]$x)',
            '[Array]::Reverse($x -as [array])',
            '[Array]::Reverse(($x))',
        ):
            with self.subTest(source):
                self.assertIs(
                    occurrence_role(self._occurrence(source)), Ps1OccurrenceRole.WRITE_THROUGH)

    def test_an_arity_no_overload_takes_writes_nothing_because_the_call_raises(self):
        self.assertIs(
            occurrence_role(self._occurrence('[Array]::Reverse($x, 0)')),
            Ps1OccurrenceRole.READ)


class TestPs1TheWrittenSlotTableIsFlooredAgainstTheCollectedMetadata(TestBase):

    def test_a_row_naming_a_slot_beyond_the_last_argument_is_refused(self):
        with self.assertRaises(ValueError):
            _floored({('array', 'reverse'): {1: (7,), 3: (0,)}}, static=True)

    def test_a_row_naming_the_slot_one_past_the_last_argument_is_refused(self):
        with self.assertRaises(ValueError):
            _floored({('array', 'reverse'): {1: (0,), 3: (3,)}}, static=True)

    def test_a_row_leaving_an_arity_of_the_member_uncovered_is_refused(self):
        with self.assertRaises(ValueError):
            _floored({('array', 'reverse'): {1: (0,)}}, static=True)

    def test_a_row_covering_an_arity_no_overload_takes_is_refused(self):
        with self.assertRaises(ValueError):
            _floored({('array', 'reverse'): {1: (0,), 2: (0,), 3: (0,)}}, static=True)

    def test_a_row_naming_a_member_the_metadata_does_not_carry_is_refused(self):
        with self.assertRaises(ValueError):
            _floored({('array', 'fill'): {2: (0,)}}, static=True)

    def test_a_row_covering_every_arity_with_slots_the_call_has_is_built(self):
        built = _floored({('array', 'reverse'): {1: (0,), 3: (0,)}}, static=True)
        self.assertEqual([member for _, member in built], ['reverse'])
        self.assertEqual(list(built.values()), [{1: frozenset({0}), 3: frozenset({0})}])

    def test_the_receiver_is_a_slot_every_arity_can_address(self):
        built = _floored(
            {('array', 'setvalue'): {2: (RECEIVER,), 3: (RECEIVER,), 4: (RECEIVER,)}}, static=False)
        self.assertEqual(
            list(built.values()),
            [{arity: frozenset({RECEIVER}) for arity in (2, 3, 4)}])


class TestPs1TheKeepNothingTableIsFlooredAgainstTheCollectedMetadata(TestBase):

    def test_a_member_returning_an_object_is_refused(self):
        with self.assertRaises(ValueError):
            _floored_keepers({('array', 'asreadonly')}, static=True)

    def test_a_member_taking_a_parameter_by_reference_is_refused(self):
        with self.assertRaises(ValueError):
            _floored_keepers({('array', 'resize')}, static=True)

    def test_a_member_the_metadata_does_not_carry_is_refused(self):
        with self.assertRaises(ValueError):
            _floored_keepers({('string', 'fill')}, static=True)

    def test_a_member_every_overload_of_which_returns_a_string_is_built(self):
        self.assertEqual(
            [member for _, member in _floored_keepers({('string', 'join')}, static=True)],
            ['join'],
        )

    def test_the_table_is_asked_by_the_type_whatever_its_spelling(self):
        string = data.resolve_type('System.String')
        assert string is not None
        self.assertTrue(keeps_nothing(string, 'JOIN', static=True))
        self.assertFalse(keeps_nothing(string, 'Split', static=True))

    def test_a_member_is_refused_on_the_side_the_metadata_does_not_carry_it(self):
        with self.assertRaises(ValueError):
            _floored_keepers({('string', 'join')}, static=False)

    def test_the_string_an_encoding_decodes_keeps_nothing_of_the_buffer(self):
        encoding = data.resolve_type('System.Text.Encoding')
        assert encoding is not None
        self.assertTrue(keeps_nothing(encoding, 'GetString', static=False))
        self.assertFalse(keeps_nothing(encoding, 'GetString', static=True))
        self.assertFalse(keeps_nothing(encoding, 'GetBytes', static=False))


class TestPs1AChainOfAliasesCostsAboutWhatItsLengthCosts(TestBase):

    _SHORT = 100
    _LONG = 400
    _BUDGET = 20
    _RUNS = 3
    _BATCH = 50

    @staticmethod
    def _chain(length: int) -> str:
        lines = ['$a0 = 1, 2, 3']
        for index in range(1, length):
            lines.append(F'$a{index} = $a{index - 1}')
            if index in (length // 3, length // 3 * 2):
                lines.append(F'[Array]::Reverse($a{index})')
        lines.append(F'Write-Output $a{length - 1}')
        return '\n'.join(lines)

    def _cost(self, length: int) -> float:
        source = self._chain(length)
        batches = [[Ps1Parser(source).parse() for _ in range(self._BATCH)] for _ in range(self._RUNS)]
        return fastest_processor_time(functools.partial(self._build_all, batch) for batch in batches)

    @staticmethod
    def _build_all(trees: list) -> None:
        for tree in trees:
            build_semantic_model(tree)

    def test_quadrupling_the_chain_does_not_cost_twenty_times_as_much(self):
        long = self._cost(self._LONG)
        short = self._cost(self._SHORT)
        self.assertLess(processor_time_ratio(long, short), self._BUDGET)


class TestPs1TheModelReadsWhichNamesTheScriptMayRemoveOrConstrain(TestBase):

    @staticmethod
    def _model(source: str):
        return build_semantic_model(Ps1Parser(source).parse())

    def test_the_names_a_script_may_remove(self):
        removed = self._model('Remove-Variable a; Remove-Item variable:b; $v = Get-Variable c; $d = 1').variables_removed
        self.assertEqual([name in removed for name in 'abcd'], [True, True, True, False])

    def test_the_names_a_script_may_constrain(self):
        constrained = self._model(
            '[int]$a = 1; New-Variable b 1 -Option ReadOnly; function f { param($c) }; $v = Get-Variable d; $e = 1'
        ).variables_constrained
        self.assertEqual([name in constrained for name in 'abcde'], [True, True, True, True, False])

    def test_a_name_nobody_can_read_may_be_every_name(self):
        model = self._model('Remove-Variable $n')
        self.assertIn('x', model.variables_removed)
        self.assertIn('x', model.variables_constrained)

    def test_a_removal_handed_a_list_of_paths_may_remove_each_name_in_it(self):
        for removal in (
            'Remove-Item -Path variable:a, variable:b',
            "'variable:a', 'variable:b' | Remove-Item",
            "@('variable:a') | Remove-Item",
        ):
            with self.subTest(removal=removal):
                self.assertIn('a', self._model(removal).variables_removed)
