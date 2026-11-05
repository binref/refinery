from __future__ import annotations

from test import TestBase, opportunity

from refinery.lib.scripts.analysis.cycles import CycleModel
from refinery.lib.scripts.ps1.analysis.blocks import (
    Ps1BlockIteration,
    Ps1BlockReach,
    Ps1BlockScope,
    binds_the_pipeline_variable,
    build_block_model,
)
from refinery.lib.scripts.ps1.analysis.cfg import build_control_flow_model
from refinery.lib.scripts.ps1.analysis.world import measure_world
from refinery.lib.scripts.ps1.model import Ps1FunctionDefinition, Ps1ScriptBlock
from refinery.lib.scripts.ps1.parser import Ps1Parser


class TestPs1BlockFacts(TestBase):

    def _facts(self, source: str, index: int = 0):
        tree = Ps1Parser(source).parse()
        blocks = build_block_model(tree)
        found = [node for node in tree.walk() if isinstance(node, Ps1ScriptBlock)]
        return blocks, found[index]

    def _scope(self, source: str, index: int = 0) -> Ps1BlockScope:
        blocks, block = self._facts(source, index)
        return blocks.facts(block).scope

    def _written_names(self, source: str, index: int = 0) -> list[str]:
        blocks, block = self._facts(source, index)
        return sorted(write.key for write in blocks.writes_reaching_caller(block))

    def test_a_dotted_block_writes_the_caller_and_an_ampersand_block_does_not(self):
        self.assertIs(self._scope(". { $x = 'b' }"), Ps1BlockScope.CALLER)
        self.assertIs(self._scope("& { $x = 'b' }"), Ps1BlockScope.CHILD)
        self.assertEqual(self._written_names(". { $x = 'b' }"), ['x'])
        self.assertEqual(self._written_names("& { $x = 'b' }"), [])

    def test_a_function_body_opens_a_child_scope(self):
        self.assertIs(self._scope("function f { $x = 'b' }"), Ps1BlockScope.CHILD)
        self.assertEqual(self._written_names("function f { $x = 'b' }"), [])

    def test_a_child_scope_contains_a_dotted_block_nested_in_it(self):
        self.assertEqual(self._written_names("& { . { $x = 'b' } }"), [])
        self.assertEqual(self._written_names(". { & { $x = 'b' } }"), [])
        self.assertEqual(self._written_names(". { . { $x = 'b' } }"), ['x'])

    def test_a_qualified_write_is_not_a_fact_about_where_the_block_runs(self):
        self.assertEqual(self._written_names(". { $script:x = 'b' }"), [])

    def test_a_foreach_object_body_writes_the_caller_and_runs_per_input(self):
        for source in (
            "1 | ForEach-Object { $x = 'b' }",
            "1 | % { $x = 'b' }",
            "1 | ForEach-Object -Process { $x = 'b' }",
        ):
            with self.subTest(source):
                blocks, block = self._facts(source)
                facts = blocks.facts(block)
                self.assertIs(facts.scope, Ps1BlockScope.CALLER)
                self.assertIs(facts.iteration, Ps1BlockIteration.REPEATED)
                self.assertEqual(self._written_names(source), ['x'])

    def test_a_where_object_body_writes_the_caller_and_runs_per_input(self):
        for source in (
            "1 | Where-Object { $x = 'b' }",
            "1 | ? { $x = 'b' }",
        ):
            with self.subTest(source):
                blocks, block = self._facts(source)
                facts = blocks.facts(block)
                self.assertIs(facts.scope, Ps1BlockScope.CALLER)
                self.assertIs(facts.iteration, Ps1BlockIteration.REPEATED)

    def test_a_block_a_command_merely_receives_is_not_claimed_to_run(self):
        blocks, block = self._facts("f { $x = 'b' }")
        self.assertIs(blocks.facts(block).reach, Ps1BlockReach.UNKNOWN)

    @opportunity
    def test_a_block_invoke_command_is_handed_runs_where_it_is_written_in_a_child_scope(self):
        source = "Invoke-Command -ScriptBlock { $x = 'b' }"
        blocks, block = self._facts(source)
        facts = blocks.facts(block)
        self.assertIs(facts.reach, Ps1BlockReach.IMMEDIATE)
        self.assertIs(facts.scope, Ps1BlockScope.CHILD)
        self.assertEqual(self._written_names(source), [])

    def test_a_block_invoked_through_a_computed_name_is_not_claimed_to_run(self):
        blocks, block = self._facts("& $c { $x = 'b' }")
        self.assertIs(blocks.facts(block).reach, Ps1BlockReach.UNKNOWN)

    def test_a_block_that_is_only_a_value_is_never_invoked_where_it_is_written(self):
        for source in ("$b = { $x = 'b' }", "{ $x = 'b' } | Out-Null"):
            with self.subTest(source):
                blocks, block = self._facts(source)
                self.assertIs(blocks.facts(block).reach, Ps1BlockReach.STORED)

    def test_an_unknown_block_is_projected_as_writing_the_caller(self):
        blocks, block = self._facts("f { $x = 'b' }")
        self.assertIs(blocks.facts(block).scope, Ps1BlockScope.UNKNOWN)
        self.assertTrue(blocks.may_write_caller_scope(block))
        self.assertEqual(self._written_names("f { $x = 'b' }"), ['x'])

    def test_a_name_addressed_write_reaches_the_caller_exactly_where_a_bare_one_does(self):
        for bare, named, expected in (
            (". { $x = 'b' }", ". { Set-Variable x 'b' }", ['x']),
            ("& { $x = 'b' }", "& { Set-Variable x 'b' }", []),
            ("function f { $x = 'b' }", "function f { Set-Variable x 'b' }", []),
            ("1 | ForEach-Object { $x = 'b' }", "1 | ForEach-Object { Set-Variable x 'b' }", ['x']),
            ("1 | Where-Object { $x = 'b' }", "1 | Where-Object { Set-Variable x 'b' }", ['x']),
        ):
            with self.subTest(named):
                self.assertEqual(self._written_names(bare), expected)
                self.assertEqual(self._written_names(named), expected)

    def test_the_variable_commands_that_write_a_name_reach_the_caller_from_a_dotted_block(self):
        for source in (
            ". { Set-Variable x 'b' }",
            ". { sv x 'b' }",
            ". { New-Variable x 'b' }",
            ". { nv x 'b' }",
            '. { Clear-Variable x }',
            '. { clv x }',
            '. { Remove-Variable x }',
            '. { rv x }',
        ):
            with self.subTest(source):
                self.assertEqual(self._written_names(source), ['x'])

    def test_the_provider_forms_that_write_a_name_reach_the_caller_from_a_dotted_block(self):
        for source in (
            ". { Set-Item Variable:x 'b' }",
            ". { si Variable:x 'b' }",
            ". { New-Item Variable:x -Value 'b' }",
            '. { Remove-Item Variable:x }',
            '. { del variable:x }',
        ):
            with self.subTest(source):
                self.assertEqual(self._written_names(source), ['x'])

    def test_a_command_that_only_reads_a_name_leaves_no_write_behind(self):
        for source in ('. { Get-Variable x }', '. { gv x }', '. { Get-Item Variable:x }'):
            with self.subTest(source):
                self.assertEqual(self._written_names(source), [])
        self.assertEqual(self._written_names('. { Get-Variable x -OutVariable y }'), ['y'])

    def test_an_out_variable_binds_its_name_in_the_scope_the_command_runs_in(self):
        for source in ('. { Get-Process -OutVariable p }', '. { Get-Process -ov p }'):
            with self.subTest(source):
                self.assertEqual(self._written_names(source), ['p'])
        self.assertEqual(self._written_names('& { Get-Process -OutVariable p }'), [])

    def test_an_appending_out_variable_still_changes_the_name_it_binds(self):
        self.assertEqual(self._written_names('. { Get-Process -OutVariable +p }'), ['p'])

    def test_a_write_that_names_its_scope_is_not_a_fact_about_where_the_block_runs(self):
        for source in (
            ". { Set-Variable x 'b' -Scope Script }",
            ". { Set-Variable script:x 'b' }",
            ". { Set-Variable x 'b' -Scope Global }",
            ". { Set-Variable global:x 'b' }",
            '. { Remove-Variable x -Scope Global }',
            ". { $global:x = 'b' }",
        ):
            with self.subTest(source):
                self.assertEqual(self._written_names(source), [])

    def test_a_write_that_names_the_scope_it_runs_in_is_still_a_fact_about_the_block(self):
        self.assertEqual(self._written_names(". { Set-Variable x 'b' -Scope Local }"), ['x'])
        self.assertEqual(self._written_names("& { Set-Variable x 'b' -Scope Local }"), [])

    def test_an_environment_write_is_not_a_fact_about_where_the_block_runs(self):
        for source in (
            ". { Set-Item Env:x 'b' }",
            ". { $env:x = 'b' }",
            "& { Set-Item Env:x 'b' }",
            "& { $env:x = 'b' }",
        ):
            with self.subTest(source):
                self.assertEqual(self._written_names(source), [])

    def test_a_name_addressed_write_dies_with_the_child_scope_around_it(self):
        self.assertEqual(self._written_names(". { & { Set-Variable x 'b' } }"), [])
        self.assertEqual(self._written_names("& { . { Set-Variable x 'b' } }"), [])
        self.assertEqual(self._written_names('. { . { Remove-Variable x } }'), ['x'])
        self.assertEqual(self._written_names('. { function f { Remove-Variable x } }'), [])

    def test_an_unknown_block_is_projected_as_writing_the_names_it_addresses(self):
        self.assertEqual(self._written_names('f { Remove-Variable x }'), ['x'])


class TestPs1BlockFactsReachCycleModel(TestBase):

    def _repeats(self, source: str) -> bool:
        tree = Ps1Parser(source).parse()
        blocks = build_block_model(tree)
        cycles = CycleModel(build_control_flow_model(tree), blocks.body_site)
        block = next(
            node for node in tree.walk() if isinstance(node, Ps1ScriptBlock) and node.body)
        return cycles.repeats(block.body[0])

    def test_a_foreach_object_body_repeats_though_the_statement_handing_it_over_does_not(self):
        self.assertTrue(self._repeats("1..3 | ForEach-Object { $x = 'b' }"))

    def test_a_body_invoked_once_beside_it_does_not_repeat(self):
        self.assertFalse(self._repeats("& { $x = 'b' }"))
        self.assertFalse(self._repeats(". { $x = 'b' }"))

    def test_a_block_written_inside_a_loop_repeats_with_the_loop_around_it(self):
        self.assertTrue(self._repeats("while ($c) { & { $x = 'b' } }"))


class TestPs1AnIteratingCommandRunsOnlyTheBlocksItIsHandedToRun(TestBase):

    @staticmethod
    def _blocks(source: str):
        tree = Ps1Parser(source).parse()
        found = [node for node in tree.walk() if isinstance(node, Ps1ScriptBlock)]
        return build_block_model(tree), sorted(found, key=lambda node: node.offset)

    def test_a_block_handed_to_a_data_slot_has_no_site(self):
        blocks, found = self._blocks("ForEach-Object -InputObject { 'x' }")
        self.assertIs(blocks.facts(found[0]).reach, Ps1BlockReach.UNKNOWN)
        self.assertIsNone(blocks.facts(found[0]).site)

    def test_a_named_process_block_has_the_command_as_its_site(self):
        blocks, found = self._blocks("1, 2 | ForEach-Object -Process { $_ }")
        facts = blocks.facts(found[0])
        self.assertIs(facts.reach, Ps1BlockReach.IMMEDIATE)
        self.assertIsNotNone(facts.site)

    def test_the_first_of_three_positional_blocks_runs_where_the_command_does(self):
        blocks, found = self._blocks("1, 2 | ForEach-Object { 'B' } { 'P' } { 'E' }")
        self.assertIs(blocks.facts(found[0]).reach, Ps1BlockReach.IMMEDIATE)

    @opportunity
    def test_the_second_and_third_of_three_positional_blocks_run_where_the_command_does(self):
        blocks, found = self._blocks("1, 2 | ForEach-Object { 'B' } { 'P' } { 'E' }")
        self.assertIs(blocks.facts(found[1]).reach, Ps1BlockReach.IMMEDIATE)
        self.assertIs(blocks.facts(found[2]).reach, Ps1BlockReach.IMMEDIATE)

    def test_a_lone_positional_block_binds_the_current_object(self):
        blocks, found = self._blocks("1, 2 | ForEach-Object { $_ }")
        self.assertIsNotNone(binds_the_pipeline_variable(found[0]))

    def test_a_begin_block_binds_no_current_object_beside_a_process_block_that_does(self):
        blocks, found = self._blocks(
            '1, 2 | ForEach-Object -Begin { "[$_]" } -Process { "[$_]" }')
        self.assertIsNone(binds_the_pipeline_variable(found[0]))
        self.assertIsNotNone(binds_the_pipeline_variable(found[1]))

    def test_a_where_object_filter_binds_the_current_object(self):
        blocks, found = self._blocks("1, 2 | Where-Object { $_ -gt 1 }")
        self.assertIsNotNone(binds_the_pipeline_variable(found[0]))

    def test_the_first_and_third_of_three_positional_blocks_bind_no_current_object(self):
        blocks, found = self._blocks("1, 2 | ForEach-Object { 'B' } { 'P' } { 'E' }")
        self.assertIsNone(binds_the_pipeline_variable(found[0]))
        self.assertIsNone(binds_the_pipeline_variable(found[2]))

    @opportunity
    def test_the_second_of_three_positional_blocks_binds_the_current_object(self):
        blocks, found = self._blocks("1, 2 | ForEach-Object { 'B' } { 'P' } { 'E' }")
        self.assertIsNotNone(binds_the_pipeline_variable(found[1]))

    def test_a_member_name_makes_the_positional_block_an_argument_rather_than_a_body(self):
        blocks, found = self._blocks("1, 2 | ForEach-Object -MemberName ToString { 'x' }")
        self.assertIs(blocks.facts(found[0]).reach, Ps1BlockReach.UNKNOWN)


class TestPs1AShadowedIteratingCommandRunsItsOwnBodyNotTheBlock(TestBase):

    def _pipeline_block(self, source: str):
        tree = Ps1Parser(source).parse()
        shadowed = measure_world(tree).world.shadowed_names
        blocks = build_block_model(tree, shadowed)
        pipeline_block = next(
            node for node in tree.walk()
            if isinstance(node, Ps1ScriptBlock)
            and not isinstance(node.parent, Ps1FunctionDefinition))
        return blocks, pipeline_block, shadowed

    def test_a_function_redefinition_makes_the_body_unplaced(self):
        blocks, block, _ = self._pipeline_block(
            "function ForEach-Object { 'HIJACK' }\n1, 2 | ForEach-Object { $_ * 2 }")
        self.assertIs(blocks.facts(block).reach, Ps1BlockReach.UNKNOWN)

    def test_the_percent_alias_follows_the_redefinition_of_foreach_object(self):
        blocks, block, shadowed = self._pipeline_block(
            "function ForEach-Object { 'HIJACK' }\n1, 2 | % { $_ * 2 }")
        self.assertIs(blocks.facts(block).reach, Ps1BlockReach.UNKNOWN)
        self.assertIsNone(binds_the_pipeline_variable(block, shadowed))

    def test_a_body_of_an_unshadowed_command_is_still_placed(self):
        blocks, block, shadowed = self._pipeline_block("1, 2 | % { $_ * 2 }")
        self.assertIs(blocks.facts(block).reach, Ps1BlockReach.IMMEDIATE)
        self.assertIsNotNone(binds_the_pipeline_variable(block, shadowed))

    def test_a_redefinition_of_the_foreach_keyword_does_not_take_over_foreach_object(self):
        blocks, block, shadowed = self._pipeline_block(
            "function foreach { 'HIJACK' }\n1, 2 | ForEach-Object { $_ * 2 }")
        self.assertIs(blocks.facts(block).reach, Ps1BlockReach.IMMEDIATE)
        self.assertIsNotNone(binds_the_pipeline_variable(block, shadowed))
