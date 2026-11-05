from __future__ import annotations

from inspect import cleandoc

from test import TestBase, lines_executed, opportunity

from refinery.lib.scripts import set_body
from refinery.lib.scripts.analysis import cfg, components
from refinery.lib.scripts.analysis.cfg import reachable_forward_from_any
from refinery.lib.scripts.ps1.analysis import worldflow
from refinery.lib.scripts.ps1.analysis.cache import Ps1ModelCache
from refinery.lib.scripts.ps1.analysis.cfg import build_ps1_control_flow
from refinery.lib.scripts.ps1.analysis.world import build_closed_world
from refinery.lib.scripts.ps1.analysis.worldflow import Ps1CommandShadows, Ps1WorldReach
from refinery.lib.scripts.ps1.ast import resolve_command_name
from refinery.lib.scripts.ps1.model import (
    Ps1CommandInvocation,
    Ps1FunctionDefinition,
    Ps1InvokeMember,
    Ps1Script,
    Ps1TrapStatement,
    Ps1WhileLoop,
)
from refinery.lib.scripts.ps1.parser import Ps1Parser


class TestPs1WorldReachIsBoundToTheTreeItMeasured(TestBase):

    def test_a_positional_grant_is_withdrawn_once_the_tree_changes(self):
        script = Ps1Parser('$Null = [Math]::Sqrt(144)\nInvoke-Expression $c').parse()
        reach = Ps1ModelCache(script).world_reach
        read = script.body[0]
        self.assertFalse(reach.closed_for_the_whole_run)
        self.assertTrue(reach.closed_at(read))
        set_body(script, [*script.body, Ps1Parser('Write-Host done').parse().body[0]])
        self.assertFalse(reach.closed_at(read))

    def test_every_grant_is_withdrawn_once_the_tree_gains_a_world_opener(self):
        script = Ps1Parser('$x = 4\nWrite-Host $x').parse()
        reach = Ps1ModelCache(script).world_reach
        read = script.body[0]
        self.assertTrue(reach.closed_for_the_whole_run)
        self.assertTrue(reach.closed_at(read))
        self.assertTrue(reach.may_trust_command_name_at('write-host', read))
        opener = Ps1Parser('Invoke-Expression $env:PAYLOAD').parse().body[0]
        set_body(script, [*script.body, opener])
        self.assertFalse(reach.closed_for_the_whole_run)
        self.assertFalse(reach.closed_at(read))
        self.assertFalse(reach.may_trust_command_name_at('write-host', read))


class TestPs1CommandTrustIsPositionalWhereTheWorldStaysClosed(TestBase):

    def test_whole_run_and_positional_trust_disagree_across_a_function_redefinition(self):
        script = Ps1Parser(
            '$Null = Get-Random -Maximum 88175\n'
            'function Get-Random { Start-Process calc }\n'
            'Get-Random').parse()
        cache = Ps1ModelCache(script)
        reach = cache.world_reach
        call_before, _, call_after = script.body
        self.assertTrue(reach.closed_for_the_whole_run)
        self.assertTrue(cache.closed_world.may_trust_command_name('Start-Process'))
        self.assertFalse(cache.closed_world.may_trust_command_name('Get-Random'))
        self.assertTrue(reach.may_trust_command_name_at('Get-Random', call_before))
        self.assertFalse(reach.may_trust_command_name_at('Get-Random', call_after))

    def test_a_name_the_whole_run_trusts_is_trusted_at_every_position(self):
        script = Ps1Parser(
            '$Null = Get-Random -Maximum 88175\n'
            'function Get-Random { Start-Process calc }\n'
            'Write-Host done').parse()
        cache = Ps1ModelCache(script)
        self.assertTrue(cache.closed_world.may_trust_command_name('Start-Process'))
        for index, statement in enumerate(script.body):
            with self.subTest(index):
                self.assertTrue(
                    cache.world_reach.may_trust_command_name_at('Start-Process', statement))


class TestPs1FloodsGoForwardThroughAResumingTrap(TestBase):

    def _reach(self, source: str) -> tuple[Ps1Script, Ps1WorldReach]:
        script = Ps1Parser(source).parse()
        return script, Ps1ModelCache(script).world_reach

    def test_an_opener_late_in_a_guarded_block_leaves_the_reads_above_it_closed(self):
        script, reach = self._reach(
            'trap { continue }\n'
            '$Null = [Math]::Sqrt(144)\n'
            'Invoke-Expression $env:PAYLOAD\n'
            '$Null = [Math]::Sqrt(169)')
        self.assertFalse(reach.closed_for_the_whole_run)
        self.assertTrue(reach.closed_at(script.body[1]))
        self.assertFalse(reach.closed_at(script.body[3]))

    def test_an_opener_poisons_the_reads_resumption_reaches_across_a_terminator(self):
        script, reach = self._reach(
            'trap { continue }\n'
            'Invoke-Expression $env:PAYLOAD\n'
            "throw 'x'\n"
            '$Null = [Math]::Sqrt(144)')
        self.assertFalse(reach.closed_at(script.body[3]))

    def test_an_opener_poisons_the_body_of_a_try_resumption_reaches(self):
        script, reach = self._reach(
            'trap { continue }\n'
            'Invoke-Expression $env:PAYLOAD\n'
            "throw 'x'\n"
            'try { $Null = [Math]::Sqrt(144) } catch { }')
        self.assertFalse(reach.closed_at(script.body[3].try_block.body[0]))

    def test_an_opener_last_in_a_nested_guarded_block_poisons_what_follows_the_block(self):
        script, reach = self._reach(
            'if ($c) { trap { continue }\n'
            'Invoke-Expression $env:PAYLOAD\n'
            "throw 'x' }\n"
            '$Null = [Math]::Sqrt(144)')
        self.assertFalse(reach.closed_at(script.body[1]))

    def test_an_opener_inside_the_handler_poisons_the_block_it_resumes_into(self):
        script, reach = self._reach(
            'trap { Invoke-Expression $env:PAYLOAD\ncontinue }\n'
            "throw 'x'\n"
            '$Null = [Math]::Sqrt(144)\n'
            '$Null = [Math]::Sqrt(169)')
        self.assertFalse(reach.closed_at(script.body[2]))
        self.assertFalse(reach.closed_at(script.body[3]))

    def test_a_redefinition_late_in_a_guarded_block_leaves_the_calls_above_it_trusted(self):
        script, reach = self._reach(
            'trap { continue }\n'
            '$Null = Get-Random -Maximum 88175\n'
            'function Get-Random { Start-Process calc }\n'
            'Get-Random')
        self.assertFalse(build_closed_world(script).may_trust_command_name('Get-Random'))
        self.assertTrue(reach.may_trust_command_name_at('Get-Random', script.body[1]))
        self.assertFalse(reach.may_trust_command_name_at('Get-Random', script.body[3]))

    def test_a_redefinition_inside_the_handler_is_distrusted_across_the_block(self):
        script, reach = self._reach(
            'trap { function script:Get-Random { Start-Process calc }\ncontinue }\n'
            "throw 'x'\n"
            '$Null = Get-Random -Maximum 88175\n'
            '$Null = Get-Random -Maximum 88176'
        )
        self.assertFalse(reach.may_trust_command_name_at('Get-Random', script.body[2]))
        self.assertFalse(reach.may_trust_command_name_at('Get-Random', script.body[3]))


class TestPs1TheStatementAResumptionLandsOnIsTheOneControlEnters(TestBase):

    def _reach(self, source: str):
        script = Ps1Parser(source).parse()
        return script, Ps1ModelCache(script).world_reach

    @staticmethod
    def _guarded(clause: str) -> str:
        return (
            'trap { continue }\n'
            'Invoke-Expression $env:PAYLOAD\n'
            F'{clause}\n'
            '$Null = [Math]::Sqrt(169)'
        )

    def test_a_read_in_the_handler_of_a_guarded_construct_is_poisoned(self):
        script, reach = self._reach(self._guarded("try { 'a' } catch { $Null = [Math]::Sqrt(144) }"))
        read = script.body[2].catch_clauses[0].body.body[0]
        self.assertFalse(reach.closed_at(read))

    @opportunity
    def test_the_same_read_is_poisoned_where_the_construct_guards_nothing(self):
        script, reach = self._reach(self._guarded('try { } catch { $Null = [Math]::Sqrt(144) }'))
        read = script.body[2].catch_clauses[0].body.body[0]
        self.assertFalse(reach.closed_at(read))


class TestPs1AReadInsideABlockTheStatementRunsHasTheStatementsPosition(TestBase):

    @staticmethod
    def _named(source: str, name: str):
        script = Ps1Parser(cleandoc(source)).parse()
        found = next(
            node for node in script.walk()
            if isinstance(node, Ps1CommandInvocation) and resolve_command_name(node) == name
        )
        return script, found

    def test_a_command_inside_an_iterated_body_above_a_leak_is_trusted(self):
        script, inner = self._named(
            """
            $Null = 1, 2 | ForEach-Object { Get-Random }
            Invoke-Expression $env:PAYLOAD
            """,
            'get-random',
        )
        reach = Ps1ModelCache(script).world_reach
        self.assertFalse(reach.closed_for_the_whole_run)
        self.assertTrue(reach.may_trust_command_name_at('get-random', inner))
        self.assertTrue(reach.closed_at(inner))

    def test_the_same_command_below_the_leak_is_refused(self):
        script, inner = self._named(
            """
            Invoke-Expression $env:PAYLOAD
            $Null = 1, 2 | ForEach-Object { Get-Random }
            """,
            'get-random',
        )
        reach = Ps1ModelCache(script).world_reach
        self.assertFalse(reach.may_trust_command_name_at('get-random', inner))
        self.assertFalse(reach.closed_at(inner))

    def test_a_command_inside_a_stored_block_is_refused_wherever_it_stands(self):
        script, inner = self._named(
            """
            $b = { Get-Random }
            Invoke-Expression $env:PAYLOAD
            """,
            'get-random',
        )
        reach = Ps1ModelCache(script).world_reach
        self.assertFalse(reach.may_trust_command_name_at('get-random', inner))
        self.assertFalse(reach.closed_at(inner))

    def test_a_redefined_iterator_refuses_the_climb_out_of_its_body(self):
        script, inner = self._named(
            """
            function ForEach-Object { param($b) $global:kept = $b }
            $Null = 1, 2 | ForEach-Object { Get-Random }
            Invoke-Expression $env:PAYLOAD
            """,
            'get-random',
        )
        reach = Ps1ModelCache(script).world_reach
        self.assertFalse(reach.may_trust_command_name_at('get-random', inner))

    def test_an_ampersand_block_needs_no_name_to_be_trusted(self):
        script, inner = self._named(
            """
            $Null = & { Get-Random }
            Invoke-Expression $env:PAYLOAD
            """,
            'get-random',
        )
        reach = Ps1ModelCache(script).world_reach
        self.assertTrue(reach.may_trust_command_name_at('get-random', inner))


class TestPs1WhatAnOpenerIsHandedIsEvaluatedBeforeItRuns(TestBase):

    @staticmethod
    def _join_is_closed(source: str) -> bool:
        script = Ps1Parser(cleandoc(source)).parse()
        join = next(
            node for node in script.walk()
            if isinstance(node, Ps1InvokeMember) and node.member == 'Join'
        )
        return Ps1ModelCache(script).world_reach.closed_at(join)

    def test_an_argument_of_the_opener_is_closed(self):
        self.assertTrue(self._join_is_closed("iex ([string]::Join(' ', $b))"))

    def test_a_node_after_the_opener_in_its_statement_is_not(self):
        self.assertFalse(self._join_is_closed("(iex $env:PAYLOAD) + [string]::Join(' ', $b)"))

    def test_an_argument_of_the_second_of_two_openers_in_a_statement_is_not(self):
        self.assertFalse(self._join_is_closed(
            "(iex $env:PAYLOAD) + (iex ([string]::Join(' ', $b)))"))

    def test_an_argument_of_an_opener_below_another_one_is_not(self):
        self.assertFalse(self._join_is_closed(
            """
            iex $env:PAYLOAD
            iex ([string]::Join(' ', $b))
            """))

    def test_an_argument_of_an_opener_in_a_loop_is_not(self):
        self.assertFalse(self._join_is_closed("while ($true) { iex ([string]::Join(' ', $b)) }"))

    def test_a_node_in_a_block_handed_to_the_opener_is_not(self):
        self.assertFalse(self._join_is_closed("& $dispatch { [string]::Join(' ', $b) }"))

    @opportunity
    def test_a_node_in_a_written_out_block_invoke_command_runs_before_the_opener_is_closed(self):
        self.assertTrue(self._join_is_closed(
            "Invoke-Command -ScriptBlock { [string]::Join(' ', $b) } -ArgumentList $env:PAYLOAD; "
            'iex $env:PAYLOAD'
        ))


class TestPs1ABindingOfAnUninvokedNameFloodsNothing(TestBase):

    @staticmethod
    def _below(source: str) -> tuple[Ps1ModelCache, object]:
        script = Ps1Parser(cleandoc(source)).parse()
        return Ps1ModelCache(script), script.body[-1]

    def test_the_positions_below_the_binding_are_granted_and_the_whole_run_stays_open(self):
        cache, read = self._below(
            """
            Set-Alias zzq i*x
            $Null = Get-Random
            """
        )
        reach = cache.world_reach
        self.assertFalse(reach.closed_for_the_whole_run)
        self.assertFalse(cache.closed_world.command_table_closed)
        self.assertTrue(cache.closed_world.type_system_closed)
        self.assertTrue(reach.may_trust_command_name_at('get-random', read))
        self.assertTrue(reach.closed_at(read))

    def test_a_dot_sourced_or_provider_target_binding_of_an_uninvoked_name_still_grants(self):
        for source in (
            """
            . Set-Alias zzq i*x
            $Null = Get-Random
            """,
            """
            Set-Alias zzq function:bar
            $Null = Get-Random
            """,
        ):
            with self.subTest(source):
                cache, read = self._below(source)
                reach = cache.world_reach
                self.assertTrue(reach.may_trust_command_name_at('get-random', read))
                self.assertTrue(reach.closed_at(read))
                self.assertFalse(reach.closed_for_the_whole_run)

    def test_a_call_to_the_bound_name_above_the_read_keeps_the_flood(self):
        for source in (
            """
            Set-Alias zzq i*x
            zzq
            $Null = Get-Random
            """,
            """
            Set-Alias Get-ChildItem iex
            gci
            $Null = Get-Random
            """,
            """
            Set-Alias gci Foo
            gci
            $Null = Get-Random
            """,
            """
            Set-Alias global:zzq iex
            global:zzq
            $Null = Get-Random
            """,
            """
            Set-Alias zzq iex
            & 'global:zzq'
            $Null = Get-Random
            """,
        ):
            with self.subTest(source):
                cache, read = self._below(source)
                reach = cache.world_reach
                self.assertFalse(reach.may_trust_command_name_at('get-random', read))
                self.assertFalse(reach.closed_at(read))

    def test_a_bare_noun_reaching_a_get_prefixed_binding_keeps_the_flood(self):
        cache, read = self._below(
            """
            Set-Alias Get-Frob iex
            Frob
            $Null = Get-Random
            """
        )
        self.assertFalse(cache.world_reach.may_trust_command_name_at('get-random', read))
        self.assertFalse(cache.world_reach.closed_at(read))

    @opportunity
    def test_a_call_to_the_bound_name_that_has_not_run_by_the_read_leaves_it_granted(self):
        for source, position in (
            (
                """
                Set-Alias zzq i*x
                $Null = Get-Random
                zzq
                """,
                1,
            ),
            (
                """
                Set-Alias zzq i*x
                function f { zzq }
                $Null = Get-Random
                """,
                2,
            ),
        ):
            with self.subTest(source):
                cache, _ = self._below(source)
                read = cache.root.body[position]
                self.assertTrue(cache.world_reach.may_trust_command_name_at('get-random', read))
                self.assertTrue(cache.world_reach.closed_at(read))

    def test_a_binding_the_walk_cannot_read_whole_floods(self):
        for source in (
            """
            Set-Alias zzq $target
            $Null = Get-Random
            """,
            """
            Set-Alias zzq i*x -Force
            $Null = Get-Random
            """,
            """
            Set-Item alias:zzq i*x
            $Null = Get-Random
            """,
        ):
            with self.subTest(source):
                cache, read = self._below(source)
                self.assertFalse(cache.world_reach.may_trust_command_name_at('get-random', read))
                self.assertFalse(cache.world_reach.closed_at(read))

    def test_a_binding_beside_another_opener_leaves_that_flood_intact(self):
        cache, read = self._below(
            """
            Set-Alias zzq i*x
            Invoke-Expression $c
            $Null = Get-Random
            """
        )
        self.assertFalse(cache.world_reach.may_trust_command_name_at('get-random', read))
        self.assertFalse(cache.world_reach.closed_at(read))


class TestPs1CommandShadowsAnswerAsOneFloodPerName(TestBase):

    _SCRIPT = cleandoc("""
        trap { function Get-Date { 'd' }
        continue }
        $Null = Get-Random -Maximum 7
        if ($x) { function Get-Random { 'r' } }
        while ($y) {
          Get-Random
          Set-Alias Get-Item Get-ChildItem
          Get-Date
        }
        function Get-Random { 'again' }
        Get-Item x
    """)

    def _graph_and_landings(self):
        script = Ps1Parser(self._SCRIPT).parse()
        graph = build_ps1_control_flow(script)[id(script)]
        loop = script.body[3]
        assert isinstance(loop, Ps1WhileLoop) and loop.body is not None
        trap = script.body[0]
        assert isinstance(trap, Ps1TrapStatement) and trap.body is not None

        def node(element):
            found = graph.node_of(element)
            assert found is not None
            return found

        landings = {
            'get-date': [node(trap.body.body[0])],
            'get-random': [node(script.body[2]), node(script.body[4])],
            'get-item': [node(loop.body.body[1])],
        }
        return graph, landings

    def test_every_name_spares_exactly_what_its_own_flood_leaves(self):
        graph, landings = self._graph_and_landings()
        shadows = Ps1CommandShadows(graph, landings)
        for name, sites in landings.items():
            flooded = reachable_forward_from_any(graph, sites)
            wrong = [
                index for index, position in enumerate(graph.nodes)
                if shadows.spares(name, position) == (id(position) in flooded)
            ]
            with self.subTest(name=name):
                self.assertEqual(wrong, [])

    def test_a_name_without_placed_sites_spares_no_position(self):
        graph, landings = self._graph_and_landings()
        shadows = Ps1CommandShadows(graph, landings)
        self.assertFalse(any(shadows.spares('write-host', position) for position in graph.nodes))

    def test_a_site_placed_in_another_body_is_refused(self):
        script = Ps1Parser("function f { 'in' }\n'out'").parse()
        graphs = build_ps1_control_flow(script)
        definition = script.body[0]
        assert isinstance(definition, Ps1FunctionDefinition) and definition.body is not None
        inside = graphs[id(definition.body)].node_of(definition.body.body[0])
        assert inside is not None
        with self.assertRaises(ValueError):
            Ps1CommandShadows(graphs[id(script)], {'f': [inside]})

    def test_the_work_of_asking_about_every_call_of_every_redefined_name_grows_linearly(self):
        def work(count: int) -> int:
            script = Ps1Parser('\n'.join(
                line
                for index in range(count)
                for line in (F"function Get-Thing{index} {{ 's' }}", F'Get-Thing{index}')
            )).parse()
            calls = script.body[1::2]

            def ask():
                reach = Ps1ModelCache(script).world_reach
                for index, call in enumerate(calls):
                    reach.may_trust_command_name_at(F'Get-Thing{index}', call)

            return lines_executed(ask, worldflow, cfg, components)

        self.assertWorkGrowsLinearly(work, 100)
