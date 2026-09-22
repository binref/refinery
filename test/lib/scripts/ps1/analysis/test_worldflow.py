from __future__ import annotations

import unittest

from inspect import cleandoc

from test import TestBase

from refinery.lib.scripts import set_body
from refinery.lib.scripts.ps1.analysis.cache import Ps1ModelCache
from refinery.lib.scripts.ps1.analysis.world import build_closed_world
from refinery.lib.scripts.ps1.analysis.worldflow import Ps1WorldReach
from refinery.lib.scripts.ps1.ast import resolve_command_name
from refinery.lib.scripts.ps1.model import Ps1CommandInvocation, Ps1Script
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
        """
        The positional query is a widening of the whole-run one and never a second opinion: it
        short-circuits on the whole-run verdict, so it grants wherever that grants and the flood is
        consulted only where it refuses. A shadow site sits below to keep the flood in play for the
        name it spells, and the untouched name has to stay trusted on both sides of it.
        """
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
    """
    A `trap { continue }` resumes the block it guards at the statement after the one that threw, so
    a leak written late in such a block cannot have run at a read written above it. Measured on 5.1:
    `trap { continue }; Write-Host 'one'; throw 'e'; Write-Host 'three'` writes `one` once and then
    `three`.

    Both floods answer this way or neither is worth having: an obfuscated script that wraps its
    whole body in a resuming trap is exactly the one whose every read the over-approximate reading
    refuses.
    """

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
        """
        Nothing but resumption joins the two: the `throw` between them ends the statement list, and
        a flood that stopped there would call the world closed at a read the leak precedes.
        """
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
        """
        Measured on 5.1: `if ($true) { trap { continue }; Write-Host 'in'; throw 'e' };
        Write-Host 'after'` writes `in` and then `after`, so a leak in the block has run by the time
        the statement after the block does.
        """
        script, reach = self._reach(
            'if ($c) { trap { continue }\n'
            'Invoke-Expression $env:PAYLOAD\n'
            "throw 'x' }\n"
            '$Null = [Math]::Sqrt(144)')
        self.assertFalse(reach.closed_at(script.body[1]))

    def test_an_opener_inside_the_handler_poisons_the_block_it_resumes_into(self):
        """
        A handler runs only after some statement of the block threw and may resume at any of them,
        so an opener written in one has run wherever the block goes on. No forward edge leaves a
        handler statement, and answering from the forward edges alone would vouch for exactly the
        statements the handler resumes into.
        """
        script, reach = self._reach(
            'trap { Invoke-Expression $env:PAYLOAD\ncontinue }\n'
            '$Null = [Math]::Sqrt(144)\n'
            '$Null = [Math]::Sqrt(169)')
        self.assertFalse(reach.closed_at(script.body[1]))
        self.assertFalse(reach.closed_at(script.body[2]))

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
            'trap { function Get-Random { Start-Process calc }\ncontinue }\n'
            '$Null = Get-Random -Maximum 88175\n'
            '$Null = Get-Random -Maximum 88176')
        self.assertFalse(reach.may_trust_command_name_at('Get-Random', script.body[1]))
        self.assertFalse(reach.may_trust_command_name_at('Get-Random', script.body[2]))


class TestPs1TheStatementAResumptionLandsOnIsTheOneControlEnters(TestBase):
    """
    Where the forward half finds the statement control resumes at, and the one shape it finds the
    wrong one for. A slot is put in front of each guarded statement and joined to whatever that
    statement is entered by; a statement that enters nothing leaves its slot unclaimed and the slot
    carries on to the next one, which is right for a `trap` declaration and wrong for a construct
    that builds nodes without being entered at any of them.

    `try { }` with an empty guarded block is that construct: it builds its `catch` clause and links
    no frontier, so the slot rolls past the whole `try` and the flood never reaches inside it. The
    grant costs nothing today — an empty `try` cannot throw, so the clause is dead — which is
    exactly why it needs pinning rather than trusting: what is wrong is the reading, not the shape,
    and the next construct built this way need not be dead.
    """

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

    @unittest.expectedFailure
    def test_the_same_read_is_poisoned_where_the_construct_guards_nothing(self):
        script, reach = self._reach(self._guarded('try { } catch { $Null = [Math]::Sqrt(144) }'))
        read = script.body[2].catch_clauses[0].body.body[0]
        self.assertFalse(reach.closed_at(read))


class TestPs1AReadInsideABlockTheStatementRunsHasTheStatementsPosition(TestBase):
    """
    A `ForEach-Object` body runs while the statement holding it runs and at no other time, so a
    command named inside it is as trustworthy as the same command named beside it. A body something
    keeps runs whenever that something says, which is a time no per-body graph orders.
    """

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
        """
        The name is what makes the climb true: a script that takes `ForEach-Object` over may hand
        the block to something that keeps it, so the body is no longer run where it is written.
        """
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


class TestPs1ABindingOfAnUninvokedNameFloodsNothing(TestBase):
    """
    A `Set-Alias` of a name no statement invokes rebinds nothing any call reaches and runs nothing
    itself, so both positional queries grant below it as they do below no opener at all — while
    the whole-run verdict, which the call graph reads, still reports the command table open. A
    binding the script does invoke anywhere, or one the walk cannot read whole, floods like every
    other opener.
    """

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
        """
        A `Set-Alias` binds exactly the one name it spells, whichever operator carries it and
        whatever its target looks like: `. Set-Alias` runs no file, and a `function:` target is the
        command the name is bound to, not a provider write. So a dot-sourced binding and one whose
        target reads as a provider path each grant below an uninvoked name the way a plain binding
        does, although both trip guards a stricter opener test excludes a `Set-Alias` for.
        """
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

    def test_a_call_to_the_bound_name_anywhere_keeps_the_flood(self):
        for source in (
            """
            Set-Alias zzq i*x
            zzq
            $Null = Get-Random
            """,
            """
            Set-Alias zzq i*x
            function f { zzq }
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
        """
        `Set-Alias Get-Frob iex` binds a name a bare `Frob` reaches through 5.1's implicit `Get-`
        retry, so the binding is invoked and must flood; the retry name is why the walk records
        `frob` and `get-frob` both. Granting below it would delete the `Get-Random` discard although
        the aliased `iex` ran first.
        """
        cache, read = self._below(
            """
            Set-Alias Get-Frob iex
            Frob
            $Null = Get-Random
            """
        )
        self.assertFalse(cache.world_reach.may_trust_command_name_at('get-random', read))
        self.assertFalse(cache.world_reach.closed_at(read))

    def test_a_call_below_the_read_keeps_the_flood_as_well(self):
        cache, call = self._below(
            """
            Set-Alias zzq i*x
            $Null = Get-Random
            zzq
            """
        )
        read = cache.root.body[1]
        self.assertFalse(cache.world_reach.may_trust_command_name_at('get-random', read))
        self.assertFalse(cache.world_reach.closed_at(read))

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
