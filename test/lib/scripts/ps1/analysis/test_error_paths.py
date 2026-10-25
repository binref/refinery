from __future__ import annotations

import gc

from inspect import cleandoc
from typing import Callable

from test import TestBase, lines_executed
from test.lib.scripts.ps1.deobfuscation import TestPs1

from refinery.lib.scripts import BodyEdit, Script, bump_mutation_epoch
from refinery.lib.scripts.analysis import cfg, components
from refinery.lib.scripts.analysis.cfg import CfgBuilder, CfgNode, ControlFlowGraph, normal_reach
from refinery.lib.scripts.ps1.analysis import effects, faults
from refinery.lib.scripts.ps1.analysis.cache import Ps1ModelCache
from refinery.lib.scripts.ps1.analysis.cfg import build_control_flow_model
from refinery.lib.scripts.ps1.analysis.effects import Ps1HandlerVerdicts
from refinery.lib.scripts.ps1.analysis.faults import (
    Ps1ErrorPaths,
    Ps1FaultReach,
    build_fault_reach,
    handler_acts,
)
from refinery.lib.scripts.ps1.analysis.world import measure_world
from refinery.lib.scripts.ps1.analysis.worldflow import Ps1WorldReach, build_world_reach
from refinery.lib.scripts.ps1.model import (
    Ps1CatchClause,
    Ps1FunctionDefinition,
    Ps1Script,
    Ps1TrapStatement,
    Ps1Variable,
)
from refinery.lib.scripts.ps1.parser import Ps1Parser


def _closure(graph: ControlFlowGraph, start: CfgNode, *, forward: bool) -> list[CfgNode]:
    """
    The nodes the error-carrying edges lead to from *start*, or from which they lead to it, in the
    order a depth-first walk first meets them, *start* itself left out.
    """
    seen = {id(start)}
    found: list[CfgNode] = []
    stack = [start]
    while stack:
        current = stack.pop()
        for node in (current.successors if forward else current.predecessors):
            edge = (current, node) if forward else (node, current)
            if id(node) in seen or not graph.is_exceptional(*edge):
                continue
            seen.add(id(node))
            found.append(node)
            stack.append(node)
    return found


def _traps(script: Ps1Script) -> list[Ps1TrapStatement]:
    return [node for node in script.walk() if isinstance(node, Ps1TrapStatement)]


class TestPs1ErrorPathsAgreeWithAWalkOverTheErrorEdges(TestBase):
    """
    Every answer the condensed error edges give is compared with a walk over the error edges from
    the node asked about, which knows nothing of components.
    """

    _SCRIPTS = [
        cleandoc("""
            try {
              Get-Item a
              try { [int]$s } catch [System.IO.IOException] { }
            } catch { 'c' } finally { 'f' }
        """),
        cleandoc("""
            trap { continue }
            Get-Item a
            if ($x) {
              trap [System.Exception] { break }
              [int]$s
            }
            'z'
        """),
        cleandoc("""
            function f {
              trap { 'h' }
              try { Get-Item b } catch { }
            }
            f
        """),
        cleandoc("""
            while ($x) {
              try { Get-Item c } catch { continue }
              try { Get-Item d } catch [System.IO.IOException] { } catch { }
            }
        """),
        "$y = $(trap { continue }; [int]$s; 'in')",
    ]

    def _graphs(self):
        for source in self._SCRIPTS:
            tree = Ps1Parser(source).parse()
            for graph in build_control_flow_model(tree, descend=True).graphs.values():
                yield source, graph

    def test_the_route_of_every_node_is_what_its_error_edges_reach(self):
        for source, graph in self._graphs():
            paths = Ps1ErrorPaths(graph)
            for index, start in enumerate(graph.nodes):
                reached = _closure(graph, start, forward=True)
                handlers = [
                    node.element for node in reached
                    if isinstance(node.element, (Ps1CatchClause, Ps1TrapStatement))
                ]
                empty = [
                    handler for handler in handlers
                    if isinstance(handler, Ps1CatchClause) and (handler.body is None or not handler.body.body)
                ]
                route = paths.route_from(start)
                with self.subTest(source=source, node=index):
                    self.assertEqual(route.acts, any(handler_acts(handler) for handler in handlers))
                    self.assertEqual(
                        route.passes_a_trap, any(isinstance(handler, Ps1TrapStatement) for handler in handlers))
                    self.assertEqual(route.offers_a_handler, bool(handlers))
                    self.assertEqual(route.leaves_the_body, any(node is graph.exit for node in reached))
                    self.assertEqual([id(c) for c in route.empty_catches], [id(c) for c in empty])
                    self.assertEqual(list(paths.handlers_from(start)), handlers)

    def test_what_lies_behind_every_node_is_what_reaches_it_over_error_edges(self):
        for source, graph in self._graphs():
            paths = Ps1ErrorPaths(graph)
            for marked in graph.nodes:
                memo: dict[int, bool] = {}
                wrong = [
                    index for index, start in enumerate(graph.nodes)
                    if paths.behind(start, lambda node: node is marked, memo)
                    != any(node is marked for node in _closure(graph, start, forward=False))
                ]
                with self.subTest(source=source):
                    self.assertEqual(wrong, [])

    def test_a_cycle_and_a_second_error_successor_are_walked_like_any_other_edge(self):
        builder = CfgBuilder(Script())
        a, b, c, d = (builder.synthetic_node() for _ in range(4))
        graph = builder.cfg
        builder.exceptional_edge(a, b)
        builder.exceptional_edge(b, c)
        builder.exceptional_edge(c, b)
        builder.exceptional_edge(a, d)
        builder.exceptional_edge(c, graph.exit)
        builder.add_edge(d, a)
        paths = Ps1ErrorPaths(graph)
        for start in graph.nodes:
            reached = _closure(graph, start, forward=True)
            self.assertEqual(paths.route_from(start).leaves_the_body, any(n is graph.exit for n in reached))
            for marked in graph.nodes:
                behind = _closure(graph, start, forward=False)
                self.assertEqual(
                    paths.behind(start, lambda node: node is marked, {}),
                    any(node is marked for node in behind),
                )


class TestPs1AStepOverRegionHoldsWhatTheFallThroughRunsBeforeTheTrapResumes(TestBase):
    """
    A raiser skips what runs over plain edges from its own step-over up to where the trap resumes,
    itself excepted. The region of a slot answers that for every raiser resuming there, and each
    answer is compared with that walk for the raiser alone.
    """

    _SCRIPTS = [
        cleandoc("""
            trap { continue }
            if ($x) {
              $a = [int]$s
              $b = 1
              if ($y) { $c = [int]$t; 'out' } else { $d = 2 }
            }
        """),
        cleandoc("""
            trap { continue }
            while ($x) { $e = [int]$u; $f = 3 }
            do { $g = [int]$v; $h = 4 } while ($x)
        """),
        "trap { continue }; $z = $([int]$w; 'k'; [int]$q; 'm')",
    ]

    def test_a_raiser_skips_exactly_what_its_own_fall_through_runs(self):
        for source in self._SCRIPTS:
            tree = Ps1Parser(source).parse()
            diverging = 0
            for graph in build_control_flow_model(tree, descend=True).graphs.values():
                paths = Ps1ErrorPaths(graph)
                for raiser in graph.nodes:
                    divergence = paths.divergence(raiser)
                    if divergence is None:
                        continue
                    diverging += 1
                    region = paths.region(divergence.slot)
                    skipped = normal_reach(divergence.step, barrier=region.resumption.resumed) - {id(raiser)}
                    members = {id(member) for member in region.members}
                    wrong = [
                        index for index, node in enumerate(graph.nodes)
                        if region.query(lambda other, node=node: other is node).skips(raiser, divergence.step)
                        != (id(node) in skipped)
                    ]
                    with self.subTest(source=source, raiser=str(raiser.element)):
                        self.assertLessEqual(skipped, members)
                        self.assertEqual(wrong, [])
            with self.subTest(source=source):
                self.assertGreater(diverging, 0)


class TestPs1HandlerVerdictsAnswerOnlyForTheTreeTheyWereBuiltOver(TestBase):

    def test_a_held_verdict_keeps_the_trap_once_the_tree_has_moved(self):
        tree = Ps1Parser("trap { Write-Host 'h'; continue }; $a; 5").parse()
        control_flow = build_control_flow_model(tree)
        reach = build_fault_reach(control_flow)
        verdicts = Ps1HandlerVerdicts(reach, build_world_reach(measure_world(tree), lambda: control_flow), tree)
        trap = tree.body[0]
        self.assertFalse(reach.removing_a_handler_is_observed(trap, verdicts.raises(True), verdicts.skips))
        edit = BodyEdit(tree, 'body')
        edit.splice(tree.body[2], [])
        edit.apply()
        self.assertTrue(reach.removing_a_handler_is_observed(trap, verdicts.raises(True), verdicts.skips))

    def test_what_a_function_reads_follows_an_edit_announced_by_the_epoch(self):
        source = cleandoc("""
            function f { Write-Host $b }
            trap { continue }
            if ($env:X) { $null = [int]$env:S; $a = 1 }
            f
        """)

        def kept(tree: Ps1Script, cache: Ps1ModelCache) -> bool:
            trap, = _traps(tree)
            handlers = cache.handlers
            return cache.faults.removing_a_handler_is_observed(trap, handlers.raises(True), handlers.skips)

        tree = Ps1Parser(source).parse()
        cache = Ps1ModelCache(tree)
        self.assertFalse(kept(tree, cache))
        function = next(node for node in tree.walk() if isinstance(node, Ps1FunctionDefinition))
        read = next(node for node in function.walk() if isinstance(node, Ps1Variable) and node.name == 'b')
        read.name = 'a'
        bump_mutation_epoch()
        cache.invalidate()
        self.assertTrue(kept(tree, cache))
        fresh = Ps1Parser(source.replace('$b', '$a')).parse()
        self.assertTrue(kept(fresh, Ps1ModelCache(fresh)))


def _weighing(source_of: Callable[[int], str]) -> Callable[[int], int]:
    """
    The work of weighing the removal of every `trap` of the script *source_of* writes for a size,
    the way the dead-code pass weighs it, counted in lines of the modules that answer.
    """
    def work(size: int) -> int:
        script = Ps1Parser(source_of(size)).parse()
        traps = _traps(script)

        def weigh():
            cache = Ps1ModelCache(script)
            handlers = cache.handlers
            for trap in traps:
                cache.faults.removing_a_handler_is_observed(trap, handlers.raises(True), handlers.skips)

        return lines_executed(weigh, faults, effects, components, cfg)
    return work


class TestPs1WeighingEveryTrapCostsLinearWork(TestBase):

    def test_many_resuming_traps_among_junk(self):
        self.assertWorkGrowsLinearly(_weighing(lambda size: '\n'.join(
            F"trap {{ continue }}\n'junk{index}'\nGet-Item x{index}" for index in range(size))), 100)

    def test_many_quiet_blocks_under_one_resuming_trap(self):
        self.assertWorkGrowsLinearly(_weighing(lambda size: 'trap { continue }\n' + '\n'.join(
            F'if ($x) {{ $v{index} = [int]$s; $w{index} = 1 }}' for index in range(size))), 100)

    def test_many_blocks_that_skip_an_output_under_one_resuming_trap(self):
        self.assertWorkGrowsLinearly(_weighing(lambda size: 'trap { continue }\n' + '\n'.join(
            F'if ($x) {{ $v{index} = [int]$s; Write-Host {index} }}' for index in range(size))), 100)

    def test_one_large_block_of_raisers_under_one_resuming_trap(self):
        self.assertWorkGrowsLinearly(_weighing(lambda size: 'trap { continue }\nif ($x) {\n' + '\n'.join(
            F'$v{index} = [int]$s{index}; $o.M{index}()' for index in range(size)) + '\n}'), 100)

    def test_many_functions_each_with_a_resuming_trap(self):
        self.assertWorkGrowsLinearly(_weighing(lambda size: '\n'.join(
            F'function f{index} {{ trap {{ continue }}; if ($x) {{ $v = [int]$s; $w = 1 }} }}'
            for index in range(size))), 100)

    def test_asking_where_the_error_of_every_statement_goes_under_many_traps(self):
        def work(size: int) -> int:
            script = Ps1Parser('\n'.join(
                F"trap {{ 'h{index}' }}\ntry {{ Get-Item a{index} }} catch {{ }}" for index in range(size))).parse()
            statements = list(script.walk())

            def ask():
                reach = build_fault_reach(build_control_flow_model(script))
                for statement in statements:
                    reach.observed_at(statement)
                    reach.an_empty_catch_skips_a_live_tail(statement)

            return lines_executed(ask, faults, components)

        self.assertWorkGrowsLinearly(work, 100)


class TestPs1NoModelOutlivesADeobfuscation(TestPs1):

    def test_a_full_collection_after_a_run_leaves_no_model_alive(self):
        kinds = (Ps1FaultReach, Ps1HandlerVerdicts, Ps1WorldReach, ControlFlowGraph)
        gc.collect()
        known = {id(item) for item in gc.get_objects() if isinstance(item, kinds)}
        self._deobfuscate(cleandoc("""
            function f { trap { continue }; $v = [int]$s; Write-Host $v }
            trap { continue }
            if ($x) { $null = [int]$t; $a = 1 }
            f
            Write-Host $a
        """))
        gc.collect()
        survivors = [
            type(item).__name__ for item in gc.get_objects()
            if isinstance(item, kinds) and id(item) not in known
        ]
        self.assertEqual(survivors, [])
