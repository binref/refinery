from __future__ import annotations

import unittest

from inspect import cleandoc
from typing import Callable

from test import TestBase, lines_executed
from test.lib.scripts.ps1.deobfuscation import TestPs1

from refinery.lib.scripts import BodyEdit, Script, bump_mutation_epoch, set_body
from refinery.lib.scripts.analysis import cfg, components
from refinery.lib.scripts.analysis.cfg import (
    CfgBuilder,
    CfgNode,
    ControlFlowGraph,
    Projection,
)
from refinery.lib.scripts.ps1 import ast
from refinery.lib.scripts.ps1.analysis import dispatch, effects, faults, worldflow
from refinery.lib.scripts.ps1.analysis import cfg as ps1_cfg
from refinery.lib.scripts.ps1.analysis.cache import Ps1ModelCache
from refinery.lib.scripts.ps1.analysis.cfg import build_control_flow_model
from refinery.lib.scripts.ps1.analysis.dispatch import Ps1ErrorKind
from refinery.lib.scripts.ps1.analysis.effects import Ps1HandlerVerdicts, deletion_is_observable
from refinery.lib.scripts.ps1.analysis.faults import (
    Ps1ErrorPaths,
    Ps1FaultReach,
    build_fault_reach,
)
from refinery.lib.scripts.ps1.analysis.handlers import handler_acts
from refinery.lib.scripts.ps1.analysis.world import measure_world
from refinery.lib.scripts.ps1.analysis.worldflow import Ps1WorldReach, build_world_reach
from refinery.lib.scripts.ps1.model import (
    Ps1CatchClause,
    Ps1CommandInvocation,
    Ps1ExpressionStatement,
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
        cleandoc("""
            try {
              try { Get-Item a } catch [System.IO.IOException] { }
              'tail'
            } catch [System.IO.IOException] { }
            'after'
        """),
    ]

    def _graphs(self):
        for source in self._SCRIPTS:
            tree = Ps1Parser(source).parse()
            model = build_control_flow_model(tree, descend=True)
            for graph in model.graphs.values():
                yield source, Ps1ErrorPaths(graph, model.trap_sets_in(graph))

    def test_the_route_of_every_node_is_what_its_error_edges_reach(self):
        for source, paths in self._graphs():
            graph = paths.graph
            for index, start in enumerate(graph.nodes):
                reached = _closure(graph, start, forward=True)
                handlers = [
                    node.element for node in reached
                    if isinstance(node.element, (Ps1CatchClause, Ps1TrapStatement))
                ]
                route = paths.route_from(start)
                with self.subTest(source=source, node=index):
                    self.assertEqual(route.acts, any(handler_acts(handler) for handler in handlers))
                    self.assertEqual(
                        route.passes_a_trap, any(isinstance(handler, Ps1TrapStatement) for handler in handlers))
                    self.assertEqual(route.offers_a_handler, bool(handlers))
                    self.assertEqual(route.leaves_the_body, any(node is graph.exit for node in reached))
                    self.assertEqual(list(paths.handlers_from(start)), handlers)

    def test_what_lies_behind_every_node_is_what_reaches_it_over_error_edges(self):
        for source, paths in self._graphs():
            graph = paths.graph
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
        paths = Ps1ErrorPaths(graph, ())
        for start in graph.nodes:
            reached = _closure(graph, start, forward=True)
            self.assertEqual(paths.route_from(start).leaves_the_body, any(n is graph.exit for n in reached))
            for marked in graph.nodes:
                behind = _closure(graph, start, forward=False)
                self.assertEqual(
                    paths.behind(start, lambda node: node is marked, {}),
                    any(node is marked for node in behind),
                )


def _runs_forward(
    step: frozenset[CfgNode],
    barrier: frozenset[CfgNode],
    within: Callable[[CfgNode], bool],
) -> tuple[set[int], bool]:
    """
    The nodes a run reaches going forward from *step* before *barrier*, and whether it leaves the
    statement *within* holds on the way. A `trap` entry is reached but not walked past, and so is a
    node outside the statement.
    """
    reached: set[int] = set()
    leaves = False
    pending = [node for node in step if node not in barrier]
    while pending:
        node = pending.pop()
        if id(node) in reached:
            continue
        reached.add(id(node))
        if isinstance(node.element, Ps1TrapStatement):
            continue
        if not within(node):
            leaves = True
            continue
        pending.extend(target for target in Projection.FORWARD.successors(node) if target not in barrier)
    return reached, leaves


class TestPs1AStepOverRegionHoldsWhatTheFallThroughRunsBeforeTheTrapResumes(TestBase):
    """
    A raiser skips what runs going forward from its own step-over up to where the trap resumes,
    itself excepted, and everything once that run leaves the statement it was raised in. The region
    of a slot answers that for every raiser resuming there, and each answer is compared with that
    walk for the raiser alone.
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
        cleandoc("""
            foreach ($q in $l) {
              trap { continue }
              if ($x) { $a = [int]$s; if ($y) { break }; $b = 1 }
              if ($x) { $c = [int]$t; try { $d = [int]$u } catch { continue } }
            }
        """),
        cleandoc("""
            function f {
              trap { continue }
              if ($x) { $a = [int]$s; if ($y) { return }; $b = 1 }
            }
        """),
    ]

    def test_a_raiser_skips_exactly_what_its_own_fall_through_runs(self):
        for source in self._SCRIPTS:
            tree = Ps1Parser(source).parse()
            diverging = 0
            model = build_control_flow_model(tree, descend=True)
            for graph in model.graphs.values():
                trap_sets = model.trap_sets_in(graph)
                paths = Ps1ErrorPaths(graph, trap_sets)
                holders = {
                    id(resumes_at): statement
                    for trap_set in trap_sets
                    for statement in trap_set.statements
                    if (resumes_at := trap_set.slots.get(id(statement))) is not None
                }
                for raiser in graph.nodes:
                    divergence = paths.divergence(raiser)
                    if divergence is None:
                        continue
                    diverging += 1
                    region = paths.region(divergence.slot)
                    within = graph.builder_of([holders[id(divergence.slot)]])
                    assert within is not None
                    reached, leaves = _runs_forward(divergence.step, region.resumed, within)
                    skipped = reached - {id(raiser)}
                    members = {id(member) for member in region.members}
                    wrong = [
                        index for index, node in enumerate(graph.nodes)
                        if region.query(lambda other, node=node: other is node).skips(raiser, divergence.step)
                        != (leaves or id(node) in skipped)
                    ]
                    with self.subTest(source=source, raiser=str(raiser.element)):
                        self.assertLessEqual(skipped, members)
                        self.assertEqual(wrong, [])
            with self.subTest(source=source):
                self.assertGreater(diverging, 0)


class TestPs1HandlerVerdictsAnswerOnlyForTheTreeTheyWereBuiltOver(TestBase):

    def test_verdicts_built_over_a_statement_answer_for_the_whole_tree(self):
        tree = Ps1Parser(cleandoc("""
            function f { Write-Host $w }
            trap { continue }
            if ($x) { $null = [int]$s; $w = 1 }
            f
        """)).parse()
        control_flow = build_control_flow_model(tree)
        calls = Ps1ModelCache(tree).call_graph
        reach = build_fault_reach(control_flow, lambda: calls)
        world = build_world_reach(measure_world(tree), lambda: control_flow)
        trap, = _traps(tree)
        for over in (tree, tree.body[2]):
            verdicts = Ps1HandlerVerdicts(reach, lambda: world, over)
            with self.subTest(over=type(over).__name__):
                self.assertTrue(reach.removing_traps_is_observed([trap], verdicts.raises(True), verdicts.skips))

    def test_a_held_verdict_keeps_the_trap_once_the_tree_has_moved(self):
        tree = Ps1Parser("trap { Write-Host 'h'; continue }; $a; 5").parse()
        control_flow = build_control_flow_model(tree)
        calls = Ps1ModelCache(tree).call_graph
        reach = build_fault_reach(control_flow, lambda: calls)
        world = build_world_reach(measure_world(tree), lambda: control_flow)
        verdicts = Ps1HandlerVerdicts(reach, lambda: world, tree)
        trap, = _traps(tree)
        self.assertFalse(reach.removing_traps_is_observed([trap], verdicts.raises(True), verdicts.skips))
        edit = BodyEdit(tree, 'body')
        edit.splice(tree.body[2], [])
        edit.apply()
        self.assertTrue(reach.removing_traps_is_observed([trap], verdicts.raises(True), verdicts.skips))

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
            return cache.faults.removing_traps_is_observed([trap], handlers.raises(True), handlers.skips)

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
        cache = Ps1ModelCache(script)
        reach = cache.faults

        def weigh():
            handlers = cache.handlers
            for trap in traps:
                reach.removing_traps_is_observed([trap], handlers.raises(True), handlers.skips)

        return lines_executed(weigh, faults, effects, components, cfg, ps1_cfg, ast)
    return work


def _batching(source_of: Callable[[int], str]) -> Callable[[int], int]:
    """
    The work of asking which of every `trap` of the script *source_of* writes for a size may go
    together, as one batch of the dead-code pass asks it, counted as `_weighing` counts it.
    """
    def work(size: int) -> int:
        script = Ps1Parser(source_of(size)).parse()
        traps = _traps(script)
        cache = Ps1ModelCache(script)
        reach = cache.faults

        def weigh():
            handlers = cache.handlers
            reach.removable_traps(traps, handlers.raises(True), handlers.skips)

        return lines_executed(weigh, faults, effects, components, cfg, ps1_cfg, ast)
    return work


class TestPs1WeighingEveryTrapCostsLinearWork(TestBase):

    def test_many_resuming_traps_among_junk(self):
        def source(size: int) -> str:
            return '\n'.join(F"trap {{ continue }}; 'junk{index}'; Get-Item x{index}" for index in range(size))

        self.assertWorkGrowsLinearly(_weighing(source), 100)

    def test_many_quiet_blocks_under_one_resuming_trap(self):
        def source(size: int) -> str:
            blocks = [F'if ($x) {{ $v{index} = [int]$s; $w{index} = 1 }}' for index in range(size)]
            return '\n'.join(['trap { continue }', *blocks])

        self.assertWorkGrowsLinearly(_weighing(source), 100)

    def test_many_blocks_that_skip_an_output_under_one_resuming_trap(self):
        def source(size: int) -> str:
            blocks = [F'if ($x) {{ $v{index} = [int]$s; Write-Host {index} }}' for index in range(size)]
            return '\n'.join(['trap { continue }', *blocks])

        self.assertWorkGrowsLinearly(_weighing(source), 100)

    def test_one_large_block_of_raisers_under_one_resuming_trap(self):
        def source(size: int) -> str:
            raisers = [F'$v{index} = [int]$s{index}; $o.M{index}()' for index in range(size)]
            return '\n'.join(['trap { continue }', 'if ($x) {', *raisers, '}'])

        self.assertWorkGrowsLinearly(_weighing(source), 100)

    def test_many_functions_each_with_a_resuming_trap(self):
        def source(size: int) -> str:
            return '\n'.join(
                F'function f{index} {{ trap {{ continue }}; if ($x) {{ $v = [int]$s; $w = 1 }} }}'
                for index in range(size)
            )

        self.assertWorkGrowsLinearly(_weighing(source), 200)

    def test_many_trapped_blocks_inside_one_statement_under_a_resuming_trap(self):
        def source(size: int) -> str:
            blocks = [F'if ($x) {{ trap {{ continue }}; $v{index} = [int]$s; Write-Host {index} }}' for index in range(size)]
            return '\n'.join(['trap { continue }', 'if ($c) {', *blocks, '}'])

        self.assertWorkGrowsLinearly(_weighing(source), 50)

    def test_many_trapped_blocks_inside_one_try_with_an_empty_catch(self):
        def source(size: int) -> str:
            blocks = [F'if ($x) {{ trap {{ continue }}; $v{index} = [int]$s; Write-Host {index} }}' for index in range(size)]
            return '\n'.join(['try {', *blocks, '} catch { }', 'Write-Host done'])

        self.assertWorkGrowsLinearly(_weighing(source), 50)

    def test_many_typed_blocks_declining_to_one_resuming_trap(self):
        def source(size: int) -> str:
            blocks = [
                F'if ($x) {{ trap [System.IO.IOException] {{ continue }}; $v{index} = [int]$s; Write-Host {index} }}'
                for index in range(size)
            ]
            return '\n'.join(['trap { continue }', 'if ($c) {', *blocks, '}'])

        self.assertWorkGrowsLinearly(_weighing(source), 50)

    def test_many_blocks_re_raising_past_a_finally_to_one_resuming_trap(self):
        def source(size: int) -> str:
            blocks = [
                F'try {{ trap {{ break }}; $v{index} = [int]$s; Write-Host {index} }} finally {{ }}'
                for index in range(size)
            ]
            return '\n'.join(['trap { continue }', 'if ($c) {', *blocks, '}'])

        self.assertWorkGrowsLinearly(_weighing(source), 50)

    def test_many_typed_blocks_declining_past_a_finally_to_one_resuming_trap(self):
        def source(size: int) -> str:
            blocks = [
                F'try {{ trap [System.IO.IOException] {{ continue }}; $v{index} = [int]$s; Write-Host {index} }} finally {{ }}'
                for index in range(size)
            ]
            return '\n'.join(['trap { continue }', *blocks])

        self.assertWorkGrowsLinearly(_weighing(source), 50)

    def test_many_regions_skipped_inside_a_try_with_an_empty_catch_and_a_tail(self):
        def source(size: int) -> str:
            blocks = [
                F'if ($c) {{ trap {{ continue }}; if ($d) {{ $v{index} = [int]$s; $w{index} = [int]$t }}; Write-Host {index} }}'
                for index in range(size)
            ]
            tail = [F'Write-Host t{index}' for index in range(size)]
            return '\n'.join([
                'trap { continue }',
                "if ($c) { $q = [int]$s; Write-Host 'x' }",
                'try {',
                *blocks,
                '} catch { }',
                *tail,
            ])

        self.assertWorkGrowsLinearly(_weighing(source), 50)

    def test_many_loops_left_by_a_jump_under_a_resuming_trap(self):
        for jump in ('break', 'continue'):
            with self.subTest(jump):
                def source(size: int) -> str:
                    return '\n'.join(
                        F'foreach ($q{index} in $l) {{ trap {{ continue }}; if ($c) {{ $v{index} = [int]$s; {jump} }}; Write-Host {index} }}'
                        for index in range(size)
                    )

                self.assertWorkGrowsLinearly(_weighing(source), 50)

    def test_many_loops_left_by_a_break_through_a_finally_under_a_resuming_trap(self):
        def source(size: int) -> str:
            return '\n'.join(
                F'foreach ($q{index} in $l) {{ try {{ trap {{ continue }}; if ($c) {{ $v{index} = [int]$s; break }}; Write-Host {index} }} finally {{ }} }}'
                for index in range(size)
            )

        self.assertWorkGrowsLinearly(_weighing(source), 50)

    def test_many_loops_left_by_a_labelled_break_under_a_resuming_trap(self):
        def source(size: int) -> str:
            return '\n'.join(
                F':o{index} foreach ($p{index} in $l) {{ foreach ($q{index} in $m) {{ trap {{ continue }}; if ($c) {{ $v{index} = [int]$s; break o{index} }}; Write-Host {index} }} }}'
                for index in range(size)
            )

        self.assertWorkGrowsLinearly(_weighing(source), 50)

    def test_many_landings_left_by_a_break(self):
        def source(size: int) -> str:
            return '\n'.join(
                F'foreach ($q{index} in $l) {{ try {{ if ($c) {{ trap {{ continue }}; $v{index} = [int]$s }}; break }} catch {{ }} }}'
                for index in range(size)
            )

        self.assertWorkGrowsLinearly(_weighing(source), 50)

    def test_many_typed_catches_handing_on_to_a_catch_and_a_tail(self):
        def source(size: int) -> str:
            blocks = [
                F'try {{ if ($c) {{ trap {{ continue }}; $v{index} = [int]$s }}; Write-Host x{index} }} catch [System.IO.IOException] {{ }}'
                for index in range(size)
            ]
            tail = [F'Write-Host t{index}' for index in range(size)]
            return '\n'.join([
                'trap { continue }',
                "if ($c) { $q = [int]$s; Write-Host 'x' }",
                'try {',
                *blocks,
                "} catch { Write-Host 'c' }",
                *tail,
            ])

        self.assertWorkGrowsLinearly(_weighing(source), 50)

    def test_many_catch_bodies_left_by_a_break_under_a_resuming_trap(self):
        def source(size: int) -> str:
            return '\n'.join(
                F'foreach ($q{index} in $l) {{ trap {{ continue }}; if ($c) {{ $v{index} = [int]$s; try {{ Get-Item x }} catch {{ break }} }}; Write-Host {index} }}'
                for index in range(size)
            )

        self.assertWorkGrowsLinearly(_weighing(source), 50)

    def test_one_block_of_many_typed_traps_asked_as_one_batch(self):
        def source(size: int) -> str:
            traps = [
                'trap [System.IO.IOException] { continue }' if index % 2 else 'trap [System.ArgumentException] { break }'
                for index in range(size)
            ]
            raisers = [F'$v{index} = [int]$s{index}; Write-Host {index}' for index in range(size)]
            return '\n'.join([*traps, 'trap { continue }', *raisers])

        self.assertWorkGrowsLinearly(_batching(source), 100)

    def test_a_trap_beside_a_deep_nest_of_plain_blocks(self):
        def source(size: int) -> str:
            nest = 'if ($c) { $v = 1; ' * size + '}' * size
            return '\n'.join([nest, 'if ($c) { trap { continue }; if ($c) { [int]$s; $q = 1 } }'])

        self.assertWorkGrowsLinearly(_weighing(source), 20)

    def test_nested_resuming_traps_cost_no_more_than_the_square_of_their_depth(self):
        """
        Each level's `if` is read as a soft raiser of the level around it, because its body holds
        one, so every level holds a step-over region over everything inside it, and the regions
        together hold the square of the depth: `test_faults` tracks that over-keep. What this pins
        is the next order up, which a pass over every region member's whole statement reaches.
        """
        def source(size: int) -> str:
            levels = ''.join(
                F'trap {{ continue }}; if ($x) {{ $v{index} = [int]$s{index}; $w{index} = 1; '
                for index in range(size)
            )
            reads = [F'Write-Host $v{index} $w{index}' for index in range(size)]
            return '\n'.join([levels + '}' * size, *reads])

        work = _weighing(source)
        small, middle, large = (work(factor * 10) for factor in (1, 2, 4))
        # the second doubling adds four times the first for a square and eight times for a cube
        self.assertLess(large - middle, 5 * (middle - small))

    def test_asking_where_the_error_goes_under_a_deep_nest_of_empty_catches(self):
        def work(size: int) -> int:
            nest = 'try { ' * size + 'Get-Item x' + ' } catch [System.IO.IOException] { }' * size
            script = Ps1Parser(nest).parse()
            statement = next(node for node in script.walk() if isinstance(node, Ps1CommandInvocation)).parent
            assert statement is not None
            control_flow = build_control_flow_model(script)
            calls = Ps1ModelCache(script).call_graph

            def ask():
                reach = build_fault_reach(control_flow, lambda: calls)
                reach.observed_at(statement, reach.kinds_a_point_may_raise(statement))
                reach.lands_past_a_live_tail(statement, Ps1ErrorKind.STATEMENT)

            return lines_executed(ask, faults, dispatch, components)

        self.assertWorkGrowsLinearly(work, 20)

    def test_asking_where_the_error_of_every_statement_goes_under_many_traps(self):
        def work(size: int) -> int:
            script = Ps1Parser('\n'.join(
                F"trap {{ 'h{index}' }}; try {{ Get-Item a{index} }} catch {{ }}" for index in range(size)
            )).parse()
            statements = list(script.walk())

            calls = Ps1ModelCache(script).call_graph

            def ask():
                reach = build_fault_reach(build_control_flow_model(script), lambda: calls)
                for statement in statements:
                    reach.observed_at(statement, reach.kinds_a_point_may_raise(statement))
                    reach.lands_past_a_live_tail(statement, Ps1ErrorKind.STATEMENT)

            return lines_executed(ask, faults, dispatch, components)

        self.assertWorkGrowsLinearly(work, 100)

    def test_asking_whether_a_long_catch_body_may_stand_in_place_of_its_try(self):
        def work(size: int) -> int:
            blocks = '; '.join(
                F'if ($x) {{ if ($y) {{ $null = [int]$s{index}; $v{index} = 1 }} }}' for index in range(size))
            script = Ps1Parser(F'try {{ throw "x" }} catch {{ {blocks} }}').parse()
            cache = Ps1ModelCache(script)
            clause = next(node for node in script.walk() if isinstance(node, Ps1CatchClause))
            cache.world_reach

            def ask():
                cache.handlers.lifts_unchanged(clause)

            return lines_executed(ask, faults, dispatch, effects, components)

        self.assertWorkGrowsLinearly(work, 50)

    def test_asking_whether_every_catch_body_of_a_nest_may_stand_in_place_of_its_try(self):
        def work(size: int) -> int:
            nest = ''.join(F'try {{ throw "x{index}" }} catch {{ Write-Host "h{index}"; ' for index in range(size))
            script = Ps1Parser(nest + '$null = [int]$s' + ' }' * size).parse()
            cache = Ps1ModelCache(script)
            clauses = [node for node in script.walk() if isinstance(node, Ps1CatchClause)]
            cache.world_reach

            def ask():
                for clause in clauses:
                    cache.handlers.lifts_unchanged(clause)

            return lines_executed(ask, faults, dispatch, effects, components)

        self.assertWorkGrowsLinearly(work, 20)

    def test_asking_of_every_statement_of_a_nest_whether_a_jump_passes_through_a_finally(self):
        def work(size: int) -> int:
            nest = ''.join(F'try {{ if ($c{index}) {{ return }}; ' for index in range(size))
            script = Ps1Parser(nest + '$v = 1' + ' } finally { $null = [int]$s }' * size).parse()
            cache = Ps1ModelCache(script)
            statements = [node for node in script.walk() if isinstance(node, Ps1ExpressionStatement)]
            cache.world_reach
            cache.error_state
            raises = cache.handlers.raises(True)

            def ask():
                for statement in statements:
                    deletion_is_observable(statement, cache.faults, cache.world_reach, cache.error_state, raises)

            return lines_executed(ask, faults, dispatch, effects, components)

        self.assertWorkGrowsLinearly(work, 20)

    def test_asking_what_every_point_of_a_nest_of_subexpressions_raises(self):
        def work(size: int) -> int:
            script = Ps1Parser('$null = $( ' * size + 'f' + ' )' * size).parse()
            statement = script.body[0]
            control_flow = build_control_flow_model(script)
            calls = Ps1ModelCache(script).call_graph
            points = list(build_fault_reach(control_flow, lambda: calls).points_in(statement))

            def ask():
                reach = build_fault_reach(control_flow, lambda: calls)
                for point in points:
                    effects.point_raise_kinds(point, statement, reach, None)

            return lines_executed(ask, faults)

        self.assertWorkGrowsLinearly(work, 5)


class TestPs1TheWorldIsBuiltOnlyForAVerdictThatReadsIt(TestBase):

    def test_weighing_a_trap_over_nothing_that_may_raise_builds_no_world(self):
        script = Ps1Parser(cleandoc("""
            function f { 'in' }
            trap { continue }
            'a'
        """)).parse()
        cache = Ps1ModelCache(script)
        reach = cache.faults
        trap, = _traps(script)

        def weigh():
            handlers = cache.handlers
            self.assertFalse(reach.removing_traps_is_observed([trap], handlers.raises(False), handlers.skips))

        self.assertEqual(lines_executed(weigh, worldflow), 0)

    def test_weighing_a_trap_under_the_world_builds_one(self):
        script = Ps1Parser(cleandoc("""
            trap { continue }
            Get-Item nope
        """)).parse()
        cache = Ps1ModelCache(script)
        reach = cache.faults
        trap, = _traps(script)

        def weigh():
            handlers = cache.handlers
            reach.removing_traps_is_observed([trap], handlers.raises(True), handlers.skips)

        self.assertGreater(lines_executed(weigh, worldflow), 0)


class TestPs1AHeldFaultModelAnswersAlikeWhateverWasAskedBeforeAnEdit(TestBase):

    @unittest.expectedFailure
    def test_a_handler_emptied_after_one_question_reads_as_it_does_without_that_question(self):
        """
        Whether a handler acts is settled for a whole graph at the first question about it, so a
        model held across an edit to a handler body answers by what was asked before the edit.
        """
        answers = []
        for asked_first in (False, True):
            tree = Ps1Parser(cleandoc("""
                trap { function b { 'y' } }
                $q = 1
                Get-Item nope
                'tail'
            """)).parse()
            calls = Ps1ModelCache(tree).call_graph
            reach = build_fault_reach(build_control_flow_model(tree), lambda: calls)
            if asked_first:
                reach.observed_at(tree.body[1], reach.kinds_a_point_may_raise(tree.body[1]))
            trap = tree.body[0]
            assert isinstance(trap, Ps1TrapStatement) and trap.body is not None
            set_body(trap.body, [])
            answers.append(reach.observed_at(tree.body[2], reach.kinds_a_point_may_raise(tree.body[2])))
        self.assertEqual(answers[0], answers[1])


class TestPs1NoModelOutlivesADeobfuscation(TestPs1):

    def test_a_full_collection_after_a_run_leaves_no_model_alive(self):
        kinds = (Ps1FaultReach, Ps1HandlerVerdicts, Ps1WorldReach, ControlFlowGraph)
        with self.assertNoInstanceSurvives(kinds, collect=True):
            self._deobfuscate(cleandoc("""
                function f { trap { continue }; $v = [int]$s; Write-Host $v }
                trap { continue }
                if ($x) { $null = [int]$t; $a = 1 }
                f
                Write-Host $a
            """))


class TestPs1EveryLandingHoldsItsRaise(TestBase):
    """
    How far out a route carries control is kept as the depth of the outermost statement it lands
    after, which says how far out only if every statement an error lands after holds the point it
    was raised at. Asked of every point of every script the corpus writes.
    """

    def test_every_statement_an_error_lands_after_holds_the_point_it_was_raised_at(self):
        from test.lib.scripts.ps1 import corpus
        checked = 0
        for source in corpus.oracle_corpus():
            tree = Ps1Parser(source).parse()
            reach = Ps1ModelCache(tree).faults
            for node in tree.walk():
                located = reach._control_flow.locate(node)
                if located is None or located[1].element is not node:
                    continue
                graph, start = located
                for catch in reach.paths_of(graph).route_from(start).empty_catches:
                    holder = catch.statement
                    assert holder is not None
                    checked += 1
                    cursor = node
                    while cursor is not None and cursor is not holder:
                        cursor = cursor.parent
                    with self.subTest(source=source):
                        self.assertIs(cursor, holder)
        self.assertGreater(checked, 200)
