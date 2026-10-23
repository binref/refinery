from __future__ import annotations

import inspect
import unittest

from test import TestBase

from test.lib.scripts.js.analysis.differential import (
    behavior,
    deobfuscate_source,
    node_executable,
)
from test.lib.scripts.js.analysis.jsgen import (
    _Generator,
    _Scope,
    generate,
)

#: The seeds whose programs the sweep deobfuscates, once it has seen each of them run cleanly.
_SWEPT_SEEDS = range(176)

#: The seeds beyond the sweep whose programs must run cleanly too.
_UNSWEPT_SEEDS = range(_SWEPT_SEEDS.stop, 256)


class TestFuzzGenerator(TestBase):
    """
    Self-validation for the seeded program generator that feeds the differential fuzzer. A
    divergence between a program and its deobfuscation is only trustworthy as a deobfuscator bug
    when the program is itself sound, so these tests pin the generator's invariants rather than any
    deobfuscation behavior. Generation being a pure function of the seed needs no Node.js and is
    checked here; the runtime invariants that require an engine live in the Node-gated class below.
    """

    def test_generation_is_deterministic(self):
        for seed in range(256):
            self.assertEqual(generate(seed), generate(seed))

    def test_mutate_call_passes_only_a_compatible_container(self):
        """
        A mutator runs array-only methods on its parameter, so `_stmt_mutate_call` must hand it an
        array-kind container. With an array and an object both in scope and one array-mutator, every
        emitted call passes the array across many RNG states; a kind-blind draw would eventually pass
        the object and throw in Node.
        """
        for seed in range(256):
            scope = _Scope()
            scope.objects.append(('arr', 'array'))
            scope.objects.append(('obj', 'object'))
            scope.mutators.append(('mut', 'array'))
            self.assertEqual(
                _Generator(seed)._stmt_mutate_call(scope, 0),
                ['mut(arr);', 'SINK.push(arr[0]);'],
            )

    def test_mutator_without_a_compatible_container_is_not_callable(self):
        """
        An array-mutator is a candidate only when an array is in scope. With only an object-kind
        container present no candidate exists, so the dispatcher never offers a `mutate_call` and can
        never feed the mutator a non-array.
        """
        scope = _Scope()
        scope.objects.append(('obj', 'object'))
        scope.mutators.append(('mut', 'array'))
        self.assertEqual(scope.mutator_candidates(), [])
        scope.objects.append(('arr', 'array'))
        self.assertEqual(scope.mutator_candidates(), [('mut', 'array')])

    def test_objfunc_registers_its_mutator_requiring_an_array(self):
        """
        The only mutator producer treats its parameter as an array, so it must register the argument
        kind it requires as `array`; dropping that kind is what let a caller pass an object.
        """
        scope = _Scope()
        _Generator(0)._stmt_objfunc(scope, 0)
        self.assertEqual(len(scope.mutators), 1)
        self.assertEqual(scope.mutators[0][1], 'array')


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestFuzzGeneratorRunsInNode(TestBase):
    """
    A generated program is a sound oracle input only if Node.js runs it without an uncaught
    exception, so a future divergence cannot be a spurious `SyntaxError` or `ReferenceError`, and
    only if it is deterministic, so comparing an original against its deobfuscation is meaningful. A
    failure here is a generator regression to fix before the fuzzer can be trusted, never a
    deobfuscator bug. The sweep runs every program it deobfuscates and asserts that it ran cleanly,
    each seed on its own whatever became of the others, so the programs of the swept seeds are not
    run here again.
    """

    def test_generated_programs_beyond_the_sweep_run_cleanly(self):
        for seed in _UNSWEPT_SEEDS:
            source = generate(seed)
            self.assertIsNone(
                behavior(source)[1],
                F'seed {seed} did not run cleanly in node:\n{source}',
            )

    def test_generated_programs_are_deterministic_in_node(self):
        for seed in range(64):
            source = generate(seed)
            first = behavior(source)
            self.assertIsNone(
                first[1],
                F'seed {seed} did not run cleanly in node:\n{source}',
            )
            self.assertEqual(
                first,
                behavior(source),
                F'seed {seed} is not deterministic in node:\n{source}',
            )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestDeobfuscationFuzzSweep(TestBase):
    """
    The differential sweep itself: over a fixed seed range, a generated program and its deobfuscation
    must behave identically in Node.js, and deobfuscation must not raise. Node is the oracle — no
    expected output is asserted. This is the permanent regression gate that keeps the three fixed
    semantics-preservation P0s closed (an effectful `if` test, negative zero, and an effectful call
    dropped with a dead store). Generator soundness is the precondition: a program that does not run
    cleanly is a generator regression, reported as such before its deobfuscation is compared, and
    any other failure here is a deobfuscator bug, not a spurious input.
    """

    def test_deobfuscation_preserves_behavior_across_seeds(self):
        for seed in _SWEPT_SEEDS:
            source = generate(seed)
            with self.subTest(seed=seed):
                original = behavior(source)
                self.assertIsNone(
                    original[1],
                    F'seed {seed} did not run cleanly in node:\n{source}',
                )
                deobfuscated = deobfuscate_source(source)
                self.assertEqual(
                    original,
                    behavior(deobfuscated),
                    F'seed {seed}: deobfuscation changed observable behavior\n'
                    F'--- source ---\n{source}\n--- deobfuscated ---\n{deobfuscated}',
                )


_PROGRAMS_THAT_ONCE_DIVERGED: dict[int, str] = {
    6805: inspect.cleandoc(
        """
        var SINK = [];
        var v0 = (2 instanceof Object);
        var v1 = [];
        for ([v0, ...v1] of [['mn', true, 1]]) {
          SINK.push(v1[1]);
          SINK.push(v0);
          var v2 = [];
          for ([...v2] of [[v1[0], false], [12, true]]) {
            SINK.push(v2[2]);
            var v3 = (delete v0);
          }
        }
        try {
          ((true, true), v1[2]);
          var v4 = 0;
          do {
            console.log((typeof (v0 * v1[0])));
            console.log((function (v5) { return function (v5) { return (-v0); }; })((v1[0] % v1[1]))(v1.filter(function (c) { return c !== undefined; }).length));
            v4++;
          } while (v4 < 2);
          function v6(v7) {
            v7[0] = ('p2' in v7);
            return v7[2];
          }
          throw v1[2];
          SINK.push(v0);
        } catch (e) {
          var v8 = 'kl';
          function v9() {
            SINK.push(v8);
            v8 = (v8 = 0);
            SINK.push(v8);
          }
          v9();
        } finally {
          var v10 = (v11) => ((false instanceof Array) === `gh${v11}`);
          SINK.push(v10(12));
        }
        var v12 = [];
        for ([...v12] of [['gh'], [false, 3]]) {
          SINK.push(v12[0]);
          const v13 = Math.floor((v0 = true));
          var v14 = 0;
          while (v14 < 4) {
            var v15 = (v16) => ((typeof false) ? (!false) : (--v16));
            SINK.push(v15(v14));
            v14++;
          }
          var v17 = (v18) => v18;
          SINK.push(v17(v13));
        }
        var v19 = 'ij';
        function v20() { return v19; }
        SINK.push(v20());
        v19 = v1[0];
        SINK.push(v20());
        v19 = v0;
        SINK.push(v20());
        v19 = v1[0];
        SINK.push(v20());
        v1[1] = v12;
        var v21 = (v22) => `ij${(v22 = false)}`;
        SINK.push(v21('ef'));
        delete v1[2];
        [v0 = ('p2' in v1)] = [];
        var v23 = v1;
        console.log(SINK.join('|'));
        """
    ),
    17550: inspect.cleandoc(
        """
        var SINK = [];
        (`cd${'ab'}` instanceof Object);
        var v0 = true;
        var v1 = [];
        for ([v0, ...v1] of [[false, 12, true]]) {
          SINK.push(v1[1]);
          SINK.push(v0);
          try {
            var v2 = [(typeof v0), (-v0), ('p2' in v1)];
          } catch (e) {
            SINK.push([false].filter((v3) => v3).length);
          }
          `ef${(5 ? v1[2] : v1[0])}`;
          (0, eval)("g0 = 12;");
          SINK.push(globalThis.g0);
        }
        ({v0 = (function (v4) { return function (v4) { return v1[2]; }; })('kl')(11)} = {});
        var v5 = (v6) => 'gh';
        SINK.push(v5('ij'));
        v1[0] = Math.floor((v0 = 10));
        var v7 = 0;
        while (v7 < 1) {
          var v8 = v1[0];
          function v9() { return v8; }
          SINK.push(v9());
          v8 = 8;
          SINK.push(v9());
          v8 = v0;
          SINK.push(v9());
          var v10 = v7;
          function v11() {
            SINK.push(v10);
            v10 = (typeof 11);
            SINK.push(v10);
          }
          v11();
          if (v1[0]) {
            var v12 = (v1?.[0] instanceof Array);
          }
          v7++;
        }
        console.log(SINK.join('|'));
        """
    ),
    19221: inspect.cleandoc(
        """
        var SINK = [];
        var v0 = 0;
        var {v0 = Number(v0)} = {};
        var v1 = 0;
        while (v1 < 2) {
          [v0 = `ab${12}`] = [];
          var v2;
          function v3() { return v2; }
          SINK.push(v3());
          v2 = true;
          SINK.push(v3());
          v1++;
        }
        (typeof `gh${6}`);
        var v4 = {
          p0: 6,
          p1: 'kl',
          f: function() { return v4.p0; },
        };
        SINK.push(v4.f());
        SINK.push(Math.floor((v0 = 4)));
        var v5 = (-true);
        var v6 = [];
        for ([v5, ...v6] of [['kl'], [v0, true], [false, 'op', 'gh']]) {
          SINK.push(v6[2]);
          SINK.push(v5);
          var v7 = 0;
          while (v7 < 2) {
            (0, eval)("g0 = 5;");
            SINK.push(globalThis.g0);
            v7++;
          }
          var v8 = 0;
          while (v8 < 0) {
            ({v5 = ('ij' instanceof Array)} = {});
            v0 ||= ('p1' in v6);
            SINK.push(('p0' in v6));
            v8++;
          }
        }
        console.log(SINK.join('|'));
        """
    ),
}
"""
The text three seeds beyond the swept range generated, frozen the day the last of the three stopped
diverging. The seed is recorded as the provenance of the text and nothing generates with it.
"""


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestTheProgramsWhoseDivergenceWasFixed(TestBase):
    """
    Programs the tool once deobfuscated into something Node said printed different things. None of
    them does any longer, and each is kept here because the sweep does not reach the seed that
    produced it: nothing else in this file would notice the day one of them diverges again.

    The text of each program is frozen rather than generated. The generator is expected to change,
    and a change to it repoints a seed at a different program, which would leave a regression named
    after a divergence exercising a program that never had one — a substitution no assertion here
    could fail on.

    Node is the oracle for these exactly as it is for the sweep, so no expected output is written
    down. Whether a divergence is a deobfuscator bug at all rests on the program being a sound
    oracle input, which is a claim about the generator rather than about the tool, so it is asserted
    on its own.
    """

    def test_each_program_is_a_sound_oracle_input(self):
        for seed, source in _PROGRAMS_THAT_ONCE_DIVERGED.items():
            first = behavior(source)
            with self.subTest(seed=seed):
                self.assertIsNone(
                    first[1],
                    F'the program from seed {seed} did not run cleanly in node:\n{source}',
                )
                self.assertEqual(
                    first,
                    behavior(source),
                    F'the program from seed {seed} is not deterministic in node:\n{source}',
                )

    def test_each_program_prints_what_its_deobfuscation_prints(self):
        for seed, source in _PROGRAMS_THAT_ONCE_DIVERGED.items():
            deobfuscated = deobfuscate_source(source)
            with self.subTest(seed=seed):
                self.assertEqual(
                    behavior(source),
                    behavior(deobfuscated),
                    F'the program from seed {seed}: deobfuscation changed observable behavior'
                    F'\n--- source ---\n{source}\n--- deobfuscated ---\n{deobfuscated}',
                )
