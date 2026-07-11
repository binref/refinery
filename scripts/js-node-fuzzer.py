#!/usr/bin/env python3
"""
Command-line differential fuzzer for the Binary Refinery JavaScript deobfuscator.

Generates small, benign JavaScript programs from integer seeds, runs each program and its deobfuscation
in Node.js, and reports every seed where the observable behavior differs - a deobfuscation that changed
program semantics, i.e. a deobfuscator bug. Node, never our own interpreter, is the oracle. Generation is
a pure function of the seed, any finding reproduces from its seed alone.

Run `sweep` to fuzz a seed range fast (batched Node oracle, parallel deobfuscation), then `run` to
reproduce and inspect any reported seed against the canonical per-process oracle.

Each seed is classified as one of:

    ok          original and deobfuscation behave identically in node
    divergence  they differ - a deobfuscator semantics bug
    crash       deobfuscation itself raised a Python exception
    dirty       the generated program threw in node (a generator-invariant violation, not a deob bug)
    skip        the generated program failed to parse or timed out in node (never a valid oracle input)

Examples:
    python scripts/js-node-fuzzer.py sweep -n 2000              # fuzz seeds 0..1999
    python scripts/js-node-fuzzer.py sweep -n 20000 -o finds    # also save an artifact per finding
    python scripts/js-node-fuzzer.py sweep -n 5000 -x           # stop at the first divergence
    python scripts/js-node-fuzzer.py run 15258                  # reproduce and inspect one seed
    python scripts/js-node-fuzzer.py gen 15258                  # just print the generated program
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
import traceback

from concurrent.futures import ProcessPoolExecutor, as_completed

if True:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test.lib.scripts.js.analysis.differential import (
    behavior,
    deobfuscate_source,
    node_executable,
)
from test.lib.scripts.js.analysis.jsgen import generate

Behavior = tuple[str, str | None]

_BATCH_RUNNER_JS = r'''
'use strict';
const vm = require('vm');
const util = require('util');
const fs = require('fs');

const programsPath = process.argv[2];
const timeoutMs = parseInt(process.argv[3] || '5000', 10);
const programs = JSON.parse(fs.readFileSync(programsPath, 'utf8'));
const results = [];

for (let i = 0; i < programs.length; i++) {
  const source = programs[i];
  let out = '';
  const capture = (...args) => { out += util.format(...args) + '\n'; };
  const sandbox = {
    console: {
      log: capture, info: capture,
      error: () => {}, warn: () => {}, debug: () => {}, trace: () => {},
    },
  };
  let error = null;
  try {
    const script = new vm.Script(source, { filename: 'snippet.js' });
    const context = vm.createContext(sandbox);
    script.runInContext(context, { timeout: timeoutMs });
  } catch (e) {
    if (e && e.code === 'ERR_SCRIPT_EXECUTION_TIMEOUT') {
      error = 'TIMEOUT';
    } else if (e && typeof e.name === 'string' && /^[A-Za-z]+Error$/.test(e.name)) {
      error = e.name;
    } else {
      error = 'ERROR';
    }
  }
  results.push([out, error]);
}
process.stdout.write(JSON.stringify(results));
'''


def _behavior_batch(programs: list[str], timeout: float) -> list[Behavior]:
    """
    Run every program in *programs* in one node process, each in an isolated `vm` context, and return
    their `(stdout, error)` pairs - element-for-element the same shape as `differential.behavior`, but
    amortizing node's cold-start across the whole batch. A per-program *timeout* (seconds) keeps one
    hang from stalling the rest.
    """
    if not programs:
        return []
    node = node_executable()
    if node is None:
        raise RuntimeError('node.js is not available')
    with tempfile.TemporaryDirectory() as folder:
        runner = os.path.join(folder, 'runner.js')
        data = os.path.join(folder, 'programs.json')
        with open(runner, 'w', encoding='utf-8') as stream:
            stream.write(_BATCH_RUNNER_JS)
        with open(data, 'w', encoding='utf-8') as stream:
            json.dump(programs, stream)
        proc = subprocess.run(
            [node, runner, data, str(int(timeout * 1000))],
            capture_output=True,
            text=True,
            timeout=min(len(programs) * timeout, 300) + 30,
        )
    return [(out, err) for out, err in json.loads(proc.stdout)]


def _behavior_node(program: str, timeout: float) -> Behavior:
    """
    Run one program in its own node process - the canonical oracle the test suite uses - mapping a hang
    to a `TIMEOUT` verdict rather than letting it propagate.
    """
    try:
        return behavior(program, timeout=timeout)
    except subprocess.TimeoutExpired:
        return ('', 'TIMEOUT')


def _run_programs(programs: list[str], timeout: float, oracle: str) -> list[Behavior]:
    if oracle == 'node':
        return [_behavior_node(program, timeout) for program in programs]
    return _behavior_batch(programs, timeout)


def _classify_chunk(seeds: list[int], timeout: float, oracle: str):
    """
    Generate, deobfuscate, and behavior-check every seed in *seeds*, returning a list of
    `(seed, kind, payload)`. The two node passes (originals, then deobfuscations) are each a single
    batched call so a chunk pays node's start-up at most twice.
    """
    sources = [generate(seed) for seed in seeds]
    originals = _run_programs(sources, timeout, oracle)
    deobfuscated: list[str | None] = []
    crashes: dict[int, str] = {}
    for seed, source in zip(seeds, sources):
        try:
            deobfuscated.append(deobfuscate_source(source))
        except Exception:
            deobfuscated.append(None)
            crashes[seed] = traceback.format_exc()
    live = [index for index, value in enumerate(deobfuscated) if value is not None]
    live_behavior = dict(zip(live, _run_programs([deobfuscated[i] or '' for i in live], timeout, oracle)))
    results = []
    for index, seed in enumerate(seeds):
        source, original = sources[index], originals[index]
        if original[1] is not None and (original[1].startswith('Syntax') or original[1] == 'TIMEOUT'):
            results.append((seed, 'skip', None))
        elif original[1] is not None:
            results.append((seed, 'dirty', (source, original[1])))
        elif deobfuscated[index] is None:
            results.append((seed, 'crash', (source, crashes[seed])))
        elif tuple(live_behavior[index]) != tuple(original):
            results.append((seed, 'divergence', (source, deobfuscated[index])))
        else:
            results.append((seed, 'ok', None))
    return results


def _process_chunk(task):
    seeds, timeout, oracle = task
    return _classify_chunk(seeds, timeout, oracle)


def _write(out_dir: str, name: str, text: str) -> None:
    with open(os.path.join(out_dir, name), 'w', encoding='utf-8') as stream:
        stream.write(text)


def _record(out_dir: str | None, kind: str, seed: int, payload) -> None:
    if out_dir is None:
        return
    if kind == 'divergence':
        source, deob = payload
        _write(out_dir, F'div_{seed}.js', source)
        _write(out_dir, F'div_{seed}.deob.js', deob)
    elif kind == 'crash':
        source, tb = payload
        _write(out_dir, F'crash_{seed}.js', source)
        _write(out_dir, F'crash_{seed}.txt', tb)
    elif kind == 'dirty':
        source, _ = payload
        _write(out_dir, F'dirty_{seed}.js', source)


def _consume(results, tally: dict[str, int], found: dict[str, list[int]], args) -> None:
    for seed, kind, payload in results:
        tally[kind] = tally.get(kind, 0) + 1
        if kind in found:
            found[kind].append(seed)
            _record(args.out, kind, seed, payload)
            if args.verbose and kind == 'divergence':
                source, deob = payload
                print(F'\n=== divergence seed {seed} ===')
                print(F'--- source ---\n{source}')
                print(F'--- deobfuscated ---\n{deob}\n')


def cmd_sweep(args) -> int:
    if node_executable() is None:
        print('error: node.js is not on PATH', file=sys.stderr)
        return 2
    if args.out is not None:
        os.makedirs(args.out, exist_ok=True)
    seeds = list(range(args.start, args.start + args.count))
    tasks = [(seeds[i:i + args.chunk], args.timeout, args.oracle) for i in range(0, len(seeds), args.chunk)]
    workers = max(1, args.workers)
    tally: dict[str, int] = {'ok': 0, 'skip': 0, 'dirty': 0, 'crash': 0, 'divergence': 0}
    found: dict[str, list[int]] = {'dirty': [], 'crash': [], 'divergence': []}
    print(
        F'sweep seeds {args.start}..{args.start + args.count - 1}  '
        F'oracle={args.oracle} workers={workers} chunk={args.chunk} timeout={args.timeout}s')
    started = time.perf_counter()
    done = 0
    stopped = False

    def progress() -> None:
        if not args.quiet:
            print(
                F'  [{done}/{len(seeds)}] divergence={tally["divergence"]} crash={tally["crash"]} '
                F'dirty={tally["dirty"]}  {time.perf_counter() - started:.0f}s')

    if workers == 1:
        for task in tasks:
            _consume(_process_chunk(task), tally, found, args)
            done += len(task[0])
            progress()
            if args.stop_on_first and found['divergence']:
                stopped = True
                break
    else:
        executor = (
            ProcessPoolExecutor(max_workers=workers, max_tasks_per_child=1)
            if sys.version_info >= (3, 11)
            else ProcessPoolExecutor(max_workers=workers)
        )
        with executor as pool:
            futures = {pool.submit(_process_chunk, task): task for task in tasks}
            for future in as_completed(futures):
                _consume(future.result(), tally, found, args)
                done += len(futures[future][0])
                progress()
                if args.stop_on_first and found['divergence']:
                    for pending in futures:
                        pending.cancel()
                    stopped = True
                    break

    print(F'\n=== summary{" (stopped early)" if stopped else ""} ===')
    print(
        F'seeds={done} ok={tally["ok"]} skip={tally["skip"]} dirty={tally["dirty"]} '
        F'crash={tally["crash"]} divergence={tally["divergence"]}  '
        F'time={time.perf_counter() - started:.1f}s')
    for kind in ('divergence', 'crash', 'dirty'):
        if found[kind]:
            print(F'{kind} seeds: {sorted(found[kind])}')
    if found['divergence'] or found['crash']:
        print('reproduce with:  python scripts/js-node-fuzzer.py run <seed>')
        return 1
    return 0


def cmd_run(args) -> int:
    if node_executable() is None:
        print('error: node.js is not on PATH', file=sys.stderr)
        return 2
    source = generate(args.seed)
    print(F'seed {args.seed}  oracle={args.oracle} timeout={args.timeout}s')
    print(F'--- generated ({len(source.splitlines())} lines) ---')
    print(source)
    try:
        deob = deobfuscate_source(source)
    except Exception:
        print('--- deobfuscation CRASHED ---')
        traceback.print_exc()
        return 1
    print(F'--- deobfuscated ({len(deob.splitlines())} lines) ---')
    print(deob)
    original = _run_programs([source], args.timeout, args.oracle)[0]
    result = _run_programs([deob], args.timeout, args.oracle)[0]
    print('--- behavior (stdout, error) ---')
    print(F'  original:     {original!r}')
    print(F'  deobfuscated: {result!r}')
    if original[1] is not None and (original[1].startswith('Syntax') or original[1] == 'TIMEOUT'):
        print(F'verdict: SKIP - generator produced {original[1]}, not a valid oracle input')
        return 0
    if original[1] is not None:
        print(F'verdict: DIRTY - original threw {original[1]} in node (generator-invariant violation)')
        return 0
    if tuple(original) != tuple(result):
        print('verdict: DIVERGENCE - deobfuscation changed observable behavior')
        return 1
    print('verdict: OK - behavior preserved')
    return 0


def cmd_gen(args) -> int:
    print(generate(args.seed))
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    commands = parser.add_subparsers(dest='command', required=True)

    run = commands.add_parser('run', help='reproduce and inspect one seed end-to-end')
    run.add_argument('seed', type=int, help='the integer seed')
    run.add_argument('-t', '--timeout', type=float, default=15.0, help='node timeout in seconds (default 15)')
    run.add_argument('-O', '--oracle', choices=('node', 'batch'), default='node',
        help='node oracle: per-process (canonical, default) or batched vm')
    run.set_defaults(func=cmd_run)

    gen = commands.add_parser('gen', help='print the generated program for a seed')
    gen.add_argument('seed', type=int, help='the integer seed')
    gen.set_defaults(func=cmd_gen)

    sweep = commands.add_parser('sweep', help='fuzz a range of seeds and report divergences')
    sweep.add_argument('-n', '--count', type=int, default=1000, help='number of seeds (default 1000)')
    sweep.add_argument('-s', '--start', type=int, default=0, help='first seed (default 0)')
    sweep.add_argument('-j', '--workers', type=int, default=min(8, os.cpu_count() or 4),
        help='parallel worker processes (default: min(8, CPU count))')
    sweep.add_argument('-c', '--chunk', type=int, default=250, help='seeds per task/batch (default 250)')
    sweep.add_argument('-t', '--timeout', type=float, default=5.0, help='per-program node timeout in seconds (default 5.0)')
    sweep.add_argument('-O', '--oracle', choices=('batch', 'node'), default='batch',
        help='node oracle: batched vm (fast, default) or per-process (canonical, ~10x slower)')
    sweep.add_argument('-o', '--out', metavar='DIR', default=None,
        help='write div_/crash_/dirty_ artifact files into DIR')
    sweep.add_argument('-x', '--stop-on-first', action='store_true', help='stop at the first divergence')
    sweep.add_argument('-q', '--quiet', action='store_true', help='suppress per-chunk progress lines')
    sweep.add_argument('-v', '--verbose', action='store_true',
        help='print each divergence source and deobfuscation as it is found')
    sweep.set_defaults(func=cmd_sweep)

    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == '__main__':
    main()
