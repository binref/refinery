"""
Run hand-written JavaScript in Node.js and report what it prints, throws or evaluates to, so that
the engine decides whether a snippet and its deobfuscation behave alike.

SECURITY: this executes JavaScript in Node.js. It must only ever be given benign, hand-authored
snippets. Never point it at the repository's malware test corpus or any untrusted sample — executing
those is forbidden.
"""
from __future__ import annotations

import functools
import json
import os
import subprocess
import sys
import tempfile

from enum import Enum
from pathlib import Path
from typing import Mapping, Sequence

from refinery.lib.scripts.js.analysis.environment import HostEnvironment
from refinery.lib.scripts.js.deobfuscation import deobfuscate
from refinery.lib.scripts.js.options import ExecutionModel
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer
from samples import refuse_script_host_near_a_sample
from test.lib.scripts.js.analysis.node_answers import ask
from test.lib.scripts.js.analysis.nodejs import (
    NODE_TIMEOUT,
    node_environment,
    node_executable,
)


def node_reads_as_a_program(source: str) -> bool:
    """
    Whether `node --check` accepts the syntax of *source*; Node does not run it. A test that decoded
    a sample is refused, even for a snippet Node checked before.
    """
    refuse_script_host_near_a_sample('node')
    return _node_checks(source)


@functools.lru_cache(maxsize=None)
def _node_checks(source: str) -> bool:
    executable = node_executable()
    assert executable is not None
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / 'snippet.js'
        path.write_text(source, encoding='utf8', newline='')
        completed = subprocess.run(
            [executable, '--check', str(path)],
            capture_output=True,
            env=node_environment(),
        )
    return completed.returncode == 0


def deobfuscate_source(
    source: str,
    *,
    execution: ExecutionModel = ExecutionModel.script,
    entrypoints: tuple[str, ...] = (),
    preserve_script_return: bool = False,
    environment: HostEnvironment = HostEnvironment.universal,
) -> str:
    """
    `behavior` runs a snippet as a CommonJS file, where a top-level declaration stays inside the
    file, so a snippet whose output depends on that compares with its deobfuscation only under the
    *execution* `commonjs` or `module`.
    """
    ast = JsParser(source).parse()
    deobfuscate(
        ast,
        execution=execution,
        entrypoints=entrypoints,
        environment=environment,
        preserve_script_return=preserve_script_return,
    )
    return JsSynthesizer().convert(ast)


_DEOBFUSCATE_IN_CHILD = R'''
import sys
sys.path.insert(0, sys.argv[1])
from test.lib.scripts.js.analysis.differential import deobfuscate_source
source = sys.stdin.buffer.read().decode('utf-8')
sys.stdout.buffer.write(deobfuscate_source(source).encode('utf-8'))
'''


class DeobfuscationFailed(Exception):
    pass


def deobfuscate_within(source: str, seconds: float) -> str | None:
    root = Path(__file__).resolve().parents[5]
    with subprocess.Popen(
        [sys.executable, '-c', _DEOBFUSCATE_IN_CHILD, str(root)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as child:
        try:
            out, err = child.communicate(source.encode('utf-8'), timeout=seconds)
        except subprocess.TimeoutExpired:
            child.kill()
            child.communicate()
            return None
        except BaseException:
            child.kill()
            raise
    if child.returncode != 0:
        raise DeobfuscationFailed(err.decode('utf-8', 'replace'))
    return out.decode('utf-8')


def _as_global_script(source: str, calls: tuple[str, ...], prelude: str = '') -> str:
    """
    An indirect `eval` runs its argument in the global scope, as a classic script runs, so a
    top-level declaration of *source* becomes a property of `globalThis`. Run directly, the file is
    a CommonJS file, whose top-level declarations stay inside it.
    """
    lines = [prelude] if prelude else []
    lines.append('const globalEval = eval;')
    lines.append(F'globalEval({json.dumps(source)});')
    for name in calls:
        key = json.dumps(name)
        lines.append(
            F'console.log({key} + "=" + JSON.stringify('
            F'typeof globalThis[{key}] === "function" ? globalThis[{key}]() : undefined));'
        )
    return '\n'.join(lines)


def host_behavior(
    source: str,
    *,
    calls: tuple[str, ...] = (),
    prelude: str = '',
    timeout: float = NODE_TIMEOUT,
) -> tuple[str, str | None]:
    """
    The observable behavior of *source* run as a classic global script, including the results of the
    host calling each name in *calls* once loading finishes. The host code *prelude* runs before the
    script. Same return shape as `behavior`.
    """
    return behavior(_as_global_script(source, calls, prelude), timeout=timeout)


def behavior(
    source: str,
    *,
    module: bool = False,
    timeout: float = NODE_TIMEOUT,
    fresh: bool = False,
) -> tuple[str, str | None]:
    """
    Run *source* in Node.js as a CommonJS file, or as an ES module with *module*, and return what it
    prints and the type of the error it ended in, or `None` when it ended without one. The message
    of the error is dropped, since a rewrite that keeps the meaning may still change it.

    Node's answer for a snippet is remembered; *fresh* asks Node again.
    """
    return module_graph_behavior(
        {'snippet.mjs' if module else 'snippet.js': source},
        'snippet.mjs' if module else 'snippet.js',
        timeout=timeout,
        fresh=fresh,
    )


def module_graph_behavior(
    files: Mapping[str, str],
    entry: str,
    *,
    timeout: float = NODE_TIMEOUT,
    fresh: bool = False,
) -> tuple[str, str | None]:
    """
    What running *entry* prints and the type of the error it ended in, as `behavior` reports them,
    with every file of *files* written beside it under its key. The extension of a key decides
    whether Node reads that file as a CommonJS file or as an ES module.

    Node's answers are remembered and may be kept for later runs. A test asking whether two runs of
    one program agree passes *fresh*, which asks Node again and keeps nothing.
    """
    return ask(tuple(sorted(files.items())), entry, timeout, fresh=fresh)


_CODE_UNIT_ENCODER = R'''
function enc(x) {
  if (x === undefined) return 'undefined';
  if (x === null) return 'null';
  if (typeof x === 'number') return Object.is(x, -0) ? '-0' : String(x);
  if (typeof x === 'boolean') return String(x);
  if (typeof x === 'function') return 'function';
  if (typeof x === 'symbol') return 'symbol';
  if (typeof x === 'string')
    return 'S[' + Array.from({length: x.length}, function (_, i) {
      return x.charCodeAt(i);
    }).join(',') + ']';
  if (Array.isArray(x)) return 'A[' + x.map(enc).join(',') + ']';
  return 'O' + Object.prototype.toString.call(x);
}
'''


def code_units(expressions: Sequence[str], *, timeout: float = NODE_TIMEOUT) -> list[str]:
    """
    Node's value for each of *expressions*, as `_CODE_UNIT_ENCODER` spells it: a string as the list
    of its UTF-16 code units, so that two spellings of one string give the same answer.

    All of *expressions* run in one scope and in order, so each must be free of effects.
    """
    probes = '\n'.join(F'console.log(enc({expression}));' for expression in expressions)
    stdout, error = behavior(F'{_CODE_UNIT_ENCODER}\n{probes}\n', timeout=timeout)
    if error is not None:
        raise AssertionError(F'node refused one of {len(expressions)} expressions: {error}')
    return stdout.splitlines()


class JsEvaluation(str, Enum):
    """
    How `completion_values` hands a program to Node: `EVAL` as the argument of an indirect `eval`,
    `SCRIPT` as a whole script.
    """
    EVAL = 'eval'
    SCRIPT = 'script'


_COMPLETION_DRIVER = R'''
const fs = require('fs');
const vm = require('vm');

function named(x) {
  if (x === undefined) return 'undefined';
  if (x === null) return 'null';
  if (typeof x === 'number') return Object.is(x, -0) ? '-0' : String(x);
  if (typeof x === 'bigint') return String(x) + 'n';
  if (typeof x === 'boolean') return String(x);
  if (typeof x === 'string') return JSON.stringify(x);
  if (typeof x === 'function') return 'function';
  if (typeof x === 'symbol') return 'symbol';
  if (Object.prototype.toString.call(x) === '[object Error]') return x.name;
  return Object.prototype.toString.call(x);
}

function evaluated(source, host) {
  const context = vm.createContext({});
  try {
    if (host === 'eval') {
      return named(vm.runInContext('(0, eval)(' + JSON.stringify(source) + ')', context));
    }
    return named(vm.runInContext(source, context));
  } catch (error) {
    return 'throw ' + named(error);
  }
}

function report(request) {
  const values = request.programs.map(function (source) {
    return evaluated(source, request.host);
  });
  fs.writeFileSync(request.report, JSON.stringify(values), 'utf8');
}
'''


def completion_values(
    programs: Sequence[str],
    evaluation: JsEvaluation = JsEvaluation.EVAL,
    *,
    timeout: float = NODE_TIMEOUT,
) -> list[str]:
    """
    The value each of *programs* evaluates to under *evaluation*, each in a context of its own, as
    `_COMPLETION_DRIVER` names it; a program that throws gives `throw` and the name of what it
    threw.
    """
    with tempfile.TemporaryDirectory() as folder:
        path = os.path.join(folder, 'values.json')
        request = json.dumps({
            'programs': list(programs),
            'host': evaluation.value,
            'report': path,
        })
        _, error = behavior(F'{_COMPLETION_DRIVER}\nreport({request});\n', timeout=timeout, fresh=True)
        if error is not None:
            raise AssertionError(F'node refused a table of {len(programs)} programs: {error}')
        with open(path, 'r', encoding='utf-8') as stream:
            return json.load(stream)
