"""
Differential testing support for JavaScript deobfuscation: run a snippet and its deobfuscated form in
a real Node.js engine and compare observable behavior. This is the strongest available oracle for the
invariant that deobfuscation preserves semantics — the engine, not our own interpreter, decides.

Three execution models are available, because they disagree about what a top-level declaration means.
`behavior` runs the snippet as `node <file>`, a CommonJS module, where a top-level `var`/`function` is
scoped to the module. `host_behavior` runs it as a classic global script and can additionally call a
name through `globalThis` afterwards, which is the only way to observe a declaration that reaches the
global object — and therefore the only way to observe whether an entrypoint a host would call survived.
`behavior(source, module=True)` runs it as an ECMAScript module, which is the only one of the three
that is strict code without a directive saying so, and the only one where `import`, `export`, and
`import.meta` are available at all. A declaration in that model names something in another file, so
a question about an import or export name needs that file to exist: `module_graph_behavior` is the
same execution with a whole graph of modules written beside the entry.

What a program prints is not all of it: a program also has a value, and `completion_values` reports
that one. `eval` hands it back to its caller and so does a script run as a unit, so a rewrite that
leaves every print in place can still change what a payload was worth to whoever ran it.

SECURITY: this executes JavaScript in Node.js. It must only ever be given benign, hand-authored
snippets. Never point it at the repository's malware test corpus or any untrusted sample — executing
those is forbidden.
"""
from __future__ import annotations

import functools
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

from contextlib import suppress
from enum import Enum
from pathlib import Path
from typing import Mapping, Sequence

from refinery.lib.scripts.js.analysis.environment import HostEnvironment
from refinery.lib.scripts.js.deobfuscation import deobfuscate
from refinery.lib.scripts.js.options import ExecutionModel
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer
from samples import refuse_script_host_near_a_sample

_ERROR_RE = re.compile(r'^([A-Za-z]+Error): .*$', re.MULTILINE)

#: The seconds a run of Node.js may take before it counts as one that never ends. A loaded test
#: machine can stall a run that needs a fraction of a second for more than a quarter of a minute.
NODE_TIMEOUT = 60.0


@functools.lru_cache(maxsize=None)
def node_executable() -> str | None:
    """
    The path to the Node.js executable, or `None` when it is not installed. It is looked up once per
    process: searching a long `PATH` takes milliseconds, far more than giving a remembered answer.
    """
    return shutil.which('node')


@functools.lru_cache(maxsize=None)
def node_reads_as_a_program(source: str) -> bool:
    """
    Whether `node --check` reads *source* as a program, parsing it as a script and never running it.
    A file the grammar refuses is a syntax error the check reports, so this is the engine answering
    the same question `refinery.lib.scripts.is_well_formed` answers about the tree the parser built.
    """
    refuse_script_host_near_a_sample('node')
    executable = node_executable()
    assert executable is not None
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / 'snippet.js'
        path.write_text(source, encoding='utf8')
        completed = subprocess.run(
            [executable, '--check', str(path)],
            capture_output=True,
            text=True,
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
    Parse, deobfuscate, and re-synthesize a snippet, returning the deobfuscated source. *execution*
    selects the execution model (the oracle runs each snippet as a CommonJS module, so a
    scope-sensitive snippet must be deobfuscated under a module model to be comparable).
    *entrypoints* names top-level functions a host calls by name, which intra-script reachability
    cannot see. *environment* is the host the deobfuscation assumes; the oracle is Node, so every
    host but the browser's describes the engine the snippet runs in.
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
    """
    The child process running a deobfuscation exited without producing one. It carries the child's
    standard error, which is where the traceback is.
    """


def deobfuscate_within(source: str, seconds: float) -> str | None:
    """
    The deobfuscation of *source*, or `None` when it did not finish within *seconds*.

    Termination is a property worth asserting on its own: a fold that computes in unbounded integer
    arithmetic can run for hours on an expression a double answers in one operation, and that is a
    defect no comparison of results can express. It runs in a child process because such a computation
    happens inside a single interpreter opcode, where no timer, signal, or thread can interrupt it —
    only killing the process can.

    Both the source and the result cross the process boundary as UTF-8 bytes over a pipe rather than
    as text through the platform's codec, so that a program the console encoding cannot spell is
    reported as what it is. The child is killed on every way out and not only on the timeout,
    because the one thing this helper must never do is leave behind the runaway process it exists to
    bound.
    """
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


def _normalize_error(stderr: str) -> str:
    """
    The error type a nonzero-exit *stderr* names — `TypeError`, `ReferenceError`, and so on — read
    off the `XxxError: …` line every thrown `Error` prints. Only the type is kept, for the reason
    `behavior` gives: the message names the offending expression, which a semantics-preserving
    rewrite may reshape.

    RESOLUTION LIMIT: a program may `throw` a value that is not an `Error` — a string, a number, an
    object, `null`, `undefined`, a symbol — and such a throw prints no `XxxError:` line, so every one
    of them collapses to the single token `ERROR` here. Two programs that throw *different* non-Error
    values are therefore indistinguishable by the error half of `behavior`, and a rewrite that changed
    which non-Error value is thrown is invisible unless the standard output leading up to the throw
    also differs. The exposure is narrow — the fuzzer never emits an uncaught non-Error throw, so only
    a hand-authored ledger entry reaches it — but an entry that must tell two non-Error throws apart
    asserts on standard output rather than on this token. Parsing the thrown value out of *stderr* is
    deliberately not attempted: Node renders it in a shape that varies by value and version (an object
    spans lines, a symbol renders as nothing), so a parse would trade a rare false match for a
    version-fragile false difference between two runs that threw the very same value.
    """
    match = _ERROR_RE.search(stderr)
    if match is not None:
        return match.group(1)
    return 'ERROR'


def _as_global_script(source: str, calls: tuple[str, ...]) -> str:
    """
    Wrap *source* so it runs under the *script* execution model and then invoke each name in *calls* as
    a host would.

    `node file.js` runs a CommonJS module, where a top-level `var`/`function` is scoped to the module,
    so `behavior` alone cannot observe anything about the global object. Indirect `eval` runs its
    argument in the true global scope — the same scope a browser `<script>`, a Windows Script Host
    `.js`, or a JXA file gets — which is what puts a top-level declaration onto `globalThis` and makes
    it reachable by name from outside.

    That reachability is the whole point: a host entrypoint has no caller inside the file, so its
    deletion changes nothing about running the file and is invisible to a stdout comparison. Calling it
    afterwards through `globalThis` is what turns the deletion into an observable difference, with Node
    rather than our own reading of the specification deciding what the difference is.
    """
    lines = [
        'const globalEval = eval;',
        F'globalEval({json.dumps(source)});',
    ]
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
    timeout: float = NODE_TIMEOUT,
) -> tuple[str, str | None]:
    """
    The observable behavior of *source* run as a classic global script, including the results of the
    host calling each name in *calls* once loading finishes. Same return shape as `behavior`.
    """
    return behavior(_as_global_script(source, calls), timeout=timeout)


def behavior(
    source: str,
    *,
    module: bool = False,
    timeout: float = NODE_TIMEOUT,
    fresh: bool = False,
) -> tuple[str, str | None]:
    """
    Execute *source* in Node.js and return its observable behavior as a pair: the captured standard
    output, and the error type (`TypeError`, `ReferenceError`, …) when execution terminated with an
    uncaught exception, or `None` on success. Only the type is kept, not the message: the message
    describes the offending expression, which a semantics-preserving rewrite may legitimately reshape
    (e.g. folding `(function(){})(x)` to `void 0` turns "(intermediate value) is not a function" into
    "(void 0) is not a function" — the same `TypeError`). Stack traces and file paths are dropped too,
    so an original snippet and its deobfuscation compare equal whenever they throw the same way.

    *module* writes the snippet to a `.mjs` file, which is what makes Node read it as an ECMAScript
    module rather than as a CommonJS one. The extension is the whole of the difference: it decides
    the goal symbol the source is parsed under, and module code is strict code whether or not any
    directive says so.

    The snippet reaches the file untranslated, because which characters end a line is a question
    the engine is asked here: the platform default rewrites every `\\n` on the way out, so a case
    written with `\\r\\n` handed Node a `\\r\\r\\n`, and the two sides of the comparison then read
    different programs.

    *fresh* runs Node even when it has answered for this snippet before; `module_graph_behavior`
    says when that is needed.
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
    The observable behavior of running *entry* with every file of *files* written beside it, in the
    same shape `behavior` reports.

    A declaration that names something across the module boundary says nothing on its own: what
    `import { x } from './m.mjs'` reaches is a name `./m.mjs` exports, and whether it reaches one at
    all is the linker's answer rather than the parser's. One file can therefore never be asked what
    such a declaration means, and a graph of them is the smallest thing that can.

    Each file reaches the folder untranslated, for the reason `behavior` gives, and the extension in
    each key is what decides the goal symbol its file is read under.

    Node's answers to the latest 1024 questions are kept and given again when the same files, entry
    and timeout are asked about: tests often ask about the same program a few questions apart, and
    starting Node costs far more than running the program. The bound keeps a process that asks
    about many programs only once, like a fuzzing sweep, from holding all of them. A test whose
    question is whether two runs of a program agree passes *fresh*, which runs Node again and keeps
    nothing.

    When the environment variable `REFINERY_TEST_NODE_ANSWERS` names a folder, as the configuration
    of the test suite makes it do, the answers that end without an error also outlive the process:
    `NodeAnswers` says how they are kept.
    """
    refuse_script_host_near_a_sample('node')
    node = node_executable()
    if node is None:
        raise RuntimeError('node.js is not available')
    graph = tuple(sorted(files.items()))
    if fresh:
        return _node_behavior(node, graph, entry, timeout)
    return _remembered_node_behavior(node, graph, entry, timeout)


class NodeAnswers:
    """
    What one version of Node printed for programs that ran without an error, kept in a folder so
    that a later run of the test suite starts Node only for the programs it has not seen. The folder
    holds one subfolder per version, and opening it for one version removes all others, because an
    answer is only ever the answer of the version that gave it.

    An answer that ends in an error is not kept. A run that fails for a reason unrelated to the
    program, such as a machine that ran out of memory, can then never be given again as what the
    program does, at the price of running every program that throws each time it is asked about.

    Each answer is one file named by a hash of its question, so that the workers of a run can read
    and write the folder at the same time: a file is written beside its name and moved onto it, and
    no reader can find it half written.
    """

    def __init__(self, folder: Path, version: str):
        folder.mkdir(parents=True, exist_ok=True)
        for other in folder.iterdir():
            if other.name != version:
                shutil.rmtree(other, ignore_errors=True)
        self.folder = folder / version
        self.folder.mkdir(exist_ok=True)

    def _path(self, question: tuple) -> Path:
        return self.folder / hashlib.sha256(json.dumps(question).encode('ascii')).hexdigest()

    def answer(self, question: tuple) -> str | None:
        """
        The standard output kept for *question*, or `None` when none is kept.
        """
        try:
            return self._path(question).read_bytes().decode('utf-8')
        except OSError:
            return None

    def keep(self, question: tuple, stdout: str) -> None:
        """
        Keep *stdout* as the answer to *question*, which ran without an error.
        """
        with tempfile.NamedTemporaryFile(dir=self.folder, delete=False) as stream:
            stream.write(stdout.encode('utf-8'))
        try:
            os.replace(stream.name, self._path(question))
        except OSError:
            with suppress(OSError):
                os.remove(stream.name)


@functools.lru_cache(maxsize=None)
def _kept_answers(node: str) -> NodeAnswers | None:
    """
    The answers kept for the version of *node* in the folder that `REFINERY_TEST_NODE_ANSWERS`
    names, or `None` when it names none.
    """
    if not (folder := os.environ.get('REFINERY_TEST_NODE_ANSWERS')):
        return None
    version = subprocess.run(
        [node, '--version'],
        capture_output=True,
        text=True,
        check=True,
        timeout=NODE_TIMEOUT,
    ).stdout.strip()
    return NodeAnswers(Path(folder), version)


@functools.lru_cache(maxsize=1024)
def _remembered_node_behavior(
    node: str,
    graph: tuple[tuple[str, str], ...],
    entry: str,
    timeout: float,
) -> tuple[str, str | None]:
    question = (graph, entry, timeout)
    kept = _kept_answers(node)
    if kept is not None and (stdout := kept.answer(question)) is not None:
        return stdout, None
    stdout, error = _node_behavior(node, graph, entry, timeout)
    if kept is not None and error is None:
        kept.keep(question, stdout)
    return stdout, error


def _node_behavior(
    node: str,
    graph: tuple[tuple[str, str], ...],
    entry: str,
    timeout: float,
) -> tuple[str, str | None]:
    with tempfile.TemporaryDirectory() as folder:
        for name, source in graph:
            with open(os.path.join(folder, name), 'w', encoding='utf-8', newline='') as stream:
                stream.write(source)
        proc = subprocess.run(
            [node, os.path.join(folder, entry)],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            timeout=timeout,
        )
    error = None if proc.returncode == 0 else _normalize_error(proc.stderr)
    return proc.stdout, error


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
    Node's value for each expression in *expressions*, rendered as the structure its UTF-16 code
    units give it: a string as `S[...codes...]`, an array as `A[...elements...]`, and everything
    else as a word naming it. The rendering is what makes a pinned value independent of how the
    value is spelled — `'\\uD83D'`, a literal lone high surrogate, and a `String.fromCharCode` call
    all render as `S[55357]` — so a test comparing two of these compares values and not escapes.

    All of *expressions* are evaluated in one process, because a table of them otherwise costs one
    Node start per row. They are therefore evaluated in one scope and in order, which is a scope any
    of them can write to; keep them free of effects.
    """
    probes = '\n'.join(F'console.log(enc({expression}));' for expression in expressions)
    stdout, error = behavior(F'{_CODE_UNIT_ENCODER}\n{probes}\n', timeout=timeout)
    if error is not None:
        raise AssertionError(F'node refused one of {len(expressions)} expressions: {error}')
    return stdout.splitlines()


class JsEvaluation(str, Enum):
    """
    The way a program is handed to the engine when the question is what it evaluates to.

    `EVAL` is the payload model: the program is the argument of a call to `eval`, which returns the
    value, and that is how a stage of a malware chain reaches this tool. `SCRIPT` is the unit model:
    the program is compiled and run whole, the way `vm.runInThisContext` and any host that embeds an
    engine run one, and the value is the script's own. Both are asked because they need not agree.
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
    The value each program in *programs* evaluates to under *evaluation*, named the way a reader can
    check by eye: a string as its JSON spelling, a number, `null`, `undefined`, `function`, and the
    class of anything else. A program that ends abruptly has no value at all, and is reported as
    `throw` and the name of what it threw, so that an ending is never confused with a result.

    Each program gets a context of its own. Programs would otherwise share one global, where a
    second `let` of the same name is a syntax error and a leftover `var` is a value the next program
    can see, and a table of programs is meant to be read one row at a time.

    The values come back through a file rather than through standard output, because a program in
    *programs* may print, and what it prints must not be mistaken for what it evaluates to. Node
    therefore always runs again here: a remembered answer would leave that file unwritten.
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
