"""
Differential testing support for JavaScript deobfuscation: run a snippet and its deobfuscated form in
a real Node.js engine and compare observable behavior. This is the strongest available oracle for the
invariant that deobfuscation preserves semantics — the engine, not our own interpreter, decides.

Two execution models are available, because they disagree about what a top-level declaration means.
`behavior` runs the snippet as `node <file>`, a CommonJS module, where a top-level `var`/`function` is
scoped to the module. `host_behavior` runs it as a classic global script and can additionally call a
name through `globalThis` afterwards, which is the only way to observe a declaration that reaches the
global object — and therefore the only way to observe whether an entrypoint a host would call survived.

SECURITY: this executes JavaScript in Node.js. It must only ever be given benign, hand-authored
snippets. Never point it at the repository's malware test corpus or any untrusted sample — executing
those is forbidden.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile

from refinery.lib.scripts.js.deobfuscation import deobfuscate
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer

_ERROR_RE = re.compile(r'^([A-Za-z]+Error): .*$', re.MULTILINE)


def node_executable() -> str | None:
    """
    The path to the Node.js executable, or `None` when it is not installed.
    """
    return shutil.which('node')


def deobfuscate_source(
    source: str,
    *,
    module: bool = False,
    entrypoints: tuple[str, ...] = (),
) -> str:
    """
    Parse, deobfuscate, and re-synthesize a snippet, returning the deobfuscated source. *module*
    selects the module execution model (the oracle runs each snippet as a CommonJS module, so a
    scope-sensitive snippet must be deobfuscated under the same model to be comparable).
    *entrypoints* names top-level functions a host calls by name, which intra-script reachability
    cannot see.
    """
    ast = JsParser(source).parse()
    deobfuscate(ast, module=module, entrypoints=entrypoints)
    return JsSynthesizer().convert(ast)


def _normalize_error(stderr: str) -> str:
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
    timeout: float = 15.0,
) -> tuple[str, str | None]:
    """
    The observable behavior of *source* run as a classic global script, including the results of the
    host calling each name in *calls* once loading finishes. Same return shape as `behavior`.
    """
    return behavior(_as_global_script(source, calls), timeout=timeout)


def behavior(source: str, *, timeout: float = 15.0) -> tuple[str, str | None]:
    """
    Execute *source* in Node.js and return its observable behavior as a pair: the captured standard
    output, and the error type (`TypeError`, `ReferenceError`, …) when execution terminated with an
    uncaught exception, or `None` on success. Only the type is kept, not the message: the message
    describes the offending expression, which a semantics-preserving rewrite may legitimately reshape
    (e.g. folding `(function(){})(x)` to `void 0` turns "(intermediate value) is not a function" into
    "(void 0) is not a function" — the same `TypeError`). Stack traces and file paths are dropped too,
    so an original snippet and its deobfuscation compare equal whenever they throw the same way.
    """
    node = node_executable()
    if node is None:
        raise RuntimeError('node.js is not available')
    with tempfile.TemporaryDirectory() as folder:
        path = os.path.join(folder, 'snippet.js')
        with open(path, 'w', encoding='utf-8') as stream:
            stream.write(source)
        proc = subprocess.run(
            [node, path],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    error = None if proc.returncode == 0 else _normalize_error(proc.stderr)
    return proc.stdout, error
