"""
Differential testing support for JavaScript deobfuscation: run a snippet and its deobfuscated form in
a real Node.js engine and compare observable behavior. This is the strongest available oracle for the
invariant that deobfuscation preserves semantics — the engine, not our own interpreter, decides.

SECURITY: this executes JavaScript in Node.js. It must only ever be given benign, hand-authored
snippets. Never point it at the repository's malware test corpus or any untrusted sample — executing
those is forbidden.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile

from refinery.lib.scripts.js.deobfuscation import deobfuscate
from refinery.lib.scripts.js.parser import JsParser
from refinery.lib.scripts.js.synth import JsSynthesizer

_ERROR_RE = re.compile(r'^([A-Za-z]+Error): (.*)$', re.MULTILINE)


def node_executable() -> str | None:
    """
    The path to the Node.js executable, or `None` when it is not installed.
    """
    return shutil.which('node')


def deobfuscate_source(source: str) -> str:
    """
    Parse, deobfuscate, and re-synthesize a snippet, returning the deobfuscated source.
    """
    ast = JsParser(source).parse()
    deobfuscate(ast)
    return JsSynthesizer().convert(ast)


def _normalize_error(stderr: str) -> str:
    match = _ERROR_RE.search(stderr)
    if match is not None:
        return match.group(1)
    return 'ERROR'


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
