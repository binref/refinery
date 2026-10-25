"""
How Node.js is asked about a program: where it is, the environment it starts in, how the files of a
program reach it, how its answer is read, and what it says it is. The digest of this file is part of
the identity of every kept answer, so that a change to how Node is asked starts them over; it holds
nothing else, so that no other change does.

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
import tempfile

from pathlib import Path

from samples import refuse_script_host_near_a_sample

#: The seconds a run of Node.js may take before it counts as one that never ends. A loaded test
#: machine can stall a run that needs a fraction of a second for more than a quarter of a minute.
NODE_TIMEOUT = 60.0

#: Variables of the environment that change how Node prints or starts without being part of any
#: program: colors, extra command line options, and extra places to look for modules. Node starts
#: without them, so that a shell setting one, such as `FORCE_COLOR`, asks the same question as any.
_NOT_FOR_NODE = frozenset({
    'FORCE_COLOR',
    'NO_COLOR',
    'NODE_DISABLE_COLORS',
    'NODE_OPTIONS',
    'NODE_PATH',
})


def node_environment() -> dict[str, str]:
    """
    The environment every run of Node gets: this process's own, without `_NOT_FOR_NODE`.
    """
    return {key: value for key, value in os.environ.items() if key.upper() not in _NOT_FOR_NODE}


@functools.lru_cache(maxsize=None)
def node_executable() -> str | None:
    """
    The path to the Node.js executable, or `None` when it is not installed. It is looked up once per
    process: searching a long `PATH` takes milliseconds, far more than giving a remembered answer.
    """
    return shutil.which('node')


_ERROR_RE = re.compile(r'^([A-Za-z]+Error): .*$', re.MULTILINE)


def _normalize_error(stderr: str) -> str:
    """
    The error type a nonzero-exit *stderr* names — `TypeError`, `ReferenceError`, and so on — read
    off the `XxxError: …` line every thrown `Error` prints. Only the type is kept, for the reason
    `test.lib.scripts.js.analysis.differential.behavior` gives: the message names the offending
    expression, which a semantics-preserving rewrite may reshape.

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


def run(
    node: str,
    graph: tuple[tuple[str, str], ...],
    entry: str,
    timeout: float,
) -> tuple[str, str | None]:
    """
    What the Node at *node* prints when it runs *entry* with every file of *graph* written beside it,
    as names and sources, and the type of the error it ended in, or `None` when it ended without one.
    Each file is written untranslated, because which characters end a line is a question the engine
    is asked.
    """
    refuse_script_host_near_a_sample('node')
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
            env=node_environment(),
        )
    error = None if proc.returncode == 0 else _normalize_error(proc.stderr)
    return proc.stdout, error


#: Asks Node what it is and where it runs: its version, the versions of what it is built with, such
#: as its Unicode, locale and time zone data, its platform and processor, and the locale and time
#: zone that every program sees. All of them change what a program prints as much as the program.
_NODE_IDENTITY = R'''
const options = Intl.DateTimeFormat().resolvedOptions();
console.log(JSON.stringify([
  process.version,
  process.versions,
  process.platform,
  process.arch,
  options.locale,
  options.timeZone,
]));
'''

_NODE_VERSION = re.compile(r'v\d+\.\d+\.\d+')

#: The variables of the environment, besides those whose name begins with `LC_`, that decide the
#: locale and time zone Node runs in and the locale data it reads.
_SURROUNDING_VARIABLES = frozenset({
    'LANG',
    'LANGUAGE',
    'NODE_ICU_DATA',
    'TZ',
})


def surroundings() -> tuple[tuple[str, str], ...]:
    """
    The variables of this process's environment that decide the locale, time zone and locale data of
    Node. Nothing else of the environment changes what Node says it is, and the rest changes all the
    time: pytest names the current test in it.
    """
    return tuple(sorted(
        (key, value) for key, value in os.environ.items()
        if key.upper() in _SURROUNDING_VARIABLES or key.upper().startswith('LC_')
    ))


def identity(node: str) -> str | None:
    """
    What the Node at *node* is, as a digest, or `None` when it cannot say. The digest covers the path
    of the executable, everything `_NODE_IDENTITY` asks, and the code of this module, which decides
    how Node is asked: an answer is only ever the answer of the Node that gave it, asked this way.
    Node is asked once per process for each of its `surroundings`, which themselves are not part of
    the digest, so that two shells that spell the same time zone differently share it.
    """
    refuse_script_host_near_a_sample('node')
    return _identity(node, surroundings())


@functools.lru_cache(maxsize=None)
def _identity(node: str, variables: tuple[tuple[str, str], ...]) -> str | None:
    """
    The digest that `identity` gives for *node*, asked where `surroundings` are *variables*: they are
    not read here, because Node reads them from the environment, but its answer depends on them.
    """
    try:
        asked = subprocess.run(
            [node, '-e', _NODE_IDENTITY],
            capture_output=True,
            text=True,
            timeout=NODE_TIMEOUT,
            env=node_environment(),
        )
        report = json.loads(asked.stdout)
    except (OSError, subprocess.SubprocessError, ValueError):
        return None
    if (
        asked.returncode != 0
        or not isinstance(report, list)
        or not report
        or not isinstance(version := report[0], str)
        or not _NODE_VERSION.fullmatch(version)
    ):
        return None
    code = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    return hashlib.sha256(json.dumps([node, report, code]).encode('utf-8')).hexdigest()
