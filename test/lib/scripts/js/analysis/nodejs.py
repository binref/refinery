"""
How Node.js is asked about a program. The digest of this file is part of the identity of every kept
answer, so that a change to how Node is asked starts them over; code that does not change how Node
is asked belongs elsewhere, so that no other change does.

SECURITY: this executes JavaScript in Node.js. It must only ever be given benign, hand-authored
snippets. Never point it at the repository's malware test corpus or any untrusted sample; executing
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
#: program. Node starts without them, so that a shell setting one, such as `FORCE_COLOR`, gets the
#: same answers as any other.
_NOT_FOR_NODE = frozenset({
    'FORCE_COLOR',
    'NO_COLOR',
    'NODE_DISABLE_COLORS',
    'NODE_OPTIONS',
    'NODE_PATH',
})


def node_environment() -> dict[str, str]:
    return {key: value for key, value in os.environ.items() if key.upper() not in _NOT_FOR_NODE}


@functools.lru_cache(maxsize=None)
def node_executable() -> str | None:
    return shutil.which('node')


_ERROR_RE = re.compile(r'^([A-Za-z]*Error)(?=:\s|\s*$)', re.MULTILINE)


def _normalize_error(stderr: str) -> str:
    """
    The type of the error that ended a run, read off the last `XxxError:` line of *stderr*, since
    Node prints the uncaught error after anything the program wrote there. The message is dropped
    because it quotes the offending expression, which a semantics-preserving rewrite may reshape.

    A thrown value that is not an `Error` prints no such line, so every such throw reads as `ERROR`;
    a test that must tell two of them apart asserts on standard output instead.
    """
    if names := _ERROR_RE.findall(stderr):
        return names[-1]
    return 'ERROR'


def run(
    node: str,
    graph: tuple[tuple[str, str], ...],
    entry: str,
    timeout: float,
) -> tuple[str, str | None]:
    """
    What Node prints when it runs *entry* with each name and source of *graph* written beside it as
    a file, and the type of the error the run ended in, or `None`. Line ends are neither translated
    when the files are written nor when the output is read, because which characters end a line is
    part of what the engine is asked.
    """
    refuse_script_host_near_a_sample('node')
    with tempfile.TemporaryDirectory() as folder:
        for name, source in graph:
            with open(os.path.join(folder, name), 'w', encoding='utf-8', newline='') as stream:
                stream.write(source)
        proc = subprocess.run(
            [node, os.path.join(folder, entry)],
            capture_output=True,
            timeout=timeout,
            env=node_environment(),
        )
    stdout = proc.stdout.decode('utf-8', 'replace')
    if proc.returncode == 0:
        return stdout, None
    return stdout, _normalize_error(proc.stderr.decode('utf-8', 'replace'))


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

_SURROUNDING_VARIABLES = frozenset({
    'LANG',
    'LANGUAGE',
    'NODE_ICU_DATA',
    'TZ',
})


def surroundings() -> tuple[tuple[str, str], ...]:
    """
    The variables of this process's environment that decide Node's locale, time zone and locale
    data. The rest is left out: it changes nothing Node says it is, and it changes all the time,
    since pytest names the current test in it.
    """
    return tuple(sorted(
        (key, value) for key, value in os.environ.items()
        if key.upper() in _SURROUNDING_VARIABLES or key.upper().startswith('LC_')
    ))


_CODE = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def identity(node: str) -> str | None:
    """
    What the Node at *node* is, as a digest, or `None` when it cannot say, so that a kept answer is
    only ever reused from the same Node asked the same way. The environment enters only through what
    Node reports, so that two shells spelling the same time zone differently give the same identity.
    """
    refuse_script_host_near_a_sample('node')
    try:
        stdout, error = run(node, (('identity.js', _NODE_IDENTITY),), 'identity.js', NODE_TIMEOUT)
        report = json.loads(stdout)
    except (OSError, subprocess.SubprocessError, ValueError):
        return None
    if (
        error is not None
        or not isinstance(report, list)
        or not report
        or not isinstance(version := report[0], str)
        or not _NODE_VERSION.fullmatch(version)
    ):
        return None
    return hashlib.sha256(json.dumps([node, report, _CODE]).encode('utf-8')).hexdigest()
