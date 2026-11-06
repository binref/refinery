"""
Checks the effect model's mutation analysis against Node.js: it generates a small program defining a
function `f`, runs it in Node while recording which outer variables `f()` rebinds, and checks the
model's answer against them. The model may name a variable that did not change on a run, but must
never miss one that did.

SECURITY: this executes JavaScript in Node.js and must only ever run the benign programs this module
generates. Never point it at the repository's malware corpus or any untrusted sample; executing
those is forbidden.
"""
from __future__ import annotations

import random
import re

from dataclasses import dataclass

from refinery.lib.scripts.js.analysis.effects import build_effects
from refinery.lib.scripts.js.analysis.model import build_semantic_model
from refinery.lib.scripts.js.model import JsFunctionDeclaration
from refinery.lib.scripts.js.parser import JsParser

from test.lib.scripts.js.analysis.differential import NODE_TIMEOUT, behavior

_CHECK_PREFIX = '__CHK__'
_CHECK_RE = re.compile(F'^{_CHECK_PREFIX}(.*)$', re.MULTILINE)


@dataclass
class ProbeProgram:
    source: str
    outer_names: list[str]
    func_name: str


class _ProbeGenerator:
    """
    Node runs every program this builds, so each must stay terminating, deterministic and benign: no
    `while`, only constant-bound `for` loops, an acyclic call graph, no clock, randomness, host
    object or reflective construct, and nothing but integer assignments, calls of local helpers and
    additions.
    """

    def __init__(self, seed: int):
        self.rng = random.Random(seed)
        self._names = 0
        self._ints = 0

    def _fresh(self, prefix: str) -> str:
        name = F'{prefix}{self._names}'
        self._names += 1
        return name

    def _int(self) -> int:
        self._ints += 1
        return self._ints

    def generate(self) -> ProbeProgram:
        rng = self.rng
        outers = [self._fresh('o') for _ in range(rng.randint(2, 4))]
        lines = [F'var {name} = {self._int()};' for name in outers]

        helpers: list[str] = []
        for _ in range(rng.randint(0, 2)):
            name = self._fresh('h')
            targets = rng.sample(outers, rng.randint(0, len(outers)))
            body = ' '.join(F'{t} = {self._int()};' for t in targets)
            lines.append(F'function {name}() {{ {body} return {self._int()}; }}')
            if rng.random() < 0.25:
                redo = rng.sample(outers, rng.randint(0, len(outers)))
                body = ' '.join(F'{t} = {self._int()};' for t in redo)
                lines.append(F'function {name}() {{ {body} return {self._int()}; }}')
            helpers.append(name)

        lines.append(F'function f() {{ {self._function_body(outers, helpers)} }}')
        return ProbeProgram('\n'.join(lines), outers, 'f')

    def _function_body(self, outers: list[str], helpers: list[str]) -> str:
        rng = self.rng
        stmts: list[str] = []
        for name in outers:
            roll = rng.random()
            if roll < 0.35:
                continue
            stmts.append(self._mutation(name))
        for helper in helpers:
            if rng.random() < 0.5:
                stmts.append(F'{helper}();')
        rng.shuffle(stmts)
        stmts.append(F'return {" + ".join(outers)};')
        return ' '.join(stmts)

    def _mutation(self, name: str) -> str:
        rng = self.rng
        form = rng.choice(('direct', 'taken', 'untaken', 'loop', 'nested', 'confined'))
        if form == 'direct':
            return F'{name} = {self._int()};'
        if form == 'taken':
            return F'if (1) {{ {name} = {self._int()}; }}'
        if form == 'untaken':
            return F'if (0) {{ {name} = {self._int()}; }}'
        if form == 'loop':
            counter = self._fresh('i')
            return F'for (var {counter} = 0; {counter} < 2; {counter}++) {{ {name} = {self._int()}; }}'
        if form == 'nested':
            inner = self._fresh('n')
            return F'function {inner}() {{ {name} = {self._int()}; }} {inner}();'
        scratch = self._fresh('t')
        return F'var {scratch} = {name}; {name} = {self._int()}; {scratch} = {name};'


def generate_probe(seed: int) -> ProbeProgram:
    return _ProbeGenerator(seed).generate()


def run_text(probe: ProbeProgram) -> str:
    """
    The program Node runs for *probe*: its source followed by code that prints which outer variables
    `f()` rebinds. That code stays out of `probe.source` because it reads every outer variable
    outside `f`, which would change what the model is asked.
    """
    snapshot = ' '.join(F'var _b{i} = {name};' for i, name in enumerate(probe.outer_names))
    compare = ' '.join(
        F"if (!Object.is(_b{i}, {name})) _c.push('{name}');"
        for i, name in enumerate(probe.outer_names)
    )
    return (
        F'{probe.source}\n'
        F'{snapshot}\n'
        F'var _c = [];\n'
        F'try {{ {probe.func_name}(); }} catch (_e) {{}}\n'
        F'{compare}\n'
        F"console.log('{_CHECK_PREFIX}' + _c.join(','));"
    )


def observed_changes(probe: ProbeProgram, *, timeout: float = NODE_TIMEOUT) -> set[str]:
    stdout, error = behavior(run_text(probe), timeout=timeout)
    if error is not None:
        raise RuntimeError(F'probe did not run cleanly in node ({error}):\n{run_text(probe)}')
    match = _CHECK_RE.search(stdout)
    if match is None:
        raise RuntimeError(F'probe produced no check line:\n{stdout}')
    return {name for name in match.group(1).split(',') if name}


@dataclass
class _ModelView:
    mutated: set[str]
    readable: set[str]
    calls_unknown: bool


def model_view(probe: ProbeProgram) -> _ModelView:
    ast = JsParser(probe.source).parse()
    model = build_semantic_model(ast)
    effects = build_effects(model)
    func = next(
        node for node in ast.walk()
        if isinstance(node, JsFunctionDeclaration)
        and node.id is not None and node.id.name == probe.func_name
    )
    scope = model.function_scope(func)
    mutated_bindings = effects.mutated_bindings(func)
    mutated: set[str] = set()
    readable: set[str] = set()
    for name in probe.outer_names:
        binding = model.lookup(name, scope)
        if binding is None:
            continue
        if binding.is_read:
            readable.add(name)
        if binding in mutated_bindings:
            mutated.add(name)
    return _ModelView(mutated, readable, effects.summary_of(func).calls_unknown)


def unsound_misses(probe: ProbeProgram, observed: set[str], view: _ModelView) -> set[str]:
    """
    The outer variables that changed when `f()` ran and that the analysed program reads, but that
    the model does not report as mutated. A write nothing in the program reads is no mutation to the
    model, and a `calls_unknown` summary claims no complete list, so neither counts as a miss.
    """
    if view.calls_unknown:
        return set()
    return (observed & view.readable) - view.mutated
