"""
Runtime ground-truth checker for the effect model's mutation analysis. It generates a small, benign,
deterministic program that defines a function `f`, runs that program in Node.js while recording which
outer variables `f` actually rebinds, then asks the effect model the same question and asserts the
model's answer COVERS what really happened: every outer variable that changed when `f()` ran is in
`mutated_bindings(f)`. Only this safe direction is checked — the model may over-approximate (name a
binding that did not change on a given run, e.g. a write in a branch that was not taken) but it must
never miss one, since a missed mutation is exactly what lets a constant be inlined past a real write.

This tests the analysis layer directly, rather than only the deobfuscator's final output: a wrong
`mutated_bindings` answer is caught on a tiny program, with no cleanup pass needed to trip over it.
Three of the soundness bugs the binding-resolved effect lift introduced were wrong answers of exactly
this kind, reachable here but not by the output-level fuzzer.

The check is scoped to a function the model resolves completely. When `f`'s summary is `calls_unknown`
the model does not claim to enumerate the bindings reached through the unknown call, so the coverage
promise does not apply and the sample is skipped. And a changed variable is only required to be
reported when the model considers it readable (`Binding.is_read`): a write whose result no code in the
analysed program can observe is, by design, not a mutated binding, even though the probe's own snapshot
reads it. The generator exercises the resolvable mutation shapes the lift bugs hid in — a write whose
reads are all confined to `f`, a redeclared helper, a mutation through a nested function or a
transitive call — and leaves the unresolved shapes to the output-level differential fuzzer.

`generate_probe(seed)` is a pure function of its integer seed, so any failure reproduces from its seed.

SECURITY: like `differential`, this executes JavaScript in Node.js and must only ever run the benign
programs this module generates. Never point it at the repository's malware corpus or any untrusted
sample — executing those is forbidden.
"""
from __future__ import annotations

import random
import re

from dataclasses import dataclass

from refinery.lib.scripts.js.analysis.effects import build_effects
from refinery.lib.scripts.js.analysis.model import build_semantic_model
from refinery.lib.scripts.js.model import JsFunctionDeclaration
from refinery.lib.scripts.js.parser import JsParser

from test.lib.scripts.js.analysis.differential import behavior

_CHECK_PREFIX = '__CHK__'
_CHECK_RE = re.compile(F'^{_CHECK_PREFIX}(.*)$', re.MULTILINE)


@dataclass
class ProbeProgram:
    """
    A generated analysis subject: *source* is an inert program (variable declarations and function
    definitions only, nothing runs at the top level), *outer_names* are its outer variables, and
    *func_name* names the function under test. The probe in `run_text` is what actually invokes it.
    """
    source: str
    outer_names: list[str]
    func_name: str


class _ProbeGenerator:
    """
    Builds one `ProbeProgram` for a seed. Every program is valid, terminating (no `while`, only
    constant-bound `for` loops, an acyclic call graph), deterministic (no clock, randomness, `this`,
    host object, or reflective construct), and benign (it only assigns integer literals, calls locally
    declared helpers, and adds its outer variables). The function under test `f` reads every outer
    variable once in its `return`, so each is a binding the model treats as read, and writes a subset
    of them through a mix of direct, conditional, looped, nested-function, and transitive-call forms —
    plus the occasional redeclared helper, whose call the model must treat as unknown.
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
    """
    Build the benign analysis subject for *seed*. The same seed always yields the same program.
    """
    return _ProbeGenerator(seed).generate()


def run_text(probe: ProbeProgram) -> str:
    """
    The runnable form of *probe*: the inert program followed by a probe that snapshots each outer
    variable, calls the function under test once, and prints the names of the variables whose identity
    changed. The snapshot reads the outer variables outside the function, so it is appended here rather
    than placed in `probe.source`, which the model analyses as the program actually written (a variable
    read only inside the function stays confined there for the analysis).
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


def observed_changes(probe: ProbeProgram, *, timeout: float = 15.0) -> set[str]:
    """
    The set of outer variables of *probe* whose identity changed when `f()` ran in Node.js.
    """
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
    """
    The effect model's answer for *probe*'s function: the outer variables it reports the function may
    mutate, the outer variables it treats as read (so a write to them is observable), and whether its
    summary is `calls_unknown` (in which case it does not claim to enumerate the bindings the unknown
    call reaches).
    """
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
    The outer variables that observably changed at runtime, are observable to the analysed program
    (read somewhere in it), yet the model did not report as mutated — the unsound under-reports. Empty
    when the model is sound for this program. Always empty, vacuously, when the summary is
    `calls_unknown`, where the model makes no completeness claim.
    """
    if view.calls_unknown:
        return set()
    return (observed & view.readable) - view.mutated
