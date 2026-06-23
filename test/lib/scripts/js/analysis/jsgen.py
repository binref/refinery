"""
A seeded generator of small, benign JavaScript programs for differential fuzzing of the
deobfuscator. Each program is the *input* to the differential oracle in `differential`; the
deobfuscator must preserve its observable behavior, and Node.js, never this generator, decides
what that behavior is. The generator only has to produce programs well suited to *finding*
divergences; it never asserts what a program should print.

For a reported divergence to always mean a deobfuscator bug rather than a generator artifact,
every generated program upholds four invariants:

- **Valid**: it is syntactically correct and every identifier reference resolves to a name in
  scope, so it neither fails to parse nor throws a spurious `ReferenceError`.
- **Terminating**: loops have a constant bound, there is no `while`, and a function may only call
  functions declared before it, so the call graph is acyclic and no recursion can diverge.
- **Deterministic**: it uses no clock, randomness, `this`, host object, or reflective construct,
  so two runs of the same source always agree; that is the precondition the self-test checks
  before trusting any original-versus-deobfuscated comparison.
- **Observable**: a shared `SINK` array accumulates values that statements and impure functions
  push, and it is logged at the end, so a dropped effect, a mis-evaluation, or a reorder shows up.

The observable output deliberately excludes two things a deobfuscator may change without altering
meaning, so they cannot masquerade as divergences: a function's source text (a function is never
logged or kept as data — it is only called, including a function returned by another function, which
is invoked immediately, since `Function.prototype.toString` reflects the very source the deobfuscator
rewrites) and a self-referential structure (`SINK` is only pushed to and joined once at the end,
never nested into itself).

`generate(seed)` is a pure function of its integer seed, so any divergence reproduces from its
seed.
"""
from __future__ import annotations

import random

from dataclasses import dataclass, field

_BIN_OPS = ('+', '-', '*', '%', '<', '<=', '>', '>=', '===', '!==', '&&', '||')
_WORDS = ('ab', 'cd', 'ef', 'gh', 'ij', 'kl', 'mn', 'op')


@dataclass
class _Scope:
    """
    The names visible while generating one lexical region. `readable` is every name that may be
    referenced; `mutable` is the subset a plain assignment may target, so a `const` is never
    reassigned; `funcs` maps a callable function name to its arity. A child scope sees its parent's
    names through `parent`, modelling JS closure so nested functions may read outer variables.
    """
    parent: _Scope | None = None
    readable: list[str] = field(default_factory=list)
    mutable: set[str] = field(default_factory=set)
    funcs: list[tuple[str, int]] = field(default_factory=list)

    def child(self) -> _Scope:
        return _Scope(parent=self)

    def all_readable(self) -> list[str]:
        names = list(self.readable)
        if self.parent is not None:
            names += self.parent.all_readable()
        return names

    def all_mutable(self) -> list[str]:
        names = [n for n in self.readable if n in self.mutable]
        if self.parent is not None:
            names += self.parent.all_mutable()
        return names

    def all_funcs(self) -> list[tuple[str, int]]:
        items = list(self.funcs)
        if self.parent is not None:
            items += self.parent.all_funcs()
        return items


class _Generator:
    def __init__(self, seed: int):
        self.rng = random.Random(seed)
        self._counter = 0

    def generate(self) -> str:
        root = _Scope()
        lines = ['var SINK = [];']
        for _ in range(self.rng.randint(4, 11)):
            lines.extend(self._statement(root, depth=0))
        lines.append("console.log(SINK.join('|'));")
        return '\n'.join(lines)

    def _fresh(self) -> str:
        name = F'v{self._counter}'
        self._counter += 1
        return name

    def _statement(self, scope: _Scope, depth: int) -> list[str]:
        choices = ['decl', 'sink', 'log', 'expr']
        if depth < 2:
            choices += ['if', 'for', 'func', 'try']
        if scope.all_mutable():
            choices.append('assign')
        kind = self.rng.choice(choices)
        return getattr(self, F'_stmt_{kind}')(scope, depth)

    def _stmt_decl(self, scope: _Scope, depth: int) -> list[str]:
        name = self._fresh()
        keyword = self.rng.choice(('var', 'let', 'const'))
        value = self._expr(scope, 2)
        scope.readable.append(name)
        if keyword != 'const':
            scope.mutable.add(name)
        return [F'{keyword} {name} = {value};']

    def _stmt_assign(self, scope: _Scope, depth: int) -> list[str]:
        name = self.rng.choice(scope.all_mutable())
        return [F'{name} = {self._expr(scope, 2)};']

    def _stmt_sink(self, scope: _Scope, depth: int) -> list[str]:
        return [F'SINK.push({self._expr(scope, 2)});']

    def _stmt_log(self, scope: _Scope, depth: int) -> list[str]:
        return [F'console.log({self._expr(scope, 2)});']

    def _stmt_expr(self, scope: _Scope, depth: int) -> list[str]:
        return [F'{self._expr(scope, 2)};']

    def _stmt_if(self, scope: _Scope, depth: int) -> list[str]:
        head = F'if ({self._expr(scope, 2)}) {{'
        lines = [head]
        lines += self._indent(self._body(scope.child(), depth + 1))
        if self.rng.random() < 0.5:
            lines.append('} else {')
            lines += self._indent(self._body(scope.child(), depth + 1))
        lines.append('}')
        return lines

    def _stmt_for(self, scope: _Scope, depth: int) -> list[str]:
        counter = self._fresh()
        bound = self.rng.randint(0, 4)
        inner = scope.child()
        inner.readable.append(counter)
        lines = [F'for (let {counter} = 0; {counter} < {bound}; {counter}++) {{']
        lines += self._indent(self._body(inner, depth + 1))
        lines.append('}')
        return lines

    def _stmt_try(self, scope: _Scope, depth: int) -> list[str]:
        lines = ['try {']
        lines += self._indent(self._body(scope.child(), depth + 1))
        lines.append('} catch (e) {')
        handler = scope.child()
        handler.readable.append('e')
        handler.mutable.add('e')
        lines += self._indent(self._body(handler, depth + 1))
        lines.append('}')
        return lines

    def _stmt_func(self, scope: _Scope, depth: int) -> list[str]:
        name = self._fresh()
        arity = self.rng.randint(0, 2)
        params = [self._fresh() for _ in range(arity)]
        body_scope = scope.child()
        for param in params:
            body_scope.readable.append(param)
            body_scope.mutable.add(param)
        body = self._body(body_scope, depth + 1)
        body.append(F'return {self._expr(body_scope, 2)};')
        lines = [F'function {name}({", ".join(params)}) {{']
        lines += self._indent(body)
        lines.append('}')
        scope.funcs.append((name, arity))
        return lines

    def _body(self, scope: _Scope, depth: int) -> list[str]:
        lines: list[str] = []
        for _ in range(self.rng.randint(1, 3)):
            lines.extend(self._statement(scope, depth))
        return lines

    def _expr(self, scope: _Scope, depth: int) -> str:
        if depth <= 0:
            return self._atom(scope)
        kinds = ['atom', 'binary', 'unary', 'ternary', 'array', 'curry']
        funcs = scope.all_funcs()
        if funcs:
            kinds.append('call')
        kind = self.rng.choice(kinds)
        if kind == 'atom':
            return self._atom(scope)
        if kind == 'binary':
            op = self.rng.choice(_BIN_OPS)
            return F'({self._expr(scope, depth - 1)} {op} {self._expr(scope, depth - 1)})'
        if kind == 'unary':
            return F'({self.rng.choice(("!", "-"))}{self._expr(scope, depth - 1)})'
        if kind == 'ternary':
            return (
                F'({self._expr(scope, depth - 1)} ? {self._expr(scope, depth - 1)}'
                F' : {self._expr(scope, depth - 1)})')
        if kind == 'array':
            items = [self._expr(scope, depth - 1) for _ in range(self.rng.randint(0, 3))]
            return F'[{", ".join(items)}]'
        if kind == 'curry':
            return self._curry(scope, depth)
        name, arity = self.rng.choice(funcs)
        args = [self._expr(scope, depth - 1) for _ in range(arity)]
        return F'{name}({", ".join(args)})'

    def _curry(self, scope: _Scope, depth: int) -> str:
        """
        A curried IIFE `(function (p) { return function (q) { return BODY; }; })(arg)(arg)`. With even
        odds the inner parameter reuses the outer's name, so the inner function shadows it: inlining
        must keep the inner binding distinct. The returned function is invoked immediately, so only the
        final value — never a function — is observed.
        """
        outer = self._fresh()
        inner = outer if self.rng.random() < 0.5 else self._fresh()
        outer_scope = scope.child()
        outer_scope.readable.append(outer)
        outer_scope.mutable.add(outer)
        inner_scope = outer_scope.child()
        inner_scope.readable.append(inner)
        inner_scope.mutable.add(inner)
        body = self._expr(inner_scope, depth - 1)
        arg1 = self._expr(scope, depth - 1)
        arg2 = self._expr(scope, depth - 1)
        return (
            F'(function ({outer}) {{ return function ({inner}) {{ return {body}; }}; }})'
            F'({arg1})({arg2})')

    def _atom(self, scope: _Scope) -> str:
        names = scope.all_readable()
        kinds = ['int', 'string', 'bool']
        if names:
            kinds += ['name', 'name']
        kind = self.rng.choice(kinds)
        if kind == 'int':
            return str(self.rng.randint(0, 12))
        if kind == 'string':
            return F"'{self.rng.choice(_WORDS)}'"
        if kind == 'bool':
            return self.rng.choice(('true', 'false'))
        return self.rng.choice(names)

    @staticmethod
    def _indent(lines: list[str]) -> list[str]:
        return [F'  {line}' for line in lines]


def generate(seed: int) -> str:
    """
    Build the benign JavaScript program for *seed*. The same seed always yields the same source.
    """
    return _Generator(seed).generate()
