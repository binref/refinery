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

The generator also builds objects and arrays and mutates them in place, so the deobfuscator's
member-write reasoning is exercised: a fresh array or object is bound to a local, its elements are
assigned, incremented, and deleted, and the object is aliased to a second binding, passed to a
function that mutates it, and stored inside another object — the escape and aliasing shapes under
which a member-write is observable. A stored property may hold another object, so an object
reference can itself reach `SINK`; the final `join` stringifies it identically on both runs, so it
cannot masquerade as a divergence, and `SINK` — never one of the pooled objects — is still never
nested into itself. A function remains something only ever called.

A `for-of` loop also reassigns outer bindings by destructuring each element of a constant array of
arrays through a rest target in its head (`for ([w0, ...w1] of ...)`). Because the head carries no
`var`/`let`/`const`, the rest target is an assignment target that parses as an array literal with a
spread — a different node shape than the array pattern a plain `[w0, ...w1] = xs` uses — so the
deobfuscator's write-target classification of a spread in a literal-shaped for-head is exercised.

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
    reassigned; `funcs` maps a callable function name to its arity. `objects` records each name bound
    to a fresh array or object together with its kind, so member accesses pick a valid key; `mutators`
    lists functions that mutate an object passed to them. A child scope sees its parent's names
    through `parent`, modelling JS closure so nested functions may read outer variables.
    """
    parent: _Scope | None = None
    readable: list[str] = field(default_factory=list)
    mutable: set[str] = field(default_factory=set)
    funcs: list[tuple[str, int]] = field(default_factory=list)
    objects: list[tuple[str, str]] = field(default_factory=list)
    mutators: list[str] = field(default_factory=list)

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

    def all_objects(self) -> list[tuple[str, str]]:
        items = list(self.objects)
        if self.parent is not None:
            items += self.parent.all_objects()
        return items

    def all_mutators(self) -> list[str]:
        items = list(self.mutators)
        if self.parent is not None:
            items += self.parent.all_mutators()
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
        choices = ['decl', 'sink', 'log', 'expr', 'obj', 'object_destructure_decl']
        if depth < 2:
            choices += ['if', 'for', 'while', 'for_destructure', 'func', 'try', 'objfunc']
        if scope.all_mutable():
            choices.append('assign')
            choices.append('destructure')
            choices.append('object_destructure')
        objects = scope.all_objects()
        if objects:
            choices += ['member_write', 'alias']
            if len(objects) >= 2:
                choices.append('member_store')
            if scope.all_mutators():
                choices.append('mutate_call')
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
        """
        A simple, compound, or logical assignment to a mutable binding (`name = e`, `name += e`,
        `name ||= e`, ...). A compound form makes *name* a READWRITE reference — read and written in
        one operation — and a logical form (`||=`/`&&=`/`??=`) writes it only conditionally
        (short-circuit), exercising the deobfuscator's classification of a target that is read and
        (maybe) written, which a plain `=` (write-only) does not.
        """
        name = self.rng.choice(scope.all_mutable())
        op = self.rng.choice((
            '=', '=', '+=', '-=', '*=', '|=', '&=', '**=', '<<=', '||=', '&&=', '??=',
        ))
        return [F'{name} {op} {self._expr(scope, 2)};']

    def _stmt_destructure(self, scope: _Scope, depth: int) -> list[str]:
        """
        An array-destructuring assignment with a default, `[name = d] = [items];`, exercising the
        deobfuscator's write-target classification of a destructuring default: *name* is reassigned to
        the first element of the fresh array, or to *d* when the array is too short, and a later read of
        the mutable *name* observes whichever it became.
        """
        name = self.rng.choice(scope.all_mutable())
        default = self._expr(scope, 1)
        items = [self._expr(scope, 1) for _ in range(self.rng.randint(0, 2))]
        return [F'[{name} = {default}] = [{", ".join(items)}];']

    def _stmt_object_destructure(self, scope: _Scope, depth: int) -> list[str]:
        """
        An object-destructuring assignment with a shorthand default, `({name = d} = src);`,
        exercising the parser's CoverInitializedName handling and the synthesizer's
        shorthand-default emission: *name* is reassigned to the source's matching property, or to
        *d* when the property is absent, and a later read of the mutable *name* observes whichever
        it became.
        """
        name = self.rng.choice(scope.all_mutable())
        default = self._expr(scope, 1)
        if self.rng.random() < 0.5:
            source = F'{{{name}: {self._expr(scope, 1)}}}'
        else:
            source = '{}'
        return [F'({{{name} = {default}}} = {source});']

    def _stmt_object_destructure_decl(self, scope: _Scope, depth: int) -> list[str]:
        """
        A destructuring DECLARATION with a shorthand default that re-declares (with `var`) a name
        first bound to a constant — `var name = <lit>; var {name = d} = src;` — exercising
        constant-inlining's handling of a constant rebound by a destructuring binding target (rather
        than an assignment target). The re-declaration sets *name* to the source's property or to
        *d*, which a later read of the mutable *name* observes.
        """
        name = self._fresh()
        scope.readable.append(name)
        scope.mutable.add(name)
        default = self._expr(scope, 1)
        if self.rng.random() < 0.5:
            source = F'{{{name}: {self._expr(scope, 1)}}}'
        else:
            source = '{}'
        return [
            F'var {name} = {self.rng.randint(0, 12)};',
            F'var {{{name} = {default}}} = {source};',
        ]

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

    def _stmt_while(self, scope: _Scope, depth: int) -> list[str]:
        """
        A `while` loop over a bounded counter that terminates via an explicit increment at the end of
        the body, so the generated program always halts. The counter is read-only to the body (it is
        not in *mutable*), so only the trailing increment advances it. Exercises the control-flow and
        dead-code transforms on a loop form other than `for`.
        """
        counter = self._fresh()
        bound = self.rng.randint(0, 4)
        inner = scope.child()
        inner.readable.append(counter)
        body = self._body(inner, depth + 1)
        body.append(F'{counter}++;')
        lines = [F'var {counter} = 0;', F'while ({counter} < {bound}) {{']
        lines += self._indent(body)
        lines.append('}')
        return lines

    def _stmt_for_destructure(self, scope: _Scope, depth: int) -> list[str]:
        """
        A `for-of` loop whose head is a destructuring-assignment target ending in a rest element,
        `for ([w0, ...w1] of [[..], ..]) { ... }`. The head carries no `var`/`let`/`const`, so its
        targets are assignment targets that parse as an array literal with a spread — the literal-shaped
        form whose write-target classification the deobfuscator must get right — and each iteration
        reassigns the outer bindings. The rest binding is tracked as an array so it is only ever read
        through a member, and a body read of an element and of the rest observes the writes.
        """
        leading = [self._fresh() for _ in range(self.rng.randint(0, 2))]
        rest = self._fresh()
        rows: list[str] = []
        for _ in range(self.rng.randint(1, 3)):
            width = self.rng.randint(len(leading), len(leading) + 2)
            rows.append(F'[{", ".join(self._atom(scope) for _ in range(width))}]')
        inits = [F'var {name} = {self._expr(scope, 1)};' for name in leading]
        for name in leading:
            scope.readable.append(name)
            scope.mutable.add(name)
        scope.objects.append((rest, 'array'))
        inner = scope.child()
        body = [F'SINK.push({self._member(rest, "array")});']
        body += [F'SINK.push({name});' for name in leading]
        body += self._body(inner, depth + 1)
        targets = ', '.join([*leading, F'...{rest}'])
        lines = [*inits, F'var {rest} = [];', F'for ([{targets}] of [{", ".join(rows)}]) {{']
        lines += self._indent(body)
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
        signature = list(params)
        prefix: list[str] = []
        if self.rng.random() < 0.4:
            rest = self._fresh()
            body_scope.objects.append((rest, 'array'))
            signature.append(F'...{rest}')
            prefix.append(F'{rest}[0] = {self._expr(body_scope, 1)};')
        body = prefix + self._body(body_scope, depth + 1)
        body.append(F'return {self._expr(body_scope, 2)};')
        lines = [F'function {name}({", ".join(signature)}) {{']
        lines += self._indent(body)
        lines.append('}')
        scope.funcs.append((name, arity))
        return lines

    def _stmt_obj(self, scope: _Scope, depth: int) -> list[str]:
        name = self._fresh()
        kind = self.rng.choice(('array', 'object'))
        if kind == 'array':
            items = [self._expr(scope, 1) for _ in range(self.rng.randint(0, 3))]
            init = F'[{", ".join(items)}]'
        else:
            parts = [F'{key}: {self._expr(scope, 1)}' for key in ('p0', 'p1', 'p2')]
            init = F'{{{", ".join(parts)}}}'
        scope.objects.append((name, kind))
        return [F'var {name} = {init};']

    def _stmt_member_write(self, scope: _Scope, depth: int) -> list[str]:
        name, kind = self.rng.choice(scope.all_objects())
        target = self._member(name, kind)
        form = self.rng.choice(('assign', 'compound', 'incr', 'decr', 'delete'))
        if form == 'assign':
            return [F'{target} = {self._expr(scope, 2)};']
        if form == 'compound':
            op = self.rng.choice(('+=', '-=', '*=', '|=', '&='))
            return [F'{target} {op} {self._expr(scope, 2)};']
        if form == 'incr':
            return [F'{target}++;']
        if form == 'decr':
            return [F'--{target};']
        return [F'delete {target};']

    def _stmt_alias(self, scope: _Scope, depth: int) -> list[str]:
        name, kind = self.rng.choice(scope.all_objects())
        alias = self._fresh()
        scope.objects.append((alias, kind))
        return [F'var {alias} = {name};']

    def _stmt_member_store(self, scope: _Scope, depth: int) -> list[str]:
        objects = scope.all_objects()
        container, kind = self.rng.choice(objects)
        value, _ = self.rng.choice([entry for entry in objects if entry[0] != container])
        return [F'{self._member(container, kind)} = {value};']

    def _stmt_objfunc(self, scope: _Scope, depth: int) -> list[str]:
        name = self._fresh()
        param = self._fresh()
        body_scope = scope.child()
        body_scope.objects.append((param, 'array'))
        body = [F'{param}[0] = {self._expr(body_scope, 1)};']
        for _ in range(self.rng.randint(0, 2)):
            body.extend(self._statement(body_scope, depth + 1))
        body.append(F'return {self._member(param, "array")};')
        lines = [F'function {name}({param}) {{']
        lines += self._indent(body)
        lines.append('}')
        scope.mutators.append(name)
        return lines

    def _stmt_mutate_call(self, scope: _Scope, depth: int) -> list[str]:
        name, kind = self.rng.choice(scope.all_objects())
        mutator = self.rng.choice(scope.all_mutators())
        return [
            F'{mutator}({name});',
            F'SINK.push({name}[0]);',
        ]

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
        if scope.all_mutable():
            kinds.append('assign')
            kinds.append('update')
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
        if kind == 'assign':
            name = self.rng.choice(scope.all_mutable())
            return F'({name} = {self._expr(scope, depth - 1)})'
        if kind == 'update':
            name = self.rng.choice(scope.all_mutable())
            op = self.rng.choice(('++', '--'))
            return F'({name}{op})' if self.rng.random() < 0.5 else F'({op}{name})'
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

    def _member(self, name: str, kind: str) -> str:
        """
        A member access on object *name*: a bracketed integer index for an array, a dotted property
        for an object. Reads and writes share this one small key space, so a write to a name is
        observable through a later read of the same name.
        """
        if kind == 'array':
            return F'{name}[{self.rng.randint(0, 2)}]'
        return F'{name}.{self.rng.choice(("p0", "p1", "p2"))}'

    def _atom(self, scope: _Scope) -> str:
        names = scope.all_readable()
        objects = scope.all_objects()
        kinds = ['int', 'string', 'bool']
        if names:
            kinds += ['name', 'name']
        if objects:
            kinds.append('member')
        kind = self.rng.choice(kinds)
        if kind == 'int':
            return str(self.rng.randint(0, 12))
        if kind == 'string':
            return F"'{self.rng.choice(_WORDS)}'"
        if kind == 'bool':
            return self.rng.choice(('true', 'false'))
        if kind == 'member':
            name, okind = self.rng.choice(objects)
            return self._member(name, okind)
        return self.rng.choice(names)

    @staticmethod
    def _indent(lines: list[str]) -> list[str]:
        return [F'  {line}' for line in lines]


def generate(seed: int) -> str:
    """
    Build the benign JavaScript program for *seed*. The same seed always yields the same source.
    """
    return _Generator(seed).generate()
