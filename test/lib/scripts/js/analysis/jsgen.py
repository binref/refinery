"""
A seeded generator of small, benign JavaScript programs, the input of the differential test that
compares what Node prints for a program and for its deobfuscation. A divergence must always mean a
deobfuscator defect and never a flaw of the program, so every generated program has to be:

- valid: it parses, and every name it reads is in scope;
- terminating: loops have a constant bound their body cannot change, and the call graph is acyclic,
  since a function calls only functions declared before it and a reassigned function calls nothing;
- deterministic: it reads no clock, no randomness and no host object, and uses `this` only where its
  value is fixed;
- observable: its effects are pushed to the array `SINK`, which is printed at the end.

Nothing whose printed form depends on source text may reach the output: a function never enters the
pool of readable names, so it is only ever called or handed to a call, and a caught exception is
never read, since its message and stack carry source positions the deobfuscator moves. `SINK` is
never pushed into itself.
"""
from __future__ import annotations

import random

from dataclasses import dataclass, field

_BIN_OPS = (
    '+', '-', '*', '%', '^', '<', '<=', '>', '>=', '===', '!==', '==', '!=', '&&', '||', '??',
)
_WORDS = ('ab', 'cd', 'ef', 'gh', 'ij', 'kl', 'mn', 'op')


@dataclass
class _Scope:
    """
    The names visible while generating one lexical region. `mutable` is the part of `readable` an
    assignment may target, `funcs` pairs each callable name with its arity, `objects` pairs each
    container name with its kind, `array` or `object`, and `mutators` pairs each function that
    changes its argument with the kind of container it must be passed.
    """
    parent: _Scope | None = None
    readable: list[str] = field(default_factory=list)
    mutable: set[str] = field(default_factory=set)
    funcs: list[tuple[str, int]] = field(default_factory=list)
    objects: list[tuple[str, str]] = field(default_factory=list)
    mutators: list[tuple[str, str]] = field(default_factory=list)

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

    def all_mutators(self) -> list[tuple[str, str]]:
        items = list(self.mutators)
        if self.parent is not None:
            items += self.parent.all_mutators()
        return items

    def mutator_candidates(self) -> list[tuple[str, str]]:
        kinds = {kind for _, kind in self.all_objects()}
        return [(name, kind) for name, kind in self.all_mutators() if kind in kinds]


class _Generator:
    def __init__(self, seed: int):
        self.rng = random.Random(seed)
        self._counter = 0
        self._global_counter = 0

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

    def _global_name(self) -> str:
        name = F'g{self._global_counter}'
        self._global_counter += 1
        return name

    def _statement(self, scope: _Scope, depth: int) -> list[str]:
        choices = ['decl', 'sink', 'log', 'expr', 'obj', 'object_destructure_decl', 'reflect']
        choices += ['arrow_callback', 'arrow_func']
        if depth < 2:
            choices += ['if', 'for', 'while', 'for_destructure', 'func', 'try', 'objfunc']
            choices += ['cross_call', 'confined_write', 'chain_across_writes', 'with', 'objadv']
            choices += ['throw']
            choices += ['switch', 'do_while', 'for_in', 'construct']
        if scope.all_mutable():
            choices.append('assign')
            choices.append('destructure')
            choices.append('object_destructure')
        objects = scope.all_objects()
        if objects:
            choices += ['member_write', 'alias']
            if len(objects) >= 2:
                choices.append('member_store')
            if scope.mutator_candidates():
                choices.append('mutate_call')
        funcs = scope.all_funcs()
        if funcs:
            choices += ['func_reassign', 'func_alias']
            if any(arity >= 1 for _, arity in funcs):
                choices.append('callback')
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
        op = self.rng.choice((
            '=', '=', '+=', '-=', '*=', '|=', '&=', '**=', '<<=', '||=', '&&=', '??=',
        ))
        return [F'{name} {op} {self._expr(scope, 2)};']

    def _stmt_destructure(self, scope: _Scope, depth: int) -> list[str]:
        name = self.rng.choice(scope.all_mutable())
        default = self._expr(scope, 1)
        items = [self._expr(scope, 1) for _ in range(self.rng.randint(0, 2))]
        return [F'[{name} = {default}] = [{", ".join(items)}];']

    def _stmt_object_destructure(self, scope: _Scope, depth: int) -> list[str]:
        name = self.rng.choice(scope.all_mutable())
        default = self._expr(scope, 1)
        if self.rng.random() < 0.5:
            source = F'{{{name}: {self._expr(scope, 1)}}}'
        else:
            source = '{}'
        return [F'({{{name} = {default}}} = {source});']

    def _stmt_object_destructure_decl(self, scope: _Scope, depth: int) -> list[str]:
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
        lines += self._indent(self._body(scope.child(), depth + 1))
        lines.append('}')
        return lines

    def _stmt_throw(self, scope: _Scope, depth: int) -> list[str]:
        body = self._body(scope.child(), depth + 1)
        body.append(F'throw {self._atom(scope)};')
        body.append(F'SINK.push({self._atom(scope)});')
        lines = ['try {']
        lines += self._indent(body)
        lines.append('} catch (e) {')
        lines += self._indent(self._body(scope.child(), depth + 1))
        if self.rng.random() < 0.5:
            lines.append('} finally {')
            lines += self._indent(self._body(scope.child(), depth + 1))
        lines.append('}')
        return lines

    def _stmt_switch(self, scope: _Scope, depth: int) -> list[str]:
        selector = self.rng.randint(0, 4)
        lines = [F'switch ({selector}) {{']
        for value in range(4):
            body = self._body(scope.child(), depth + 1)
            if self.rng.random() < 0.6:
                body.append('break;')
            lines.append(F'case {value}:')
            lines += self._indent(body)
        lines.append('default:')
        lines += self._indent(self._body(scope.child(), depth + 1))
        lines.append('}')
        return lines

    def _stmt_do_while(self, scope: _Scope, depth: int) -> list[str]:
        counter = self._fresh()
        bound = self.rng.randint(0, 3)
        inner = scope.child()
        inner.readable.append(counter)
        body = self._body(inner, depth + 1)
        body.append(F'{counter}++;')
        lines = [F'var {counter} = 0;', 'do {']
        lines += self._indent(body)
        lines.append(F'}} while ({counter} < {bound});')
        return lines

    def _stmt_for_in(self, scope: _Scope, depth: int) -> list[str]:
        obj = self._fresh()
        key = self._fresh()
        init = ', '.join(F'{name}: {self._expr(scope, 1)}' for name in ('p0', 'p1', 'p2'))
        inner = scope.child()
        inner.readable.append(key)
        body = [F'SINK.push({key});', F'SINK.push({obj}[{key}]);']
        body += self._body(inner, depth + 1)
        lines = [F'var {obj} = {{{init}}};', F'for (var {key} in {obj}) {{']
        lines += self._indent(body)
        lines.append('}')
        return lines

    def _stmt_func(self, scope: _Scope, depth: int) -> list[str]:
        name = self._fresh()
        arity = self.rng.randint(0, 2)
        lines = self._one_function(scope, depth, name, arity)
        if self.rng.random() < 0.15:
            lines += self._one_function(scope, depth, name, arity)
        scope.funcs.append((name, arity))
        return lines

    def _one_function(self, scope: _Scope, depth: int, name: str, arity: int) -> list[str]:
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
        return lines

    def _stmt_func_reassign(self, scope: _Scope, depth: int) -> list[str]:
        name, arity = self.rng.choice(scope.all_funcs())
        params = [self._fresh() for _ in range(arity)]
        body_scope = _Scope()
        for param in params:
            body_scope.readable.append(param)
            body_scope.mutable.add(param)
        body = self._expr(body_scope, 2)
        return [F'{name} = function ({", ".join(params)}) {{ return {body}; }};']

    def _stmt_func_alias(self, scope: _Scope, depth: int) -> list[str]:
        name, arity = self.rng.choice(scope.all_funcs())
        alias = self._fresh()
        scope.funcs.append((alias, arity))
        return [F'var {alias} = {name};']

    def _stmt_callback(self, scope: _Scope, depth: int) -> list[str]:
        candidates = [(name, arity) for name, arity in scope.all_funcs() if arity >= 1]
        name, _ = self.rng.choice(candidates)
        items = ', '.join(self._atom(scope) for _ in range(self.rng.randint(1, 3)))
        if self.rng.random() < 0.5:
            return [F"SINK.push([{items}].map({name}).join('|'));"]
        return [F'SINK.push([{items}].filter({name}).length);']

    def _stmt_arrow_callback(self, scope: _Scope, depth: int) -> list[str]:
        param = self._fresh()
        body_scope = _Scope()
        body_scope.readable.append(param)
        body_scope.mutable.add(param)
        body = self._expr(body_scope, 2)
        items = ', '.join(self._atom(scope) for _ in range(self.rng.randint(1, 3)))
        if self.rng.random() < 0.5:
            return [F"SINK.push([{items}].map(({param}) => {body}).join('|'));"]
        return [F'SINK.push([{items}].filter(({param}) => {body}).length);']

    def _stmt_arrow_func(self, scope: _Scope, depth: int) -> list[str]:
        name = self._fresh()
        param = self._fresh()
        body_scope = _Scope()
        body_scope.readable.append(param)
        body_scope.mutable.add(param)
        body = self._expr(body_scope, 2)
        scope.funcs.append((name, 1))
        return [F'var {name} = ({param}) => {body};', F'SINK.push({name}({self._atom(scope)}));']

    def _stmt_construct(self, scope: _Scope, depth: int) -> list[str]:
        ctor = self._fresh()
        obj = self._fresh()
        param = self._fresh()
        return [
            F'function {ctor}({param}) {{ this.p0 = {param}; this.p1 = {self.rng.randint(0, 12)}; }}',
            F'var {obj} = new {ctor}({self._atom(scope)});',
            F'SINK.push({obj}.p0);',
            F'SINK.push({obj}.p1);',
        ]

    def _stmt_cross_call(self, scope: _Scope, depth: int) -> list[str]:
        var = self._fresh()
        func = self._fresh()
        if self.rng.random() < 0.5:
            decl = F'var {var};'
        else:
            decl = F'var {var} = {self._atom(scope)};'
        lines = [decl, F'function {func}() {{ return {var}; }}', F'SINK.push({func}());']
        for _ in range(self.rng.randint(1, 3)):
            lines.append(F'{var} = {self._atom(scope)};')
            lines.append(F'SINK.push({func}());')
        return lines

    def _stmt_confined_write(self, scope: _Scope, depth: int) -> list[str]:
        var = self._fresh()
        func = self._fresh()
        body_scope = _Scope()
        body_scope.readable.append(var)
        body_scope.mutable.add(var)
        value = self._expr(body_scope, 1)
        lines = [
            F'var {var} = {self._atom(scope)};',
            F'function {func}() {{',
            F'  SINK.push({var});',
            F'  {var} = {value};',
            F'  SINK.push({var});',
            '}',
            F'{func}();',
        ]
        if self.rng.random() < 0.5:
            lines.append(F'{func}();')
        return lines

    def _stmt_chain_across_writes(self, scope: _Scope, depth: int) -> list[str]:
        var = self._fresh()
        setter = self._fresh()
        writer = self._fresh()
        lines = [
            F'var {var} = {self.rng.randint(0, 9)};',
            F'function {setter}() {{ {var} = {self.rng.randint(0, 9)}; }}',
            F'function {writer}() {{ {var} = {self.rng.randint(10, 99)}; }}',
            F'{setter}();',
        ]
        previous = var
        for _ in range(self.rng.randint(2, 4)):
            link = self._fresh()
            op = self.rng.choice(('+', '-', '*', '|', '^'))
            lines.append(F'var {link} = {previous} {op} {self.rng.randint(1, 9)};')
            previous = link
        lines.append(F'{writer}();')
        lines.append(F'SINK.push({previous});')
        return lines

    def _stmt_with(self, scope: _Scope, depth: int) -> list[str]:
        obj = self._fresh()
        var = self._fresh()
        keys = ('p0', 'p1', 'p2')
        props = [F'{key}: {self._expr(scope, 1)}' for key in keys]
        body_scope = scope.child()
        for key in keys:
            body_scope.readable.append(key)
        body_scope.readable.append(var)
        body_scope.mutable.add(var)
        body: list[str] = []
        for _ in range(self.rng.randint(2, 4)):
            body.extend(self._with_stmt(body_scope, keys))
        lines = [
            F'var {var} = {self._atom(scope)};',
            F'SINK.push({var});',
        ]
        if self.rng.random() < 0.5:
            getter = self._fresh()
            props.append(
                F"get {getter}() {{ SINK.push('g_{getter}'); return {self.rng.randint(0, 9)}; }}")
            lines.append(F'var {getter} = {self._atom(scope)};')
            lines.append(F'SINK.push({getter});')
            body.extend(self._with_getter_read(getter))
        if self.rng.random() < 0.4:
            prop, calls = self._with_reflect()
            props.append(prop)
            body.extend(calls)
        lines.append(F'var {obj} = {{{", ".join(props)}}};')
        lines.append(F'with ({obj}) {{')
        lines += self._indent(body)
        lines.append('}')
        lines.append(F'SINK.push({var});')
        lines.append(F'SINK.push({obj}.p0);')
        return lines

    def _with_getter_read(self, name: str) -> list[str]:
        literal = self.rng.randint(0, 9)
        form = self.rng.choice(('sequence', 'iife', 'iftest'))
        if form == 'sequence':
            return [F'SINK.push(({name}, {literal}));']
        if form == 'iife':
            param = self._fresh()
            return [F'SINK.push((function({param}) {{ return {literal}; }})({name}));']
        return [F'if ([{name}]) SINK.push({literal});']

    def _with_reflect(self) -> tuple[str, list[str]]:
        left = self.rng.randint(0, 9)
        right = self.rng.randint(1, 9)
        op = self.rng.choice(('+', '-', '*'))
        form = self.rng.choice(('eval', 'indirect_eval', 'chain'))
        if form == 'chain':
            base = self._fresh()
            word = self.rng.choice(_WORDS)
            prop = F"get {base}() {{ SINK.push('g_{base}'); return '{word}'; }}"
            call = F"{base}.constructor.constructor('return {left} {op} {right}')()"
            return prop, [F'SINK.push({call});']
        result = self.rng.randint(0, 9)
        callee = 'eval' if form == 'eval' else '(0, eval)'
        prop = F"get eval() {{ SINK.push('g_eval'); return function (s) {{ return {result}; }}; }}"
        return prop, [F'SINK.push({callee}("{left} {op} {right}"));']

    def _with_stmt(self, scope: _Scope, keys: tuple[str, ...]) -> list[str]:
        """
        One statement of a `with` body. The keys of the object are write targets here but never
        enter `mutable`: a value expression may `delete` a mutable name, and once a key is deleted
        from the object, a later bare read of it throws.
        """
        kinds = ['read', 'write', 'compound']
        funcs = scope.all_funcs()
        if funcs:
            kinds.append('call')
        kind = self.rng.choice(kinds)
        if kind == 'read':
            return [F'SINK.push({self._atom(scope)});']
        if kind == 'call':
            name, arity = self.rng.choice(funcs)
            args = ', '.join(self._atom(scope) for _ in range(arity))
            return [F'SINK.push({name}({args}));']
        target = self.rng.choice([*keys, *scope.all_mutable()])
        if kind == 'compound':
            op = self.rng.choice(('+=', '-=', '*=', '|=', '&='))
            return [F'{target} {op} {self._expr(scope, 1)};']
        return [F'{target} = {self._expr(scope, 1)};']

    def _stmt_reflect(self, scope: _Scope, depth: int) -> list[str]:
        kinds = ['eval_expr', 'eval_global', 'function_ctor', 'return_this', 'global_write_read']
        if scope.all_mutable():
            kinds.append('eval_assign_local')
        return getattr(self, F'_reflect_{self.rng.choice(kinds)}')(scope)

    def _reflect_eval_expr(self, scope: _Scope) -> list[str]:
        left = self.rng.randint(0, 9)
        right = self.rng.randint(1, 9)
        op = self.rng.choice(('+', '-', '*'))
        form = self.rng.choice(('eval', '(eval)'))
        return [F'SINK.push({form}("{left} {op} {right}"));']

    def _reflect_eval_assign_local(self, scope: _Scope) -> list[str]:
        name = self.rng.choice(scope.all_mutable())
        value = self.rng.randint(0, 12)
        return [F'eval("{name} = {value}");', F'SINK.push({name});']

    def _reflect_eval_global(self, scope: _Scope) -> list[str]:
        name = self._global_name()
        value = self.rng.randint(0, 12)
        return [F'(0, eval)("{name} = {value};");', F'SINK.push(globalThis.{name});']

    def _reflect_function_ctor(self, scope: _Scope) -> list[str]:
        name = self._fresh()
        param = self._fresh()
        value = self.rng.randint(0, 9)
        op = self.rng.choice(('+', '-', '*'))
        ctor = self.rng.choice(('Function', 'new Function'))
        scope.funcs.append((name, 1))
        return [
            F'var {name} = {ctor}("{param}", "return {param} {op} {value};");',
            F'SINK.push({name}({self.rng.randint(0, 9)}));',
        ]

    def _reflect_return_this(self, scope: _Scope) -> list[str]:
        obj = self._fresh()
        name = self._global_name()
        value = self.rng.randint(0, 12)
        return [
            F'var {obj} = Function("return this")();',
            F'{obj}.{name} = {value};',
            F'SINK.push(globalThis.{name});',
        ]

    def _reflect_global_write_read(self, scope: _Scope) -> list[str]:
        name = self._global_name()
        value = self.rng.randint(0, 12)
        return [F'globalThis.{name} = {value};', F'SINK.push(globalThis.{name});']

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
        scope.mutators.append((name, 'array'))
        return lines

    def _stmt_mutate_call(self, scope: _Scope, depth: int) -> list[str]:
        mutator, kind = self.rng.choice(scope.mutator_candidates())
        name = self.rng.choice([n for n, k in scope.all_objects() if k == kind])
        return [
            F'{mutator}({name});',
            F'SINK.push({name}[0]);',
        ]

    def _stmt_objadv(self, scope: _Scope, depth: int) -> list[str]:
        kind = self.rng.choice(('accessor', 'proto', 'method', 'self_ref'))
        return getattr(self, F'_obj_{kind}')(scope)

    def _obj_accessor(self, scope: _Scope) -> list[str]:
        obj = self._fresh()
        store = self._fresh()
        return [
            F'var {store} = {self.rng.randint(0, 12)};',
            F'var {obj} = {{',
            F'  get p0() {{ return {store}; }},',
            F'  set p0(v) {{ {store} = v; SINK.push(v); }},',
            F'  p1: {self._expr(scope, 1)},',
            '};',
            F'SINK.push({obj}.p0);',
            F'{obj}.p0 = {self.rng.randint(0, 12)};',
            F'{obj}.p0 += {self.rng.randint(0, 12)};',
            F'SINK.push({obj}.p1);',
        ]

    def _obj_proto(self, scope: _Scope) -> list[str]:
        base = self._fresh()
        obj = self._fresh()
        base_init = ', '.join(F'{key}: {self._atom(scope)}' for key in ('p0', 'p1', 'p2'))
        lines = [F'var {base} = {{{base_init}}};']
        if self.rng.random() < 0.5:
            lines.append(F'var {obj} = {{__proto__: {base}, p0: {self._atom(scope)}}};')
            lines.append(F'SINK.push({obj}.p0);')
            lines.append(F'SINK.push({obj}.p1);')
        else:
            lines.append(F"var {obj} = {{['__proto__']: {base}, p0: {self._atom(scope)}}};")
            lines.append(F'SINK.push({obj}.p0);')
            lines.append(F'SINK.push({obj}.p1 === undefined);')
        return lines

    def _obj_method(self, scope: _Scope) -> list[str]:
        obj = self._fresh()
        body = self._expr(_Scope(), 2)
        return [
            F'var {obj} = {{ m0() {{ return {body}; }}, p1: {self._expr(scope, 1)} }};',
            F'SINK.push({obj}.m0());',
            F'SINK.push({obj}.p1);',
        ]

    def _obj_self_ref(self, scope: _Scope) -> list[str]:
        obj = self._fresh()
        return [
            F'var {obj} = {{',
            F'  p0: {self.rng.randint(0, 12)},',
            F'  p1: {self._expr(scope, 1)},',
            F'  f: function() {{ return {obj}.p0; }},',
            '};',
            F'SINK.push({obj}.f());',
        ]

    def _body(self, scope: _Scope, depth: int) -> list[str]:
        lines: list[str] = []
        for _ in range(self.rng.randint(1, 3)):
            lines.extend(self._statement(scope, depth))
        return lines

    def _expr(self, scope: _Scope, depth: int) -> str:
        if depth <= 0:
            return self._atom(scope)
        kinds = ['atom', 'binary', 'unary', 'ternary', 'array', 'curry', 'sequence']
        kinds += ['typeof', 'template', 'instanceof', 'builtin']
        funcs = scope.all_funcs()
        if funcs:
            kinds.append('call')
        objects = scope.all_objects()
        if objects:
            kinds += ['computed', 'optional', 'contains']
        if scope.all_mutable():
            kinds.append('assign')
            kinds.append('update')
            kinds.append('delete')
        kind = self.rng.choice(kinds)
        if kind == 'atom':
            return self._atom(scope)
        if kind == 'binary':
            op = self.rng.choice(_BIN_OPS)
            return F'({self._expr(scope, depth - 1)} {op} {self._expr(scope, depth - 1)})'
        if kind == 'typeof':
            return F'(typeof {self._expr(scope, depth - 1)})'
        if kind == 'template':
            return '`' + self.rng.choice(_WORDS) + '${' + self._expr(scope, depth - 1) + '}`'
        if kind == 'instanceof':
            return F'({self._expr(scope, depth - 1)} instanceof {self.rng.choice(("Array", "Object"))})'
        if kind == 'builtin':
            return self._builtin_call(scope, depth)
        if kind == 'computed':
            name, okind = self.rng.choice(objects)
            return self._computed_member(name, okind)
        if kind == 'optional':
            name, okind = self.rng.choice(objects)
            if okind == 'array':
                return F'{name}?.[{self.rng.randint(0, 2)}]'
            return F'{name}?.{self.rng.choice(("p0", "p1", "p2"))}'
        if kind == 'contains':
            name, _ = self.rng.choice(objects)
            return F"('{self.rng.choice(('p0', 'p1', 'p2'))}' in {name})"
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
        if kind == 'sequence':
            return F'({self._expr(scope, depth - 1)}, {self._expr(scope, depth - 1)})'
        if kind == 'assign':
            name = self.rng.choice(scope.all_mutable())
            return F'({name} = {self._expr(scope, depth - 1)})'
        if kind == 'update':
            name = self.rng.choice(scope.all_mutable())
            op = self.rng.choice(('++', '--'))
            return F'({name}{op})' if self.rng.random() < 0.5 else F'({op}{name})'
        if kind == 'delete':
            name = self.rng.choice(scope.all_mutable())
            return F'(delete {name})'
        name, arity = self.rng.choice(funcs)
        args = [self._expr(scope, depth - 1) for _ in range(arity)]
        form = self.rng.choice(('direct', 'direct', 'paren', 'call'))
        if form == 'paren':
            return F'({name})({", ".join(args)})'
        if form == 'call':
            return F'{name}.call({", ".join(["null", *args])})'
        return F'{name}({", ".join(args)})'

    def _builtin_call(self, scope: _Scope, depth: int) -> str:
        arrays = [name for name, kind in scope.all_objects() if kind == 'array']
        kinds = ['math2', 'math1', 'convert', 'decode']
        if arrays:
            kinds.append('arraymethod')
        kind = self.rng.choice(kinds)
        if kind == 'math2':
            fn = self.rng.choice(('max', 'min'))
            return F'Math.{fn}({self._expr(scope, depth - 1)}, {self._expr(scope, depth - 1)})'
        if kind == 'math1':
            fn = self.rng.choice(('abs', 'floor', 'round'))
            return F'Math.{fn}({self._expr(scope, depth - 1)})'
        if kind == 'convert':
            fn = self.rng.choice(('String', 'Number', 'Boolean'))
            return F'{fn}({self._expr(scope, depth - 1)})'
        if kind == 'decode':
            return self._decoder_chain()
        arr = self.rng.choice(arrays)
        method = self.rng.choice(('join', 'indexOf', 'slice', 'map', 'filter', 'length'))
        if method == 'join':
            return F"{arr}.join(',')"
        if method == 'indexOf':
            return F'{arr}.indexOf({self._atom(scope)})'
        if method == 'map':
            return F"{arr}.map(function (c) {{ return String(c) + '!'; }}).join(',')"
        if method == 'filter':
            return F'{arr}.filter(function (c) {{ return c !== undefined; }}).length'
        if method == 'length':
            return F'{arr}.length'
        return F"{arr}.slice(1).join(',')"

    def _decoder_chain(self) -> str:
        form = self.rng.choice(('xor', 'plain', 'reverse', 'indexed'))
        if form == 'reverse':
            word = self.rng.choice(_WORDS)
            return F"'{word}'.split('').reverse().join('')"
        if form == 'indexed':
            word = self.rng.choice(_WORDS)
            return F"'{word}'.split('')[{self.rng.randint(0, 1)}]"
        codes = [self.rng.randint(0x41, 0x5A) for _ in range(self.rng.randint(1, 4))]
        if form == 'plain':
            body = 'return String.fromCharCode(c);'
        else:
            mask = self.rng.randint(1, 0x3F)
            body = F'return String.fromCharCode(c ^ {mask});'
            codes = [c ^ mask for c in codes]
        listing = ', '.join(str(c) for c in codes)
        return F"[{listing}].map(function (c) {{ {body} }}).join('')"


    def _computed_member(self, name: str, kind: str) -> str:
        if kind == 'array':
            return F'{name}[{self.rng.randint(0, 2)}]'
        return F"{name}['{self.rng.choice(('p0', 'p1', 'p2'))}']"

    def _curry(self, scope: _Scope, depth: int) -> str:
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
