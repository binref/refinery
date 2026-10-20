"""
Function flattening moves the body of a function into a flat function at the top of the program and
leaves the function a wrapper that calls it with its arguments and with an object of getters,
setters and methods standing for the names the body used. Each program below holds functions in
that shape, written by hand after what the obfuscation writes, and each row says what Node prints
for it run as a CommonJS file; the deobfuscation prints the same. Where the deobfuscation puts the
body back into its wrapper, or moves the flat function of an async function into it, the text it
writes is pinned as well.
"""
from __future__ import annotations

import inspect
import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import deobfuscate_source, node_executable
from test.lib.scripts.js.ledger import Program, Reading, a_program, prints, wontfix

from refinery.lib.scripts.js.analysis.environment import HostEnvironment
from refinery.lib.scripts.js.options import ExecutionModel


def deobfuscated(source: str) -> str:
    return deobfuscate_source(source, execution=ExecutionModel.commonjs, environment=HostEnvironment.node)


#: Programs holding functions in the shape function flattening writes, mapped to what Node prints for
#: each run as a CommonJS file.
FLATTENED: dict[str, Program] = {
    'setters of every write form': Program(
        a_program("""
            function F([step], O) { O.k1 += step; O.k1++; [O.k2] = ['b' + step]; for (O.k2 of ['c', 'd']) {} for (O.k2 in { e: 1 }) {} O.k2 = O.k2 + '!'; return O.k1 + O.k2; }
            var counter = 0; let label = 'a';
            function bump(...A) { var O = { get k1() { return counter; }, get k2() { return label; }, set k1(v) { counter = v; }, set k2(v) { label = v; } }; return F(A, O); }
            console.log(bump(2), counter, label);
            """),
        prints('3e! 3 e!'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'typeof members': Program(
        a_program("""
            function F([v], O) { return O.t1 + ':' + typeof v + ':' + O.t2; }
            var later; function helper() {}
            function kind(...A) { var O = { get t1() { return typeof later; }, get t2() { return typeof helper; } }; return F(A, O); }
            console.log(kind(1)); later = 1; console.log(kind('x'));
            """),
        prints('undefined:number:function', 'number:string:function'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'call members, new through a getter, recursion': Program(
        a_program("""
            class Box { constructor(v) { this.v = v; } }
            function twice(x) { return x * 2; }
            function F([n], O) { if (n <= 0) { return new O.g1(0); } return new O.g1(O.c1(n) + O.c2(n - 1).v); }
            function sum(...A) { var O = { get g1() { return Box; }, c1(...args) { return twice(...args); }, c2(...args) { return sum(...args); } }; return F(A, O); }
            console.log(sum(3).v);
            """),
        prints('12'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a default reading an outer name before the object is bound (arguments first)': Program(
        a_program("""
            const LIMIT = 3;
            function F([a, b = O.k], O) { return a + b; }
            function add(...A) { var O = { get k() { return LIMIT; } }; return F(A, O); }
            console.log(add(1, 2));
            try { console.log(add(1)); } catch (e) { console.log(e.name); }
            """),
        prints('3', 'ReferenceError'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a default reading an outer name (object first)': Program(
        a_program("""
            const LIMIT = 3;
            function F(O, [a, b = O.k]) { return a + b; }
            function add(...A) { var O = { get k() { return LIMIT; } }; return F(O, A); }
            console.log(add(1, 2), add(1));
            """),
        prints('3 4'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a local of the flat function named like an outer name it reads': Program(
        a_program("""
            var a = 'outer';
            function F([], O) { var a = 'inner'; return O.k + a; }
            function show(...A) { var O = { get k() { return a; } }; return F(A, O); }
            console.log(show());
            """),
        prints('outerinner'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a name the flat function reads directly is bound around the wrapper': Program(
        a_program("""
            var log = function (s) { console.log('top ' + s); };
            function F([], O) { log('x'); }
            function outer() { var log = function (s) { console.log('inner ' + s); }; function W(...A) { var O = {}; return F(A, O); } log('y'); return W(); }
            outer();
            """),
        prints('inner y', 'top x'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'this in an arrow of the flat function': Program(
        a_program("""
            function F([], O) { return (() => this === undefined || this === globalThis)(); }
            var holder = { read(...A) { var O = {}; return F(A, O); } };
            console.log(holder.read());
            """),
        prints('true'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'arguments in an arrow of the flat function': Program(
        a_program("""
            function F([a], O) { return (() => arguments.length)(); }
            function count(...A) { var O = {}; return F(A, O); }
            console.log(count(1, 2, 3));
            """),
        prints('2'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a const written through a getter without setter (object first, sloppy)': Program(
        a_program("""
            const C = 1;
            function F(O, []) { O.k = 2; return O.k; }
            function write(...A) { var O = { get k() { return C; } }; return F(O, A); }
            console.log(write());
            """),
        prints('1'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'an optional call through a getter': Program(
        a_program("""
            var maybe = function () { return this === undefined || this === globalThis ? 'plain' : 'bound'; };
            function F([], O) { return O.k?.(); }
            function call(...A) { var O = { get k() { return maybe; } }; return F(A, O); }
            console.log(call());
            """),
        prints('bound'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a tagged template through a getter': Program(
        a_program("""
            var tag = function () { return this === undefined || this === globalThis ? 'plain' : 'bound'; };
            function F([], O) { return O.k`x`; }
            function call(...A) { var O = { get k() { return tag; } }; return F(A, O); }
            console.log(call());
            """),
        prints('bound'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a call member whose arguments reassign the callee': Program(
        a_program("""
            var f = function (x) { return 'old ' + x; };
            var g = function (x) { return 'new ' + x; };
            function F([], O) { return O.c((O.k = g, 1)); }
            function run(...A) { var O = { get k() { return f; }, set k(v) { f = v; }, c(...args) { return f(...args); } }; return F(A, O); }
            console.log(run());
            """),
        prints('new 1'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a call member in the dead zone of its callee': Program(
        a_program("""
            function F([], O) { return O.c(console.log('arg')); }
            function run(...A) { var O = { c(...args) { return helper(...args); } }; return F(A, O); }
            try { run(); } catch (e) { console.log(e.name); }
            const helper = function () { return 1; };
            """),
        prints('arg', 'ReferenceError'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'the length of the wrapper is read': Program(
        a_program("""
            function F([a, b], O) { return a + b; }
            function add(...A) { var O = {}; return F(A, O); }
            console.log(add.length, add(1, 2));
            """),
        prints('0 3'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'the length helper of the obfuscator': Program(
        a_program("""
            function H(fn, length = 1) { Object.defineProperty(fn, 'length', { value: length, configurable: false }); return fn; }
            H(add, 2);
            function F([a, b], O) { return a + b; }
            function add(...A) { var O = {}; return F(A, O); }
            console.log(add.length, add(1, 2), Object.getOwnPropertyDescriptor(add, 'length').configurable);
            """),
        prints('2 3 false'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'an async function racing a promise chain': Program(
        a_program("""
            async function F([], O) { console.log('a'); }
            async function a(...A) { var O = {}; return F(A, O); }
            (async () => { await a(); console.log('after a'); })();
            Promise.resolve().then(() => console.log(1)).then(() => console.log(2)).then(() => console.log(3));
            """),
        prints('a', '1', '2', 'after a', '3'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'the strict form (arguments first)': Program(
        a_program("""
            'use strict';
            var total = 0;
            function F() { 'use strict'; var [[a, b = 1], O] = arguments; O.k = O.k + a + b; return O.k; }
            function addTo(...A) { var O = { get k() { return total; }, set k(v) { total = v; } }; return F(A, O); }
            console.log(addTo(2), addTo(3, 4));
            """),
        prints('3 10'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'the strict form (object first) with a default reading an outer name': Program(
        a_program("""
            'use strict';
            const STEP = 5;
            function F() { 'use strict'; var [O, [a, b = O.k]] = arguments; return a + b; }
            function addTo(...A) { var O = { get k() { return STEP; } }; return F(O, A); }
            console.log(addTo(2), addTo(3, 4));
            """),
        prints('7 7'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'the strict form with a body function named like a parameter': Program(
        a_program("""
            'use strict';
            function F() { 'use strict'; var [[g], O] = arguments; function g() { return 'fn'; } return typeof g; }
            function W(...A) { var O = {}; return F(A, O); }
            console.log(W(5));
            """),
        prints('number'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a static method of a class in the strict form': Program(
        a_program("""
            function F() { 'use strict'; var [[v], O] = arguments; return O.c(v); }
            function double(x) { return x * 2; }
            class Tool { static twice(...A) { var O = { c(...args) { return double(...args); } }; return F(A, O); } }
            console.log(Tool.twice(4), Tool.twice.length);
            """),
        prints('8 0'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a function flattened inside a flattened function (arguments first)': Program(
        a_program("""
            function F_outer([x], Oo) {
            function inner(...Ai) { var Oi = { get kx() { return x; }, get kb() { return Oo.kb2; } }; return Oo.cF(Ai, Oi); }
            return inner(1) + inner(2);
            }
            function F_inner([y], Oi) { return Oi.kx + y + Oi.kb; }
            var base = 10;
            function outer(...Ao) { var Oo = { get kb2() { return base; }, cF(...args) { return F_inner(...args); } }; return F_outer(Ao, Oo); }
            console.log(outer(5));
            """),
        prints('33'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a function flattened inside a flattened function (object first)': Program(
        a_program("""
            function F_outer(Oo, [x]) {
            function inner(...Ai) { var Oi = { get kx() { return x; }, get kb() { return Oo.kb2; } }; return Oo.cF(Oi, Ai); }
            return inner(1) + inner(2);
            }
            function F_inner(Oi, [y]) { return Oi.kx + y + Oi.kb; }
            var base = 10;
            function outer(...Ao) { var Oo = { get kb2() { return base; }, cF(...args) { return F_inner(...args); } }; return F_outer(Oo, Ao); }
            console.log(outer(5));
            """),
        prints('33'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'an object method': Program(
        a_program("""
            var counter = 1;
            function F([a], O) { return a + O.k; }
            var api = { m(...A) { var O = { get k() { return counter; } }; return F(A, O); } };
            console.log(api.m(1), api.m.length);
            """),
        prints('2 0'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a closure reading through the object after the call returned': Program(
        a_program("""
            var counter = 1;
            function F([], O) { return () => O.k; }
            function reader(...A) { var O = { get k() { return counter; } }; return F(A, O); }
            var r = reader(); counter = 5; console.log(r());
            """),
        prints('5'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a named function expression whose flat function reads its name': Program(
        a_program("""
            var fact = function self(...A) { var O = {}; return F(A, O); };
            function F([n], O) { return n <= 1 ? 1 : n * self(n - 1); }
            try { console.log(fact(5)); } catch (e) { console.log(e.name); }
            """),
        prints('ReferenceError'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'the wrapper inside a with': Program(
        a_program("""
            var obj = { console: { log: function (s) { console.log('with ' + s); } } };
            function F([], O) { console.log('x'); }
            with (obj) { var W = function (...A) { var O = {}; return F(A, O); }; }
            W();
            """),
        prints('x'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a direct eval around the wrapper declares a name the flat function reads': Program(
        a_program("""
            var name = 'top';
            function F([], O) { return name; }
            function outer() { eval('var name = "evaled"'); function W(...A) { var O = {}; return F(A, O); } return W(); }
            console.log(outer());
            """),
        prints('top'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a const written through its setter (arguments first)': Program(
        a_program("""
            const C = 1;
            function F([], O) { O.k = 2; return O.k; }
            function write(...A) { var O = { get k() { return C; }, set k(v) { C = v; } }; return F(A, O); }
            try { console.log(write()); } catch (e) { console.log(e.name); }
            """),
        prints('TypeError'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'delete of a member': Program(
        a_program("""
            var v = 1;
            function F([], O) { return delete O.k; }
            function W(...A) { var O = { get k() { return v; } }; return F(A, O); }
            console.log(W(), v);
            """),
        prints('true 1'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a callback wrapper': Program(
        a_program("""
            var offset = 10;
            function F([x], O) { return x + O.k; }
            console.log([1, 2].map(function (...A) { var O = { get k() { return offset; } }; return F(A, O); }).join());
            """),
        prints('11,12'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'the strict form with a body var of a parameter name and a default closing over it': Program(
        a_program("""
            'use strict';
            function F() { 'use strict'; var [[a, b = () => a], O] = arguments; var a; a = 2; return b(); }
            function W(...A) { var O = {}; return F(A, O); }
            console.log(W(1));
            """),
        prints('2'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'the strict form with a default reading a later parameter': Program(
        a_program("""
            'use strict';
            function F() { 'use strict'; var [[a = b, b], O] = arguments; return String(a) + b; }
            function W(...A) { var O = {}; return F(A, O); }
            try { console.log(W(undefined, 2)); } catch (e) { console.log(e.name); }
            """),
        prints('undefined2'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a direct eval nothing can fold declares a name the flat function reads': Program(
        a_program("""
            var name = 'top';
            function F([], O) { return name; }
            function outer() { eval(process.argv.length > 100 ? '' : 'var name = "evaled"'); function W(...A) { var O = {}; return F(A, O); } return W(); }
            console.log(outer());
            """),
        prints('top'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a wrapper called with new': Program(
        a_program("""
            function F([v], O) { return { v: v }; }
            function Make(...A) { var O = {}; return F(A, O); }
            console.log(new Make(3).v, new Make(3) instanceof Make);
            """),
        prints('3 false'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'an async flat function reading its arguments in an arrow': Program(
        a_program("""
            async function F([a], O) { return (() => arguments.length)(); }
            async function count(...A) { var O = {}; return F(A, O); }
            count(1).then(console.log);
            """),
        prints('2'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'an async wrapper whose object stands for a local of an enclosing function': Program(
        a_program("""
            async function F([], O) { return O.k; }
            function outer() { var local = 'local'; async function W(...A) { var O = { get k() { return local; } }; return F(A, O); } return W(); }
            outer().then(console.log);
            """),
        prints('local'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'an async function in the strict form (object first)': Program(
        a_program("""
            'use strict';
            var total = 1;
            async function F() { 'use strict'; var [O, [a]] = arguments; O.k = O.k + a; return O.k; }
            async function add(...A) { var O = { get k() { return total; }, set k(v) { total = v; } }; return F(O, A); }
            add(2).then(console.log);
            """),
        prints('3'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'an async flat function with this in an arrow': Program(
        a_program("""
            async function F([], O) { return (() => this === undefined || this === globalThis)(); }
            var holder = { async read(...A) { var O = {}; return F(A, O); } };
            holder.read().then(console.log);
            """),
        prints('true'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'an async function racing, its flat body reading an outer name': Program(
        a_program("""
            var tag = 'a';
            async function F([], O) { console.log(O.k); }
            async function a(...A) { var O = { get k() { return tag; } }; return F(A, O); }
            (async () => { await a(); console.log('after a'); })();
            Promise.resolve().then(() => console.log(1)).then(() => console.log(2)).then(() => console.log(3));
            """),
        prints('a', '1', '2', 'after a', '3'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a default reads a name the flat body also declares': Program(
        a_program("""
            var x = 'top';
            function F([a = x], O) { var x = 'body'; return a; }
            function outer() { var x = 'outer'; function W(...A) { var O = {}; return F(A, O); } return W(); }
            console.log(outer());
            """),
        prints('top'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a default calls a name the flat body declares as a function': Program(
        a_program("""
            function g() { return 'top'; }
            function F([a = g()], O) { function g() { return 'body'; } return a; }
            function outer() { function g() { return 'outer'; } function W(...A) { var O = {}; return F(A, O); } return W(); }
            console.log(outer());
            """),
        prints('top'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a default reads a name the flat body declares with let': Program(
        a_program("""
            var y = 'top';
            function F([a = y], O) { let y = 'body'; return a; }
            function outer() { var y = 'outer'; function W(...A) { var O = {}; return F(A, O); } return W(); }
            console.log(outer());
            """),
        prints('top'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a sloppy block function in the flat body named like a member name, read after the block': Program(
        a_program("""
            var V = 'outer';
            function F([], O) { { function V() {} } return typeof O.k; }
            function W(...A) { var O = { get k() { return V; } }; return F(A, O); }
            console.log(W());
            """),
        prints('string'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a sloppy block function in the flat body named like a member name, read before the block': Program(
        a_program("""
            var V = 'outer';
            function F([], O) { var r = typeof O.k; { function V() {} } return r; }
            function W(...A) { var O = { get k() { return V; } }; return F(A, O); }
            console.log(W());
            """),
        prints('string'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a wrapper inside a flat function calls its own flat function directly; both merge in one pass': Program(
        a_program("""
            function FA([], OA) { function WB(...AB) { var OB = {}; return FB(AB, OB); } return WB(); }
            function FB([], OB) { return typeof x; }
            function host() { var x = 1; function WA(...AA) { var OA = {}; return FA(AA, OA); } return WA(); }
            console.log(host());
            """),
        prints('undefined'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'async: the wrapper sits in a with whose object supplies the member name': Program(
        a_program("""
            var tag = 'top';
            async function F([], O) { return O.k; }
            var obj = { tag: 'with' };
            var W;
            with (obj) { W = async function (...A) { var O = { get k() { return tag; } }; return F(A, O); }; }
            W().then(console.log);
            """),
        prints('with'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'async: a direct eval around the wrapper declares the member name': Program(
        a_program("""
            var name = 'top';
            async function F([], O) { return O.k; }
            function outer() { eval(process.argv.length > 100 ? '' : 'var name = "evaled"'); async function W(...A) { var O = { get k() { return name; } }; return F(A, O); } return W(); }
            outer().then(console.log);
            """),
        prints('evaled'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'async: a with around the wrapper supplies the callee of a call member': Program(
        a_program("""
            var run = function () { return this === undefined || this === globalThis ? 'top' : 'with'; };
            async function F([], O) { return O.c(); }
            var obj = { run: function () { return 'with ' + (this === obj); } };
            var W;
            with (obj) { W = async function (...A) { var O = { c(...args) { return run(...args); } }; return F(A, O); }; }
            W().then(console.log);
            """),
        prints('with true'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'typeof members in positions where the operator binds differently': Program(
        a_program("""
            var later;
            function F([], O) { return [O.t.length, O.t ** 1, -O.t, !O.t, O.t[0]]; }
            function W(...A) { var O = { get t() { return typeof later; } }; return F(A, O); }
            console.log(JSON.stringify(W()));
            """),
        prints('[9,null,null,false,"u"]'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'literal members in positions where the operator binds differently': Program(
        a_program("""
            function F([], O) { return [O.n ** 2, O.n.toFixed(1), 2 / O.q, O.u === undefined, O.s.length]; }
            function W(...A) { var O = { get n() { return -1.5; }, get q() { return 0 / 0; }, get u() { return void 0; }, get s() { return 'ab'; } }; return F(A, O); }
            console.log(JSON.stringify(W()));
            """),
        prints('[2.25,"-1.5",null,true,2]'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'the length of the wrapper is read through bind': Program(
        a_program("""
            function F([a, b], O) { return a + b; }
            function add(...A) { var O = {}; return F(A, O); }
            console.log(add.bind(null).length, add(1, 2));
            """),
        prints('0 3'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'the length of the wrapper is read in its own body through a getter': Program(
        a_program("""
            function F([a, b], O) { return O.self.length + a + b; }
            function add(...A) { var O = { get self() { return add; } }; return F(A, O); }
            console.log(add(1, 2));
            """),
        prints('3'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'the object parameter is redeclared by a function of the flat body': Program(
        a_program("""
            var V = 'outer';
            function F([], O) { function O() {} return O.k; }
            function W(...A) { var O = { get k() { return V; } }; return F(A, O); }
            console.log(W());
            """),
        prints('undefined'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a call member whose argument runs a getter that reassigns the callee': Program(
        a_program("""
            var f = function (x) { return 'old ' + x; };
            var obj = { get p() { f = function (x) { return 'new ' + x; }; return 1; } };
            function F([], O) { return O.c(obj.p); }
            function run(...A) { var O = { c(...args) { return f(...args); } }; return F(A, O); }
            console.log(run());
            """),
        prints('new 1'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a call member whose argument runs valueOf that reassigns the callee': Program(
        a_program("""
            var f = function (x) { return 'old ' + x; };
            var n = { valueOf() { f = function (x) { return 'new ' + x; }; return 1; } };
            function F([], O) { return O.c(n + 1); }
            function run(...A) { var O = { c(...args) { return f(...args); } }; return F(A, O); }
            console.log(run());
            """),
        prints('new 2'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a call member whose argument calls a function that reassigns the callee': Program(
        a_program("""
            var f = function (x) { return 'old ' + x; };
            function swap() { f = function (x) { return 'new ' + x; }; return 1; }
            function F([], O) { return O.c(swap()); }
            function run(...A) { var O = { c(...args) { return f(...args); } }; return F(A, O); }
            console.log(run());
            """),
        prints('new 1'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a catch parameter of the flat body named like a member name': Program(
        a_program("""
            var V = 'outer';
            function F([], O) { try { throw 'caught'; } catch (V) { return O.k; } }
            function W(...A) { var O = { get k() { return V; } }; return F(A, O); }
            console.log(W());
            """),
        prints('outer'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'async: a getter reads the inner name of a class whose outer name is reassigned': Program(
        a_program("""
            async function F() { 'use strict'; var [[v], O] = arguments; return typeof O.k; }
            class C { static async m(...A) { var O = { get k() { return C; } }; return F(A, O); } }
            var m = C.m;
            C = null;
            m(1).then(console.log);
            """),
        prints('function'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a getter reads the inner name of a class whose outer name is reassigned': Program(
        a_program("""
            function F() { 'use strict'; var [[v], O] = arguments; return typeof O.k; }
            class C { static m(...A) { var O = { get k() { return C; } }; return F(A, O); } }
            var m = C.m;
            C = null;
            console.log(m(1));
            """),
        prints('function'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'async: the wrapper sits in a with over an object literal that supplies the member name': Program(
        a_program("""
            var tag = 'top';
            async function F([], O) { return O.k; }
            var W;
            with ({ tag: 'with' }) { W = async function (...A) { var O = { get k() { return tag; } }; return F(A, O); }; }
            W().then(console.log);
            """),
        prints('with'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'async: a direct eval of a known string around the wrapper declares the member name': Program(
        a_program("""
            var name = 'top';
            async function F([], O) { return O.k; }
            function outer() { eval('var name = "evaled"'); async function W(...A) { var O = { get k() { return name; } }; return F(A, O); } return W(); }
            outer().then(console.log);
            """),
        prints('evaled'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'async: a static field initializer calls an async static method whose flat body names the class': Program(
        a_program("""
            async function F() { 'use strict'; var [[v], O] = arguments; return new O.k(v); }
            class C {
            static async create(...A) { var O = { get k() { return C; } }; return F(A, O); }
            static ready = C.create(1);
            constructor(v) { this.v = v; }
            }
            C.ready.then(c => console.log(c.v), e => console.log(e.name));
            """),
        prints('1'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'async: a static block calls an async static method whose flat body names the class': Program(
        a_program("""
            async function F() { 'use strict'; var [[v], O] = arguments; return new O.k(v); }
            class C {
            static async create(...A) { var O = { get k() { return C; } }; return F(A, O); }
            static { C.create(2).then(c => console.log(c.v), e => console.log(e.name)); }
            constructor(v) { this.v = v; }
            }
            """),
        prints('2'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a static field initializer calls a static method whose flat body names the class': Program(
        a_program("""
            function F() { 'use strict'; var [[v], O] = arguments; return new O.k(v); }
            class C {
            static create(...A) { var O = { get k() { return C; } }; return F(A, O); }
            static ready = C.create(3);
            constructor(v) { this.v = v; }
            }
            console.log(C.ready.v);
            """),
        prints('3'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a class expression assigned to a var, its method reads the var': Program(
        a_program("""
            function F() { 'use strict'; var [[v], O] = arguments; return O.k === undefined ? 'undef' : typeof O.k; }
            var K = class { static m(...A) { var O = { get k() { return K; } }; return F(A, O); } };
            console.log(K.m(1));
            """),
        prints('function'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a wrapper inside a flat function calls its own flat function directly, both declared last': Program(
        a_program("""
            function host(n) { for (var x = 0; x < n; x++) {} function WA(...AA) { var OA = {}; return FA(AA, OA); } return WA() + ' ' + x; }
            console.log(host(3));
            function FA([], OA) { function WB(...AB) { var OB = {}; return FB(AB, OB); } return WB(); }
            function FB([], OB) { return typeof x; }
            """),
        prints('undefined 3'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a default reads a name the flat body also declares, its values unknown to the deobfuscation': Program(
        a_program("""
            var x = process.argv.length > 100 ? 'no' : 'top';
            function F([a = x], O) { var x = 'body'; return a + x; }
            function outer() { var x = process.argv.length > 100 ? 'no' : 'outer'; function W(...A) { var O = {}; return F(A, O); } return W() + x; }
            console.log(outer());
            """),
        prints('topbodyouter'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a default calls a name the flat body declares as a function, its values unknown to the deobfuscation': Program(
        a_program("""
            var g = function () { return process.argv.length > 100 ? 'no' : 'top'; };
            function F([a = g()], O) { function g() { return 'body'; } return a + g(); }
            function outer() { var g = function () { return process.argv.length > 100 ? 'no' : 'outer'; }; function W(...A) { var O = {}; return F(A, O); } return W() + g(); }
            console.log(outer());
            """),
        prints('topbodyouter'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a default reads a name the flat body declares with let, its values unknown to the deobfuscation': Program(
        a_program("""
            var y = process.argv.length > 100 ? 'no' : 'top';
            function F([a = y], O) { let y = 'body'; return a + y; }
            function outer() { var y = process.argv.length > 100 ? 'no' : 'outer'; function W(...A) { var O = {}; return F(A, O); } return W() + y; }
            console.log(outer());
            """),
        prints('topbodyouter'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a sloppy block function in the flat body named like a member name, read after the block, its values unknown to the deobfuscation': Program(
        a_program("""
            var V = process.argv.length > 100 ? 1 : 'outer';
            function F([], O) { { function V() {} } return typeof O.k; }
            function W(...A) { var O = { get k() { return V; } }; return F(A, O); }
            console.log(W(), V);
            """),
        prints('string outer'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a sloppy block function in the flat body named like a member name, read before the block, its values unknown to the deobfuscation': Program(
        a_program("""
            var V = process.argv.length > 100 ? 1 : 'outer';
            function F([], O) { var r = typeof O.k; { function V() {} } return r; }
            function W(...A) { var O = { get k() { return V; } }; return F(A, O); }
            console.log(W(), V);
            """),
        prints('string outer'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a catch parameter of the flat body named like a member name, its values unknown to the deobfuscation': Program(
        a_program("""
            var V = process.argv.length > 100 ? 'no' : 'outer';
            function F([], O) { try { throw 'caught'; } catch (V) { return O.k; } }
            function W(...A) { var O = { get k() { return V; } }; return F(A, O); }
            console.log(W(), V);
            """),
        prints('outer outer'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a default with the object first reads through the object a name the flat body declares': Program(
        a_program("""
            var V = process.argv.length > 100 ? 'no' : 'outer';
            function F(O, [a = O.k]) { var V = 'body'; return a + V; }
            function W(...A) { var O = { get k() { return V; } }; return F(O, A); }
            console.log(W(), V);
            """),
        prints('outerbody outer'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a default with the object first reads through the object a name a later parameter binds': Program(
        a_program("""
            var b = process.argv.length > 100 ? 'no' : 'outer';
            function F(O, [a = O.k, b]) { return a + b; }
            function W(...A) { var O = { get k() { return b; } }; return F(O, A); }
            console.log(W(undefined, 'p'), b);
            """),
        prints('outerp outer'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'for-of head writes a member without setter': Program(
        a_program("""
            var item = process.argv.length > 100 ? 'no' : 'init';
            function F([list], O) { for (O.k of list) {} return O.k; }
            function each(...A) { var O = { get k() { return item; } }; return F(A, O); }
            console.log(each([1, 2]), item);
            """),
        prints('init init'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'for-in head writes a member without setter': Program(
        a_program("""
            var key = process.argv.length > 100 ? 'no' : 'init';
            function F([obj], O) { for (O.k in obj) {} return O.k; }
            function keys(...A) { var O = { get k() { return key; } }; return F(A, O); }
            console.log(keys({ a: 1 }), key);
            """),
        prints('init init'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'array rest pattern writes a member without setter': Program(
        a_program("""
            var rest = process.argv.length > 100 ? 'no' : 'init';
            function F([list], O) { [...O.k] = list; return O.k; }
            function take(...A) { var O = { get k() { return rest; } }; return F(A, O); }
            console.log(take([1, 2]), rest);
            """),
        prints('init init'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'object rest pattern writes a member without setter': Program(
        a_program("""
            var rest = process.argv.length > 100 ? 'no' : 'init';
            function F([obj], O) { ({ ...O.k } = obj); return O.k; }
            function take(...A) { var O = { get k() { return rest; } }; return F(A, O); }
            console.log(take({ a: 1 }), rest);
            """),
        prints('init init'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a destructuring default writes a member without setter': Program(
        a_program("""
            var v = process.argv.length > 100 ? 'no' : 'init';
            function F([obj], O) { ({ a: O.k = 2 } = obj); return O.k; }
            function take(...A) { var O = { get k() { return v; } }; return F(A, O); }
            console.log(take({}), v);
            """),
        prints('init init'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a for-of head with an array pattern writes a member without setter': Program(
        a_program("""
            var v = process.argv.length > 100 ? 'no' : 'init';
            function F([list], O) { for ([O.k] of list) {} return O.k; }
            function take(...A) { var O = { get k() { return v; } }; return F(A, O); }
            console.log(take([[1], [2]]), v);
            """),
        prints('init init'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a parenthesized member assigned, logical assignment, exponent assignment, no setter': Program(
        a_program("""
            var v = process.argv.length > 100 ? 'no' : 0;
            function F([], O) { (O.k) = 3; O.k ??= 4; O.k ||= 5; O.k **= 2; return O.k; }
            function take(...A) { var O = { get k() { return v; } }; return F(A, O); }
            console.log(take(), v);
            """),
        prints('0 0'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a member assigned inside a for-await head without setter': Program(
        a_program("""
            var v = process.argv.length > 100 ? 'no' : 'init';
            async function F([list], O) { for await (O.k of list) {} return O.k; }
            async function take(...A) { var O = { get k() { return v; } }; return F(A, O); }
            take([1, 2]).then(r => console.log(r, v));
            """),
        prints('init init'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'async: a getter in a block reads a block function before the block reaches its declaration': Program(
        a_program("""
            async function F([], O) { return typeof O.k; }
            {
            W().then(console.log);
            async function W(...A) { var O = { get k() { return helper; } }; return F(A, O); }
            function helper() { return 'block'; }
            }
            """),
        prints('function'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'async: a getter in a block reads a block function the block reassigns': Program(
        a_program("""
            async function F([], O) { return typeof O.k; }
            {
            function helper() { return 'block'; }
            helper = 5;
            async function W(...A) { var O = { get k() { return helper; } }; return F(A, O); }
            W().then(console.log);
            }
            """),
        prints('number'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'async: a getter in a class method reads the class name while the class is being defined': Program(
        a_program("""
            async function F() { 'use strict'; var [[v], O] = arguments; return new O.k(v); }
            class C {
            static async create(...A) { var O = { get k() { return C; } }; return F(A, O); }
            static ready = C.create(1);
            constructor(v) { this.v = v; }
            }
            C.ready.then(c => console.log(c.v), e => console.log(e.name));
            """),
        prints('1'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'async: a getter in an object method reads a top-level let in its dead zone': Program(
        a_program("""
            async function F([], O) { return O.k; }
            var api = { async m(...A) { var O = { get k() { return late; } }; return F(A, O); } };
            api.m().then(console.log, e => console.log(e.name));
            let late = 'late';
            """),
        prints('ReferenceError'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'new.target in an arrow of the flat function, the wrapper constructed': Program(
        a_program("""
            function F([], O) { return { t: (() => new.target === undefined)() }; }
            function W(...A) { var O = {}; return F(A, O); }
            console.log(new W().t, W().t);
            """),
        prints('true true'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a getter reads a name a sloppy function body of the flat function declares by var under the same name as the wrapper': Program(
        a_program("""
            var log = process.argv.length > 100 ? null : function (s) { return 'outer ' + s; };
            function F([], O) { var r = O.c('x'); var log = function (s) { return 'local ' + s; }; return r + ' ' + log('y'); }
            function W(...A) { var O = { c(...args) { return log(...args); } }; return F(A, O); }
            console.log(W());
            """),
        prints('outer x local y'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a sloppy flat function behind a strict wrapper writes an undeclared name': Program(
        a_program("""
            function F([v], O) { undeclaredName = v; return 'wrote'; }
            class K { static m(...A) { var O = {}; return F(A, O); } }
            try { console.log(K.m(1)); } catch (e) { console.log(e.name); }
            """),
        prints('wrote'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'the arguments resume the generator that runs the declaration of the callee': Program(
        a_program("""
            function F([], O) { return O.c(it.next().done); }
            function* G() {
            yield function (...A) { var O = { c(...args) { return f(...args); } }; return F(A, O); };
            var f = function (x) { return 'declared ' + x; };
            }
            var it = G();
            var W = it.next().value;
            try { console.log(W()); } catch (e) { console.log(e.name); }
            """),
        prints('declared true'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'async: an awaited argument lets the file run the declaration of the callee': Program(
        a_program("""
            async function F([], O) { return O.c(await null); }
            async function W(...A) { var O = { c(...args) { return f(...args); } }; return F(A, O); }
            W().then(console.log, e => console.log(e.name));
            var f = function (x) { return 'declared ' + x; };
            """),
        prints('declared null'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'async: an awaited argument lets the file reassign the callee': Program(
        a_program("""
            var f = function (x) { return 'old ' + x; };
            async function F([], O) { return O.c(await null); }
            async function W(...A) { var O = { c(...args) { return f(...args); } }; return F(A, O); }
            W().then(console.log, e => console.log(e.name));
            f = function (x) { return 'new ' + x; };
            """),
        prints('new null'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'async: an awaited argument, the callee a function declaration redeclared by a later var': Program(
        a_program("""
            function f(x) { return 'declared ' + x; }
            async function F([], O) { return O.c(await null); }
            async function W(...A) { var O = { c(...args) { return f(...args); } }; return F(A, O); }
            W().then(console.log, e => console.log(e.name));
            var f = function (x) { return 'redeclared ' + x; };
            """),
        prints('redeclared null'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'two merges in one pass, the second flat function holding the first wrapper': Program(
        a_program("""
            var t = 100, z = 10, w = 1000;
            function fA([x], O) { return O.k1 + x + t; }
            function fB([y], O) {
            function a(...A) { var O = { get k1() { return z; } }; return fA(A, O); }
            return a(y) + O.k2;
            }
            var b = function t(...A) { var O = { get k2() { return w; } }; return fB(A, O); };
            console.log(b(1));
            """),
        prints('1111'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'typeof of a getter reading a name nothing binds': Program(
        a_program("""
            function F([], O) { return typeof O.k; }
            function W(...A) { var O = { get k() { return notDeclaredAnywhere; } }; return F(A, O); }
            try { console.log(W()); } catch (e) { console.log(e.name); }
            """),
        prints('ReferenceError'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a getter reading a name nothing binds, the name declared by the flat body later': Program(
        a_program("""
            function F([], O) { var r = O.k; return r; }
            function W(...A) { var O = { get k() { return later; } }; return F(A, O); }
            try { console.log(W()); } catch (e) { console.log(e.name); }
            """),
        prints('ReferenceError'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'two merges in one pass, the second flat function holding the first wrapper (wrapper first)': Program(
        a_program("""
            var t = process.argv.length, z = process.argv.length, w = process.argv.length;
            function fA([x], O) { return O.k1 + x + typeof t; }
            var b = function t(...A) { var O = { get k2() { return w; } }; return fB(A, O); };
            function fB([y], O) {
            function a(...A) { var O = { get k1() { return z; } }; return fA(A, O); }
            return a(y) + O.k2;
            }
            console.log(b(1));
            """),
        prints('3number2'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'an async wrapper inside a with whose getter reads a name only the with object has': Program(
        a_program("""
            var obj = { V: 'from with' };
            async function F([], O) { return O.k; }
            with (obj) { var W = async function (...A) { var O = { get k() { return V; } }; return F(A, O); }; }
            W().then(console.log, function (e) { console.log(e.name); });
            """),
        prints('from with'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'an async wrapper under a direct eval that declares the name its getter reads': Program(
        a_program("""
            async function F([], O) { return O.k; }
            function outer() { eval(process.argv.length > 100 ? '' : 'var V = "evaled"'); async function W(...A) { var O = { get k() { return V; } }; return F(A, O); } return W(); }
            outer().then(console.log, function (e) { console.log(e.name); });
            """),
        prints('evaled'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a call member calling a name that holds eval': Program(
        a_program("""
            var eval = globalThis.eval;
            var x = 'outer';
            function F([], O) { var x = 'inner'; return O.c('x'); }
            function W(...A) { var O = { c(...args) { return eval(...args); } }; return F(A, O); }
            console.log(W());
            """),
        ('', 'ReferenceError'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
}

#: The rows of `FLATTENED` whose deobfuscation puts a flat body back into its wrapper or moves a flat
#: function into it, mapped to the text it writes.
PUT_BACK: dict[str, str] = {
    'setters of every write form': inspect.cleandoc(
        """
            var counter = 0;
            let label = 'a';
            function bump(step) {
              counter += step;
              counter++;
              [label] = ['b' + step];
              for (label of ['c', 'd']) {}
              for (label in { e: 1 }) {}
              label = label + '!';
              return counter + label;
            }
            console.log(bump(2), counter, label);
        """
    ),
    'typeof members': inspect.cleandoc(
        """
            var later;
            function helper() {}
            console.log(typeof later + ':number:' + typeof helper);
            later = 1;
            console.log('number:string:function');
        """
    ),
    'call members, new through a getter, recursion': inspect.cleandoc(
        """
            class Box {
              constructor(v) {
                this.v = v;
              }
            }
            function twice(x) {
              return x * 2;
            }
            function sum(n) {
              if (n <= 0) {
                return new Box(0);
              }
              return new Box(twice(n) + sum(n - 1).v);
            }
            console.log(sum(3).v);
        """
    ),
    'a default reading an outer name (object first)': inspect.cleandoc(
        """
            function add(a, b = 3) {
              return a + b;
            }
            console.log(add(1, 2), add(1));
        """
    ),
    'a local of the flat function named like an outer name it reads': inspect.cleandoc(
        """
            console.log('outerinner');
        """
    ),
    'the length of the wrapper is read': inspect.cleandoc(
        """
            function add(...[a, b]) {
              return a + b;
            }
            console.log(add.length, add(1, 2));
        """
    ),
    'the length helper of the obfuscator': inspect.cleandoc(
        """
            function H(fn, length = 1) {
              Object.defineProperty(fn, 'length', { value: length, configurable: false });
              return fn;
            }
            H(add, 2);
            function add(...[a, b]) {
              return a + b;
            }
            console.log(add.length, add(1, 2), Object.getOwnPropertyDescriptor(add, 'length').configurable);
        """
    ),
    'an async function racing a promise chain': inspect.cleandoc(
        """
            async function a(...A) {
              async function F([]) {
                console.log('a');
              }
              return F(A);
            }
            (async () => {
              await a();
              console.log('after a');
            })();
            Promise.resolve().then(() => console.log(1)).then(() => console.log(2)).then(() => console.log(3));
        """
    ),
    'the strict form (arguments first)': inspect.cleandoc(
        """
            'use strict';
            var total = 0;
            function addTo(a, b = 1) {
              total = total + a + b;
              return total;
            }
            console.log(addTo(2), addTo(3, 4));
        """
    ),
    'the strict form (object first) with a default reading an outer name': inspect.cleandoc(
        """
            'use strict';
            function addTo(a, b = 5) {
              return a + b;
            }
            console.log(addTo(2), addTo(3, 4));
        """
    ),
    'a static method of a class in the strict form': inspect.cleandoc(
        """
            function double(x) {
              return x * 2;
            }
            class Tool {
              static twice(...[v]) {
                return double(v);
              }
            }
            console.log(Tool.twice(4), Tool.twice.length);
        """
    ),
    'a function flattened inside a flattened function (arguments first)': inspect.cleandoc(
        """
            function outer(x) {
              function inner(y) {
                return x + y + 10;
              }
              return inner(1) + inner(2);
            }
            console.log(outer(5));
        """
    ),
    'a function flattened inside a flattened function (object first)': inspect.cleandoc(
        """
            function outer(x) {
              function inner(y) {
                return x + y + 10;
              }
              return inner(1) + inner(2);
            }
            console.log(outer(5));
        """
    ),
    'an object method': inspect.cleandoc(
        """
            var api = { m(...[a]) {
              return a + 1;
            } };
            console.log(2, api.m.length);
        """
    ),
    'a closure reading through the object after the call returned': inspect.cleandoc(
        """
            var counter = 1;
            function reader() {
              return () => counter;
            }
            var r = reader();
            counter = 5;
            console.log(r());
        """
    ),
    'a direct eval around the wrapper declares a name the flat function reads': inspect.cleandoc(
        """
            console.log('top');
        """
    ),
    'a const written through its setter (arguments first)': inspect.cleandoc(
        """
            const C = 1;
            function write() {
              C = 2;
              return C;
            }
            try {
              console.log(write());
            } catch (e) {
              console.log(e.name);
            }
        """
    ),
    'a callback wrapper': inspect.cleandoc(
        """
            console.log([1, 2].map(function(...[x]) {
              return x + 10;
            }).join());
        """
    ),
    'a wrapper called with new': inspect.cleandoc(
        """
            function Make(...[v]) {
              return { v: v };
            }
            console.log(new Make(3).v, new Make(3) instanceof Make);
        """
    ),
    'an async wrapper whose object stands for a local of an enclosing function': inspect.cleandoc(
        """
            function outer() {
              async function W(...A) {
                async function F([]) {
                  return 'local';
                }
                return F(A);
              }
              return W();
            }
            outer().then(console.log);
        """
    ),
    'an async function in the strict form (object first)': inspect.cleandoc(
        """
            'use strict';
            var total = 1;
            async function add(...A) {
              async function F() {
                'use strict';
                var [[a]] = arguments;
                total = total + a;
                return total;
              }
              return F(A);
            }
            add(2).then(console.log);
        """
    ),
    'an async flat function with this in an arrow': inspect.cleandoc(
        """
            (async function(...A) {
              async function F([]) {
                return (() => this === undefined || this === globalThis)();
              }
              return F(A);
            }().then(console.log));
        """
    ),
    'an async function racing, its flat body reading an outer name': inspect.cleandoc(
        """
            async function a(...A) {
              async function F([]) {
                console.log('a');
              }
              return F(A);
            }
            (async () => {
              await a();
              console.log('after a');
            })();
            Promise.resolve().then(() => console.log(1)).then(() => console.log(2)).then(() => console.log(3));
        """
    ),
    'a default reads a name the flat body also declares': inspect.cleandoc(
        """
            function outer() {
              function W(a = 'top') {
                return a;
              }
              return W();
            }
            console.log(outer());
        """
    ),
    'a default calls a name the flat body declares as a function': inspect.cleandoc(
        """
            function outer() {
              function W(a = 'top') {
                return a;
              }
              return W();
            }
            console.log(outer());
        """
    ),
    'a default reads a name the flat body declares with let': inspect.cleandoc(
        """
            function outer() {
              function W(a = 'top') {
                return a;
              }
              return W();
            }
            console.log(outer());
        """
    ),
    'a sloppy block function in the flat body named like a member name, read after the block': inspect.cleandoc(
        """
            function W() {
              {
                function V() {}
              }
              return 'string';
            }
            console.log(W());
        """
    ),
    'a sloppy block function in the flat body named like a member name, read before the block': inspect.cleandoc(
        """
            function W() {
              {
                function V() {}
              }
              return 'string';
            }
            console.log(W());
        """
    ),
    'a wrapper inside a flat function calls its own flat function directly; both merge in one pass': inspect.cleandoc(
        """
            function host() {
              function WA() {
                function WB() {
                  return typeof x;
                }
                return WB();
              }
              return WA();
            }
            console.log(host());
        """
    ),
    'typeof members in positions where the operator binds differently': inspect.cleandoc(
        """
            var later;
            function W() {
              return [(typeof later).length, (typeof later) ** 1, -typeof later, !typeof later, (typeof later)[0]];
            }
            console.log(JSON.stringify(W()));
        """
    ),
    'literal members in positions where the operator binds differently': inspect.cleandoc(
        """
            function W() {
              return [2.25, (-1.5).toFixed(1), 2 / (0 / 0), void 0 === undefined, 2];
            }
            console.log(JSON.stringify(W()));
        """
    ),
    'the length of the wrapper is read through bind': inspect.cleandoc(
        """
            function add(...[a, b]) {
              return a + b;
            }
            console.log(add.bind(null).length, add(1, 2));
        """
    ),
    'the length of the wrapper is read in its own body through a getter': inspect.cleandoc(
        """
            function add(...[a, b]) {
              return add.length + a + b;
            }
            console.log(add(1, 2));
        """
    ),
    'a catch parameter of the flat body named like a member name': inspect.cleandoc(
        """
            console.log('outer');
        """
    ),
    'async: a static field initializer calls an async static method whose flat body names the class': inspect.cleandoc(
        """
            class C {
              static async create(...A) {
                async function F() {
                  'use strict';
                  var [[v]] = arguments;
                  return new C(v);
                }
                return F(A);
              }
              static ready = C.create(1);
              constructor(v) {
                this.v = v;
              }
            }
            C.ready.then(c => console.log(c.v), e => console.log(e.name));
        """
    ),
    'async: a static block calls an async static method whose flat body names the class': inspect.cleandoc(
        """
            class C {
              static async create(...A) {
                async function F() {
                  'use strict';
                  var [[v]] = arguments;
                  return new C(v);
                }
                return F(A);
              }
              static {
                C.create(2).then(c => console.log(c.v), e => console.log(e.name));
              }
              constructor(v) {
                this.v = v;
              }
            }
        """
    ),
    'a static field initializer calls a static method whose flat body names the class': inspect.cleandoc(
        """
            class C {
              static create(...[v]) {
                return new C(v);
              }
              static ready = C.create(3);
              constructor(v) {
                this.v = v;
              }
            }
            console.log(C.ready.v);
        """
    ),
    'a wrapper inside a flat function calls its own flat function directly, both declared last': inspect.cleandoc(
        """
            function host(n) {
              for (var x = 0; x < n; x++) {}
              function WA(...AA) {
                var OA = {};
                return FA(AA, OA);
              }
              return WA() + ' ' + x;
            }
            console.log(host(3));
            function FA([], OA) {
              function WB() {
                return typeof x;
              }
              return WB();
            }
        """
    ),
    'a default with the object first reads through the object a name the flat body declares': inspect.cleandoc(
        """
            var V = process.argv.length > 100 ? 'no' : 'outer';
            function W(a = V) {
              return a + 'body';
            }
            console.log(W(), V);
        """
    ),
    'async: a getter in a class method reads the class name while the class is being defined': inspect.cleandoc(
        """
            class C {
              static async create(...A) {
                async function F() {
                  'use strict';
                  var [[v]] = arguments;
                  return new C(v);
                }
                return F(A);
              }
              static ready = C.create(1);
              constructor(v) {
                this.v = v;
              }
            }
            C.ready.then(c => console.log(c.v), e => console.log(e.name));
        """
    ),
    'async: a getter in an object method reads a top-level let in its dead zone': inspect.cleandoc(
        """
            (async function(...A) {
              async function F([]) {
                return late;
              }
              return F(A);
            }().then(console.log, e => console.log(e.name)));
            let late = 'late';
        """
    ),
    'a getter reads a name a sloppy function body of the flat function declares by var under the same name as the wrapper': inspect.cleandoc(
        """
            var log = process.argv.length > 100 ? null : function(s) {
              return 'outer ' + s;
            };
            function W() {
              var r = log('x');
              return r + ' local y';
            }
            console.log(W());
        """
    ),
    'two merges in one pass, the second flat function holding the first wrapper': inspect.cleandoc(
        """
            console.log(1111);
        """
    ),
    'a getter reading a name nothing binds, the name declared by the flat body later': inspect.cleandoc(
        """
            function W() {
              return later;
            }
            try {
              console.log(W());
            } catch (e) {
              console.log(e.name);
            }
        """
    ),
    'two merges in one pass, the second flat function holding the first wrapper (wrapper first)': inspect.cleandoc(
        """
            var t = process.argv.length, z = process.argv.length, w = process.argv.length;
            var b = function t(...A) {
              var O = { get k2() {
                return w;
              } };
              return fB(A, O);
            };
            function fB([y], O) {
              function a(x) {
                return z + x + typeof t;
              }
              return a(y) + O.k2;
            }
            console.log(b(1));
        """
    ),
}


#: A file the obfuscation wrote for one program with function flattening alone, passing the arguments
#: first, and its deobfuscation.
ARGUMENTS_FIRST = inspect.cleandoc(
    """
    async function __p_AbCC_flat_delayed([value], __p_cdXZ_flat_object) {
      await null;
      return __p_cdXZ_flat_object["c_f_U_X"](value);
    }
    function __p_YXf2_flat_sum([left, right], __p_Ka8T_flat_object) {
      return left + right + __p_Ka8T_flat_object["AoLFia"];
    }
    function __p_fmHs_flat_holder([], __p_tVkl_flat_object) {
      return [1, 2]["map"](item => {
        return item + this["length"];
      });
    }
    function __p_xjH5_flat_addLimit() {
      "use strict";

      var [[value, extra = __p_TheW_flat_object["ixyuWK4"]], __p_TheW_flat_object] = arguments;
      return value + extra + __p_TheW_flat_object["eDu8dj"];
    }
    function __p_eALQ_flat_outer([base], __p_Cdmq_flat_object) {
      function inner(...__p_T30z_args) {
        var __p_nSb6_flat_object = {
          get "KFewk2c"() {
            return base;
          },
          get "YQqA_aj"() {
            return __p_Cdmq_flat_object["YqRtNZ"];
          }
        };
        return __p_Cdmq_flat_object["X8mYU4u"](__p_T30z_args, __p_nSb6_flat_object);
      }
      return inner(1) + inner(2);
    }
    function __p_tHS1_flat_inner([step], __p_nSb6_flat_object) {
      return __p_nSb6_flat_object["KFewk2c"] + step + __p_nSb6_flat_object["YQqA_aj"];
    }
    function __p_Oze0_flat_lockLimit([], __p_7JeI_flat_object) {
      try {
        __p_7JeI_flat_object["r0tZLy"] = 4;
        return 'changed';
      } catch (error) {
        return error["name"];
      }
    }
    function __p_uQNZ_flat_scale([value, factor = __p_5YPj_flat_object["Ogv2BRA"]], __p_5YPj_flat_object) {
      return __p_5YPj_flat_object["wgeOkS"](value) * factor;
    }
    function __p_9NX5_flat_describe([value], __p_zfIQ_flat_object) {
      return __p_zfIQ_flat_object["J0pr2H"] + ':' + typeof value + ':' + __p_zfIQ_flat_object["bqcY484"];
    }
    function __p_nBVF_flat_bump([step], __p_Huzi_flat_object) {
      __p_Huzi_flat_object["cG9S9v"] += step;
      __p_Huzi_flat_object["cG9S9v"]++;
      __p_Huzi_flat_object["M4ISTP2"] = __p_Huzi_flat_object["M4ISTP2"] + step;
      return __p_Huzi_flat_object["cG9S9v"];
    }
    function __p_0H6R_flat_twice([value], __p_kv7G_flat_object) {
      return value * 2;
    }
    function __p_KaAJ_flat_origin() {
      "use strict";

      var [[offset], __p_I2Uc_flat_object] = arguments;
      return new __p_I2Uc_flat_object["l4b7Lz"](offset);
    }
    var counter = 0;
    let label = 'start';
    const LIMIT = 3;
    var later;
    class Point {
      constructor(x) {
        this["x"] = x;
      }
      static ["origin"](...__p_cAd0_args) {
        var __p_I2Uc_flat_object = {
          get "l4b7Lz"() {
            return Point;
          }
        };
        return __p_KaAJ_flat_origin(__p_cAd0_args, __p_I2Uc_flat_object);
      }
    }
    function twice(...__p_M6Dc_args) {
      var __p_kv7G_flat_object = {};
      return __p_0H6R_flat_twice(__p_M6Dc_args, __p_kv7G_flat_object);
    }
    function bump(...__p_zvuz_args) {
      var __p_Huzi_flat_object = {
        get "cG9S9v"() {
          return counter;
        },
        set "cG9S9v"(__p_wrzg_value) {
          counter = __p_wrzg_value;
        },
        get "M4ISTP2"() {
          return label;
        },
        set "M4ISTP2"(__p_3T66_value) {
          label = __p_3T66_value;
        }
      };
      return __p_nBVF_flat_bump(__p_zvuz_args, __p_Huzi_flat_object);
    }
    function describe(...__p_tEQJ_args) {
      var __p_zfIQ_flat_object = {
        get "J0pr2H"() {
          return typeof later;
        },
        get "bqcY484"() {
          return typeof twice;
        }
      };
      return __p_9NX5_flat_describe(__p_tEQJ_args, __p_zfIQ_flat_object);
    }
    function scale(...__p_6ioN_args) {
      var __p_5YPj_flat_object = {
        get "Ogv2BRA"() {
          return LIMIT;
        },
        "wgeOkS"(...args) {
          return twice(...args);
        }
      };
      return __p_uQNZ_flat_scale(__p_6ioN_args, __p_5YPj_flat_object);
    }
    function lockLimit(...__p_dp8T_args) {
      var __p_7JeI_flat_object = {
        get "r0tZLy"() {
          return LIMIT;
        },
        set "r0tZLy"(__p_4UMd_value) {
          LIMIT = __p_4UMd_value;
        }
      };
      return __p_Oze0_flat_lockLimit(__p_dp8T_args, __p_7JeI_flat_object);
    }
    function outer(...__p_Ym4t_args) {
      var __p_Cdmq_flat_object = {
        get "YqRtNZ"() {
          return counter;
        },
        "X8mYU4u"(...args) {
          return __p_tHS1_flat_inner(...args);
        }
      };
      return __p_eALQ_flat_outer(__p_Ym4t_args, __p_Cdmq_flat_object);
    }
    function strictZone(first) {
      'use strict';

      function addLimit(...__p_i04V_args) {
        var __p_TheW_flat_object = {
          get "ixyuWK4"() {
            return LIMIT;
          },
          get "eDu8dj"() {
            return counter;
          }
        };
        return __p_xjH5_flat_addLimit(__p_i04V_args, __p_TheW_flat_object);
      }
      return addLimit(first, 1);
    }
    function holder(...__p_xv1W_args) {
      var __p_tVkl_flat_object = {};
      return __p_fmHs_flat_holder(__p_xv1W_args, __p_tVkl_flat_object);
    }
    const tools = {
      ["sum"](...__p_ZoCw_args) {
        var __p_Ka8T_flat_object = {
          get "AoLFia"() {
            return counter;
          }
        };
        return __p_YXf2_flat_sum(__p_ZoCw_args, __p_Ka8T_flat_object);
      }
    };
    async function delayed(...__p_ubGd_args) {
      var __p_cdXZ_flat_object = {
        "c_f_U_X"(...args) {
          return twice(...args);
        }
      };
      return __p_AbCC_flat_delayed(__p_ubGd_args, __p_cdXZ_flat_object);
    }
    console["log"](bump(2), label, describe(1), scale(2, 1), lockLimit());
    console["log"](outer(10), strictZone(5), tools["sum"](1, 2), Point["origin"](7)["x"], twice["length"]);
    console["log"](holder["call"]([0])["join"]());
    delayed(4)["then"](result => {
      return console["log"](result);
    });
    """
)

ARGUMENTS_FIRST_DEOBFUSCATED = inspect.cleandoc(
    """
    function __p_fmHs_flat_holder([], __p_tVkl_flat_object) {
      return [1, 2].map(item => {
        return item + this.length;
      });
    }
    function __p_xjH5_flat_addLimit() {
      "use strict";
      var [[value, extra = __p_TheW_flat_object.ixyuWK4], __p_TheW_flat_object] = arguments;
      return value + extra + __p_TheW_flat_object.eDu8dj;
    }
    function __p_uQNZ_flat_scale([value, factor = __p_5YPj_flat_object.Ogv2BRA], __p_5YPj_flat_object) {
      return __p_5YPj_flat_object.wgeOkS(value) * factor;
    }
    var counter = 0;
    let label = 'start';
    const LIMIT = 3;
    var later;
    class Point {
      constructor(x) {
        this.x = x;
      }
      static ["origin"](...[offset]) {
        return new Point(offset);
      }
    }
    function twice(...[value]) {
      return value * 2;
    }
    function bump(step) {
      counter += step;
      counter++;
      label = label + step;
      return counter;
    }
    function describe(value) {
      return typeof later + ':' + typeof value + ':' + typeof twice;
    }
    function scale(...__p_6ioN_args) {
      var __p_5YPj_flat_object = { get "Ogv2BRA"() {
        return LIMIT;
      }, "wgeOkS"(...args) {
        return twice(...args);
      } };
      return __p_uQNZ_flat_scale(__p_6ioN_args, __p_5YPj_flat_object);
    }
    function lockLimit() {
      try {
        LIMIT = 4;
        return 'changed';
      } catch (error) {
        return error.name;
      }
    }
    function outer(base) {
      function inner(step) {
        return base + step + counter;
      }
      return inner(1) + inner(2);
    }
    function strictZone(first) {
      'use strict';
      function addLimit(...__p_i04V_args) {
        var __p_TheW_flat_object = { get "ixyuWK4"() {
          return LIMIT;
        }, get "eDu8dj"() {
          return counter;
        } };
        return __p_xjH5_flat_addLimit(__p_i04V_args, __p_TheW_flat_object);
      }
      return addLimit(first, 1);
    }
    function holder(...__p_xv1W_args) {
      var __p_tVkl_flat_object = {};
      return __p_fmHs_flat_holder(__p_xv1W_args, __p_tVkl_flat_object);
    }
    const tools = { sum(...[left, right]) {
      return left + right + counter;
    } };
    async function delayed(...__p_ubGd_args) {
      async function __p_AbCC_flat_delayed([value]) {
        await null;
        return twice(value);
      }
      return __p_AbCC_flat_delayed(__p_ubGd_args);
    }
    console.log(bump(2), label, describe(1), scale(2, 1), lockLimit());
    console.log(outer(10), strictZone(5), tools.sum(1, 2), Point.origin(7).x, twice.length);
    console.log(holder.call([0]).join());
    delayed(4).then(result => {
      return console.log(result);
    });
    """
)

#: The file a later version of the obfuscation wrote for the same program, passing the object first,
#: and its deobfuscation.
OBJECT_FIRST = inspect.cleandoc(
    """
    async function __p_JIiq_flat_delayed(__p_18XH_flat_object, [value]) {
      await null;
      return __p_18XH_flat_object["vhNkvHJ"](value);
    }
    function __p_rgI0_flat_sum(__p_mgRw_flat_object, [left, right]) {
      return left + right + __p_mgRw_flat_object["SFPgmK"];
    }
    function __p_6JIH_flat_addLimit() {
      "use strict";

      var [__p_a8dS_flat_object, [value, extra = __p_a8dS_flat_object["UEhMw8P"]]] = arguments;
      return value + extra + __p_a8dS_flat_object["_Uepnhc"];
    }
    function __p_zdPQ_flat_outer(__p_XFRt_flat_object, [base]) {
      function inner(...__p_Rv7l_args) {
        var __p_5we5_flat_object = {
          get "ohOLrq8"() {
            return base;
          },
          get "pHNY1M"() {
            return __p_XFRt_flat_object["NmgmdZ"];
          }
        };
        return __p_XFRt_flat_object["O6KctD"](__p_5we5_flat_object, __p_Rv7l_args);
      }
      return inner(1) + inner(2);
    }
    function __p_oNWt_flat_inner(__p_5we5_flat_object, [step]) {
      return __p_5we5_flat_object["ohOLrq8"] + step + __p_5we5_flat_object["pHNY1M"];
    }
    function __p_hQcw_flat_lockLimit(__p_gnYa_flat_object, []) {
      try {
        __p_gnYa_flat_object["gxpP7h"] = 4;
        return 'changed';
      } catch (error) {
        return error["name"];
      }
    }
    function __p_DEbc_flat_scale(__p_YWxj_flat_object, [value, factor = __p_YWxj_flat_object["NnyWl3"]]) {
      return __p_YWxj_flat_object["I47DePi"](value) * factor;
    }
    function __p_Pczw_flat_describe(__p_4QhI_flat_object, [value]) {
      return __p_4QhI_flat_object["h5EASjW"] + ':' + typeof value + ':' + __p_4QhI_flat_object["xATG94n"];
    }
    function __p_0neK_flat_bump(__p_SGJy_flat_object, [step]) {
      __p_SGJy_flat_object["q6doI9"] += step;
      __p_SGJy_flat_object["q6doI9"]++;
      __p_SGJy_flat_object["EOtDoVp"] = __p_SGJy_flat_object["EOtDoVp"] + step;
      return __p_SGJy_flat_object["q6doI9"];
    }
    function __p_gdVf_flat_twice(__p_CMQd_flat_object, [value]) {
      return value * 2;
    }
    function __p_F8vf_flat_origin() {
      "use strict";

      var [__p_zxXg_flat_object, [offset]] = arguments;
      return new __p_zxXg_flat_object["q8qt55"](offset);
    }
    var counter = 0;
    let label = 'start';
    const LIMIT = 3;
    var later;
    class Point {
      constructor(x) {
        this["x"] = x;
      }
      static ["origin"](...__p_AiAi_args) {
        var __p_zxXg_flat_object = {
          get "q8qt55"() {
            return Point;
          }
        };
        return __p_F8vf_flat_origin(__p_zxXg_flat_object, __p_AiAi_args);
      }
    }
    function twice(...__p_067z_args) {
      var __p_CMQd_flat_object = {};
      return __p_gdVf_flat_twice(__p_CMQd_flat_object, __p_067z_args);
    }
    function bump(...__p_puLV_args) {
      var __p_SGJy_flat_object = {
        get "q6doI9"() {
          return counter;
        },
        set "q6doI9"(__p_rxAj_value) {
          counter = __p_rxAj_value;
        },
        get "EOtDoVp"() {
          return label;
        },
        set "EOtDoVp"(__p_SPgk_value) {
          label = __p_SPgk_value;
        }
      };
      return __p_0neK_flat_bump(__p_SGJy_flat_object, __p_puLV_args);
    }
    function describe(...__p_JKzs_args) {
      var __p_4QhI_flat_object = {
        get "h5EASjW"() {
          return typeof later;
        },
        get "xATG94n"() {
          return typeof twice;
        }
      };
      return __p_Pczw_flat_describe(__p_4QhI_flat_object, __p_JKzs_args);
    }
    function scale(...__p_epba_args) {
      var __p_YWxj_flat_object = {
        get "NnyWl3"() {
          return LIMIT;
        },
        "I47DePi"(...args) {
          return twice(...args);
        }
      };
      return __p_DEbc_flat_scale(__p_YWxj_flat_object, __p_epba_args);
    }
    function lockLimit(...__p_v81m_args) {
      var __p_gnYa_flat_object = {
        get "gxpP7h"() {
          return LIMIT;
        }
      };
      return __p_hQcw_flat_lockLimit(__p_gnYa_flat_object, __p_v81m_args);
    }
    function outer(...__p_zd5X_args) {
      var __p_XFRt_flat_object = {
        get "NmgmdZ"() {
          return counter;
        },
        "O6KctD"(...args) {
          return __p_oNWt_flat_inner(...args);
        }
      };
      return __p_zdPQ_flat_outer(__p_XFRt_flat_object, __p_zd5X_args);
    }
    function strictZone(first) {
      'use strict';

      function addLimit(...__p_xcZ7_args) {
        var __p_a8dS_flat_object = {
          get "UEhMw8P"() {
            return LIMIT;
          },
          get "_Uepnhc"() {
            return counter;
          }
        };
        return __p_6JIH_flat_addLimit(__p_a8dS_flat_object, __p_xcZ7_args);
      }
      return addLimit(first, 1);
    }
    function holder() {
      return [1, 2]["map"](item => {
        return item + this["length"];
      });
    }
    const tools = {
      ["sum"](...__p_6udw_args) {
        var __p_mgRw_flat_object = {
          get "SFPgmK"() {
            return counter;
          }
        };
        return __p_rgI0_flat_sum(__p_mgRw_flat_object, __p_6udw_args);
      }
    };
    async function delayed(...__p_fFEl_args) {
      var __p_18XH_flat_object = {
        "vhNkvHJ"(...args) {
          return twice(...args);
        }
      };
      return __p_JIiq_flat_delayed(__p_18XH_flat_object, __p_fFEl_args);
    }
    console["log"](bump(2), label, describe(1), scale(2, 1), lockLimit());
    console["log"](outer(10), strictZone(5), tools["sum"](1, 2), Point["origin"](7)["x"], twice["length"]);
    console["log"](holder["call"]([0])["join"]());
    delayed(4)["then"](result => {
      return console["log"](result);
    });
    """
)

OBJECT_FIRST_DEOBFUSCATED = inspect.cleandoc(
    """
    function __p_hQcw_flat_lockLimit(__p_gnYa_flat_object, []) {
      try {
        __p_gnYa_flat_object.gxpP7h = 4;
        return 'changed';
      } catch (error) {
        return error.name;
      }
    }
    var counter = 0;
    let label = 'start';
    var later;
    class Point {
      constructor(x) {
        this.x = x;
      }
      static ["origin"](...[offset]) {
        return new Point(offset);
      }
    }
    function twice(...[value]) {
      return value * 2;
    }
    function bump(step) {
      counter += step;
      counter++;
      label = label + step;
      return counter;
    }
    function describe(value) {
      return typeof later + ':' + typeof value + ':' + typeof twice;
    }
    function scale(value, factor = 3) {
      return twice(value) * factor;
    }
    function lockLimit(...__p_v81m_args) {
      var __p_gnYa_flat_object = { get "gxpP7h"() {
        return 3;
      } };
      return __p_hQcw_flat_lockLimit(__p_gnYa_flat_object, __p_v81m_args);
    }
    function outer(base) {
      function inner(step) {
        return base + step + counter;
      }
      return inner(1) + inner(2);
    }
    function strictZone(first) {
      'use strict';
      function addLimit(value, extra = 3) {
        return value + extra + counter;
      }
      return addLimit(first, 1);
    }
    function holder() {
      return [1, 2].map(item => {
        return item + this.length;
      });
    }
    const tools = { sum(...[left, right]) {
      return left + right + counter;
    } };
    async function delayed(...__p_fFEl_args) {
      async function __p_JIiq_flat_delayed([value]) {
        await null;
        return twice(value);
      }
      return __p_JIiq_flat_delayed(__p_fFEl_args);
    }
    console.log(bump(2), label, describe(1), scale(2, 1), lockLimit());
    console.log(outer(10), strictZone(5), tools.sum(1, 2), Point.origin(7).x, twice.length);
    console.log(holder.call([0]).join());
    delayed(4).then(result => {
      return console.log(result);
    });
    """
)


class TestTheFilesTheObfuscationWrote(TestBase):

    def test_the_file_passing_the_arguments_first_reads_as_pinned(self):
        self.assertEqual(deobfuscated(ARGUMENTS_FIRST), ARGUMENTS_FIRST_DEOBFUSCATED)

    def test_the_file_passing_the_object_first_reads_as_pinned(self):
        self.assertEqual(deobfuscated(OBJECT_FIRST), OBJECT_FIRST_DEOBFUSCATED)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAFlattenedFunctionBehavesAsItDid(TestBase):

    def test_node_prints_what_each_row_pins(self):
        for label, row in FLATTENED.items():
            with self.subTest(label=label):
                self.assertEqual(row.behaves(), row.prints)

    def test_each_program_still_prints_it_after_the_deobfuscation(self):
        for label, row in FLATTENED.items():
            with self.subTest(label=label):
                self.assertEqual(row.read(), row.required())


class TestAFlattenedFunctionIsPutBackTogether(TestBase):

    def test_each_function_put_back_reads_as_pinned(self):
        self.assertEqual(
            {label: deobfuscated(FLATTENED[label].text) for label in PUT_BACK},
            PUT_BACK,
        )


#: Programs whose deobfuscation behaves differently only through a shape made up for it, mapped to
#: what Node prints for each run as a CommonJS file: a program replacing the iterator of every array,
#: which the parameter list `(a, b)` does not run where the unpacking did, and a flat function
#: reading the name of a class directly, whose name inside the class is a binding of its own.
A_SHAPE_MADE_UP_FOR_THE_DEFECT = {
    'a program replacing the array iterator': Program(
        a_program("""
            var log = [];
            var original = Array.prototype[Symbol.iterator];
            Array.prototype[Symbol.iterator] = function () { log.push('iterated'); return original.call(this); };
            function F([a, b], O) { return a + b; }
            function add(...A) { var O = {}; return F(A, O); }
            console.log(add(1, 2), log.length);
            """),
        prints('3 1'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
    'a flat function reading the class name directly, the class name reassigned': Program(
        a_program("""
            function F() { 'use strict'; var [[], O] = arguments; return typeof C; }
            class C { static m(...A) { var O = {}; return F(A, O); } }
            var m = C.m;
            C = null;
            console.log(m());
            """),
        prints('object'),
        Reading.COMMONJS,
        HostEnvironment.node,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAShapeMadeUpForTheDefect(TestBase):

    def test_node_prints_what_each_row_pins(self):
        for label, row in A_SHAPE_MADE_UP_FOR_THE_DEFECT.items():
            with self.subTest(label=label):
                self.assertEqual(row.behaves(), row.prints)

    @wontfix(
        'no program replaces the iterator of every array; the deobfuscation trusts it as the '
        'recovery of flattened control flow does'
    )
    def test_a_program_replacing_the_array_iterator_still_prints_it(self):
        row = A_SHAPE_MADE_UP_FOR_THE_DEFECT['a program replacing the array iterator']
        self.assertEqual(row.read(), row.required())

    @wontfix(
        'the obfuscation reads every name of the program through the object, so no flat function '
        'it writes reads the name of a class directly'
    )
    def test_a_flat_function_reading_the_class_name_still_prints_it(self):
        row = A_SHAPE_MADE_UP_FOR_THE_DEFECT[
            'a flat function reading the class name directly, the class name reassigned'
        ]
        self.assertEqual(row.read(), row.required())
