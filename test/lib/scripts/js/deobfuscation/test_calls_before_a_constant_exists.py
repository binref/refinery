"""
Programs that call a function reading a constant before the constant exists, through a channel
other than a read of the function's own name: a method reached through the object that holds it, a
host calling a declared entry point, and an importer calling an export. JavaScript throws
`ReferenceError` at the read, and a deobfuscation that folds the constant into the function returns
a value where the input threw. Each program has a twin making the same call after the constant
exists, where the constant must still fold.
"""
from __future__ import annotations

import inspect
import json
import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import (
    behavior,
    deobfuscate_source,
    module_graph_behavior,
    node_executable,
)
from test.lib.scripts.js.ledger import (
    a_program,
    before_and_after,
    each_program_still_prints,
)

#: Programs that hand the object holding `NS.g` to code before `a` exists, where that code calls
#: `NS.g` without the text spelling a read of it: a method call passes the object as `this`, and an
#: accessor on the object, on its prototype, or on `Object.prototype` runs with it as `this`.
A_METHOD_CALLED_THROUGH_ITS_OBJECT_BEFORE_THE_CONSTANT = {
    'a sibling method called on the object': a_program("""
        var NS = {h: 1};
        NS.g = function () { return a[0]; };
        NS.f = function () { return this.g(); };
        console.log(NS.f());
        const a = [7, 8];
        """),
    'a parenthesized method call': a_program("""
        var NS = {h: 1};
        NS.g = function () { return a[0]; };
        NS.f = function () { return this.g(); };
        console.log((NS.f)());
        const a = [7, 8];
        """),
    'a tagged method call': a_program("""
        var NS = {h: 1};
        NS.g = function () { return a[0]; };
        NS.f = function () { return this.g(); };
        console.log(NS.f``);
        const a = [7, 8];
        """),
    'an optional method call': a_program("""
        var NS = {h: 1};
        NS.g = function () { return a[0]; };
        NS.f = function () { return this.g(); };
        console.log(NS.f?.());
        const a = [7, 8];
        """),
    'a method call on an optional member': a_program("""
        var NS = {h: 1};
        NS.g = function () { return a[0]; };
        NS.f = function () { return this.g(); };
        console.log(NS?.f());
        const a = [7, 8];
        """),
    'a method call through a string key': a_program("""
        var NS = {h: 1};
        NS.g = function () { return a[0]; };
        NS.f = function () { return this.g(); };
        console.log(NS['f']());
        const a = [7, 8];
        """),
    'a method call through a variable key': a_program("""
        var NS = {h: 1};
        NS.g = function () { return a[0]; };
        NS.f = function () { return this.g(); };
        var k = 'f';
        console.log(NS[k]());
        const a = [7, 8];
        """),
    'a method call whose callee keeps this in a local': a_program("""
        var NS = {h: 1};
        NS.g = function () { return a[0]; };
        NS.f = function () { var self = this; return self.g(); };
        console.log(NS.f());
        const a = [7, 8];
        """),
    'a method the literal declares': a_program("""
        var NS = { f() { return this.g(); } };
        NS.g = function () { return a[0]; };
        console.log(NS.f());
        const a = [7, 8];
        """),
    'a built-in method calling toString on its receiver': a_program("""
        var NS = {h: 1};
        NS.toString = function () { return a[0]; };
        console.log(NS.toLocaleString());
        const a = [7, 8];
        """),
    'a getter the literal declares': a_program("""
        var NS = { get k() { return this.g(); } };
        NS.g = function () { return a[0]; };
        console.log(NS.k);
        const a = [7, 8];
        """),
    'a setter the literal declares': a_program("""
        var NS = { set k(v) { this.g(); } };
        NS.g = function () { console.log(a[0]); };
        NS.k = 1;
        const a = [7, 8];
        """),
    'a getter installed on the object': a_program("""
        var NS = {h: 1};
        NS.g = function () { return a[0]; };
        NS.__defineGetter__('k', function () { return this.g(); });
        console.log(NS.k);
        const a = [7, 8];
        """),
    'a getter on the prototype the literal sets': a_program("""
        var P = { get k() { return this.g(); } };
        var NS = { __proto__: P };
        NS.g = function () { return a[0]; };
        console.log(NS.k);
        const a = [7, 8];
        """),
    'a getter on a prototype written through the object': a_program("""
        var P = { get k() { return this.g(); } };
        var NS = {h: 1};
        NS.g = function () { return a[0]; };
        NS.__proto__ = P;
        console.log(NS.k);
        const a = [7, 8];
        """),
    'a getter defined on the object prototype': a_program("""
        Object.defineProperty(Object.prototype, 'k', { get() { return this.g(); } });
        var NS = {h: 1};
        NS.g = function () { return a[0]; };
        console.log(NS.k);
        const a = [7, 8];
        """),
    'a getter installed on the object prototype': a_program("""
        Object.prototype.__defineGetter__('k', function () { return this.g(); });
        var NS = {h: 1};
        NS.g = function () { return a[0]; };
        console.log(NS.k);
        const a = [7, 8];
        """),
    'a method on the object prototype': a_program("""
        Object.prototype.m = function () { return this.g(); };
        var NS = {h: 1};
        NS.g = function () { return a[0]; };
        console.log(NS.m());
        const a = [7, 8];
        """),
    'a setter on the object prototype': a_program("""
        Object.defineProperty(Object.prototype, 'k', { set(v) { console.log(this.g()); } });
        var NS = {h: 1};
        NS.g = function () { return a[0]; };
        NS.k = 1;
        const a = [7, 8];
        """),
    'a setter on the object prototype receiving the method itself': a_program("""
        Object.defineProperty(Object.prototype, 'g', { set(v) { console.log(v()); } });
        var NS = {h: 1};
        NS.g = function () { return a[0]; };
        const a = [7, 8];
        """),
    'a getter code the file cannot read installs on the object prototype': a_program("""
        function main(code) {
          var NS = {h: 1};
          NS.g = function () { return a[0]; };
          (0, eval)(code);
          console.log(NS.k);
          const a = [7, 8];
        }
        main(process.argv[2] || "Object.prototype.__defineGetter__('k', function () { return this.g(); })");
        """),
    'a getter installed through the constructor of the object': a_program("""
        var NS = {h: 1};
        NS.g = function () { return a[0]; };
        NS.constructor.prototype.__defineGetter__('k', function () { return this.g(); });
        console.log(NS.k);
        const a = [7, 8];
        """),
    'a getter an earlier call installed through the object': a_program("""
        function main() {
          var NS = {h: 1};
          NS.g = function () { return a[0]; };
          var r = NS.k;
          const a = [7, 8];
          NS.__proto__.__defineGetter__('k', function () { return this.g(); });
          return r;
        }
        main();
        main();
        """),
    'a method called through the value of the assignment installing it': a_program("""
        var NS = {h: 1};
        var f = NS.g = function () { return a[0]; };
        console.log(f());
        const a = [7, 8];
        """),
    'a recursive method called through the value of the assignment installing it': a_program("""
        var NS = {h: 1};
        var f = NS.g = function (n) { return n > 0 ? NS.g(n - 1) : a[0]; };
        console.log(f(1));
        const a = [7, 8];
        """),
    'a function installed as the prototype of the object': a_program("""
        var NS = {h: 1};
        NS.__proto__ = function () { return a[0]; };
        console.log(NS.prototype.constructor());
        const a = [7, 8];
        """),
}

#: The programs of `A_METHOD_CALLED_THROUGH_ITS_OBJECT_BEFORE_THE_CONSTANT` with `a` declared first,
#: mapped to what Node prints for them: every call now runs after `a` exists.
THE_SAME_CALLS_AFTER_THE_CONSTANT = {
    a_program("""
        const a = [7, 8];
        var NS = {h: 1};
        NS.g = function () { return a[0]; };
        NS.f = function () { return this.g(); };
        console.log(NS.f());
        """): '7\n',
    a_program("""
        const a = [7, 8];
        var NS = {h: 1};
        NS.g = function () { return a[0]; };
        NS.f = function () { return this.g(); };
        console.log((NS.f)());
        """): '7\n',
    a_program("""
        const a = [7, 8];
        var NS = {h: 1};
        NS.g = function () { return a[0]; };
        NS.f = function () { return this.g(); };
        console.log(NS.f``);
        """): '7\n',
    a_program("""
        const a = [7, 8];
        var NS = {h: 1};
        NS.g = function () { return a[0]; };
        NS.f = function () { return this.g(); };
        console.log(NS.f?.());
        """): '7\n',
    a_program("""
        const a = [7, 8];
        var NS = {h: 1};
        NS.g = function () { return a[0]; };
        NS.f = function () { return this.g(); };
        console.log(NS?.f());
        """): '7\n',
    a_program("""
        const a = [7, 8];
        var NS = {h: 1};
        NS.g = function () { return a[0]; };
        NS.f = function () { return this.g(); };
        console.log(NS['f']());
        """): '7\n',
    a_program("""
        const a = [7, 8];
        var NS = {h: 1};
        NS.g = function () { return a[0]; };
        NS.f = function () { return this.g(); };
        var k = 'f';
        console.log(NS[k]());
        """): '7\n',
    a_program("""
        const a = [7, 8];
        var NS = {h: 1};
        NS.g = function () { return a[0]; };
        NS.f = function () { var self = this; return self.g(); };
        console.log(NS.f());
        """): '7\n',
    a_program("""
        const a = [7, 8];
        var NS = { f() { return this.g(); } };
        NS.g = function () { return a[0]; };
        console.log(NS.f());
        """): '7\n',
    a_program("""
        const a = [7, 8];
        var NS = {h: 1};
        NS.toString = function () { return a[0]; };
        console.log(NS.toLocaleString());
        """): '7\n',
    a_program("""
        const a = [7, 8];
        var NS = { get k() { return this.g(); } };
        NS.g = function () { return a[0]; };
        console.log(NS.k);
        """): '7\n',
    a_program("""
        const a = [7, 8];
        var NS = { set k(v) { this.g(); } };
        NS.g = function () { console.log(a[0]); };
        NS.k = 1;
        """): '7\n',
    a_program("""
        const a = [7, 8];
        var NS = {h: 1};
        NS.g = function () { return a[0]; };
        NS.__defineGetter__('k', function () { return this.g(); });
        console.log(NS.k);
        """): '7\n',
    a_program("""
        const a = [7, 8];
        var P = { get k() { return this.g(); } };
        var NS = { __proto__: P };
        NS.g = function () { return a[0]; };
        console.log(NS.k);
        """): '7\n',
    a_program("""
        const a = [7, 8];
        var P = { get k() { return this.g(); } };
        var NS = {h: 1};
        NS.g = function () { return a[0]; };
        NS.__proto__ = P;
        console.log(NS.k);
        """): '7\n',
    a_program("""
        const a = [7, 8];
        Object.defineProperty(Object.prototype, 'k', { get() { return this.g(); } });
        var NS = {h: 1};
        NS.g = function () { return a[0]; };
        console.log(NS.k);
        """): '7\n',
    a_program("""
        const a = [7, 8];
        Object.prototype.__defineGetter__('k', function () { return this.g(); });
        var NS = {h: 1};
        NS.g = function () { return a[0]; };
        console.log(NS.k);
        """): '7\n',
    a_program("""
        const a = [7, 8];
        Object.prototype.m = function () { return this.g(); };
        var NS = {h: 1};
        NS.g = function () { return a[0]; };
        console.log(NS.m());
        """): '7\n',
    a_program("""
        const a = [7, 8];
        Object.defineProperty(Object.prototype, 'k', { set(v) { console.log(this.g()); } });
        var NS = {h: 1};
        NS.g = function () { return a[0]; };
        NS.k = 1;
        """): '7\n',
    a_program("""
        const a = [7, 8];
        Object.defineProperty(Object.prototype, 'g', { set(v) { console.log(v()); } });
        var NS = {h: 1};
        NS.g = function () { return a[0]; };
        """): '7\n',
    a_program("""
        function main(code) {
          const a = [7, 8];
          var NS = {h: 1};
          NS.g = function () { return a[0]; };
          (0, eval)(code);
          console.log(NS.k);
        }
        main(process.argv[2] || "Object.prototype.__defineGetter__('k', function () { return this.g(); })");
        """): '7\n',
    a_program("""
        const a = [7, 8];
        var NS = {h: 1};
        NS.g = function () { return a[0]; };
        NS.constructor.prototype.__defineGetter__('k', function () { return this.g(); });
        console.log(NS.k);
        """): '7\n',
    a_program("""
        function main() {
          const a = [7, 8];
          var NS = {h: 1};
          NS.g = function () { return a[0]; };
          var r = NS.k;
          NS.__proto__.__defineGetter__('k', function () { return this.g(); });
          return r;
        }
        main();
        console.log(main());
        """): '7\n',
    a_program("""
        const a = [7, 8];
        var NS = {h: 1};
        var f = NS.g = function () { return a[0]; };
        console.log(f());
        """): '7\n',
    a_program("""
        const a = [7, 8];
        var NS = {h: 1};
        var f = NS.g = function (n) { return n > 0 ? NS.g(n - 1) : a[0]; };
        console.log(f(1));
        """): '7\n',
    a_program("""
        const a = [7, 8];
        var NS = {h: 1};
        NS.__proto__ = function () { return a[0]; };
        console.log(NS.prototype.constructor());
        """): '7\n',
}


#: Programs that hand the object holding `NS.g` to code before `a` exists but store `NS.g` only
#: after it, mapped to what Node prints for them: no call can reach `NS.g` before it is stored.
A_METHOD_STORED_AFTER_THE_CONSTANT_ON_AN_OBJECT_HANDED_OVER_BEFORE = {
    a_program("""
        var NS = {h: 1};
        NS.f = function () { return this.h; };
        console.log(NS.f());
        const a = [7, 8];
        NS.g = function () { return a[0]; };
        console.log(NS.g());
        """): '1\n7\n',
    a_program("""
        Object.prototype.z = 1;
        var NS = {h: 1};
        console.log(NS.k);
        const a = [7, 8];
        NS.g = function () { return a[0]; };
        console.log(NS.g());
        """): 'undefined\n7\n',
}


#: Modules that export a function reading `x` before `x` exists, mapped to a module in a cycle with
#: each: the exporter imports it, so it runs first, and it imports the function back and calls it.
AN_EXPORT_AN_IMPORTER_IN_A_CYCLE_CALLS_BEFORE_THE_CONSTANT = {
    a_program("""
        import { g } from './b.mjs';
        const x = 1;
        export { f };
        function f() { return x; }
        g();
        """): a_program("""
        export function g() {}
        import { f } from './main.mjs';
        console.log(f());
        """),
    a_program("""
        import './b.mjs';
        export function f() { return x[0]; }
        const x = [1];
        """): a_program("""
        import { f } from './main.mjs';
        console.log(f());
        """),
    a_program("""
        import './b.mjs';
        export default function () { return x[0]; }
        const x = [1];
        """): a_program("""
        import f from './main.mjs';
        console.log(f());
        """),
    a_program("""
        export * from './b.mjs';
        export default function () { return x[0]; }
        const x = [1];
        """): a_program("""
        import f from './main.mjs';
        console.log(f());
        """),
}


#: Modules that import nothing and export a function reading `y`, which only some runs of their body
#: define, mapped to a module importing the function that calls it once the exporter has finished.
AN_EXPORT_AN_IMPORTER_CALLS_AFTER_A_BODY_THAT_SKIPPED_THE_CONSTANT = {
    a_program("""
        export function f() { return y; }
        if (globalThis.c) {
          var y = 5;
          console.log(f());
        }
        """): a_program("""
        import { f } from './main.mjs';
        console.log(f());
        """),
}


def run_by_a_host_that_fires(
    source: str,
    entrypoint: str,
    method: str | None = None,
) -> tuple[str, str | None]:
    """
    What Node makes of *source* run as a classic global script by a host that offers it one
    function, `fire`, which calls the global function *entrypoint* at once, or with *method* the
    function stored at that key of the global object *entrypoint*: an event the host dispatches
    while the script is still running, as Windows Script Host does for a connected object.
    """
    target = F'globalThis[{json.dumps(entrypoint)}]'
    if method is not None:
        target = F'{target}[{json.dumps(method)}]'
    return behavior(inspect.cleandoc(F"""
        globalThis.fire = function () {{ {target}(); }};
        (0, eval)({json.dumps(source)});
        """))


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAMethodCalledThroughItsObject(TestBase):

    def test_a_call_before_the_constant_still_throws(self):
        rows = A_METHOD_CALLED_THROUGH_ITS_OBJECT_BEFORE_THE_CONSTANT
        self.assertEqual(
            {name: before_and_after(source) for name, source in rows.items()},
            {name: (('', 'ReferenceError'), ('', 'ReferenceError')) for name in rows},
        )

    def test_a_call_after_the_constant_still_prints_the_same(self):
        rows = {
            **THE_SAME_CALLS_AFTER_THE_CONSTANT,
            **A_METHOD_STORED_AFTER_THE_CONSTANT_ON_AN_OBJECT_HANDED_OVER_BEFORE,
        }
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


class TestAMethodCalledAfterTheConstantReadsItFolded(TestBase):

    def test_the_constant_is_folded_into_the_method(self):
        rows = THE_SAME_CALLS_AFTER_THE_CONSTANT
        self.assertEqual(
            {source: 'a[0]' in deobfuscate_source(source, module=True) for source in rows},
            {source: False for source in rows},
        )

    def test_the_constant_is_folded_into_a_method_stored_after_it(self):
        rows = A_METHOD_STORED_AFTER_THE_CONSTANT_ON_AN_OBJECT_HANDED_OVER_BEFORE
        self.assertEqual(
            {source: 'a[0]' in deobfuscate_source(source, module=True) for source in rows},
            {source: False for source in rows},
        )


class TestAFunctionCalledFromOutsideTheFile(TestBase):

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_a_host_firing_an_entrypoint_before_the_constant_still_throws(self):
        source = a_program("""
            function OnEvent() { console.log(K[0]); }
            fire();
            const K = ['x'];
            """)
        rewritten = deobfuscate_source(source, entrypoints=('OnEvent',))
        self.assertEqual(
            (
                run_by_a_host_that_fires(source, 'OnEvent'),
                run_by_a_host_that_fires(rewritten, 'OnEvent'),
            ),
            (('', 'ReferenceError'), ('', 'ReferenceError')),
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_a_host_firing_a_method_of_an_entrypoint_object_before_the_constant_still_throws(self):
        source = a_program("""
            var handlers = {};
            handlers.onload = function () { console.log(K[0]); };
            fire();
            const K = ['x'];
            """)
        rewritten = deobfuscate_source(source, entrypoints=('handlers',))
        self.assertEqual(
            (
                run_by_a_host_that_fires(source, 'handlers', 'onload'),
                run_by_a_host_that_fires(rewritten, 'handlers', 'onload'),
            ),
            (('', 'ReferenceError'), ('', 'ReferenceError')),
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_an_importer_calling_an_export_after_a_body_that_skipped_the_constant_reads_it_unset(self):
        """
        An importer outside every import cycle calls the export once the exporter has finished, and
        the run of the exporter it follows never defined `y`.
        """
        rows = AN_EXPORT_AN_IMPORTER_CALLS_AFTER_A_BODY_THAT_SKIPPED_THE_CONSTANT
        results = {}
        for exporter, importer in rows.items():
            rewritten = deobfuscate_source(exporter, module=True)
            results[exporter] = (
                module_graph_behavior({'main.mjs': exporter, 'b.mjs': importer}, 'b.mjs'),
                module_graph_behavior({'main.mjs': rewritten, 'b.mjs': importer}, 'b.mjs'),
            )
        self.assertEqual(
            results,
            {exporter: (('undefined\n', None), ('undefined\n', None)) for exporter in rows},
        )

    def test_an_entrypoint_no_host_reaches_by_name_reads_the_constant_folded(self):
        """
        Under the module model a top-level declaration is no property of the global object, so a
        declared entry point is called only where the file calls it.
        """
        source = a_program("""
            function OnEvent() { console.log(K[0]); }
            const K = ['x'];
            OnEvent();
            """)
        self.assertNotIn('K[0]', deobfuscate_source(source, module=True, entrypoints=('OnEvent',)))

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_an_importer_calling_an_export_before_the_constant_still_throws(self):
        """
        A function declaration crosses a module boundary at link time: a module the exporter
        imports, and which imports the exporter back, runs first and can call the function while a
        `const` it reads is still in its dead zone.
        """
        rows = AN_EXPORT_AN_IMPORTER_IN_A_CYCLE_CALLS_BEFORE_THE_CONSTANT
        results = {}
        for exporter, importer in rows.items():
            rewritten = deobfuscate_source(exporter, module=True)
            results[exporter] = (
                module_graph_behavior({'b.mjs': importer, 'main.mjs': exporter}, 'main.mjs'),
                module_graph_behavior({'b.mjs': importer, 'main.mjs': rewritten}, 'main.mjs'),
            )
        self.assertEqual(
            results,
            {exporter: (('', 'ReferenceError'), ('', 'ReferenceError')) for exporter in rows},
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_an_export_of_a_module_that_imports_nothing_reads_the_constant_folded(self):
        """
        A module that imports nothing is in no cycle, so it runs its whole body before any importer
        calls into it.
        """
        exporter = a_program("""
            export function f() { return x[0]; }
            const x = [1];
            """)
        importer = a_program("""
            import { f } from './main.mjs';
            console.log(f());
            """)
        rewritten = deobfuscate_source(exporter, module=True)
        self.assertNotIn('x[0]', rewritten)
        self.assertEqual(
            (
                module_graph_behavior({'main.mjs': exporter, 'b.mjs': importer}, 'b.mjs'),
                module_graph_behavior({'main.mjs': rewritten, 'b.mjs': importer}, 'b.mjs'),
            ),
            (('1\n', None), ('1\n', None)),
        )
