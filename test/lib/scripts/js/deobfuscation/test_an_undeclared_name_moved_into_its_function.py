"""
A name a function stores into without declaring it, and that nothing else uses, behaves as a local
of that function where every run stores before it reads, and it moves into the function as a
file-level `var` does (`refinery.lib.scripts.js.analysis.localization`). A store into it creates a
property of the global object, so it stays where a store may do anything else: throw in strict
code, run a setter, or be read by code the file does not hold
(`refinery.lib.scripts.js.analysis.foreign`). Each program is written by hand, and each row says
what Node prints for it.
"""
from __future__ import annotations

import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import deobfuscate_source, node_executable
from test.lib.scripts.js.ledger import Program, Reading, a_program, folded, prints

from refinery.lib.scripts.js.analysis.environment import HostEnvironment
from refinery.lib.scripts.js.options import ExecutionModel

_A_DECODER = """
    const decode = function (s) {
      rr = '';
      for (var i = 0; i < s.length; i++) {
        rr += String.fromCharCode(s.charCodeAt(i) ^ 1);
      }
      return rr;
    };
    """

#: Programs a function of which stores into a name no declaration binds and then reads it, where
#: nothing but that function uses the name, mapped to what a host prints for each.
A_NAME_ONLY_ONE_FUNCTION_USES: dict[str, Program] = {
    'a decoder': Program(
        a_program(_A_DECODER + """
            var x = decode('Idmmn');
            console.log(x);
            """),
        prints('Hello'),
        Reading.SCRIPT,
    ),
    'a decoder in a CommonJS file': Program(
        a_program(_A_DECODER + """
            console.log(decode('Idmmn'));
            """),
        prints('Hello'),
        Reading.COMMONJS,
    ),
    'a name Object.prototype carries as a writable value': Program(
        a_program("""
            function f(v) { constructor = v; return constructor; }
            console.log(f(5));
            """),
        prints('5'),
        Reading.SCRIPT,
    ),
}

#: Programs a function of which stores into a name no declaration binds and then reads it, where a
#: store into the name does something a store into a local does not, mapped to what a host prints.
A_NAME_A_STORE_INTO_WHICH_DOES_MORE: dict[str, Program] = {
    'a store in strict code': Program(
        a_program("""
            function f(v) { 'use strict'; rr = v; return rr; }
            try { console.log(f(1)); } catch (e) { console.log(e.constructor.name); }
            """),
        prints('ReferenceError'),
        Reading.SCRIPT,
    ),
    'a decoder read as an ES module': Program(
        a_program(_A_DECODER + """
            try { console.log(decode('Idmmn')); } catch (e) { console.log(e.constructor.name); }
            """),
        prints('ReferenceError'),
        Reading.ES_MODULE,
    ),
    'a delete of the name': Program(
        a_program("""
            function f(v) { rr = v; delete rr; return typeof rr; }
            console.log(f(1));
            """),
        prints('undefined'),
        Reading.SCRIPT,
    ),
    'a setter Object.prototype carries under the name': Program(
        a_program("""
            Object.defineProperty(Object.prototype, 'rr', {
              get: function () { return 'kept'; },
              set: function (v) { console.log('set ' + v); },
              configurable: true
            });
            function f(v) { rr = v; return rr; }
            console.log(f(1));
            """),
        prints('set 1', 'kept'),
        Reading.SCRIPT,
    ),
    'a setter put under the name on the prototype of an object literal': Program(
        a_program("""
            Object.defineProperty(({}).__proto__, 'rr', {
              get: function () { return 'kept'; },
              set: function (v) { console.log('set ' + v); },
              configurable: true
            });
            function f(v) { rr = v; return rr; }
            console.log(f(1));
            """),
        prints('set 1', 'kept'),
        Reading.SCRIPT,
    ),
    'a setter put under the name on a prototype of the global object': Program(
        a_program("""
            Object.defineProperty(Object.getPrototypeOf(globalThis), 'rr', {
              get: function () { return 'kept'; },
              set: function (v) { console.log('set ' + v); },
              configurable: true
            });
            function f(v) { rr = v; return rr; }
            console.log(f(1));
            """),
        prints('set 1', 'kept'),
        Reading.SCRIPT,
    ),
    'a setter installed through a method of globalThis': Program(
        a_program("""
            globalThis.__defineSetter__('rr', function (v) { console.log('set ' + v); });
            function f(v) { rr = v; return rr; }
            console.log(f(1));
            """),
        prints('set 1', 'undefined'),
        Reading.SCRIPT,
    ),
    'the prototype of the global object replaced through the bare name __proto__': Program(
        a_program("""
            __proto__ = { set rr(v) { console.log('set ' + v); }, get rr() { return 'kept'; } };
            function f(v) { rr = v; return rr; }
            console.log(f(1));
            """),
        prints('set 1', 'kept'),
        Reading.SCRIPT,
    ),
    'a run of the function between the store and the read': Program(
        a_program("""
            function f(n) { x = n; if (n) f(n - 1); console.log(x); }
            f(2);
            """),
        prints('0', '0', '0'),
        Reading.SCRIPT,
    ),
    'a read before the store': Program(
        a_program("""
            function f(v) { var y = typeof x === 'undefined' ? 'none' : x; x = v; return y; }
            console.log(f(1));
            console.log(f(2));
            """),
        prints('none', '1'),
        Reading.SCRIPT,
    ),
    'the status of a window': Program(
        a_program("""
            function f(v) { status = v; return status === v; }
            console.log(f(5));
            """),
        prints('false', 'onload=undefined'),
        Reading.WINDOW,
        HostEnvironment.browser,
    ),
    'a constant a window inherits': Program(
        a_program("""
            function f(v) { TEMPORARY = v; return TEMPORARY; }
            console.log(f(5));
            """),
        prints('0', 'onload=undefined'),
        Reading.WINDOW,
        HostEnvironment.browser,
    ),
    'a setter Object.prototype carries, put there by an installer bound out of Object': Program(
        a_program("""
            const { defineProperty } = Object;
            defineProperty(Object.prototype, 'rr', {
              get: function () { return 'kept'; },
              set: function (v) { console.log('set ' + v); },
              configurable: true
            });
            function f(v) { rr = v; return rr; }
            console.log(f(1));
            """),
        prints('set 1', 'kept'),
        Reading.SCRIPT,
    ),
    'a setter Object.prototype carries, put there by a call spreading its arguments': Program(
        a_program("""
            var install = [Object.prototype, 'rr', {
              get: function () { return 'kept'; },
              set: function (v) { console.log('set ' + v); },
              configurable: true
            }];
            Object.defineProperty(...install);
            function f(v) { rr = v; return rr; }
            console.log(f(1));
            """),
        prints('set 1', 'kept'),
        Reading.SCRIPT,
    ),
    'code run by vm storing into the name between the store and the read': Program(
        a_program("""
            function stage(code) {
              result = 0;
              require('vm').runInThisContext(code);
              return result;
            }
            console.log(stage('result = 6 * 7'));
            """),
        prints('42'),
        Reading.COMMONJS,
    ),
    'code run by vm reading the name between the store and the read': Program(
        a_program("""
            function configure(v) {
              cfg = v;
              require('vm').runInThisContext("console.log('vm sees ' + cfg)");
              return cfg;
            }
            console.log(configure('x'));
            """),
        prints('vm sees x', 'x'),
        Reading.COMMONJS,
    ),
}

#: A program storing into a name no declaration binds where a setter the program installed under it
#: runs at the store, which nothing reads after, mapped to what a host prints.
A_STORE_A_SETTER_THE_PROGRAM_INSTALLED_RUNS = Program(
    a_program("""
        globalThis.__defineSetter__('tmp', function (v) { console.log('set ' + v); });
        function f(v) { tmp = v; return 1; }
        console.log(f(2));
        """),
    prints('set 2', '1'),
    Reading.SCRIPT,
)

#: A program storing into a name no declaration binds where a setter an installer bound out of
#: `Object` put under it runs at the store, which nothing reads after, mapped to what a host prints.
A_STORE_A_SETTER_AN_INSTALLER_BOUND_OUT_OF_OBJECT_INSTALLED_RUNS = Program(
    a_program("""
        const { defineProperty } = Object;
        defineProperty(Object.prototype, 'tmp', {
          set: function (v) { console.log('set ' + v); },
          configurable: true
        });
        function f(v) { tmp = v; return 1; }
        console.log(f(2));
        """),
    prints('set 2', '1'),
    Reading.SCRIPT,
)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestANameOnlyOneFunctionUsesMovesIntoIt(TestBase):

    def test_a_host_prints_what_each_row_pins(self):
        for label, row in A_NAME_ONLY_ONE_FUNCTION_USES.items():
            with self.subTest(label=label):
                self.assertEqual(row.behaves(), row.prints)

    def test_each_program_still_prints_it_after_the_deobfuscation(self):
        for label, row in A_NAME_ONLY_ONE_FUNCTION_USES.items():
            with self.subTest(label=label):
                self.assertEqual(row.deobfuscated(), row.prints)


class TestTheCallOfAFunctionUsingANameOfItsOwnFolds(TestBase):

    def test_the_decoder_folds_to_the_string_it_returns(self):
        self.assertEqual(folded(A_NAME_ONLY_ONE_FUNCTION_USES['a decoder'].text), "console.log('Hello');")

    def test_the_decoder_folds_in_a_commonjs_file(self):
        source = A_NAME_ONLY_ONE_FUNCTION_USES['a decoder in a CommonJS file'].text
        self.assertEqual(deobfuscate_source(source, execution=ExecutionModel.commonjs), "console.log('Hello');")

    def test_the_decoder_folds_in_each_host(self):
        source = A_NAME_ONLY_ONE_FUNCTION_USES['a decoder'].text
        for environment in HostEnvironment:
            with self.subTest(environment=environment.name):
                self.assertEqual(folded(source, environment=environment), "console.log('Hello');")

    def test_a_name_object_prototype_carries_as_a_writable_value_folds(self):
        source = A_NAME_ONLY_ONE_FUNCTION_USES['a name Object.prototype carries as a writable value'].text
        self.assertEqual(folded(source), 'console.log(5);')


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestANameAStoreIntoWhichDoesMoreStays(TestBase):

    def test_a_host_prints_what_each_row_pins(self):
        for label, row in A_NAME_A_STORE_INTO_WHICH_DOES_MORE.items():
            with self.subTest(label=label):
                self.assertEqual(row.behaves(), row.prints)

    def test_each_program_still_prints_it_after_the_deobfuscation(self):
        for label, row in A_NAME_A_STORE_INTO_WHICH_DOES_MORE.items():
            with self.subTest(label=label):
                self.assertEqual(row.deobfuscated(), row.prints)

    def test_a_store_a_setter_the_program_installed_runs_is_kept(self):
        row = A_STORE_A_SETTER_THE_PROGRAM_INSTALLED_RUNS
        self.assertEqual(row.read(), row.required())

    def test_a_store_a_setter_installed_by_an_installer_bound_out_of_object_runs_is_kept(self):
        row = A_STORE_A_SETTER_AN_INSTALLER_BOUND_OUT_OF_OBJECT_INSTALLED_RUNS
        self.assertEqual(row.read(), row.required())


class TestAGlobalStaysWhereTheFileMayRunCodeItDoesNotHold(TestBase):

    def test_an_undeclared_name_stays_across_a_call_of_a_function_nothing_defines(self):
        source = a_program("""
            function f(v) { rr = v; run(); return rr; }
            console.log(f(1));
            """)
        self.assertIn('rr = v', folded(source))

    def test_a_var_of_a_classic_script_stays_across_a_call_of_a_function_nothing_defines(self):
        source = a_program("""
            var rr;
            function f(v) { rr = v; run(); return rr; }
            console.log(f(1));
            """)
        self.assertIn('rr = v', folded(source))

    def test_a_var_of_a_commonjs_file_moves_across_a_call_of_a_function_nothing_defines(self):
        source = a_program("""
            var rr;
            function f(v) { rr = v; run(); return rr; }
            console.log(f(1));
            """)
        self.assertNotIn('rr = v', deobfuscate_source(source, execution=ExecutionModel.commonjs))

    def test_an_undeclared_name_stays_across_a_read_of_a_global_nothing_defines(self):
        source = a_program("""
            function f(v, o) { rr = v; o.x; return rr; }
            console.log(f(1, globalThis.o));
            """)
        self.assertIn('rr = v', folded(source))

    def test_an_undeclared_name_stays_where_markup_written_into_the_document_may_read_it(self):
        source = a_program("""
            function f(v) { rr = v; document.write('<script>console.log(rr)</' + 'script>'); return rr; }
            f(1);
            """)
        self.assertIn('rr = v', folded(source))

    def test_a_var_of_a_classic_script_stays_where_markup_written_into_the_document_may_read_it(self):
        source = a_program("""
            var rr;
            function f(v) { rr = v; document.write('<script>console.log(rr)</' + 'script>'); return rr; }
            f(1);
            """)
        self.assertIn('rr = v', folded(source))

    def test_an_undeclared_name_stays_where_markup_is_written_through_the_call_of_the_writer(self):
        source = a_program("""
            function f(v) { rr = v; document.write.call(document, '<script>rr = 5</' + 'script>'); return rr; }
            console.log(f(1));
            """)
        self.assertIn('rr = v', folded(source))

    def test_an_undeclared_name_stays_where_a_script_element_is_made_through_the_call_of_the_maker(self):
        source = a_program("""
            function f(v) {
              rr = v;
              var s = document.createElement.call(document, 'script');
              s.text = 'rr = 5';
              document.head.appendChild(s);
              return rr;
            }
            console.log(f(1));
            """)
        self.assertIn('rr = v', folded(source))

    def test_an_undeclared_name_stays_where_a_script_element_is_made_under_a_prefix(self):
        source = a_program("""
            function f(v) {
              rr = v;
              var s = document.createElementNS('http://www.w3.org/2000/svg', 'svg:script');
              s.textContent = 'rr = 5';
              document.documentElement.appendChild(s);
              return rr;
            }
            console.log(f(1));
            """)
        self.assertIn('rr = v', folded(source))

    def test_an_undeclared_name_stays_where_a_javascript_address_may_read_it(self):
        source = a_program("""
            function f(v) { rr = v; location.href = 'javascript:console.log(rr)'; return rr; }
            console.log(f(1));
            """)
        self.assertIn('rr = v', folded(source))

    def test_an_undeclared_name_stays_where_a_javascript_address_split_by_a_tab_may_read_it(self):
        source = a_program("""
            function f(v) { rr = v; location.href = 'java\\tscript:console.log(rr)'; return rr; }
            console.log(f(1));
            """)
        self.assertIn('rr = v', folded(source))

    def test_an_undeclared_name_stays_where_a_computed_address_may_read_it(self):
        source = a_program("""
            function f(v, u) { rr = v; location.href = u; return rr; }
            console.log(f(1, location.hash));
            """)
        self.assertIn('rr = v', folded(source))

    def test_an_undeclared_name_stays_where_a_module_is_loaded_through_the_main_module(self):
        source = a_program("""
            function f(v) { rr = v; require.main.require('./x'); return rr; }
            console.log(f(1));
            """)
        self.assertIn('rr = v', deobfuscate_source(source, execution=ExecutionModel.commonjs))

    def test_an_undeclared_name_stays_where_require_is_handed_on(self):
        source = a_program("""
            function f(v) { rr = v; require.call(null, './x'); return rr; }
            console.log(f(1));
            """)
        self.assertIn('rr = v', deobfuscate_source(source, execution=ExecutionModel.commonjs))

    def test_an_undeclared_name_stays_where_the_listeners_of_an_event_run(self):
        source = a_program("""
            function f(v) { rr = v; window.dispatchEvent(new Event('go')); return rr; }
            console.log(f(1));
            """)
        self.assertIn('rr = v', folded(source))


class TestANameAHostInheritsWithoutASetterIsNoVariable(TestBase):

    def test_a_strict_store_into_the_self_of_a_worker_is_kept(self):
        source = "'use strict'; self = 1; console.log('after');"
        self.assertIn('self = 1', folded(source, environment=HostEnvironment.worker))

    def test_a_strict_store_into_the_self_of_a_worker_is_kept_without_a_pin(self):
        source = "'use strict'; self = 1; console.log('after');"
        self.assertIn('self = 1', folded(source))

    def test_a_name_with_an_accessor_on_the_prototype_of_a_window_stays(self):
        source = a_program("""
            Object.defineProperty(EventTarget.prototype, 'rr', { set: function (v) { console.log('set ' + v); } });
            function f(v) { rr = v; return rr; }
            console.log(f(1));
            """)
        self.assertIn('rr = v', folded(source, environment=HostEnvironment.browser))
