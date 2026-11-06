from __future__ import annotations

import inspect

from test import TestBase

from refinery.lib.scripts.js.analysis.environment import FileKind, HostEnvironment
from refinery.lib.scripts.js.analysis.foreign import may_run_code_it_does_not_hold
from refinery.lib.scripts.js.analysis.model import build_semantic_model
from refinery.lib.scripts.js.parser import JsParser

_A_DECODER = inspect.cleandoc("""
    const decode = function (s) {
      rr = '';
      for (var i = 0; i < s.length; i++) {
        rr += String.fromCharCode(s.charCodeAt(i) ^ 1);
      }
      return rr;
    };
    console.log(decode('Idmmn'));
    """)


def _runs_foreign_code(
    source: str,
    *,
    trust_eval: bool = False,
    file_kind: FileKind = FileKind.script,
    environment: HostEnvironment = HostEnvironment.universal,
) -> bool:
    model = build_semantic_model(JsParser(source).parse(), environment, trust_eval, file_kind)
    return may_run_code_it_does_not_hold(model)


class TestAFileRunningOnlyWhatItHoldsRunsNoForeignCode(TestBase):

    def test_the_decoder_runs_none_in_each_host_and_model(self):
        for environment in HostEnvironment:
            for trust_eval in (False, True):
                for file_kind in (FileKind.script, FileKind.commonjs):
                    with self.subTest(environment=environment.name, trust_eval=trust_eval, file_kind=file_kind.name):
                        self.assertFalse(_runs_foreign_code(
                            _A_DECODER,
                            trust_eval=trust_eval,
                            file_kind=file_kind,
                            environment=environment,
                        ))

    def test_what_the_file_defines_or_only_tests_for_runs_none(self):
        for source in (
            'x = 1; console.log(x);',
            'var o = {}; console.log(globalThis.o);',
            "if (typeof run === 'function') { console.log(1); }",
            'function P() { this.n = 1; } P.prototype.get = function () { return this.n; };',
            'var stream = { write: function () {} }; stream.write(1);',
            "var e = { createElement: function () {} }; e.createElement('div');",
            'console.log(globalThis.Math.PI, constructor, toString);',
            "document.createElement('div');",
            "document.createElementNS('http://www.w3.org/2000/svg', 'svg:path');",
            "if (typeof importScripts === 'function') { console.log(1); }",
            "if (typeof document.write === 'function') { console.log(1); }",
            'globalThis.counter = 1;',
        ):
            with self.subTest(source=source):
                self.assertFalse(_runs_foreign_code(source))


class TestAFileRunningWhatItDoesNotHoldRunsForeignCode(TestBase):

    def test_a_reflection_surface_runs_it(self):
        for source in (
            'eval(s);',
            'new Function(s)();',
            "setTimeout('tick()', 0);",
            "import('./m.js');",
            'with (o) { x; }',
        ):
            with self.subTest(source=source):
                self.assertTrue(_runs_foreign_code(source))

    def test_code_a_file_loads_runs_it(self):
        self.assertTrue(_runs_foreign_code("require('./x');", file_kind=FileKind.commonjs))
        self.assertTrue(_runs_foreign_code("require('lodash');", file_kind=FileKind.commonjs))
        self.assertTrue(_runs_foreign_code("import 'x';", file_kind=FileKind.es_module))

    def test_code_vm_runs_counts_only_under_the_suspecting_model(self):
        source = "function stage(code) { require('vm').runInThisContext(code); }"
        self.assertTrue(_runs_foreign_code(source, file_kind=FileKind.commonjs))
        self.assertFalse(_runs_foreign_code(source, file_kind=FileKind.commonjs, trust_eval=True))

    def test_a_script_a_browser_or_a_worker_loads_runs_it_under_both_models(self):
        for source in (
            "document.createElement('script');",
            "document.createElement('SCRIPT');",
            'var tag = location.hash; document.createElement(tag);',
            "document.createElementNS('http://www.w3.org/2000/svg', 'script');",
            "document.createElementNS('http://www.w3.org/2000/svg', 'svg:script');",
            "document.createElement.call(document, 'script');",
            'var create = document.createElement.bind(document); create(location.hash);',
            "importScripts('a.js');",
            "self.importScripts('a.js');",
            "document.write('<p>');",
            "document.writeln('<p>');",
            "document.createRange().createContextualFragment('<p>');",
            "document.write.call(document, '<p>');",
            "document.write.apply(document, ['<p>']);",
            "var write = document.write.bind(document); write('<p>');",
        ):
            for trust_eval in (False, True):
                with self.subTest(source=source, trust_eval=trust_eval):
                    self.assertTrue(_runs_foreign_code(source, trust_eval=trust_eval))

    def test_a_string_run_as_code_runs_it_only_under_the_suspecting_model(self):
        for source in (
            "location.href = 'javascript:alert(1)';",
            'location = `JavaScript:${1}`;',
            "document.body.innerHTML = '<b>';",
            "document.body.outerHTML = '<b>';",
            "document.body.firstChild.srcdoc = '<b>';",
            "document.body.insertAdjacentHTML('beforeend', '<b>');",
            "document.body.setHTMLUnsafe('<b>');",
            "document.body.setAttribute('onclick', 'go()');",
            "document.body.setAttribute(location.hash, 'go()');",
            "document.body.setAttributeNS(null, 'onload', 'go()');",
            "document.body.setAttribute.call(document.body, 'onclick', 'go()');",
            "document.body.insertAdjacentHTML.call(document.body, 'beforeend', '<b>');",
            "location.href = 'java\\tscript:alert(1)';",
            "location.href = 'java\\nscript:alert(1)';",
        ):
            with self.subTest(source=source):
                self.assertTrue(_runs_foreign_code(source))
                self.assertFalse(_runs_foreign_code(source, trust_eval=True))

    def test_a_module_compiled_from_a_string_runs_it_only_under_the_suspecting_model(self):
        source = "module._compile('x = 1', 'x.js');"
        self.assertTrue(_runs_foreign_code(source, file_kind=FileKind.commonjs))
        self.assertFalse(_runs_foreign_code(source, file_kind=FileKind.commonjs, trust_eval=True))

    def test_a_use_of_a_global_nothing_defines_runs_it(self):
        for source in (
            'run(code);',
            'lib.decode(s);',
            'console.log(globalThis.o.x);',
            'var g = globalThis; g.o();',
        ):
            with self.subTest(source=source):
                self.assertTrue(_runs_foreign_code(source))

    def test_a_global_only_another_host_defines_runs_it_under_a_pin(self):
        self.assertFalse(_runs_foreign_code('console.log(document.title);'))
        self.assertTrue(_runs_foreign_code('console.log(document.title);', environment=HostEnvironment.node))

    def test_a_member_of_the_global_object_a_commonjs_file_declares_runs_it(self):
        source = 'var o = 1; console.log(globalThis.o);'
        self.assertFalse(_runs_foreign_code(source))
        self.assertTrue(_runs_foreign_code(source, file_kind=FileKind.commonjs))

    def test_a_require_the_load_sites_do_not_follow_runs_it(self):
        for source in (
            "require.call(null, './x');",
            "require.apply(null, ['./x']);",
            "var load = require; load('./x');",
            "require.main.require('./x');",
            "process.mainModule.require('./x');",
            "process.mainModule.require.call(null, 'fs');",
        ):
            for trust_eval in (False, True):
                with self.subTest(source=source, trust_eval=trust_eval):
                    self.assertTrue(_runs_foreign_code(source, file_kind=FileKind.commonjs, trust_eval=trust_eval))

    def test_a_require_of_a_built_in_module_running_no_code_runs_none(self):
        for source in (
            "require('fs');",
            "process.mainModule.require('child_process');",
            "require.main.require('node:path');",
            "if (typeof require === 'function') { console.log(1); }",
        ):
            with self.subTest(source=source):
                self.assertFalse(_runs_foreign_code(source, file_kind=FileKind.commonjs))

    def test_a_call_running_the_listeners_of_an_event_runs_it(self):
        for source in (
            "window.dispatchEvent(new Event('go'));",
            "document.fireEvent('onclick');",
            "var fire = document.dispatchEvent.bind(document); fire(new Event('go'));",
        ):
            for trust_eval in (False, True):
                with self.subTest(source=source, trust_eval=trust_eval):
                    self.assertTrue(_runs_foreign_code(source, trust_eval=trust_eval))

    def test_a_navigation_to_a_computed_address_runs_it_only_under_the_suspecting_model(self):
        for source in (
            'var u = location.hash; location = u;',
            'var u = location.hash; location.href = u;',
            'var u = location.hash; window.location = u;',
            'var u = location.hash; document.location.href = u;',
            'var u = location.hash; location.assign(u);',
            'var u = location.hash; location.replace(u);',
            "location.href += '#x';",
        ):
            with self.subTest(source=source):
                self.assertTrue(_runs_foreign_code(source))
                self.assertFalse(_runs_foreign_code(source, trust_eval=True))

    def test_a_navigation_to_a_literal_address_or_a_store_into_a_local_runs_none(self):
        for source in (
            "location.href = 'https://example.test/';",
            "location.assign('https://example.test/');",
            'function f(u) { var location = {}; location = u; return location; }',
        ):
            with self.subTest(source=source):
                self.assertFalse(_runs_foreign_code(source))
