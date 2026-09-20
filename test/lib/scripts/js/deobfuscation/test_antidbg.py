from __future__ import annotations

import inspect
import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import behavior, node_executable
from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator
from test.lib.scripts.js.ledger import Program, Reading, a_program, prints

from refinery.lib.scripts.js.deobfuscation.antidbg import JsRemoveSelfDefending


class TestAntiDebug(TestJsDeobfuscator):

    _DEFENSE_CODE = (
        "var a = (function() {"
        "  var b = true;"
        "  return function(c, d) {"
        "    var e = b ? function() {"
        "      if (d) { var f = d.apply(c, arguments); return d = null, f; }"
        "    } : function() {};"
        "    return b = false, e;"
        "  };"
        "}()), g = a(this, function() {"
        "  return g.toString().search('(((.+)+)+)+$')"
        "    .toString().constructor(g).search('(((.+)+)+)+$');"
        "});"
    )

    def test_remove_self_defending_redos(self):
        source = self._DEFENSE_CODE + (
            "g();"
            "console.log('hello');"
        )
        self.assertEqual(self._deobfuscate(source), "console.log('hello');")

    def test_preserves_code_without_redos(self):
        source = inspect.cleandoc(
            """
            var x = 1;
            console.log(x);
            """
        )
        self.assertEqual(source, self._run_transformer(source, JsRemoveSelfDefending))

    _REFERENCED_FACTORY = _DEFENSE_CODE + (
        "g();"
        "var other = a;"
        "console.log(typeof other);"
    )

    def test_redos_factory_preserved_when_referenced(self):
        """
        The factory is kept because `other` still names it once the guard is gone; removing its
        declaration would strand that reference. The reference does not call the factory again: a
        second call to this run-once factory would take its already-flipped branch and return the
        empty function, a shape no real guard payload carries and the removal is not answerable to,
        so the fixture references the factory without re-invoking it and stays stdout-equivalent.
        """
        self.assertEqual(
            inspect.cleandoc(
                """
                var a = (function() {
                  var b = true;
                  return function(c, d) {
                    var e = b ? function() {
                      if (d) {
                        var f = d.apply(c, arguments);
                        return d = null, f;
                      }
                    } : function() {};
                    return b = false, e;
                  };
                }());
                var other = a;
                console.log(typeof other);
                """
            ),
            self._run_transformer(self._REFERENCED_FACTORY, JsRemoveSelfDefending),
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_redos_factory_preserved_when_referenced_preserves_behaviour(self):
        source = self._REFERENCED_FACTORY
        self.assertEqual(
            behavior(source),
            behavior(self._run_transformer(source, JsRemoveSelfDefending)),
        )

    _SAME_NAME_FACTORY = (
        'var fac = function() { return function() {}; };'
        " var g = fac('(((.+)+)+)+$');"
        ' g();'
        ' function other() { var fac = 7; return fac; }'
        ' console.log(other());'
    )

    def test_factory_removed_despite_same_name_in_other_scope(self):
        """
        The outer `fac` factory returns a function, so the guard `g()` is a no-op and the fixture runs
        to print `7` rather than throwing — a program the deobfuscation is answerable to. Removing the
        outer factory must leave `other`'s own `fac`, a distinct binding, untouched.
        """
        self.assertEqual(
            inspect.cleandoc(
                """
                function other() {
                  var fac = 7;
                  return fac;
                }
                console.log(other());
                """
            ),
            self._run_transformer(self._SAME_NAME_FACTORY, JsRemoveSelfDefending),
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_factory_removed_despite_same_name_in_other_scope_preserves_behaviour(self):
        source = self._SAME_NAME_FACTORY
        self.assertEqual(
            behavior(source),
            behavior(self._run_transformer(source, JsRemoveSelfDefending)),
        )

    def test_redos_guard_invoked_as_return_sequence_operand_is_removed_whole(self):
        source = inspect.cleandoc(
            """
            var total = 0;
            function add(n) {
              var a = (function () {
                var b = true;
                return function (c, d) {
                  var e = b ? function () {
                    if (d) { var f = d.apply(c, arguments); return d = null, f; }
                  } : function () {};
                  return b = false, e;
                };
              }());
              var g = a(this, function () {
                return g.toString().length + 'x'.search('(((.+)+)+)+$');
              });
              return g(), total += n, total;
            }
            add(1);
            add(2);
            console.log(total);
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                var total = 0;
                function add(n) {
                  return total += n, total;
                }
                add(1);
                add(2);
                console.log(total);
                """
            ),
            self._run_transformer(source, JsRemoveSelfDefending),
        )

    def test_redos_guard_whose_result_is_read_is_preserved_whole(self):
        source = inspect.cleandoc(
            """
            var a = (function () {
              var b = true;
              return function (c, d) {
                var e = b ? function () {
                  if (d) { var f = d.apply(c, arguments); return d = null, f; }
                } : function () {};
                return b = false, e;
              };
            }());
            var g = a(this, function () {
              return g.toString().length + 'x'.search('(((.+)+)+)+$');
            });
            var r = g();
            console.log(typeof r);
            """
        )
        self.assertEqual(
            self._run_transformers(source),
            self._run_transformer(source, JsRemoveSelfDefending),
        )


class TestRemoveSelfDefendingStructural(TestJsDeobfuscator):

    _FACTORY = (
        "var a = (function() {"
        "  var b = true;"
        "  return function(c, d) {"
        "    var e = b ? function() {"
        "      if (d) { var f = d.apply(c, arguments); return d = null, f; }"
        "    } : function() {};"
        "    return b = false, e;"
        "  };"
        "}());"
    )

    def test_console_disable_payload_immediate_guard_is_removed(self):
        source = (
            self._FACTORY
            + "a(this, function() { console.log = function() {}; })();"
            + " console.log('done');"
        )
        self.assertEqual(
            "console.log('done');",
            self._run_transformer(source, JsRemoveSelfDefending),
        )

    def test_source_regexp_payload_iife_wrapped_guard_is_removed(self):
        source = (
            self._FACTORY
            + "(function() { a(this, function() {"
            + " return new RegExp('function *\\\\( *\\\\)').test('x'); })(); })();"
            + " console.log('done');"
        )
        self.assertEqual(
            "console.log('done');",
            self._run_transformer(source, JsRemoveSelfDefending),
        )

    def test_iife_wrapped_guard_as_sequence_operand_removes_only_guard(self):
        source = (
            self._FACTORY
            + "(function() { a(this, function() { console.error = null; })(); })(),"
            + " setInterval(function() {}, 1000);"
            + " console.log('main');"
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                setInterval(function() {}, 1000);
                console.log('main');
                """
            ),
            self._run_transformer(source, JsRemoveSelfDefending),
        )

    def test_stored_guard_as_sequence_operand_removes_only_guard(self):
        source = (
            self._FACTORY
            + "var g = a(this, function() { console.warn = 0; });"
            + " g(), console.log('main');"
        )
        self.assertEqual(
            "console.log('main');",
            self._run_transformer(source, JsRemoveSelfDefending),
        )

    def test_stored_result_only_read_is_not_removed(self):
        source = (
            self._FACTORY
            + "var g = a(this, function() { console.log = function() {}; return 42; });"
            + " console.log(g);"
        )
        self.assertEqual(
            self._run_transformers(source),
            self._run_transformer(source, JsRemoveSelfDefending),
        )

    def test_unmarked_payload_guard_is_not_removed(self):
        source = (
            self._FACTORY
            + "a(this, function() { setup(); })();"
            + " console.log('done');"
        )
        self.assertEqual(
            self._run_transformers(source),
            self._run_transformer(source, JsRemoveSelfDefending),
        )

    def test_console_reading_payload_guard_is_not_removed(self):
        source = (
            self._FACTORY
            + "a(this, function() { console.log('probe'); })();"
            + " console.log('done');"
        )
        self.assertEqual(
            self._run_transformers(source),
            self._run_transformer(source, JsRemoveSelfDefending),
        )

    def test_empty_payload_guard_is_not_removed(self):
        source = self._FACTORY + "a(this, function() {})();"
        self.assertEqual(
            self._run_transformers(source),
            self._run_transformer(source, JsRemoveSelfDefending),
        )

    def test_stored_guard_self_referencing_payload_is_removed(self):
        source = (
            self._FACTORY
            + "var g = a(this, function() { console.log = g; });"
            + " g(); console.log('main');"
        )
        self.assertEqual(
            "console.log('main');",
            self._run_transformer(source, JsRemoveSelfDefending),
        )


#: Classic scripts whose run-once wrapper spells the template's shapes for reasons of its own,
#: handed the global object as its receiver, mapped to the behavior a host gives them: the wrapper
#: runs its payload. The structural detector must not take any of them for the self-defending
#: template.
A_BENIGN_RUN_ONCE_WRAPPER = {
    'the conditional tests the payload parameter': Program(
        a_program("""
            var once = function (context, fn) {
              var run = fn
                ? function () { var r = fn.apply(context, arguments); fn = null; return r; }
                : function () {};
              return run;
            };
            var boot = once(this, function () { console.log('ran'); });
            boot();
            """),
        prints('ran'),
        Reading.SCRIPT,
    ),
    'the flag is a closure variable and the payload is benign': Program(
        a_program("""
            var once = function () {
              var live = true;
              return function (context, fn) {
                var run = live
                  ? function () { var r = fn.apply(context, arguments); fn = null; return r; }
                  : function () {};
                return live = false, run;
              };
            }();
            var boot = once(this, function () { console.log('ran'); });
            boot();
            """),
        prints('ran'),
        Reading.SCRIPT,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestABenignRunOnceWrapperKeepsRunning(TestBase):

    def test_every_program_behaves_the_way_the_host_does(self):
        for label, row in A_BENIGN_RUN_ONCE_WRAPPER.items():
            with self.subTest(label):
                self.assertEqual(row.read(), row.required())


#: Programs spelling the ReDoS-marked guard the way real emissions do, mapped to the behavior an
#: engine gives them. The payload closes over its own guard and carries the signature string
#: without running the catastrophic search, so an engine finishes the original; a removal must
#: excise every invocation it orphans, and a guard whose result the program reads must stay whole.
A_REDOS_GUARD_EMISSION = {
    'the guard is invoked as a return sequence operand': Program(
        a_program("""
            var total = 0;
            function add(n) {
              var a = (function () {
                var b = true;
                return function (c, d) {
                  var e = b ? function () {
                    if (d) { var f = d.apply(c, arguments); return d = null, f; }
                  } : function () {};
                  return b = false, e;
                };
              }());
              var g = a(this, function () {
                return g.toString().length + 'x'.search('(((.+)+)+)+$');
              });
              return g(), total += n, total;
            }
            add(1);
            add(2);
            console.log(total);
            """),
        prints('3'),
    ),
    'the guard result is read': Program(
        a_program("""
            var a = (function () {
              var b = true;
              return function (c, d) {
                var e = b ? function () {
                  if (d) { var f = d.apply(c, arguments); return d = null, f; }
                } : function () {};
                return b = false, e;
              };
            }());
            var g = a(this, function () {
              return g.toString().length + 'x'.search('(((.+)+)+)+$');
            });
            var r = g();
            console.log(typeof r);
            """),
        prints('number'),
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestARedosGuardRemovalLeavesARunningProgram(TestBase):

    def test_every_program_behaves_the_way_the_engine_does(self):
        for label, row in A_REDOS_GUARD_EMISSION.items():
            with self.subTest(label):
                self.assertEqual(row.read(), row.required())
