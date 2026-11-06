from __future__ import annotations

import inspect
import unittest

from test import TestBase
from test.lib.scripts.js.analysis.differential import behavior, deobfuscate_source, node_executable
from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator
from test.lib.scripts.js.ledger import (
    Program,
    Reading,
    a_program,
    before_and_after,
    each_program_still_prints,
    prints,
)

from refinery.lib.scripts.js.deobfuscation.restunpack import JsRestArrayUnpacking
from refinery.lib.scripts.js.options import ExecutionModel


class TestVariableDemasking(TestJsDeobfuscator):

    def _demask(self, source: str) -> str:
        return self._run_transformer(source, JsRestArrayUnpacking)

    def test_simple_two_params(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var f = function(p0, p1) {
                  return p0 + p1;
                };
                """
            ),
            self._demask('var f = function(...s) { s.length = 2; return s[0] + s[1]; }'),
        )

    def test_simple_zero_params_with_locals(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var f = function() {
                  var v0;
                  v0 = 10;
                  return v0;
                };
                """
            ),
            self._demask('var f = function(...s) { s.length = 0; s.a = 10; return s.a; }'),
        )

    def test_simple_negative_keys(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var f = function(p0) {
                  var v0;
                  v0 = p0 + 1;
                  return v0;
                };
                """
            ),
            self._demask(
                'var f = function(...s) { s.length = 1; s[-42] = s[0] + 1; return s[-42]; }'
            ),
        )

    def test_a_stack_an_object_holds_is_not_the_rest_parameter(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var NS = {};
                NS.fn = function(...r) {
                  NS.F.stk.length = 1;
                  return NS.F.stk[0] * 2;
                };
                """
            ),
            self._demask(
                'var NS = {}; NS.fn = function(...r) { NS.F.stk.length = 1; return NS.F.stk[0] * 2; }'
            ),
        )

    def test_skips_unresolvable_access(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var f = function(...s) {
                  s.length = 1;
                  return s[x];
                };
                """
            ),
            self._demask('var f = function(...s) { s.length = 1; return s[x]; }'),
        )

    def test_skips_rest_param_aliased(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var f = function(...s) {
                  s.length = 1;
                  foo(s);
                  return s[0];
                };
                """
            ),
            self._demask('var f = function(...s) { s.length = 1; foo(s); return s[0]; }'),
        )

    def test_nested_function_unpacked_in_own_scope(self):
        source = inspect.cleandoc(
            """
            var outer = function(...s) {
              s.length = 1;
              s.x = function(...t) { t.length = 0; t.a = 5; return t.a; };
              return s[0] + s.x();
            }
            """
        )
        self.assertEqual(
            inspect.cleandoc(
                """
                var outer = function(p0) {
                  var v0;
                  v0 = function() {
                    var v0;
                    v0 = 5;
                    return v0;
                  };
                  return p0 + v0();
                };
                """
            ),
            self._demask(source),
        )

    def test_frame_qualified_missing_accesses_skipped(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var f = function(...r) {
                  A.B.C.length = 2;
                  return A.X.C[0];
                };
                """
            ),
            self._demask('var f = function(...r) { A.B.C.length = 2; return A.X.C[0]; }'),
        )

    def test_unpacks_a_rest_array_a_closure_reads(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var f = function(p0) {
                  var g = function() {
                    return p0 + 1;
                  };
                  return p0 + g();
                };
                """
            ),
            self._demask('var f = function(...s) { s.length = 1; var g = function() { return s[0] + 1; }; return s[0] + g(); }'),
        )

    def test_keeps_a_rest_array_a_closure_reads_before_the_truncation(self):
        source = inspect.cleandoc(
            """
            var f = function(...s) {
              var g = function() {
                return s[1];
              };
              var early = g();
              s.length = 1;
              return early + s[0];
            };
            """
        )
        self.assertEqual(source, self._demask(source))

    def test_keeps_a_rest_array_a_var_declares_again(self):
        source = inspect.cleandoc(
            """
            var f = function(...s) {
              s.length = 1;
              var a = s[0];
              var s = [9];
              return a + s[0];
            };
            """
        )
        self.assertEqual(source, self._demask(source))

    def test_keeps_a_rest_array_with_a_deleted_slot(self):
        source = inspect.cleandoc(
            """
            var f = function(...s) {
              s.length = 0;
              s[0] = 1;
              delete s[0];
              return s[0];
            };
            """
        )
        self.assertEqual(source, self._demask(source))

    def test_keeps_a_rest_array_whose_inherited_method_is_called(self):
        source = inspect.cleandoc(
            """
            var f = function(...s) {
              s.length = 0;
              s[0] = 7;
              s.push(8);
              return s[1];
            };
            """
        )
        self.assertEqual(source, self._demask(source))

    def test_keeps_a_rest_array_whose_length_is_read_through_a_computed_key(self):
        source = inspect.cleandoc(
            """
            var f = function(...s) {
              s.length = 1;
              return s[0] + s["length"];
            };
            """
        )
        self.assertEqual(source, self._demask(source))

    def test_keeps_a_rest_array_whose_parameter_slot_is_called_with_it_as_receiver(self):
        source = inspect.cleandoc(
            """
            var f = function(...s) {
              s.length = 1;
              return s[0]();
            };
            """
        )
        self.assertEqual(source, self._demask(source))

    def test_unpacks_a_local_slot_called_with_the_array_as_receiver_that_holds_a_function_reading_none(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var f = function() {
                  var v0;
                  v0 = function() {
                    return 1;
                  };
                  return v0();
                };
                """
            ),
            self._demask('var f = function(...s) { s.length = 0; s[3] = function() { return 1; }; return s[3](); }'),
        )

    def test_keeps_a_rest_array_whose_local_slot_called_with_it_as_receiver_holds_a_function_reading_it(self):
        source = inspect.cleandoc(
            """
            var f = function(...s) {
              s.length = 0;
              s[3] = function() {
                return this.length;
              };
              return s[3]();
            };
            """
        )
        self.assertEqual(source, self._demask(source))

    def test_skips_rest_param_named_by_eval(self):
        source = inspect.cleandoc(
            """
            var f = function(...s) {
              s.length = 1;
              eval("s[2] = 9");
              return s[0];
            };
            """
        )
        self.assertEqual(source, self._demask(source))

    _REST_LENGTH_BEFORE_AN_UNRELATED_ONE = inspect.cleandoc(
        """
        var f = function(...s) {
          s.length = LENGTH;
          NS.F.stk.length = 1;
          return NS.F.stk[0] + s[0];
        };
        """
    )
    """
    A rest array whose own truncation is written first and an unrelated chain whose length is
    written after it, with the count the pass reads left open. The second statement is a truncation
    of a shape this pass does accept, so it is what a match that gives up on the first one lands on.
    """

    def _rest_length_before_an_unrelated_one(self, length: str) -> str:
        return self._REST_LENGTH_BEFORE_AN_UNRELATED_ONE.replace('LENGTH', length)

    def test_binds_the_first_length_written_to_the_rest_array(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var f = function(p0, p1) {
                  NS.F.stk.length = 1;
                  return NS.F.stk[0] + p0;
                };
                """
            ),
            self._demask(self._rest_length_before_an_unrelated_one('2')),
        )

    def test_skips_oversized_truncation_without_binding_a_later_length_assignment(self):
        source = self._rest_length_before_an_unrelated_one('1000000')
        self.assertEqual(source, self._demask(source))

    def test_skips_negative_truncation_without_binding_a_later_length_assignment(self):
        source = self._rest_length_before_an_unrelated_one('-1')
        self.assertEqual(source, self._demask(source))

    def test_skips_fractional_truncation_without_binding_a_later_length_assignment(self):
        source = self._rest_length_before_an_unrelated_one('1.5')
        self.assertEqual(source, self._demask(source))

    def test_skips_unreadable_truncation_without_binding_a_later_length_assignment(self):
        source = self._rest_length_before_an_unrelated_one('n')
        self.assertEqual(source, self._demask(source))

    def test_skips_oversized_frame_truncation_without_binding_a_later_length_assignment(self):
        source = inspect.cleandoc(
            """
            var g = function(...r) {
              NS.F.stk.length = 1000000;
              OT.G.buf.length = 1;
              return OT.G.buf[0];
            };
            """
        )
        self.assertEqual(source, self._demask(source))


class TestStackKeysThatOnlyLookLikeIndices(TestJsDeobfuscator):

    def _demask(self, source: str) -> str:
        return self._run_transformer(source, JsRestArrayUnpacking)

    def test_an_arabic_indic_digit_names_a_property_and_not_a_parameter(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var f = function(p0, p1, p2) {
                  var v0;
                  v0 = 9;
                  return p2 + v0;
                };
                """
            ),
            self._demask(
                'var f = function(...s) {'
                " s.length = 3; s['٢'] = 9; return s[2] + s['٢']; };"
            ),
        )

    def test_a_superscript_two_names_a_property_and_does_not_end_the_pass(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var f = function(p0) {
                  var v0;
                  v0 = 9;
                  return p0 + v0;
                };
                """
            ),
            self._demask(
                'var f = function(...s) {'
                " s.length = 1; s['²'] = 9; return s[0] + s['²']; };"
            ),
        )

    def test_a_leading_zero_names_a_property_and_not_the_index_its_digits_spell(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var f = function(p0, p1) {
                  var v0;
                  v0 = 9;
                  return p1 + v0;
                };
                """
            ),
            self._demask(
                'var f = function(...s) {'
                " s.length = 2; s['01'] = 9; return s[1] + s['01']; };"
            ),
        )


#: A sloppy program whose rest parameter would become a list of plain names, mapped to that rewrite,
#: to the rest pattern the pass writes instead, to what Node prints for the program and to what it
#: prints for the rewrite. The `arguments` object of a function with a rest parameter holds a copy
#: of the call's arguments, while that of a sloppy function with plain names aliases its parameters,
#: so a write under one name is read back under the other.
_A_REWRITE_THE_ARGUMENTS_OBJECT_WOULD_OBSERVE: dict[str, tuple[str, str, str, str]] = {
    'function f(...s) { s.length = 1; s[0] = 9; return arguments[0]; } console.log(f(3));': (
        'function f(p0) { p0 = 9; return arguments[0]; } console.log(f(3));',
        inspect.cleandoc(
            """
            function f(...[p0]) {
              p0 = 9;
              return arguments[0];
            }
            console.log(f(3));
            """
        ),
        '3\n',
        '9\n',
    ),
    'function f(...s) { s.length = 1; arguments[0] = 9; return s[0]; } console.log(f(3));': (
        'function f(p0) { arguments[0] = 9; return p0; } console.log(f(3));',
        inspect.cleandoc(
            """
            function f(...[p0]) {
              arguments[0] = 9;
              return p0;
            }
            console.log(f(3));
            """
        ),
        '3\n',
        '9\n',
    ),
    'function f(...s) { s.length = 2; s[1] = 9; return arguments[1]; } console.log(f(3, 4));': (
        'function f(p0, p1) { p1 = 9; return arguments[1]; } console.log(f(3, 4));',
        inspect.cleandoc(
            """
            function f(...[p0, p1]) {
              p1 = 9;
              return arguments[1];
            }
            console.log(f(3, 4));
            """
        ),
        '4\n',
        '9\n',
    ),
    'function f(...s) { s.length = 1; var b = arguments; s[0] = 9; return b[0]; }'
    ' console.log(f(3));': (
        'function f(p0) { var b = arguments; p0 = 9; return b[0]; } console.log(f(3));',
        inspect.cleandoc(
            """
            function f(...[p0]) {
              var b = arguments;
              p0 = 9;
              return b[0];
            }
            console.log(f(3));
            """
        ),
        '3\n',
        '9\n',
    ),
    'function g(x) { return x[0]; }'
    ' function f(...s) { s.length = 1; s[0] = 9; return g(arguments); } console.log(f(3));': (
        'function g(x) { return x[0]; }'
        ' function f(p0) { p0 = 9; return g(arguments); } console.log(f(3));',
        inspect.cleandoc(
            """
            function g(x) {
              return x[0];
            }
            function f(...[p0]) {
              p0 = 9;
              return g(arguments);
            }
            console.log(f(3));
            """
        ),
        '3\n',
        '9\n',
    ),
    'function f(...s) { s.length = 1; s[0] = 9; return [...arguments][0]; } console.log(f(3));': (
        'function f(p0) { p0 = 9; return [...arguments][0]; } console.log(f(3));',
        inspect.cleandoc(
            """
            function f(...[p0]) {
              p0 = 9;
              return [...arguments][0];
            }
            console.log(f(3));
            """
        ),
        '3\n',
        '9\n',
    ),
    'function f(...s) { s.length = 1; s[0] = 9; return (() => arguments[0])(); }'
    ' console.log(f(3));': (
        'function f(p0) { p0 = 9; return (() => arguments[0])(); } console.log(f(3));',
        inspect.cleandoc(
            """
            function f(...[p0]) {
              p0 = 9;
              return (() => arguments[0])();
            }
            console.log(f(3));
            """
        ),
        '3\n',
        '9\n',
    ),
}

#: In each function no element of an `arguments` object can alias a parameter: the function is
#: strict, reads no `arguments` object of its own, or is left with no parameter.
_A_REST_ARRAY_THE_PASS_UNPACKS: dict[str, tuple[str, str]] = {
    "'use strict';"
    ' function f(...s) { s.length = 1; s[0] = 9; return arguments[0] + s[0]; }'
    ' console.log(f(3));': (
        inspect.cleandoc(
            """
            'use strict';
            function f(p0) {
              p0 = 9;
              return arguments[0] + p0;
            }
            console.log(f(3));
            """
        ),
        '12\n',
    ),
    "function o() { 'use strict';"
    ' function f(...s) { s.length = 1; s[0] = 9; return arguments[0] + s[0]; }'
    ' return f(3); } console.log(o());': (
        inspect.cleandoc(
            """
            function o() {
              'use strict';
              function f(p0) {
                p0 = 9;
                return arguments[0] + p0;
              }
              return f(3);
            }
            console.log(o());
            """
        ),
        '12\n',
    ),
    'class C { m(...s) { s.length = 1; s[0] = 9; return arguments[0] + s[0]; } }'
    ' console.log(new C().m(3));': (
        inspect.cleandoc(
            """
            class C {
              m(p0) {
                p0 = 9;
                return arguments[0] + p0;
              }
            }
            console.log(new C().m(3));
            """
        ),
        '12\n',
    ),
    'function f(...s) { s.length = 1; s[0] = 9;'
    ' return (function () { return arguments[0]; })(7) + s[0]; } console.log(f(3));': (
        inspect.cleandoc(
            """
            function f(p0) {
              p0 = 9;
              return (function() {
                return arguments[0];
              })(7) + p0;
            }
            console.log(f(3));
            """
        ),
        '16\n',
    ),
    'function f(...s) { s.length = 0; s.a = arguments[0]; return s.a; } console.log(f(3));': (
        inspect.cleandoc(
            """
            function f() {
              var v0;
              v0 = arguments[0];
              return v0;
            }
            console.log(f(3));
            """
        ),
        '3\n',
    ),
    'function f(...s) { s.length = 1; var argumentsx = [7]; s[0] = 9;'
    ' return argumentsx[0] + s[0]; } console.log(f(3));': (
        inspect.cleandoc(
            """
            function f(p0) {
              var argumentsx = [7];
              p0 = 9;
              return argumentsx[0] + p0;
            }
            console.log(f(3));
            """
        ),
        '16\n',
    ),
    'function f(...s) { s.length = 2; return s[0] + s[1]; } console.log(f(3, 4));': (
        inspect.cleandoc(
            """
            function f(p0, p1) {
              return p0 + p1;
            }
            console.log(f(3, 4));
            """
        ),
        '7\n',
    ),
    'function f(...s) { s.length = 2; s.t = s[0] * s[1]; return s.t; } console.log(f(3, 4));': (
        inspect.cleandoc(
            """
            function f(p0, p1) {
              var v0;
              v0 = p0 * p1;
              return v0;
            }
            console.log(f(3, 4));
            """
        ),
        '12\n',
    ),
}


class TestARestParameterTheArgumentsObjectWouldObserve(TestJsDeobfuscator):

    def _demask(self, source: str) -> str:
        return self._run_transformer(source, JsRestArrayUnpacking)

    def test_the_pass_keeps_the_names_inside_a_rest_pattern(self):
        rows = _A_REWRITE_THE_ARGUMENTS_OBJECT_WOULD_OBSERVE
        self.assertEqual(
            {source: self._demask(source) for source in rows},
            {source: written for source, (_, written, _, _) in rows.items()},
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_reads_the_plain_names_differently_and_the_rest_pattern_alike(self):
        rows = _A_REWRITE_THE_ARGUMENTS_OBJECT_WOULD_OBSERVE
        self.assertEqual(
            {
                source: (behavior(source), behavior(plain), behavior(self._demask(source)))
                for source, (plain, _, _, _) in rows.items()
            },
            {
                source: ((kept, None), (changed, None), (kept, None))
                for source, (_, _, kept, changed) in rows.items()
            },
        )


class TestARestArrayThePassUnpacks(TestJsDeobfuscator):

    def _demask(self, source: str) -> str:
        return self._run_transformer(source, JsRestArrayUnpacking)

    def test_the_rest_parameter_becomes_the_named_list_the_row_records(self):
        rows = _A_REST_ARRAY_THE_PASS_UNPACKS
        self.assertEqual(
            {source: self._demask(source) for source in rows},
            {source: unpacked for source, (unpacked, _) in rows.items()},
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_prints_the_same_before_and_after_the_unpacking(self):
        rows = _A_REST_ARRAY_THE_PASS_UNPACKS
        self.assertEqual(
            {
                source: (behavior(source), behavior(self._demask(source)))
                for source in rows
            },
            {
                source: ((printed, None), (printed, None))
                for source, (_, printed) in rows.items()
            },
        )


class TestABodyThatOpensWithADirective(TestJsDeobfuscator):
    """
    A body under a rest parameter may not open with `'use strict'`, so the program the pass is given
    is a `SyntaxError`, and only the unpacked function can tell Node which mode it runs in.
    """

    def _demask(self, source: str) -> str:
        return self._run_transformer(source, JsRestArrayUnpacking)

    A_BODY_DECLARING_STRICT_MODE = (
        "var f = function (...s) { 'use strict'; s.length = 1; s.a = 1; leaked = s.a;"
        ' return s[0] + s.a; };\n'
        'try { console.log(f(1)); } catch (e) { console.log(e.name); }'
    )

    def test_the_directive_still_opens_the_unpacked_body(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var f = function(p0) {
                  'use asm';
                  var v0;
                  v0 = 10;
                  return p0 + v0;
                };
                """
            ),
            self._demask(
                "var f = function (...s) { 'use asm'; s.length = 1; s.a = 10; return s[0] + s.a; };"
            ),
        )

    def test_the_unpacked_function_declares_the_mode_the_directive_declares(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var f = function(p0) {
                  'use strict';
                  var v0;
                  v0 = 1;
                  leaked = v0;
                  return p0 + v0;
                };
                try {
                  console.log(f(1));
                } catch (e) {
                  console.log(e.name);
                }
                """
            ),
            self._demask(self.A_BODY_DECLARING_STRICT_MODE),
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_runs_the_unpacked_function_strict(self):
        self.assertEqual(
            ('ReferenceError\n', None),
            behavior(self._demask(self.A_BODY_DECLARING_STRICT_MODE)),
        )


_A_REST_ARRAY_NAMED_BEYOND_ITS_OWN_BODY = {
    (
        'function f(...m) { m.length = 0; m[3] = function () { return m[4]; }; m[4] = "v"; return m[3](); }\n'
        'console.log(f());\n'
    ): 'v\n',
    (
        'function f(...m) { m.length = 1; var set = function (x) { m[0] = x; }; set(m[0] + 1); return m[0]; }\n'
        'console.log(f(4));\n'
    ): '5\n',
    (
        'function f(...m) { m.length = 0; m[0] = 1; delete m[0]; return m[0]; }\n'
        'console.log(f());\n'
    ): 'undefined\n',
    (
        'function f(...a) { a.length = 0; a[0] = 1; var g = function (a) { return a[0]; }; return g([5]) + a[0]; }\n'
        'console.log(f());\n'
    ): '6\n',
    (
        'function f(...a) { a.length = 0; a[0] = 1; return function () { return eval("a[0]"); }(); }\n'
        'console.log(f());\n'
    ): '1\n',
    (
        'function f(...a) { a.length = 0; a[0] = 1; var o = { a: [7] }; with (o) { return a[0]; } }\n'
        'console.log(f());\n'
    ): '7\n',
    (
        'function f(...m) { m.length = 1; return function () { return m[0]; }; }\n'
        'var x = f(1), y = f(2);\n'
        'console.log(x(), y());\n'
    ): '1 2\n',
    (
        'function f(...m) { m.length = 0; m[1] = 2; var g = function () { var v0 = 9; return v0 + m[1]; }; return g(); }\n'
        'console.log(f());\n'
    ): '11\n',
    (
        'function f(...m) { m.length = 0; m[0] = 7; var g = function () { return m["length"]; }; return g(); }\n'
        'console.log(f());\n'
    ): '1\n',
    (
        'function f(...m) { m.length = 0; m[0] = 7; m.push(8); return m[1]; }\n'
        'console.log(f());\n'
    ): '8\n',
    (
        'function f(...m) { m.length = 0; m[0] = 7; var g = function () { m.push(8); }; g(); return m[1]; }\n'
        'console.log(f());\n'
    ): '8\n',
    (
        'function f(...m) { m.length = 0; m[0] = 7; m[1] = 8; var g = function () { return m.join("-"); }; return g(); }\n'
        'console.log(f());\n'
    ): '7-8\n',
    (
        'function run(...m) { m.length = 1; var call = function () { return m[0](); }; return call(); }\n'
        'console.log(run(function () { return Array.isArray(this); }));\n'
    ): 'true\n',
    (
        'function run(...m) { m.length = 1; return m[0](); }\n'
        'console.log(run(function () { return Array.isArray(this); }));\n'
    ): 'true\n',
    (
        'function f(...m) { var g = function () { return m[1]; }; var early = g(); m.length = 1; return early + m[0]; }\n'
        'console.log(f("a", "b"));\n'
    ): 'ba\n',
    (
        'function f(...m) { var early = g(); m.length = 1; return early + m[0]; function g() { return m[1]; } }\n'
        'console.log(f("a", "b"));\n'
    ): 'ba\n',
    (
        'function f(...m) { var early = m[1]; m.length = 1; return early + m[0]; }\n'
        'console.log(f("a", "b"));\n'
    ): 'ba\n',
    (
        'function f(...m) { m.length = 1; var a = m[0]; var m = [9]; return a + m[0]; }\n'
        'console.log(f(1));\n'
    ): '10\n',
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestARestArrayNamedBeyondItsOwnBody(TestJsDeobfuscator):

    def _demask(self, source: str) -> str:
        return self._run_transformer(source, JsRestArrayUnpacking)

    def test_node_prints_the_same_before_and_after_the_unpacking(self):
        rows = _A_REST_ARRAY_NAMED_BEYOND_ITS_OWN_BODY
        self.assertEqual(
            {source: (behavior(source), behavior(self._demask(source))) for source in rows},
            {source: ((printed, None), (printed, None)) for source, printed in rows.items()},
        )


_A_REST_ARRAY_AN_OBJECT_HOLDS = {
    (
        'function h(o) { o.k[0] = 10; }\n'
        'function f(...r) { var j = {}; j["k"] = r; j.k.length = 2; h(j); return j.k[0] + j.k[1]; }\n'
        'console.log(f(1, 2));\n'
    ): '12\n',
    (
        'function f(...r) {\n'
        '  var j = {}; j["k"] = r; j.k.length = 2; console.log(j.k.join()); return j.k[0] + j.k[1];\n'
        '}\n'
        'console.log(f(1, 2, 3));\n'
    ): '1,2\n3\n',
    (
        'function h(o, i) { return o.k[i]; }\n'
        'function f(...r) { var j = {}; j["k"] = r; j.k.length = 2; return h(j, 1) + j.k[0]; }\n'
        'console.log(f(1, 2));\n'
    ): '3\n',
}


class TestARestArrayAnObjectHoldsIsNotTheRestParameter(TestJsDeobfuscator):

    def _demask(self, source: str) -> str:
        return self._run_transformer(source, JsRestArrayUnpacking)

    def test_a_truncation_written_on_an_object_holding_the_rest_array_is_left_alone(self):
        source = inspect.cleandoc(
            """
            var f = function(...r) {
              var j = {};
              j.k = r;
              j.k.length = 2;
              return j.k[0] + j.k[1];
            };
            """
        )
        self.assertEqual(source, self._demask(source))

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_prints_the_same_before_and_after_the_deobfuscation(self):
        rows = _A_REST_ARRAY_AN_OBJECT_HOLDS
        deobfuscated = {
            source: deobfuscate_source(source, execution=ExecutionModel.commonjs) for source in rows
        }
        self.assertEqual(
            {source: (behavior(source), behavior(deobfuscated[source])) for source in rows},
            {source: ((printed, None), (printed, None)) for source, printed in rows.items()},
        )


A_STACK_REACHED_THROUGH_A_QUALIFIED_NAME = {
    'var NS = { F: {} };\n'
    'function f(...r) { NS.F.stk.length = 1; return NS.F.stk[0] * 2; }\n'
    'NS.F.stk = [5];\n'
    'console.log(f());\n': '10\n',

    'var NS = { F: { stk: [5] } };\n'
    'function f(...r) { NS.F.stk.length = 1; return NS.F.stk[0] * 2; }\n'
    'console.log(f(3));\n': '10\n',

    'var NS = { stk: [5] };\n'
    'function f(...r) { NS.stk.length = 1; return NS.stk[0] * 2; }\n'
    'console.log(f(3));\n': '10\n',

    'var NS = { F: { stk: [5, 7] } };\n'
    'function f(...r) { NS.F.stk.length = 2; return NS.F.stk[0] + NS.F.stk[1]; }\n'
    'console.log(f());\n': '12\n',

    'var NS = { F: { stk: [5] } };\n'
    'function f(...r) { NS.F.stk.length = 1; return NS.F.stk[0] * 2; }\n'
    'console.log(f() + f());\n': '20\n',

    'var NS = { F: { stk: [5] } };\n'
    'function f(...r) { NS.F.stk.length = 1; NS.F.stk[0] = NS.F.stk[0] + 1; }\n'
    'f();\n'
    'console.log(NS.F.stk[0]);\n': '6\n',
}


A_QUALIFIED_STACK_KEY_THAT_NAMES_NO_PARAMETER = {
    "'use strict';\n"
    'var NS = { F: { stk: [] } };\n'
    'function f(...r) { NS.F.stk.length = 0; NS.F.stk.a = 3; return NS.F.stk.a; }\n'
    'console.log(f());\n': '3\n',

    "'use strict';\n"
    'var NS = { F: { stk: [] } };\n'
    "function f(...r) { NS.F.stk.length = 0; NS.F.stk['zz'] = 3; return NS.F.stk['zz']; }\n"
    'console.log(f());\n': '3\n',

    "'use strict';\n"
    'var NS = { F: { stk: [] } };\n'
    'function f(...r) { NS.F.stk.length = 0; NS.F.stk[-1] = 3; return NS.F.stk[-1]; }\n'
    'console.log(f());\n': '3\n',

    "'use strict';\n"
    'var NS = { F: { stk: [] } };\n'
    "function f(...r) { NS.F.stk.length = 0; NS.F.stk['01'] = 3; return NS.F.stk['01']; }\n"
    'console.log(f());\n': '3\n',

    "'use strict';\n"
    'var NS = { stk: [] };\n'
    'function f(...r) { NS.stk.length = 0; NS.stk.a = 3; return NS.stk.a; }\n'
    'console.log(f());\n': '3\n',

    "'use strict';\n"
    'var NS = { F: { stk: [] } };\n'
    'function f(...r) { NS.F.stk.length = 0; NS.F.stk.a = 3; NS.F.stk.b = 4;'
    ' return NS.F.stk.a * NS.F.stk.b; }\n'
    'console.log(f());\n': '12\n',

    "'use strict';\n"
    'var NS = { F: { stk: [4] } };\n'
    'function f(...r) { NS.F.stk.length = 1; NS.F.stk.a = 3; return NS.F.stk[0] + NS.F.stk.a; }\n'
    'console.log(f(4));\n': '7\n',

    'var NS = { F: { stk: [] } };\n'
    'function f(...r) { NS.F.stk.length = 0; NS.F.stk.a = 3; return NS.F.stk.a; }\n'
    'var before = Object.getOwnPropertyNames(globalThis).length;\n'
    'f();\n'
    'console.log(Object.getOwnPropertyNames(globalThis).length - before);\n': '0\n',

    'var NS = { stk: [] };\n'
    'function f(...r) { NS.stk.length = 0; NS.stk.a = 3; return NS.stk.a; }\n'
    'var before = Object.getOwnPropertyNames(globalThis).length;\n'
    'f();\n'
    'console.log(Object.getOwnPropertyNames(globalThis).length - before);\n': '0\n',
}


A_REST_ARRAY_READ_THROUGH_A_CHAIN_OF_MEMBERS = {
    'the rest array stored on a local object': Program(
        a_program("""
            var f = function (...a) {
              var s = { k: a };
              s.k.length = 2;
              return s.k[1](s.k[0]);
            };
            console.log(f(1, function () { return this.length; }));
            """),
        prints('2'),
        Reading.COMMONJS,
    ),
    'an array of another object': Program(
        a_program("""
            var s = { k: [] };
            var f = function (...a) {
              s.k.length = 2;
              return s.k[1](s.k[0]);
            };
            s.k[1] = function (x) { return x; };
            console.log(f(5, 6));
            """),
        prints('undefined'),
        Reading.COMMONJS,
    ),
}


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAStackHangingOffAnObjectIsNotTheArgumentsOfACall(TestBase):

    def test_the_elements_the_object_holds_survive_the_unpacking(self):
        rows = A_STACK_REACHED_THROUGH_A_QUALIFIED_NAME
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestAKeyOfAStackHangingOffAnObjectStaysAKeyOfTheStack(TestBase):

    def test_each_program_still_prints_what_it_prints(self):
        rows = A_QUALIFIED_STACK_KEY_THAT_NAMES_NO_PARAMETER
        self.assertEqual(
            {source: before_and_after(source) for source in rows},
            each_program_still_prints(rows),
        )


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestARestArrayIsUnpackedOnlyFromItsOwnName(TestBase):

    def test_node_prints_what_each_row_pins(self):
        for label, row in A_REST_ARRAY_READ_THROUGH_A_CHAIN_OF_MEMBERS.items():
            with self.subTest(label=label):
                self.assertEqual(row.behaves(), row.prints)

    def test_the_deobfuscation_prints_what_the_program_prints(self):
        for label, row in A_REST_ARRAY_READ_THROUGH_A_CHAIN_OF_MEMBERS.items():
            with self.subTest(label=label):
                self.assertEqual(row.read(), row.required())
