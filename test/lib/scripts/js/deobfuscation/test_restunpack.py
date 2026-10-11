from __future__ import annotations

import inspect
import unittest

from test.lib.scripts.js.analysis.differential import behavior, node_executable
from test.lib.scripts.js.deobfuscation import TestJsDeobfuscator

from refinery.lib.scripts.js.deobfuscation.restunpack import JsRestArrayUnpacking


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

    def test_frame_qualified(self):
        self.assertEqual(
            inspect.cleandoc(
                """
                var NS = {};
                NS.fn = function(p0) {
                  return p0 * 2;
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
        """
        The control the refusals below are read against. Two is a parameter count, so the rest array
        is unpacked into two parameters and the unrelated chain is left exactly where it was. Node
        prints `8 [7]` for both programs with `NS.F.stk` starting as `[7, 8, 9]` and `f(1, 2, 3)`.
        """
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
        """
        A million is no parameter list, so the pattern is not this one. Reading on until some other
        `.length =` fits would unpack the function around a stack it never had, dropping the rest
        parameter that the surviving statements still name.
        """
        source = self._rest_length_before_an_unrelated_one('1000000')
        self.assertEqual(source, self._demask(source))

    def test_skips_negative_truncation_without_binding_a_later_length_assignment(self):
        source = self._rest_length_before_an_unrelated_one('-1')
        self.assertEqual(source, self._demask(source))

    def test_skips_fractional_truncation_without_binding_a_later_length_assignment(self):
        source = self._rest_length_before_an_unrelated_one('1.5')
        self.assertEqual(source, self._demask(source))

    def test_skips_unreadable_truncation_without_binding_a_later_length_assignment(self):
        """
        The count is a name rather than a number, so nothing about it is known. That is the same
        answer as an unusable number and not a reason to look for a different statement.
        """
        source = self._rest_length_before_an_unrelated_one('n')
        self.assertEqual(source, self._demask(source))

    def test_skips_oversized_frame_truncation_without_binding_a_later_length_assignment(self):
        """
        The same refusal when the oversized truncation is the frame-qualified form, where the
        candidate that follows is another chain rather than the rest parameter.
        """
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
    """
    A stack key is a property name, and only the canonical decimal spelling of an index names the
    element a parameter stands in for. `str.isdigit` answers a different question: it is true of every
    Unicode decimal digit and of the superscripts, so it accepts names that index nothing. Restricting
    it to ASCII answers a different question still: a run of ASCII digits behind a zero is a name no
    element of any array has.
    """

    def _demask(self, source: str) -> str:
        return self._run_transformer(source, JsRestArrayUnpacking)

    def test_an_arabic_indic_digit_names_a_property_and_not_a_parameter(self):
        """
        `s['٢']` and `s[2]` are two properties in JavaScript, so a rewrite that gives them one
        name computes a different sum: with the arguments `(0, 0, 5)` the function returns `14`
        where the rewritten one returns `18`.
        """
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
        """
        `s['²']` and `s[0]` are two properties, and the superscript is a name no index has, so the
        one parameter stays alone and the key becomes a local beside it.
        """
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
        """
        `s['01']` and `s[1]` are two properties in JavaScript — `Object.keys` of the array reports
        `0`, `1` and `01` — so a rewrite that gives them one name computes a different sum: with
        the arguments `(0, 5)` the function returns `14` where the rewritten one returns `18`.
        """
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


#: A sloppy program whose single rest parameter would become a list of plain names, mapped to the
#: program that rewrite would produce and to what Node prints for each of the two. A rest parameter
#: is not a simple parameter list, so the `arguments` object such a function has holds a copy of the
#: call's arguments; a list of plain names makes its elements alias the parameters instead, and the
#: write each program makes is then read back under the other name. No pair here agrees, which is
#: what the refusal is worth.
_A_REWRITE_THE_ARGUMENTS_OBJECT_WOULD_OBSERVE: dict[str, tuple[str, str, str]] = {
    'function f(...s) { s.length = 1; s[0] = 9; return arguments[0]; } console.log(f(3));': (
        'function f(p0) { p0 = 9; return arguments[0]; } console.log(f(3));',
        '3\n',
        '9\n',
    ),
    'function f(...s) { s.length = 1; arguments[0] = 9; return s[0]; } console.log(f(3));': (
        'function f(p0) { arguments[0] = 9; return p0; } console.log(f(3));',
        '3\n',
        '9\n',
    ),
    'function f(...s) { s.length = 2; s[1] = 9; return arguments[1]; } console.log(f(3, 4));': (
        'function f(p0, p1) { p1 = 9; return arguments[1]; } console.log(f(3, 4));',
        '4\n',
        '9\n',
    ),
    'function f(...s) { s.length = 1; var b = arguments; s[0] = 9; return b[0]; }'
    ' console.log(f(3));': (
        'function f(p0) { var b = arguments; p0 = 9; return b[0]; } console.log(f(3));',
        '3\n',
        '9\n',
    ),
    'function g(x) { return x[0]; }'
    ' function f(...s) { s.length = 1; s[0] = 9; return g(arguments); } console.log(f(3));': (
        'function g(x) { return x[0]; }'
        ' function f(p0) { p0 = 9; return g(arguments); } console.log(f(3));',
        '3\n',
        '9\n',
    ),
    'function f(...s) { s.length = 1; s[0] = 9; return [...arguments][0]; } console.log(f(3));': (
        'function f(p0) { p0 = 9; return [...arguments][0]; } console.log(f(3));',
        '3\n',
        '9\n',
    ),
    'function f(...s) { s.length = 1; s[0] = 9; return (() => arguments[0])(); }'
    ' console.log(f(3));': (
        'function f(p0) { p0 = 9; return (() => arguments[0])(); } console.log(f(3));',
        '3\n',
        '9\n',
    ),
}

#: A program whose rest array the pass unpacks, mapped to the text it writes for it and to what Node
#: prints for the program either way. Every function here either runs in a mode where no `arguments`
#: object aliases anything, or names none of its own, so a list of plain names observes nothing the
#: rest parameter did not.
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

    def test_the_pass_hands_each_program_back_as_the_printer_writes_it(self):
        rows = _A_REWRITE_THE_ARGUMENTS_OBJECT_WOULD_OBSERVE
        self.assertEqual(
            {source: self._demask(source) for source in rows},
            {source: self._run_transformers(source) for source in rows},
        )

    @unittest.skipIf(node_executable() is None, 'node.js is not available')
    def test_node_reads_the_two_spellings_of_each_program_differently(self):
        rows = _A_REWRITE_THE_ARGUMENTS_OBJECT_WOULD_OBSERVE
        self.assertEqual(
            {
                source: (behavior(source), behavior(unpacked))
                for source, (unpacked, _, _) in rows.items()
            },
            {
                source: ((kept, None), (changed, None))
                for source, (_, kept, changed) in rows.items()
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
    The locals the unpacking mints are declared behind the body's Directive Prologue and not ahead
    of it. A statement written above the prologue ends it, so a declaration at the head of the body
    takes the directive out of the prologue and leaves what was written as a mode declaration as an
    expression whose value is discarded.

    Which mode that costs cannot be asked of the source: a Use Strict Directive may not stand under
    a parameter list that is not simple, so the function this pass takes in is one no engine reads.
    The function it hands back has a list of plain names and is a program, and the mode it runs in
    is the question the engine can answer.
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


#: Programs whose rest array a nested function reads or writes, or whose key is no slot of it, mapped
#: to what Node prints for each. The pass unpacks an array every reference of which, nested
#: functions included, is a slot, and keeps one with a deleted slot, a key the array inherits, a
#: parameter slot called with the array as its receiver, a `with` body or a direct `eval` reaching it.
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
