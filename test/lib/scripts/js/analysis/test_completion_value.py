from __future__ import annotations

import unittest

from test import TestBase

from test.lib.scripts.js.analysis.differential import (
    JsEvaluation,
    completion_values,
    deobfuscate_source,
    node_executable,
)

#: Programs whose value a caller receives, chosen so that removing a statement which computes
#: nothing changes it. Most of them end on a bare literal or a bare name — the shape that looks
#: inert and is not — and several are shapes the tool itself folds down to one, so that a pass
#: deleting inert statements would throw away the very value the fold had just computed.
PROGRAMS_WITH_A_VALUE_TO_PRESERVE: tuple[str, ...] = (
    "'a';",
    '1;',
    '1 + 2;',
    "'a'; 'b';",
    "'a'; var x = 1;",
    "'a'; let y = 1;",
    "'a'; class C {}",
    "'a'; ;",
    "'a'; {}",
    "'a'; debugger;",
    "'use strict'; 'a';",
    "console.log('side'); 'a';",
    "{ 'a'; }",
    "{ console.log('side'); 'a'; }",
    "'a'; { 'b'; var z = 1; }",
    "if (true) { 'a'; }",
    "if (false) { 'a'; } else { 'b'; }",
    'for (var i = 0; i < 3; i++) { i; }',
    "for (var i = 0; i < 2; i++) { console.log('side'); i; }",
    'for (var k in { p: 1 }) { k; }',
    'for (var v of [7, 8]) { v; }',
    "while (true) { 'a'; break; }",
    "while (true) { console.log('side'); 'a'; break; }",
    "do { 'a'; } while (false);",
    "switch (1) { case 1: 'a'; }",
    "switch (1) { case 1: console.log('side'); 'a'; }",
    "try { 'a'; } catch (e) {}",
    "try { console.log('side'); 'a'; } catch (e) {}",
    "try { throw 0; } catch (e) { 'a'; }",
    "try { 'a'; } finally { 'b'; }",
    "l: { 'a'; }",
    'l: ;',
    "with ({}) { 'a'; }",
    'var x = 5; x;',
    "[1, 2].join('-');",
    "console.log('side'); [1, 2].join('-');",
    "function f() { return 'a'; } f();",
    "function f() { return 'a'; } console.log('side'); f();",
    '(function () { return 5; })();',
    "(function () { 'a'; })();",
    "'a'; function f() { return 1; } f();",
    'var s = []; s.push(1); s.length;',
    '1; { function g() {} }',
    "console.log('side');",
    'null;',
    'undefined;',
    'void 0;',
    "'a'; throw 0;",
    "'a'; null.x;",
)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestWhichStatementSuppliesTheValueOfAProgram(TestBase):
    """
    A run of statements has a value and not only an effect, and JavaScript hands that value back:
    `eval` returns it to its caller and so does a script run as a unit. Every row below is what Node
    answered when it was asked, under both of those models; none of it is read off a specification
    or off what this tool makes of the same program.
    """

    def _pins(self, table: dict[str, str]):
        programs = list(table)
        for evaluation in JsEvaluation:
            for program, value in zip(programs, completion_values(programs, evaluation)):
                with self.subTest(evaluation=evaluation.value, program=program):
                    self.assertEqual(value, table[program])

    def test_a_program_in_which_nothing_supplies_a_value_evaluates_to_undefined(self):
        self._pins({
            ''               : 'undefined',
            ';'              : 'undefined',
            ';;'             : 'undefined',
            '{}'             : 'undefined',
            '{ ; }'          : 'undefined',
            'debugger;'      : 'undefined',
            'var x = 1;'     : 'undefined',
            'function f(){}' : 'undefined',
            'let y = 1;'     : 'undefined',
            'const z = 1;'   : 'undefined',
            'class C {}'     : 'undefined',
        })

    def test_an_expression_statement_supplies_the_value_and_the_last_one_to_do_so_wins(self):
        self._pins({
            "'a';"                   : '"a"',
            '1;'                     : '1',
            'null;'                  : 'null',
            "'a'; 'b';"              : '"b"',
            "'a'; 1;"                : '1',
            "'a'; console.log('x');" : 'undefined',
        })

    def test_a_statement_that_supplies_nothing_leaves_the_value_before_it_standing(self):
        self._pins({
            "'a'; var x = 1;"      : '"a"',
            "'a'; function f(){}"  : '"a"',
            "'a'; let y = 1;"      : '"a"',
            "'a'; const z = 1;"    : '"a"',
            "'a'; class C {}"      : '"a"',
            "'a'; ;"               : '"a"',
            "'a'; {}"              : '"a"',
            "'a'; { var x = 1; }"  : '"a"',
            "'a'; debugger;"       : '"a"',
            "'a'; l: ;"            : '"a"',
            "'a'; l: {}"           : '"a"',
            "'a'; l: { break l; }" : '"a"',
        })

    def test_a_branch_loop_switch_try_or_with_that_supplies_nothing_resets_the_value(self):
        """
        Each of these computes nothing, and unlike an empty statement or a declaration each replaces
        the value with `undefined` rather than leaving the one before it standing. A label is not
        one of them and passes the value through, so the last row answers `undefined` on account of
        `if` beneath the label and not on account of the label.
        """
        self._pins({
            "'a'; if (false) 1;"                  : 'undefined',
            "'a'; if (true) {}"                   : 'undefined',
            "'a'; if (false) {} else {}"          : 'undefined',
            "'a'; while (false) 1;"               : 'undefined',
            "'a'; do {} while (false);"           : 'undefined',
            "'a'; for (var i = 0; i < 0; i++) 1;" : 'undefined',
            "'a'; for (var k in {}) 1;"           : 'undefined',
            "'a'; for (var v of []) 1;"           : 'undefined',
            "'a'; switch (2) { case 1: 3; }"      : 'undefined',
            "'a'; switch (1) { case 1: ; }"       : 'undefined',
            "'a'; try {} catch (e) {}"            : 'undefined',
            "'a'; with ({}) {}"                   : 'undefined',
            "'a'; l: if (false) 1;"               : 'undefined',
        })

    def test_a_statement_nested_in_a_block_branch_case_or_label_supplies_the_value(self):
        self._pins({
            "'a'; { 'b'; }"                            : '"b"',
            "'a'; { { 'b'; } }"                        : '"b"',
            "'a'; { 'b'; var x = 1; }"                 : '"b"',
            "'a'; if (true) { 'b'; }"                  : '"b"',
            "'a'; if (false) 1; else 'b';"             : '"b"',
            "'a'; switch (1) { case 1: 'b'; }"         : '"b"',
            "'a'; switch (1) { case 1: 'b'; case 2: }" : '"b"',
            "'a'; try { 'b'; } catch (e) {}"           : '"b"',
            "'a'; try { throw 0; } catch (e) { 'b'; }" : '"b"',
            "'a'; l: { 'b'; }"                         : '"b"',
            "'a'; with ({}) { 'b'; }"                  : '"b"',
        })

    def test_a_loop_supplies_the_value_of_the_last_iteration_that_supplied_one(self):
        self._pins({
            "'a'; for (var i = 0; i < 3; i++) { i; }"           : '2',
            "'a'; for (var k in { p: 1, q: 2 }) { k; }"         : '"q"',
            "'a'; for (var v of [7, 8]) { v; }"                 : '8',
            "'a'; while (true) { 'b'; break; }"                 : '"b"',
            "'a'; do { 'b'; } while (false);"                   : '"b"',
            "'a'; for (var i = 0; i < 3; i++) { if (i) 'b'; }"  : '"b"',
            "'a'; for (var i = 0; i < 3; i++) { if (!i) 'b'; }" : 'undefined',
        })

    def test_a_finally_block_never_supplies_the_value(self):
        self._pins({
            "'a'; try { 'b'; } finally { 'c'; }"                  : '"b"',
            "'a'; try {} finally { 'c'; }"                        : 'undefined',
            "'a'; try { throw 0; } catch (e) {} finally { 'c'; }" : 'undefined',
        })

    def test_a_function_body_supplies_nothing_to_the_program_that_calls_it(self):
        self._pins({
            "'a'; (function () { 'b'; })();"        : 'undefined',
            "'a'; (function () { return 'b'; })();" : '"b"',
        })

    def test_a_program_that_ends_abruptly_has_no_value_at_all(self):
        self._pins({
            "'a'; throw 0;"      : 'throw 0',
            "'a'; throw 'boom';" : 'throw "boom"',
            "'a'; null.x;"       : 'throw TypeError',
        })

    def test_a_sloppy_block_level_function_declaration_supplies_a_value_to_a_script_only(self):
        """
        The only shape in this file the two models answer differently, which is why it is pinned
        against each of them separately instead of through `_pins`. Node was asked and a script
        takes the function for its value where an `eval` of the same text does not; the two agree
        again once the text declares itself strict, where the declaration is no longer sloppy
        mode's and the web compatibility rules for it no longer apply.
        """
        divergent = ["'a'; { function g(){} }", "'a'; if (true) { function g(){} }"]
        self.assertEqual(
            completion_values(divergent, JsEvaluation.EVAL), ['"a"', 'undefined']
        )
        self.assertEqual(
            completion_values(divergent, JsEvaluation.SCRIPT), ['function', 'function']
        )
        settled = ["'use strict'; 'a'; { function g(){} }"]
        self.assertEqual(completion_values(settled, JsEvaluation.EVAL), ['"a"'])
        self.assertEqual(completion_values(settled, JsEvaluation.SCRIPT), ['"a"'])


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestDeobfuscationPreservesWhatAProgramEvaluatesTo(TestBase):
    """
    What a deobfuscated program evaluates to must be what the program it came from evaluated to.
    The value is observable to whoever called `eval` on the payload and to whoever ran the script as
    a unit, so both are asked, and neither is answered by looking at what the program printed. What
    the default drops is a completion of `undefined` a fold left behind, which changes no value a
    caller reads; a computed end value the program itself carries stays under the default too.
    """

    def test_the_deobfuscation_of_a_program_evaluates_to_what_the_program_does(self):
        deobfuscated = [
            deobfuscate_source(program) for program in PROGRAMS_WITH_A_VALUE_TO_PRESERVE
        ]
        for evaluation in JsEvaluation:
            before = completion_values(PROGRAMS_WITH_A_VALUE_TO_PRESERVE, evaluation)
            after = completion_values(deobfuscated, evaluation)
            rows = zip(PROGRAMS_WITH_A_VALUE_TO_PRESERVE, deobfuscated, before, after)
            for program, result, source_value, result_value in rows:
                with self.subTest(evaluation=evaluation.value, program=program):
                    self.assertEqual(
                        result_value,
                        source_value,
                        F'deobfuscation changed what the program evaluates to; result was:'
                        F'{chr(10)}{result}',
                    )


#: Single-use wrappers and a `Function` construction whose call ran off its end returning `undefined`,
#: leaving the body's own last value in the end position the call did not hold. Node evaluates each
#: original to `undefined` under both the eval and the script model.
A_WRAPPER_WHOSE_END_VALUE_WOULD_LEAK = (
    'var n = 1; function w(){ n++; } w();',
    "function w(){ console.log('side'); 42; } w();",
    'function w(){ L: { 7; } } w();',
    'new Function("1; 42")();',
)


@unittest.skipIf(node_executable() is None, 'node.js is not available')
class TestPreserveScriptReturnHoldsAWrapperEndValue(TestBase):
    """
    A single-use wrapper or a `Function` construction whose call ran off its end returned `undefined`;
    inlining the body leaves the body's own last value where the call stood. `preserve_script_return`
    holds the script's end value at `undefined`, so an `eval` or a `vm` run of the file receives what
    it did before the fold. Without the option the end value is not defended and the tail's value
    stands — which changes no observable a reader of the deobfuscated script consults — and no `void 0`
    is inserted to hold it.
    """

    def test_the_option_holds_the_end_value_the_call_gave(self):
        deobfuscated = [
            deobfuscate_source(program, preserve_script_return=True)
            for program in A_WRAPPER_WHOSE_END_VALUE_WOULD_LEAK
        ]
        for evaluation in JsEvaluation:
            before = completion_values(A_WRAPPER_WHOSE_END_VALUE_WOULD_LEAK, evaluation)
            after = completion_values(deobfuscated, evaluation)
            rows = zip(A_WRAPPER_WHOSE_END_VALUE_WOULD_LEAK, deobfuscated, before, after)
            for program, result, source_value, result_value in rows:
                with self.subTest(evaluation=evaluation.value, program=program):
                    self.assertEqual(
                        result_value,
                        source_value,
                        F'preserve_script_return did not hold the end value; result was:'
                        F'{chr(10)}{result}',
                    )

    def test_the_default_drops_the_inserted_undefined(self):
        self.assertEqual('', deobfuscate_source('function w(){ Math.max(7); } w();'))
        self.assertEqual(
            'var n = 1;\nn++;',
            deobfuscate_source('var n = 1; function w(){ n++; } w();'),
        )
        for program in A_WRAPPER_WHOSE_END_VALUE_WOULD_LEAK:
            with self.subTest(program=program):
                self.assertNotIn('void 0', deobfuscate_source(program))
