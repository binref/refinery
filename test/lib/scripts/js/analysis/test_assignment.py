from __future__ import annotations

import inspect

from typing import Callable

from test import TestBase, opportunity

from refinery.lib.scripts.js.analysis.assignment import build_definite_assignment
from refinery.lib.scripts.js.analysis.environment import FileKind
from refinery.lib.scripts.js.analysis.model import build_semantic_model
from refinery.lib.scripts.js.model import JsCallExpression, JsIdentifier
from refinery.lib.scripts.js.parser import JsParser


class TestDefiniteAssignment(TestBase):

    @staticmethod
    def _vouched(
        source: str,
        *,
        file_kind: FileKind = FileKind.script,
        host_entrypoint: Callable[[str], bool] | None = None,
    ) -> bool:
        ast = JsParser(source).parse()
        model = build_semantic_model(ast, file_kind=file_kind, host_entrypoint=host_entrypoint)
        assignment = build_definite_assignment(model)
        for node in ast.walk():
            if (
                isinstance(node, JsCallExpression)
                and isinstance(node.callee, JsIdentifier)
                and node.callee.name == 'probe'
            ):
                argument = node.arguments[0]
                assert isinstance(argument, JsIdentifier)
                return assignment.definitely_assigned_at(model.resolve(argument), argument)
        raise AssertionError('no probe call in the program')

    def test_a_straight_line_write_vouches(self):
        self.assertTrue(self._vouched('X = 1;\nprobe(X);'))

    def test_a_write_whose_right_hand_side_may_throw_still_vouches(self):
        self.assertTrue(self._vouched('X = f();\nprobe(X);'))

    def test_a_compound_write_vouches(self):
        self.assertTrue(self._vouched('X += 1;\nprobe(X);'))

    def test_an_increment_vouches(self):
        self.assertTrue(self._vouched('X++;\nprobe(X);'))

    def test_a_member_spelled_increment_through_this_realms_global_vouches(self):
        self.assertTrue(self._vouched('globalThis.X++;\nprobe(X);'))

    def test_a_member_spelled_increment_through_another_realm_does_not_vouch(self):
        self.assertFalse(self._vouched('top.X++;\nprobe(X);'))

    def test_a_member_spelled_write_through_this_realms_global_vouches(self):
        self.assertTrue(self._vouched('globalThis.X = 1;\nprobe(X);'))

    def test_a_destructuring_target_vouches(self):
        for source in [
            '[X] = [1];\nprobe(X);',
            '({ p: X } = { p: 1 });\nprobe(X);',
            '[X = 2] = [];\nprobe(X);',
            '[...X] = [1, 2];\nprobe(X);',
            '({ p: [X] } = { p: [1] });\nprobe(X);',
        ]:
            with self.subTest(source=source):
                self.assertTrue(self._vouched(source))

    def test_a_strict_destructuring_target_a_try_catches_does_not_vouch(self):
        source = inspect.cleandoc("""
            function s() { 'use strict'; try { [X] = [1]; } catch (e) {} }
            s();
            probe(X);
        """)
        self.assertFalse(self._vouched(source))

    def test_a_ternary_writing_in_both_arms_vouches(self):
        self.assertTrue(self._vouched('c ? (X = 1) : (X = 2);\nprobe(X);'))

    def test_a_literal_store_inside_a_try_vouches(self):
        self.assertTrue(self._vouched('try { X = 1; } catch (e) {}\nprobe(X);'))

    def test_a_literal_store_beside_a_pattern_declarator_inside_a_try_does_not_vouch(self):
        self.assertFalse(self._vouched(
            'try { var {a} = null, b = (X = 1); } catch (e) {}\nprobe(X);'))

    def test_a_destructuring_store_inside_a_try_does_not_vouch(self):
        self.assertFalse(self._vouched('try { [X] = 1; } catch (e) {}\nprobe(X);'))

    def test_a_throwable_store_inside_a_try_does_not_vouch(self):
        self.assertFalse(self._vouched('try { X = f(); } catch (e) {}\nprobe(X);'))

    def test_a_called_functions_exit_summary_vouches(self):
        self.assertTrue(self._vouched('function w() { X = 1; }\nw();\nprobe(X);'))

    def test_an_iifes_exit_summary_vouches(self):
        self.assertTrue(self._vouched('(function () { X = 1; })();\nprobe(X);'))

    def test_a_generator_callee_does_not_vouch(self):
        self.assertFalse(self._vouched('function* g() { X = 1; }\ng();\nprobe(X);'))

    def test_an_async_callee_writing_after_an_await_does_not_vouch(self):
        source = inspect.cleandoc("""
            async function a() { await 0; X = 1; }
            a();
            probe(X);
        """)
        self.assertFalse(self._vouched(source))

    @opportunity
    def test_an_async_callee_writing_before_its_first_await_vouches(self):
        self.assertTrue(self._vouched('async function a() { X = 1; }\na();\nprobe(X);'))

    def test_a_summary_forgets_a_write_the_path_through_an_empty_finally_skips(self):
        self.assertFalse(self._vouched(
            'function w() {\n'
            '  if (c) {\n'
            '    X = 1;\n'
            '    return;\n'
            '  }\n'
            '  try { g(); } finally {}\n'
            '}\n'
            'w();\n'
            'probe(X);'))

    def test_a_summary_keeps_a_write_every_returning_path_performs(self):
        self.assertTrue(self._vouched(
            'function w() {\n'
            '  if (c) {\n'
            '    X = 1;\n'
            '    return;\n'
            '  }\n'
            '  throw 1;\n'
            '}\n'
            'w();\n'
            'probe(X);'))

    def test_a_fact_at_every_direct_call_site_enters_the_body(self):
        self.assertTrue(self._vouched('X = 1;\nfunction f() { probe(X); }\nf();'))

    def test_a_fact_at_a_parenthesized_call_site_enters_the_body(self):
        self.assertTrue(self._vouched('X = 1;\nfunction f() { probe(X); }\n(f)();'))

    def test_a_fact_at_a_tagging_call_site_enters_the_body(self):
        self.assertTrue(self._vouched('X = 1;\nfunction f() { probe(X); }\nf`t`;'))

    def test_a_fact_at_an_iifes_call_site_enters_the_body(self):
        self.assertTrue(self._vouched('X = 1;\n(function () { probe(X); })();'))

    def test_a_call_site_before_the_write_gives_the_body_no_fact(self):
        self.assertFalse(self._vouched('function f() { probe(X); }\nf();\nX = 1;'))

    def test_a_host_entrypoint_gets_no_entry_fact(self):
        """
        A host calls `f` by name, so it may call it from inside `host()`, before the write.
        """
        source = inspect.cleandoc("""
            function f() { probe(X); }
            host();
            X = 1;
            f();
        """)
        self.assertTrue(self._vouched(source))
        self.assertFalse(self._vouched(source, host_entrypoint=lambda name: name == 'f'))

    @opportunity
    def test_a_host_entrypoint_gets_the_fact_of_a_write_before_the_host_runs(self):
        source = 'X = 1;\nfunction f() { probe(X); }\nf();'
        self.assertTrue(self._vouched(source, host_entrypoint=lambda name: name == 'f'))

    def test_a_function_a_second_name_reaches_gets_no_entry_fact(self):
        source = inspect.cleandoc("""
            function f() { probe(X); }
            var h = f;
            h();
            X = 1;
            f();
        """)
        self.assertFalse(self._vouched(source))

    @opportunity
    def test_a_function_called_through_a_second_name_after_the_write_gets_its_fact(self):
        self.assertTrue(self._vouched('X = 1;\nfunction f() { probe(X); }\nvar h = f;\nh();'))

    def test_a_write_after_the_read_does_not_vouch(self):
        self.assertFalse(self._vouched('probe(X);\nX = 1;'))

    def test_a_write_in_the_reads_own_statement_does_not_vouch(self):
        self.assertFalse(self._vouched('(X = 1, probe(X));'))

    def test_a_short_circuited_write_does_not_vouch(self):
        self.assertFalse(self._vouched('c && (X = 1);\nprobe(X);'))

    def test_a_ternary_writing_in_one_arm_does_not_vouch(self):
        self.assertFalse(self._vouched('c ? (X = 1) : 0;\nprobe(X);'))

    def test_a_logical_assignments_right_hand_side_does_not_vouch(self):
        self.assertFalse(self._vouched('a ||= (X = 1);\nprobe(X);'))

    def test_a_write_behind_an_optional_link_does_not_vouch(self):
        self.assertFalse(self._vouched('o?.p[X = 1];\nprobe(X);'))

    def test_a_loop_head_target_does_not_vouch(self):
        self.assertFalse(self._vouched('for (X in obj) {}\nprobe(X);'))

    def test_a_write_under_an_opaque_loop_test_does_not_vouch(self):
        self.assertFalse(self._vouched('while (c) { X = 1; break; }\nprobe(X);'))

    def test_a_name_a_bare_delete_addresses_is_never_vouched_for(self):
        self.assertFalse(self._vouched('X = 1;\ndelete X;\nprobe(X);'))

    def test_a_name_a_member_delete_addresses_is_never_vouched_for(self):
        source = inspect.cleandoc("""
            var o = { get p() { delete globalThis.X; } };
            X = 1;
            o.p;
            probe(X);
        """)
        self.assertFalse(self._vouched(source))

    @opportunity
    def test_a_member_delete_that_runs_after_the_read_leaves_the_write_vouched_for(self):
        self.assertTrue(self._vouched('X = 1;\nprobe(X);\ndelete globalThis.X;'))

    def test_a_computed_delete_through_the_global_unvouches_everything(self):
        self.assertFalse(self._vouched('X = 1;\ndelete globalThis[k];\nprobe(X);'))

    def test_a_computed_delete_on_a_base_the_scan_cannot_read_unvouches_everything(self):
        self.assertFalse(self._vouched('X = 1;\ndelete someObj[k];\nprobe(X);'))

    def test_a_computed_delete_on_an_object_the_file_allocates_forgets_nothing(self):
        self.assertTrue(self._vouched('var o = {};\nX = 1;\ndelete o[k];\nprobe(X);'))

    def test_a_named_delete_on_an_object_the_file_allocates_forgets_nothing(self):
        self.assertTrue(self._vouched('var o = {};\nX = 1;\ndelete o.X;\nprobe(X);'))

    def test_a_name_carried_into_a_body_this_file_does_not_read_is_never_vouched_for(self):
        for hand_over in ['host(globalThis);', "Reflect.deleteProperty(globalThis, 'X');"]:
            with self.subTest(hand_over=hand_over):
                self.assertFalse(self._vouched(F'X = 1;\n{hand_over}\nprobe(X);'))

    def test_a_reflection_reachable_name_is_never_vouched_for(self):
        self.assertFalse(self._vouched('X = 1;\neval(c);\nprobe(X);'))

    def test_a_strict_write_a_try_catches_does_not_vouch(self):
        source = inspect.cleandoc("""
            function s() { 'use strict'; try { X = 1; } catch (e) {} }
            s();
            probe(X);
        """)
        self.assertFalse(self._vouched(source))

    def test_no_bare_write_a_try_catches_vouches_where_the_file_may_be_an_es_module(self):
        for kind in (FileKind.es_module, FileKind.commonjs_or_es_module):
            with self.subTest(kind.name):
                source = 'try { X = 1; } catch (e) {}\nprobe(X);'
                self.assertFalse(self._vouched(source, file_kind=kind))

    def test_a_bare_write_vouches_in_a_commonjs_file(self):
        self.assertTrue(self._vouched('X = 1;\nprobe(X);', file_kind=FileKind.commonjs))

    def test_a_bare_write_a_try_catches_in_strict_code_of_a_commonjs_file_does_not_vouch(self):
        source = inspect.cleandoc("""
            'use strict';
            try { X = 1; } catch (e) {}
            probe(X);
        """)
        self.assertFalse(self._vouched(source, file_kind=FileKind.commonjs))

    @opportunity
    def test_a_store_completing_in_strict_code_vouches(self):
        for source, kind in (
            ("function s() { 'use strict'; X = 1; }\ns();\nprobe(X);", FileKind.script),
            ("function s() { 'use strict'; [X] = [1]; }\ns();\nprobe(X);", FileKind.script),
            ('X = 1;\nprobe(X);', FileKind.es_module),
            ('X = 1;\nprobe(X);', FileKind.commonjs_or_es_module),
            ("'use strict';\nX = 1;\nprobe(X);", FileKind.commonjs),
        ):
            with self.subTest(source=source, kind=kind.name):
                self.assertTrue(self._vouched(source, file_kind=kind))

    def test_a_top_level_this_write_vouches_in_a_script_and_not_in_commonjs(self):
        source = 'this.X = 1;\nprobe(X);'
        self.assertTrue(self._vouched(source))
        for kind in (FileKind.commonjs, FileKind.commonjs_or_es_module):
            with self.subTest(kind.name):
                self.assertFalse(self._vouched(source, file_kind=kind))

    def test_a_write_through_top_does_not_vouch(self):
        source = inspect.cleandoc("""
            top.X = 1;
            probe(X);
        """)
        self.assertFalse(self._vouched(source))

    @opportunity
    def test_a_write_through_frames_vouches(self):
        source = inspect.cleandoc("""
            frames.X = 1;
            probe(X);
        """)
        self.assertTrue(self._vouched(source))

    def test_a_write_before_the_class_vouches_in_a_field(self):
        self.assertTrue(self._vouched('X = 1;\nclass A { v = probe(X); }\nnew A();'))

    def test_a_write_before_the_class_vouches_in_a_function_only_a_field_calls(self):
        self.assertTrue(self._vouched(
            'X = 1;\nfunction d() { return probe(X); }\nclass A { v = d(); }\nnew A();'
        ))

    def test_a_write_after_a_construction_inside_the_class_statement_does_not_vouch_in_a_field(self):
        self.assertFalse(self._vouched(
            'class A { v = probe(X); static s = new A(); static { X = 1; } }'
        ))
