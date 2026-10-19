from __future__ import annotations

from typing import Callable

from test import TestBase

from refinery.lib.scripts.js.analysis.assignment import build_definite_assignment
from refinery.lib.scripts.js.analysis.environment import FileKind
from refinery.lib.scripts.js.analysis.model import build_semantic_model
from refinery.lib.scripts.js.model import JsCallExpression, JsIdentifier
from refinery.lib.scripts.js.parser import JsParser


class TestDefiniteAssignment(TestBase):
    """
    Laws over `DefiniteAssignmentModel.definitely_assigned_at`. Each program reads the implicit
    global `X` exactly once as the argument of a call to `probe`, and the assertion is whether a
    write to `X` has certainly completed before that read runs — under JavaScript semantics, never
    under what any transform would like the answer to be.
    """

    @staticmethod
    def _vouched(
        source: str,
        *,
        file_kind: FileKind = FileKind.script,
        host_entrypoint: Callable[[str], bool] | None = None,
    ) -> bool:
        ast = JsParser(source).parse()
        model = build_semantic_model(ast, file_kind=file_kind)
        assignment = build_definite_assignment(model, host_entrypoint=host_entrypoint)
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
        """
        `f()` may throw, but then the statement does not complete and the raising edge carries no
        facts; on the one path that reaches the probe, the write completed.
        """
        self.assertTrue(self._vouched('X = f();\nprobe(X);'))

    def test_a_compound_write_vouches(self):
        """
        `X += 1` reads `X` before writing it, so a normal completion proves the name already existed.
        """
        self.assertTrue(self._vouched('X += 1;\nprobe(X);'))

    def test_an_increment_vouches(self):
        """
        `X++` reads `X` before writing it, in strict code as much as in sloppy, so a normal
        completion proves the name already existed.
        """
        self.assertTrue(self._vouched('X++;\nprobe(X);'))

    def test_a_member_spelled_increment_through_this_realms_global_vouches(self):
        """
        Reading a missing property answers `undefined` rather than throwing, and storing the result
        creates it.
        """
        self.assertTrue(self._vouched('globalThis.X++;\nprobe(X);'))

    def test_a_member_spelled_increment_through_another_realm_does_not_vouch(self):
        self.assertFalse(self._vouched('top.X++;\nprobe(X);'))

    def test_a_member_spelled_write_through_this_realms_global_vouches(self):
        self.assertTrue(self._vouched('globalThis.X = 1;\nprobe(X);'))

    def test_a_destructuring_target_vouches(self):
        """
        A destructuring assignment that completes normally has assigned every target the pattern
        holds, a defaulted or nested one included; a default's own expression runs conditionally
        and is not a target.
        """
        for source in [
            '[X] = [1];\nprobe(X);',
            '({ p: X } = { p: 1 });\nprobe(X);',
            '[X = 2] = [];\nprobe(X);',
            '[...X] = [1, 2];\nprobe(X);',
            '({ p: [X] } = { p: [1] });\nprobe(X);',
        ]:
            with self.subTest(source=source):
                self.assertTrue(self._vouched(source))

    def test_a_strict_destructuring_target_does_not_vouch(self):
        self.assertFalse(self._vouched(
            "function s() { 'use strict'; [X] = [1]; }\ns();\nprobe(X);"))

    def test_a_ternary_writing_in_both_arms_vouches(self):
        self.assertTrue(self._vouched('c ? (X = 1) : (X = 2);\nprobe(X);'))

    def test_a_literal_store_inside_a_try_vouches(self):
        """
        Evaluating `X = 1` in sloppy script code cannot throw, so the raising edge out of the `try`
        is never taken and may carry the write vacuously.
        """
        self.assertTrue(self._vouched('try { X = 1; } catch (e) {}\nprobe(X);'))

    def test_a_literal_store_beside_a_pattern_declarator_inside_a_try_does_not_vouch(self):
        """
        Destructuring `null` throws where the initializers alone say nothing can, and it throws
        before the second declarator runs, so the raising edge out of the `try` is taken with `X`
        never written.
        """
        self.assertFalse(self._vouched(
            'try { var {a} = null, b = (X = 1); } catch (e) {}\nprobe(X);'))

    def test_a_destructuring_store_inside_a_try_does_not_vouch(self):
        """
        Destructuring a non-iterable throws with no target assigned, so the raising edge out of the
        `try` may be taken with `X` never written, however literal the right-hand side is.
        """
        self.assertFalse(self._vouched('try { [X] = 1; } catch (e) {}\nprobe(X);'))

    def test_a_throwable_store_inside_a_try_does_not_vouch(self):
        """
        When `f()` throws, the `catch` runs with `X` still unbound, and both paths join in front of
        the probe.
        """
        self.assertFalse(self._vouched('try { X = f(); } catch (e) {}\nprobe(X);'))

    def test_a_called_functions_exit_summary_vouches(self):
        self.assertTrue(self._vouched('function w() { X = 1; }\nw();\nprobe(X);'))

    def test_an_iifes_exit_summary_vouches(self):
        self.assertTrue(self._vouched('(function () { X = 1; })();\nprobe(X);'))

    def test_a_generator_callee_does_not_vouch(self):
        """
        Calling a generator runs no statement of its body; the body runs when the result is driven,
        which the call completing says nothing about.
        """
        self.assertFalse(self._vouched('function* g() { X = 1; }\ng();\nprobe(X);'))

    def test_an_async_callee_does_not_vouch(self):
        """
        An async call completing normally means the promise exists, not that the body ran to its
        end; the write is real here, and the refusal is the conservative side of that gap.
        """
        self.assertFalse(self._vouched('async function a() { X = 1; }\na();\nprobe(X);'))

    def test_a_summary_forgets_a_write_the_path_through_an_empty_finally_skips(self):
        """
        `w()` returns through the empty `finally` whenever `c` is falsy, having written nothing. The
        graph joins that path and the unwinding one to the exit as a single pair of nodes and
        records the pair as raise-taken, so a summary that dropped every raise-taken predecessor met
        over the `return` alone and claimed the write.
        """
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
        """
        The control for the entry above: the tail is a `throw`, which completes on no run at all, so
        the one path that returns is the one that wrote.
        """
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
        """
        A tagged template invokes its tag exactly as a call does, so the meet over `f`'s sites sees
        every invocation here too.
        """
        self.assertTrue(self._vouched('X = 1;\nfunction f() { probe(X); }\nf`t`;'))

    def test_a_fact_at_an_iifes_call_site_enters_the_body(self):
        self.assertTrue(self._vouched('X = 1;\n(function () { probe(X); })();'))

    def test_a_call_site_before_the_write_gives_the_body_no_fact(self):
        self.assertFalse(self._vouched('function f() { probe(X); }\nf();\nX = 1;'))

    def test_a_host_entrypoint_gets_no_entry_fact(self):
        """
        A function the analyst declared a host calls by name has a call site outside the file, so
        the meet over its spelled sites does not bound what its body may assume.
        """
        source = 'X = 1;\nfunction f() { probe(X); }\nf();'
        self.assertTrue(self._vouched(source))
        self.assertFalse(self._vouched(source, host_entrypoint=lambda name: name == 'f'))

    def test_a_function_a_second_name_reaches_gets_no_entry_fact(self):
        """
        `h()` is not a direct call of `f`'s own name, so the meet over `f`'s call sites cannot see
        every invocation and the body starts empty.
        """
        self.assertFalse(self._vouched('X = 1;\nfunction f() { probe(X); }\nvar h = f;\nh();'))

    def test_a_write_after_the_read_does_not_vouch(self):
        self.assertFalse(self._vouched('probe(X);\nX = 1;'))

    def test_a_write_in_the_reads_own_statement_does_not_vouch(self):
        """
        Facts hold at statement entry, so strict dominance is required and a same-statement write is
        refused.
        """
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
        """
        A `for-in` over an empty subject writes its target zero times.
        """
        self.assertFalse(self._vouched('for (X in obj) {}\nprobe(X);'))

    def test_a_write_under_an_opaque_loop_test_does_not_vouch(self):
        self.assertFalse(self._vouched('while (c) { X = 1; break; }\nprobe(X);'))

    def test_a_name_a_bare_delete_addresses_is_never_vouched_for(self):
        self.assertFalse(self._vouched('X = 1;\ndelete X;\nprobe(X);'))

    def test_a_name_a_member_delete_addresses_is_never_vouched_for(self):
        """
        The delete stands after the probe, but a getter or an iterator can run it between any write
        and any read, so the name is not tracked at all.
        """
        self.assertFalse(self._vouched('X = 1;\nprobe(X);\ndelete globalThis.X;'))

    def test_a_computed_delete_through_the_global_unvouches_everything(self):
        self.assertFalse(self._vouched('X = 1;\ndelete globalThis[k];\nprobe(X);'))

    def test_a_computed_delete_on_a_base_the_scan_cannot_read_unvouches_everything(self):
        """
        The base need not be spelled as the global object to be it, so a computed delete on a name
        nothing pins fails closed.
        """
        self.assertFalse(self._vouched('X = 1;\ndelete someObj[k];\nprobe(X);'))

    def test_a_computed_delete_on_an_object_the_file_allocates_forgets_nothing(self):
        self.assertTrue(self._vouched('var o = {};\nX = 1;\ndelete o[k];\nprobe(X);'))

    def test_a_named_delete_on_an_object_the_file_allocates_forgets_nothing(self):
        self.assertTrue(self._vouched('var o = {};\nX = 1;\ndelete o.X;\nprobe(X);'))

    def test_a_name_carried_into_a_body_this_file_does_not_read_is_never_vouched_for(self):
        """
        Handing the global object to a call this file cannot read through carries every global into
        a body that may `delete` the property or freeze the object, neither of which the file
        spells.
        """
        for hand_over in ['host(globalThis);', "Reflect.deleteProperty(globalThis, 'X');"]:
            with self.subTest(hand_over=hand_over):
                self.assertFalse(self._vouched(F'X = 1;\n{hand_over}\nprobe(X);'))

    def test_a_reflection_reachable_name_is_never_vouched_for(self):
        self.assertFalse(self._vouched('X = 1;\neval(c);\nprobe(X);'))

    def test_a_strict_write_does_not_vouch(self):
        """
        In strict code the assignment throws instead of creating the property.
        """
        self.assertFalse(self._vouched(
            "function s() { 'use strict'; X = 1; }\ns();\nprobe(X);"))

    def test_no_bare_write_vouches_where_the_file_may_be_an_es_module(self):
        for kind in (FileKind.es_module, FileKind.commonjs_or_es_module):
            with self.subTest(kind.name):
                self.assertFalse(self._vouched('X = 1;\nprobe(X);', file_kind=kind))

    def test_a_bare_write_vouches_in_a_commonjs_file(self):
        self.assertTrue(self._vouched('X = 1;\nprobe(X);', file_kind=FileKind.commonjs))

    def test_a_bare_write_in_strict_code_of_a_commonjs_file_does_not_vouch(self):
        source = "'use strict';\nX = 1;\nprobe(X);"
        self.assertFalse(self._vouched(source, file_kind=FileKind.commonjs))

    def test_a_top_level_this_write_vouches_only_under_the_script_reading(self):
        source = 'this.X = 1;\nprobe(X);'
        self.assertTrue(self._vouched(source))
        for kind in (FileKind.commonjs, FileKind.es_module, FileKind.commonjs_or_es_module):
            with self.subTest(kind.name):
                self.assertFalse(self._vouched(source, file_kind=kind))

    def test_a_write_through_another_realms_alias_does_not_vouch(self):
        for alias in ['top', 'frames']:
            with self.subTest(alias=alias):
                self.assertFalse(self._vouched(F'{alias}.X = 1;\nprobe(X);'))

    def test_an_unreachable_read_is_not_vouched_for(self):
        self.assertFalse(self._vouched('X = 1;\nfunction f() { return; probe(X); }\nf();'))
