"""
`Execute` flattening on its own: the gates the pinned `Execute` semantics draw around what a
string-literal argument may splice into, and the no-effect cases the interpreter answered `""`
for, which a splice must never make fatal.
"""
from __future__ import annotations

import pytest

from test.lib.scripts.au3.deobfuscation import TestAu3

from refinery.lib.scripts.au3.deobfuscation.execute import Au3ExecuteFlattening


class TestAu3ExecuteFlattening(TestAu3):

    def test_a_literal_expression_splices_in_expression_position(self):
        self.assertEqual(
            self._apply('$x = Execute("1 + 1")', Au3ExecuteFlattening),
            '$x = 1 + 1\n')

    def test_a_literal_expression_splices_in_statement_position(self):
        self.assertEqual(
            self._apply(
                '''
                Func f()
                    Return 1
                EndFunc

                Execute("f()")
                ''',
                Au3ExecuteFlattening,
            ),
            'Func f()\n    Return 1\nEndFunc\nf()\n')

    def test_an_assignment_inside_the_literal_stays_a_comparison(self):
        """
        The interpreter parses `=` inside an `Execute` argument as a comparison and writes
        nothing (probe3 10), so the splice keeps the comparison the argument held.
        """
        self.assertEqual(
            self._apply('$x = Execute("$y = 5")', Au3ExecuteFlattening),
            '$x = $y = 5\n')

    def test_an_assignment_as_the_whole_statement_is_not_spliced(self):
        """
        A top-level `=` in statement position would re-parse as an assignment, which the
        interpreter never ran (probe3 10: the write did not happen), so the call stands.
        """
        self.assertEqual(
            self._apply('Execute("$y = 5")', Au3ExecuteFlattening),
            'Execute("$y = 5")\n')

    def test_a_bare_name_is_never_spliced(self):
        """
        What a bare name evaluates to is not a fact any probe pinned — an unseen include may
        declare it — and the alias map owns the declaration, so the call stands.
        """
        self.assertEqual(
            self._apply('$x = Execute("f")', Au3ExecuteFlattening),
            '$x = Execute("f")\n')

    def test_an_unparseable_literal_is_not_spliced(self):
        """
        A literal that fails to parse never ran at runtime (probe 111: `Execute("1 +")` answered
        `""`), so splicing it would change a no-op into a parse error.
        """
        self.assertEqual(
            self._apply('$x = Execute("1 +")', Au3ExecuteFlattening),
            '$x = Execute("1 +")\n')

    def test_a_statement_sequence_is_not_spliced(self):
        """
        Declarations and statement sequences are parse errors inside `Execute` (probe3 12/14:
        both answered `""` and wrote nothing), so the call stands.
        """
        self.assertEqual(
            self._apply('$x = Execute("Local $y = 3")', Au3ExecuteFlattening),
            '$x = Execute("Local $y = 3")\n')
        self.assertEqual(
            self._apply('$x = Execute("$y = 1" & @LF & "$y = 2")', Au3ExecuteFlattening),
            '$x = Execute("$y = 1" & @LF & "$y = 2")\n')

    def test_a_return_is_not_spliced(self):
        """
        `Return` inside `Execute` answers `""` and does not return from the enclosing function
        (probe3 15), which no splice can spell.
        """
        self.assertEqual(
            self._apply('$x = Execute("Return 42")', Au3ExecuteFlattening),
            '$x = Execute("Return 42")\n')

    def test_a_call_to_an_unknown_function_is_not_spliced(self):
        """
        An unknown callee is one of `Execute`'s pinned failure modes (probe 112: it answered
        `""`), and a splice would make that error fatal where the original swallowed it.
        """
        self.assertEqual(
            self._apply('$x = Execute("Undefined()")', Au3ExecuteFlattening),
            '$x = Execute("Undefined()")\n')

    def test_a_call_to_a_real_but_unemulated_builtin_is_spliced(self):
        """
        `MsgBox` is a real builtin this project never emulates the return value of; the splice
        resolves it on the strength of the builtin name table alone, with no value emulation
        needed.
        """
        self.assertEqual(
            self._apply('Execute("MsgBox(0, 0, 1)")', Au3ExecuteFlattening),
            'MsgBox(0, 0, 1)\n')

    def test_a_splice_refuses_where_the_error_state_is_read(self):
        """
        A successful `Call`, `Assign`, and `Eval` clear `@error` and `@extended` (probe9 A17,
        probe9f A21/A22); whether a successful `Execute` clears them is unpinned, so a splice
        refuses wherever a later read could see the difference.
        """
        self.assertEqual(
            self._apply(
                '''
                $x = Execute("MsgBox(0, 0, 1)")
                If @error Then
                    $y = 1
                EndIf
                ''',
                Au3ExecuteFlattening,
            ),
            '$x = Execute("MsgBox(0, 0, 1)")\nIf @error Then\n    $y = 1\nEndIf\n')

    def test_a_splice_refuses_where_another_payload_reads_the_error_state(self):
        """
        The payload of another `Execute` is a reader no walk of the tree sees, so it keeps every
        wrapper in the tree standing — a payload provably free of the two macros splices first
        once that reader is gone.
        """
        self.assertEqual(
            self._apply(
                '''
                $x = Execute("MsgBox(0, 0, 1)")
                $y = Execute("MsgBox(0, 0, @error)")
                ''',
                Au3ExecuteFlattening,
            ),
            '$x = Execute("MsgBox(0, 0, 1)")\n$y = Execute("MsgBox(0, 0, @error)")\n')

    def test_a_splice_refuses_where_a_call_spelled_execute_reads_the_error_state(self):
        """
        `Call` dispatches builtins as well as script functions, so a `Call` over the name runs a
        payload no walk of the tree sees — the same reader an `Execute` payload is, through the
        one spelling the flattening itself never touches.
        """
        self.assertEqual(
            self._apply(
                '''
                $x = Execute("MsgBox(0, 0, 1)")
                Call("Execute", "MsgBox(0, 0, @error)")
                ''',
                Au3ExecuteFlattening,
            ),
            '$x = Execute("MsgBox(0, 0, 1)")\n'
            'Call("Execute", "MsgBox(0, 0, @error)")\n')

    def test_a_splice_refuses_where_a_sigiled_call_of_execute_reads_the_error_state(self):
        """
        A string names a function without its leading `$`, as `call_target` resolves it.
        """
        self.assertEqual(
            self._apply(
                '''
                $x = Execute("MsgBox(0, 0, 1)")
                Call("$Execute", "MsgBox(0, 0, @error)")
                ''',
                Au3ExecuteFlattening,
            ),
            '$x = Execute("MsgBox(0, 0, 1)")\n'
            'Call("$Execute", "MsgBox(0, 0, @error)")\n')

    def test_a_splice_refuses_where_a_call_forwarded_through_call_may_read_the_error_state(self):
        """
        A `Call` of `Call` dispatches the name its second argument holds, a position no walk
        resolves, so it may reach `Execute` and read `@error` there.
        """
        self.assertEqual(
            self._apply(
                '''
                $x = Execute("MsgBox(0, 0, 1)")
                Call("Call", "Execute", "MsgBox(0, 0, @error)")
                ''',
                Au3ExecuteFlattening,
            ),
            '$x = Execute("MsgBox(0, 0, 1)")\n'
            'Call("Call", "Execute", "MsgBox(0, 0, @error)")\n')

    @pytest.mark.xfail(
        strict=True,
        reason='names are identified by `str.lower`, which folds U+212A into `k`',
    )
    def test_a_payload_call_python_folds_into_a_builtin_is_not_spliced(self):
        """
        U+212A KELVIN SIGN lowercases to ASCII `k` for Python; whether AutoIt folds it too is
        unpinned. If it does not, the spliced call names no function and fails when the script
        loads, where the original `Execute` fails softly when it runs.
        """
        self.assertEqual(
            self._apply('$x = Execute("WinKill(""t"")")', Au3ExecuteFlattening),
            '$x = Execute("WinKill(""t"")")\n')

    def test_a_call_through_a_variable_is_not_spliced(self):
        self.assertEqual(
            self._apply('$x = Execute("$f()")', Au3ExecuteFlattening),
            '$x = Execute("$f()")\n')

    def test_a_shadowed_execute_is_not_flattened(self):
        self.assertEqual(
            self._apply(
                '''
                Func Execute($s)
                    Return 1
                EndFunc

                $x = Execute("1 + 1")
                ''',
                Au3ExecuteFlattening,
            ),
            'Func Execute($s)\n    Return 1\nEndFunc\n$x = Execute("1 + 1")\n')

    def test_an_array_literal_inside_the_parsed_expression_is_not_spliced(self):
        """
        An array literal is legal AutoIt only where a declaration initializes, and no splice
        position is one, so the call stands.
        """
        self.assertEqual(
            self._apply('$x = Execute("[1, 2]")', Au3ExecuteFlattening),
            '$x = Execute("[1, 2]")\n')

    def test_a_missing_or_extra_argument_is_not_flattened(self):
        self.assertEqual(
            self._apply('$x = Execute()', Au3ExecuteFlattening),
            '$x = Execute()\n')
        self.assertEqual(
            self._apply('$x = Execute("1", "2")', Au3ExecuteFlattening),
            '$x = Execute("1", "2")\n')

    def test_a_non_literal_argument_is_not_flattened(self):
        self.assertEqual(
            self._apply('$x = Execute($y)', Au3ExecuteFlattening),
            '$x = Execute($y)\n')
