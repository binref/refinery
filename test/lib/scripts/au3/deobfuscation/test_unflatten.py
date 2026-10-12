"""
The fold-group deflattening transform on its own: which dispatcher regions splice, when the state
assignment stays versus leaves, and which gate — dispatch, terminator, loop control, deleted parts,
or one of the read-back rules for the state name — keeps a region the shape alone would match.
"""
from __future__ import annotations

import inspect

from refinery.lib.scripts.au3.deobfuscation.unflatten import Au3ControlFlowDeflattening
from refinery.lib.scripts.au3.parser import Au3Parser
from refinery.lib.scripts.au3.synth import Au3Synthesizer
from test.lib.scripts.au3.deobfuscation import TestAu3


class TestAu3ControlFlowDeflattening(TestAu3):

    def _assertSplicesTo(self, source: str, expected: str) -> None:
        self.assertEqual(
            self._apply(source, Au3ControlFlowDeflattening),
            Au3Synthesizer().convert(Au3Parser(inspect.cleandoc(expected)).parse()),
        )

    def _assertRefused(self, source: str) -> None:
        self._assertSplicesTo(source, source)

    def test_a_dispatcher_region_splices_to_its_live_payload(self):
        self._assertSplicesTo(
            '''
            Func f()
                While 1
                    $state = 2
                    Switch $state
                    Case 1
                        MsgBox(0, 0, 1)
                    Case 2
                        MsgBox(0, 0, 2)
                        ExitLoop
                    Case 3
                        MsgBox(0, 0, 3)
                    EndSwitch
                Wend
            EndFunc
            ''',
            '''
            Func f()
                MsgBox(0, 0, 2)
            EndFunc
            ''')

    def test_the_state_assignment_stays_when_a_channel_stands_in_its_scope(self):
        self._assertSplicesTo(
            '''
            Func f()
                Execute($x)
                While 1
                    $state = 2
                    Switch $state
                    Case 2
                        MsgBox(0, 0, 2)
                        ExitLoop
                    EndSwitch
                Wend
            EndFunc
            ''',
            '''
            Func f()
                Execute($x)
                $state = 2
                MsgBox(0, 0, 2)
            EndFunc
            ''')

    def test_the_state_assignment_stays_when_a_channel_stands_in_another_scope(self):
        self._assertSplicesTo(
            '''
            Func g()
                Execute($x)
            EndFunc

            Func f()
                While 1
                    $state = 2
                    Switch $state
                    Case 2
                        MsgBox(0, 0, 2)
                        ExitLoop
                    EndSwitch
                Wend
            EndFunc
            ''',
            '''
            Func g()
                Execute($x)
            EndFunc

            Func f()
                $state = 2
                MsgBox(0, 0, 2)
            EndFunc
            ''')

    def test_the_state_assignment_stays_when_a_string_spells_the_name(self):
        self._assertSplicesTo(
            '''
            Func f()
                $x = "state"
                While 1
                    $state = 2
                    Switch $state
                    Case 2
                        MsgBox(0, 0, 2)
                        ExitLoop
                    EndSwitch
                Wend
            EndFunc
            ''',
            '''
            Func f()
                $x = "state"
                $state = 2
                MsgBox(0, 0, 2)
            EndFunc
            ''')

    def test_the_state_assignment_stays_when_the_name_is_read_after_the_region(self):
        self._assertSplicesTo(
            '''
            Func f()
                While 1
                    $state = 2
                    Switch $state
                    Case 2
                        MsgBox(0, 0, 2)
                        ExitLoop
                    EndSwitch
                Wend
                MsgBox(0, 0, $state)
            EndFunc
            ''',
            '''
            Func f()
                $state = 2
                MsgBox(0, 0, 2)
                MsgBox(0, 0, $state)
            EndFunc
            ''')

    def test_the_state_assignment_stays_when_the_live_payload_reads_the_name(self):
        self._assertSplicesTo(
            '''
            Func f()
                While 1
                    $state = 2
                    Switch $state
                    Case 2
                        MsgBox(0, 0, $state)
                        ExitLoop
                    EndSwitch
                Wend
            EndFunc
            ''',
            '''
            Func f()
                $state = 2
                MsgBox(0, 0, $state)
            EndFunc
            ''')

    def test_the_state_assignment_stays_when_error_text_holds_the_name(self):
        self._assertSplicesTo(
            '''
            Func f()
                $state = 1 + +
                While 1
                    $state = 2
                    Switch $state
                    Case 2
                        MsgBox(0, 0, 2)
                        ExitLoop
                    EndSwitch
                Wend
            EndFunc
            ''',
            '''
            Func f()
                $state = 1 + +
                $state = 2
                MsgBox(0, 0, 2)
            EndFunc
            ''')

    def test_the_first_of_two_matching_labels_wins(self):
        self._assertSplicesTo(
            '''
            Func f()
                While 1
                    $state = 2
                    Switch $state
                    Case 2
                        MsgBox(0, 0, 1)
                        ExitLoop
                    Case 2
                        MsgBox(0, 0, 2)
                        ExitLoop
                    EndSwitch
                Wend
            EndFunc
            ''',
            '''
            Func f()
                MsgBox(0, 0, 1)
            EndFunc
            ''')

    def test_a_case_else_before_the_matching_label_is_the_live_case(self):
        self._assertSplicesTo(
            '''
            Func f()
                While 1
                    $state = 2
                    Switch $state
                    Case Else
                        MsgBox(0, 0, 0)
                        ExitLoop
                    Case 2
                        MsgBox(0, 0, 2)
                        ExitLoop
                    EndSwitch
                Wend
            EndFunc
            ''',
            '''
            Func f()
                MsgBox(0, 0, 0)
            EndFunc
            ''')

    def test_a_case_else_dispatches_when_no_label_matches(self):
        self._assertSplicesTo(
            '''
            Func f()
                While 1
                    $state = 9
                    Switch $state
                    Case 2
                        MsgBox(0, 0, 2)
                        ExitLoop
                    Case Else
                        MsgBox(0, 0, 0)
                        ExitLoop
                    EndSwitch
                Wend
            EndFunc
            ''',
            '''
            Func f()
                MsgBox(0, 0, 0)
            EndFunc
            ''')

    def test_a_range_label_dispatches_by_containment(self):
        self._assertSplicesTo(
            '''
            Func f()
                While 1
                    $state = 3
                    Switch $state
                    Case 1 To 5
                        MsgBox(0, 0, 1)
                        ExitLoop
                    Case 3
                        MsgBox(0, 0, 3)
                        ExitLoop
                    EndSwitch
                Wend
            EndFunc
            ''',
            '''
            Func f()
                MsgBox(0, 0, 1)
            EndFunc
            ''')

    def test_a_label_the_evaluator_cannot_pin_after_the_live_case_stands(self):
        self._assertSplicesTo(
            '''
            Func f()
                While 1
                    $state = 2
                    Switch $state
                    Case 2
                        MsgBox(0, 0, 2)
                        ExitLoop
                    Case $unknown
                        MsgBox(0, 0, 9)
                        ExitLoop
                    EndSwitch
                Wend
            EndFunc
            ''',
            '''
            Func f()
                MsgBox(0, 0, 2)
            EndFunc
            ''')

    def test_a_label_the_evaluator_cannot_pin_ahead_of_the_live_case_refuses(self):
        self._assertRefused(
            '''
            Func f()
                While 1
                    $state = 2
                    Switch $state
                    Case $unknown
                        MsgBox(0, 0, 9)
                        ExitLoop
                    Case 2
                        MsgBox(0, 0, 2)
                        ExitLoop
                    EndSwitch
                Wend
            EndFunc
            ''')

    def test_a_falsy_while_test_refuses(self):
        self._assertRefused(
            '''
            Func f()
                While 0
                    $state = 2
                    Switch $state
                    Case 2
                        MsgBox(0, 0, 2)
                        ExitLoop
                    EndSwitch
                Wend
            EndFunc
            ''')

    def test_a_non_constant_state_refuses(self):
        self._assertRefused(
            '''
            Func f()
                While 1
                    $state = $x
                    Switch $state
                    Case 2
                        MsgBox(0, 0, 2)
                        ExitLoop
                    EndSwitch
                Wend
            EndFunc
            ''')

    def test_an_array_element_state_refuses(self):
        self._assertRefused(
            '''
            Func f()
                While 1
                    $state[0] = 7
                    Switch $state
                    Case 7
                        MsgBox(0, 0, 7)
                        ExitLoop
                    EndSwitch
                Wend
            EndFunc
            ''')

    def test_a_live_case_without_a_terminating_statement_refuses(self):
        self._assertRefused(
            '''
            Func f()
                While 1
                    $state = 2
                    Switch $state
                    Case 2
                        MsgBox(0, 0, 2)
                    EndSwitch
                Wend
            EndFunc
            ''')

    def test_an_exitloop_of_level_two_in_the_live_body_refuses(self):
        self._assertRefused(
            '''
            Func f()
                While 1
                    $state = 2
                    Switch $state
                    Case 2
                        ExitLoop 2
                        ExitLoop
                    EndSwitch
                Wend
            EndFunc
            ''')

    def test_an_expression_exitloop_level_in_the_live_body_refuses(self):
        self._assertRefused(
            '''
            Func f()
                While 1
                    $state = 2
                    Switch $state
                    Case 2
                        ExitLoop $n
                        ExitLoop
                    EndSwitch
                Wend
            EndFunc
            ''')

    def test_a_bare_continueloop_in_the_live_body_refuses(self):
        self._assertRefused(
            '''
            Func f()
                While 1
                    $state = 2
                    Switch $state
                    Case 2
                        ContinueLoop
                        ExitLoop
                    EndSwitch
                Wend
            EndFunc
            ''')

    def test_a_continueloop_inside_a_nested_loop_of_the_payload_splices(self):
        self._assertSplicesTo(
            '''
            Func f()
                While 1
                    $state = 2
                    Switch $state
                    Case 2
                        For $i = 1 To 3
                            ContinueLoop
                            MsgBox(0, 0, $i)
                        Next
                        ExitLoop
                    EndSwitch
                Wend
            EndFunc
            ''',
            '''
            Func f()
                For $i = 1 To 3
                    ContinueLoop
                    MsgBox(0, 0, $i)
                Next
            EndFunc
            ''')

    def test_a_directive_inside_a_dead_case_refuses(self):
        self._assertRefused(
            '''
            Func f()
                While 1
                    $state = 2
                    Switch $state
                    Case 1
                        #forcedef something
                        MsgBox(0, 0, 1)
                    Case 2
                        MsgBox(0, 0, 2)
                        ExitLoop
                    EndSwitch
                Wend
            EndFunc
            ''')

    def test_error_text_holding_a_block_keyword_inside_a_dead_case_refuses(self):
        self._assertRefused(
            '''
            Func f()
                While 1
                    $state = 2
                    Switch $state
                    Case 1
                        $x = 1 + If
                        MsgBox(0, 0, 1)
                    Case 2
                        MsgBox(0, 0, 2)
                        ExitLoop
                    EndSwitch
                Wend
            EndFunc
            ''')

    def test_error_text_without_a_block_keyword_inside_a_dead_case_splices(self):
        self._assertSplicesTo(
            '''
            Func f()
                While 1
                    $state = 2
                    Switch $state
                    Case 1
                        $x = 1 + +
                        MsgBox(0, 0, 1)
                    Case 2
                        MsgBox(0, 0, 2)
                        ExitLoop
                    EndSwitch
                Wend
            EndFunc
            ''',
            '''
            Func f()
                MsgBox(0, 0, 2)
            EndFunc
            ''')

    def test_a_return_terminated_live_case_splices_and_keeps_the_return(self):
        self._assertSplicesTo(
            '''
            Func f()
                While 1
                    $state = 2
                    Switch $state
                    Case 2
                        MsgBox(0, 0, 2)
                        Return 5
                    Case 3
                        MsgBox(0, 0, 3)
                    EndSwitch
                Wend
            EndFunc
            ''',
            '''
            Func f()
                MsgBox(0, 0, 2)
                Return 5
            EndFunc
            ''')

    def test_an_exit_terminated_live_case_splices_and_keeps_the_exit(self):
        self._assertSplicesTo(
            '''
            Func f()
                While 1
                    $state = 2
                    Switch $state
                    Case 2
                        Exit
                    Case 3
                        MsgBox(0, 0, 3)
                    EndSwitch
                Wend
            EndFunc
            ''',
            '''
            Func f()
                Exit
            EndFunc
            ''')

    def test_two_regions_sharing_one_state_name_both_splice_and_keep_their_assignments(self):
        self._assertSplicesTo(
            '''
            Func f()
                While 1
                    $state = 1
                    Switch $state
                    Case 1
                        MsgBox(0, 0, 1)
                        ExitLoop
                    EndSwitch
                Wend
                While 1
                    $state = 1
                    Switch $state
                    Case 1
                        MsgBox(0, 0, 2)
                        ExitLoop
                    EndSwitch
                Wend
            EndFunc
            ''',
            '''
            Func f()
                $state = 1
                MsgBox(0, 0, 1)
                $state = 1
                MsgBox(0, 0, 2)
            EndFunc
            ''')

    def test_a_region_nested_in_a_live_case_body_splices_in_the_same_sweep(self):
        self._assertSplicesTo(
            '''
            Func f()
                While 1
                    $outer = 1
                    Switch $outer
                    Case 1
                        While 1
                            $inner = 2
                            Switch $inner
                            Case 2
                                MsgBox(0, 0, 9)
                                ExitLoop
                            EndSwitch
                        Wend
                        ExitLoop
                    EndSwitch
                Wend
            EndFunc
            ''',
            '''
            Func f()
                MsgBox(0, 0, 9)
            EndFunc
            ''')

    def test_disguised_constants_splice_through_the_evaluator(self):
        self._assertSplicesTo(
            '''
            Func f()
                While (821 - 212)
                    $state = BitXOR(711892, 171542)
                    Switch $state
                    Case BitXOR(711892, 171542)
                        MsgBox(0, 0, 2)
                        ExitLoop
                    EndSwitch
                Wend
            EndFunc
            ''',
            '''
            Func f()
                MsgBox(0, 0, 2)
            EndFunc
            ''')

    def test_a_flattened_region_reduces_to_its_payload_end_to_end(self):
        self._assertDeobfuscatesTo(
            '''
            Func f()
                While (821 - 212)
                    $state = (521451 - 521450)
                    Switch $state
                    Case (521450 + 1 - 521450)
                        MsgBox(0, 0, 7)
                        ExitLoop
                    Case 99
                        MsgBox(0, 0, 99)
                    EndSwitch
                Wend
            EndFunc

            f()
            ''',
            '''
            Func f()
                MsgBox(0, 0, 7)
            EndFunc

            f()
            ''')
