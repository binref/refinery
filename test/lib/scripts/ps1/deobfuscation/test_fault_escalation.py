from __future__ import annotations

import inspect
import unittest

from test.lib.scripts.ps1.deobfuscation import TestPs1

#: A discarded conversion that Windows PowerShell 5.1 answers with an implicit terminating error.
#: Left to itself it is reported and stepped over, so it neither stops the script nor leaves a value
#: behind. Every claim below is about the shapes in which deleting it does change what runs.
_RAISE = "$Null = [Int]'abc'"

#: The same failing cast written as its own statement rather than stored, so the raise survives
#: where `_RAISE` is dropped as a dead store. It is the witness for an arming that escalates *every*
#: error rather than only what a command reports: under a `Stop` preference this cast ends the
#: script, so a `trap` over it is load bearing, and under a default-table `Stop` — which reaches
#: commands only — it is not, which is the difference the two armings are told apart by.
_BARE_CAST_RAISE = "[int]'a'"

#: The type Windows PowerShell 5.1 gives that error, so a handler filtered on it matches the raise.
_MATCHING = '[System.Management.Automation.RuntimeException]'

#: A type the raise is not, so a handler filtered on it never matches the raise.
_DIFFERENT = '[System.IO.IOException]'

#: A statement written after the raise. Whether it runs is the whole question wherever the raise
#: ends the script or abandons the remainder of a block.
_FOLLOWER = "Write-Host 'FOLLOWER_RAN'"

#: A handler body that writes to the host, so that a handler which runs is one the output names.
_HANDLER = "Write-Host 'HANDLER_RAN'"

#: A second handler body, for the shapes where an error raised inside one handler is taken by
#: another, so that the output names which of the two ran.
_OUTER_HANDLER = "Write-Host 'OUTER_HANDLER_RAN'"

#: An acting statement that is never a removal candidate, so its survival says only that the pass
#: did not empty the script wholesale.
_ANCHOR = "Write-Host 'ANCHOR_SURVIVES'"

#: A condition the analysis cannot decide, so that a branch is neither taken nor folded away.
_OPAQUE = '$args'

#: A command Windows PowerShell 5.1 answers with a *terminating* error rather than with the implicit
#: one `_RAISE` produces, because `-ErrorAction Stop` makes every error the command reports
#: terminating. Left to itself it ends the script, which is the whole difference between the two.
_STOPPING_RAISE = 'Get-Item nope -ErrorAction Stop'

#: The same command as `_STOPPING_RAISE` with no action of its own, so what it reports is
#: terminating exactly when a preference says every error is. It is the raise that makes a write of
#: `$ErrorActionPreference` the only reason a `trap` over it is load bearing.
_UNSPECIFIED_RAISE = 'Get-Item nope'

#: A command 5.1 answers with a parameter-binding failure — a terminating error that fires a `trap`
#: with no `-ErrorAction Stop` anywhere. The firing gate counts no plain command, so a `trap` body
#: raise this fires is deleted although the host keeps it; the delete is tracked by an xfail below.
_BINDING_FAILURE_RAISE = 'Get-Item -BogusParam foo'

#: A member access on `$Null`, which under `Set-StrictMode` raises a statement-terminating error
#: that fires a `trap`. `is_soft_error_source` excludes member and index access by design, so the
#: firing gate does not count this either — the second tracked unsound delete.
_STRICT_MEMBER_RAISE = '$Null.Nonexistent'

#: A read of a never-set variable, which under `Set-StrictMode` raises a statement-terminating error
#: that fires a `trap`. `is_soft_error_source` counts no bare variable read, so the firing gate
#: misses it the way it misses the member access above — the third tracked unsound delete.
_STRICT_UNSET_VAR_RAISE = '$ThisVarWasNeverSet'


class _Ps1FaultEscalation(TestPs1):

    def _assertDeobfuscatesTo(self, source: str, expected: str) -> None:
        """
        Both arguments are written as ordinary indented PowerShell, and `expected` is rendered
        through the synthesizer before the comparison, so that brace layout cannot be mistaken for a
        statement having been removed.
        """
        self.assertEqual(
            self._deobfuscate(inspect.cleandoc(source)),
            self._apply(inspect.cleandoc(expected)),
        )

    def _assertKept(self, source: str) -> None:
        self._assertDeobfuscatesTo(source, source)


class TestPs1AStopPreferenceMakesTheRaiseEndTheScript(_Ps1FaultEscalation):
    """
    An implicit terminating error is reported and stepped over, but under
    `$ErrorActionPreference = 'Stop'` it ends the script instead. Nothing written after the raise
    runs, neither in the raise's own block nor in any block enclosing it. Deleting the raise starts
    running all of it, so the raise and the assignment that arms it both survive.

    The fault model reads the same `Stop` preference on the forward path that weighs deleting the
    raise as on the transpose that weighs deleting a `trap`, so a raise the preference makes
    terminating is observed and kept. `TestPs1APreferenceThatResumesLeavesTheRaiseRemovable` is the
    control: with any resuming preference the identical raise still goes.
    """

    def test_a_raising_cast_under_a_stop_preference_is_kept(self):
        self._assertKept(F"""
            $ErrorActionPreference = 'Stop'
            {_RAISE}
            {_FOLLOWER}
        """)

    def test_a_raising_cast_in_a_branch_under_a_stop_preference_is_kept(self):
        self._assertKept(F"""
            $ErrorActionPreference = 'Stop'
            if ({_OPAQUE}) {{
              {_RAISE}
            }}
            {_FOLLOWER}
        """)


class TestPs1APreferenceThatResumesLeavesTheRaiseRemovable(_Ps1FaultEscalation):
    """
    Every preference other than `Stop` reports the error at most and resumes at the next statement,
    so the script reaches the same statement whether the raise is there or not. These are the shapes
    a refusal keyed to the preference variable being assigned at all would break.
    """

    def test_a_raising_cast_under_a_continue_preference_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            $ErrorActionPreference = 'Continue'
            {_RAISE}
            {_ANCHOR}
        """, F"""
            $ErrorActionPreference = 'Continue'
            {_ANCHOR}
        """)

    def test_a_raising_cast_under_a_silently_continue_preference_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            $ErrorActionPreference = 'SilentlyContinue'
            {_RAISE}
            {_ANCHOR}
        """, F"""
            $ErrorActionPreference = 'SilentlyContinue'
            {_ANCHOR}
        """)

    def test_a_raising_cast_under_a_preference_copied_from_another_preference_is_removed(self):
        """
        `$VerbosePreference` holds `SilentlyContinue` and is inlined as the cast of that member's
        name, which the fault model reads as the member it is rather than as a value it cannot read
        and so must take for `Stop`.
        """
        self._assertDeobfuscatesTo(F"""
            $ErrorActionPreference = $VerbosePreference
            {_RAISE}
            {_ANCHOR}
        """, F"""
            $ErrorActionPreference = [System.Management.Automation.ActionPreference]'SilentlyContinue'
            {_ANCHOR}
        """)


class TestPs1ATrapWhoseTypeFilterMissesTheErrorEndsTheScript(_Ps1FaultEscalation):
    """
    A `trap` whose type filter does not match the error is not merely inert. With no other `trap` in
    scope to take the error, it ends the script: the body of that `trap` never runs and neither does
    anything written after the raise, whether the body is empty or writes to the host. Deleting the
    raise starts running the rest of the script.
    """

    def test_a_raising_cast_under_an_empty_trap_whose_filter_misses_is_kept(self):
        self._assertKept(F"""
            trap {_DIFFERENT} {{ }}
            {_RAISE}
            {_FOLLOWER}
        """)

    def test_a_raising_cast_under_a_live_trap_whose_filter_misses_is_kept(self):
        self._assertKept(F"""
            trap {_DIFFERENT} {{ {_HANDLER} }}
            {_RAISE}
            {_FOLLOWER}
        """)


class TestPs1ATrapBodyThatReachesBreakEndsTheScript(_Ps1FaultEscalation):
    """
    A `trap` body that reaches `break` rethrows the error once it has run, which ends the script.
    Nothing written after the raise runs, so deleting the raise starts running it. The one-word
    variant of the same `trap` that reaches `continue` instead is licensed to lose the raise.
    """

    def test_a_raising_cast_under_a_trap_that_breaks_is_kept(self):
        self._assertKept(F"""
            trap {{ break }}
            {_RAISE}
            {_FOLLOWER}
        """)

    def test_a_raising_cast_under_a_trap_that_writes_then_breaks_is_kept(self):
        self._assertKept(F"""
            trap {{
              {_HANDLER}
              break
            }}
            {_RAISE}
            {_FOLLOWER}
        """)


class TestPs1ATrapThatTakesTheErrorAndSwallowsLeavesTheRaiseRemovable(_Ps1FaultEscalation):
    """
    A `trap` that matches the error and reaches `continue` suppresses it and resumes at the next
    statement, so the script runs the same code with the raise as without it. A `trap` whose filter
    misses ends the script only when no other `trap` in scope takes the error, so an untyped one
    written beside it swallows and the script does not end after all.
    """

    def test_a_raising_cast_under_a_matching_trap_that_continues_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            trap {_MATCHING} {{ continue }}
            {_RAISE}
            {_FOLLOWER}
        """, _FOLLOWER)

    def test_a_raising_cast_under_an_untyped_trap_that_continues_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            trap {{ continue }}
            {_RAISE}
            {_FOLLOWER}
        """, _FOLLOWER)

    def test_a_raising_cast_a_continuing_trap_takes_from_a_missing_filter_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            trap {_DIFFERENT} {{ }}
            trap {{ continue }}
            {_RAISE}
            {_FOLLOWER}
        """, _FOLLOWER)


class TestPs1ACatchWhoseTypeFilterMissesLeavesTheRaiseRemovable(_Ps1FaultEscalation):
    """
    A `catch` whose type filter does not match the error is the opposite of a `trap` whose filter
    does not match. The error leaves the construct unhandled, the script resumes at the statement
    written after it, and the `catch` body never runs, so the raise may go. The clause here carries
    the same filter and the same empty body as the `trap` that ends the script, and only the keyword
    differs.
    """

    def test_a_raising_cast_under_an_empty_catch_whose_filter_misses_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            try {{ {_RAISE} }} catch {_DIFFERENT} {{ }}
            {_FOLLOWER}
        """, _FOLLOWER)


class TestPs1ATypedCatchThatMissesDoesNotShieldAnEnclosingCatch(_Ps1FaultEscalation):
    """
    A type filter decides whether a `catch` handles the error, so a `catch` that does not match
    passes it on to the enclosing `catch`, whose body then runs. The raise is what makes that
    handler run and must survive.
    """

    def test_a_raising_cast_a_missing_filter_passes_to_a_live_outer_catch_is_kept(self):
        self._assertKept(F"""
            try {{
              try {{ {_RAISE} }} catch {_DIFFERENT} {{ }}
            }} catch {{
              {_HANDLER}
            }}
        """)


class TestPs1ATypedCatchThatMatchesShieldsAnEnclosingCatch(_Ps1FaultEscalation):
    """
    The same nesting with a filter that does match the error is handled by the inner `catch`, so the
    enclosing handler never runs and the script carries on inside the outer `try` block. The removal
    is then unobservable and stays allowed.
    """

    def test_a_raising_cast_an_empty_matching_filter_swallows_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            try {{
              try {{ {_RAISE} }} catch {_MATCHING} {{ }}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """, F"""
            try {{
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """)


class TestPs1AnEmptyCatchDoesNotCoverWhatFollowsTheRaiseInItsBlock(_Ps1FaultEscalation):
    """
    An empty `catch` swallows the error, but the raise still abandons the rest of its `try` block,
    so a statement written after it there never runs. A proven raise folds the whole construct away
    — the swallowed error and the dead tail with it — leaving only what stands after the `try`. What
    the tail must never do is run, and it does not: the fold drops it rather than resurrecting it,
    which is the wrong answer a raise deleted on its own would give.
    """

    def test_a_proven_raise_before_a_dead_tail_folds_the_construct_away(self):
        self._assertDeobfuscatesTo(F"""
            try {{
              {_RAISE}
              {_FOLLOWER}
            }} catch {{ }}
            {_ANCHOR}
        """, _ANCHOR)


class TestPs1AProvenThrowFoldsTheTryConstruct(_Ps1FaultEscalation):
    """
    A `try` body proven to throw runs the statements before the throw, then the body of the `catch`
    that takes it, then the `finally`, and nothing else. A terminating error abandons the rest of
    the block, so the statements after the throw are dead and go. The sibling
    `TestPs1ASoftFaultBeforeALiveTailInAnEmptyCatchIsKept` holds a construct whose throw it cannot
    prove; this one folds one whose throw it can.

    A `throw` and a cast of a non-numeric literal are both proven throws, and an empty `catch`, a
    bare catch-all and a universally typed one all take every error, so each lifts its body out
    over the throw.
    """

    def test_a_proven_raise_under_an_empty_catch_folds_to_nothing(self):
        self._assertDeobfuscatesTo(F"try {{ {_RAISE} }} catch {{ }}", '')

    def test_a_throw_lifts_the_body_of_the_catch_that_takes_it(self):
        self._assertDeobfuscatesTo(F"try {{ throw 'x' }} catch {{ {_HANDLER} }}", _HANDLER)

    def test_a_proven_cast_lifts_the_body_of_a_bare_catch(self):
        self._assertDeobfuscatesTo(F"try {{ {_RAISE} }} catch {{ {_HANDLER} }}", _HANDLER)

    def test_a_dead_tail_after_the_throw_goes_while_the_handler_body_is_lifted(self):
        self._assertDeobfuscatesTo(F"""
            try {{
              {_RAISE}
              {_FOLLOWER}
            }} catch {{ {_HANDLER} }}
        """, _HANDLER)

    def test_a_universally_typed_catch_takes_the_throw_and_lifts_its_body(self):
        self._assertDeobfuscatesTo(
            F"try {{ {_RAISE} }} catch [System.Exception] {{ {_HANDLER} }}", _HANDLER)

    def test_an_empty_catch_beside_a_finally_folds_to_the_finally(self):
        self._assertDeobfuscatesTo(
            F"try {{ {_RAISE} }} catch {{ }} finally {{ {_HANDLER} }}", _HANDLER)


class TestPs1AProvenThrowIsNotFoldedWhereTheLiftWouldChangeWhatRuns(_Ps1FaultEscalation):
    """
    The fold lifts the `catch` body out of its construct, and three things a lifted body could
    observe are refused rather than reasoned about, so the construct is left whole. A body naming
    `$_` or `$PSItem` loses the error record those hold only inside a `catch`. A read of `$Error`
    anywhere in the script would answer a different count once the raise that filled it is gone. And
    a `catch` body beside a `finally` runs the `finally` before it leaves, which a flat sequence of
    the two does not preserve if the body does not complete normally.
    """

    def test_a_catch_that_reads_the_error_variable_is_not_folded(self):
        self._assertKept(F"try {{ {_RAISE} }} catch {{ Write-Host $_ }}")

    def test_a_catch_that_reads_the_error_item_is_not_folded(self):
        self._assertKept(F"try {{ {_RAISE} }} catch {{ Write-Host $PSItem }}")

    def test_a_later_read_of_the_error_record_stops_the_fold(self):
        # A `throw` rather than the discard `_RAISE`, so that folding the construct is the only way
        # the raise could go: a discarded cast under an empty `catch` is removed on its own by a
        # separate limit, which would collapse the construct here whether the fold declined or not.
        self._assertKept(F"""
            try {{ throw 'x' }} catch {{ }}
            Write-Host $Error.Count
        """)

    def test_a_catch_body_beside_a_finally_is_not_folded(self):
        self._assertKept(
            F"try {{ {_RAISE} }} catch {{ {_HANDLER} }} finally {{ {_OUTER_HANDLER} }}")


class TestPs1AThrowThatEvaluatesAnEffectIsNotFolded(_Ps1FaultEscalation):
    """
    A `throw` evaluates its argument before it raises, and that evaluation runs on 5.1 whether or
    not the error is later caught: `throw ($x = 5)` assigns, `throw (Write-Host 'a')` writes to the
    host. The fold drops the throwing statement and stands the lifted `catch` body in for the raise,
    so a `throw` whose argument is not side-effect-free is left whole rather than have that effect
    dropped with it. A `throw` of a literal has no such effect and folds, which
    `TestPs1AProvenThrowFoldsTheTryConstruct` covers.
    """

    def test_a_throw_of_an_assignment_argument_is_not_folded(self):
        self._assertKept(F"try {{ throw ($script:x = 5) }} catch {{ {_HANDLER} }}")

    def test_a_throw_of_a_command_argument_is_not_folded(self):
        self._assertKept(F"try {{ throw (Write-Host 'a') }} catch {{ {_HANDLER} }}")


class TestPs1ATrapInTheTryBodyTakesTheThrowBeforeTheCatch(_Ps1FaultEscalation):
    """
    A `trap` written in the `try` body is hoisted over the whole block, so a `trap { continue }`
    there takes the throw and resumes past it — the `catch` never runs. The fold reads the landing
    handler off the fault routing rather than off the `catch` clauses alone, so it declines to lift
    a `catch` body the trap keeps the throw from ever reaching, whichever side of the throw the trap
    is written on.
    """

    def test_a_resuming_trap_after_the_throw_keeps_the_construct(self):
        self._assertKept(F"try {{ throw 'x'; trap {{ continue }} }} catch {{ {_HANDLER} }}")

    def test_a_resuming_trap_before_the_throw_keeps_the_construct(self):
        self._assertKept(F"try {{ trap {{ continue }}; throw 'x' }} catch {{ {_HANDLER} }}")


class TestPs1AnEmptyCatchCoversARaiseThatIsLastInItsBlock(_Ps1FaultEscalation):
    """
    With the same statement written before the raise rather than after it, nothing in the `try`
    block is abandoned: the statement runs, the empty `catch` swallows, and the script carries on.
    The raise may go.
    """

    def test_a_raising_cast_after_every_other_statement_of_its_try_block_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            try {{
              {_FOLLOWER}
              {_RAISE}
            }} catch {{ }}
            {_ANCHOR}
        """, F"""
            try {{
              {_FOLLOWER}
            }} catch {{ }}
            {_ANCHOR}
        """)


class TestPs1ASoftFaultBeforeALiveTailInAnEmptyCatchIsKept(_Ps1FaultEscalation):
    """
    A statement whose fault its own `try` catches, written before a live statement of the same block
    under an empty `catch`, is the only reason that live statement is dead — the empty `catch`
    swallows the fault and resumes past the tail. It is kept whenever the analysis cannot *prove*
    the fault, whatever the caught-terminating fault is: a possible division by zero it cannot rule
    out, a bitwise operator over a string of unknown value (whose spelling the normalize pass
    canonicalizes before the removal weighs it), or a command the script's `Stop` preference makes
    terminating. A command left to its default non-terminating error is the control: 5.1 reports it
    and steps over it, so the tail runs whether the command stands or not and the discard goes.

    A fault the analysis *proves* is not kept here but folded away with the construct around it, in
    `TestPs1AProvenThrowFoldsTheTryConstruct`: this class is the may-throw region that fold cannot
    reach, so a certain operand (a literal `'zz' -bxor 3`) belongs there, not here.
    """

    def test_a_possible_division_by_zero_before_a_live_tail_is_kept(self):
        self._assertKept(F"""
            try {{
              $Null = ($PID / $PID)
              {_FOLLOWER}
            }} catch {{ }}
        """)

    def test_a_bitwise_operator_over_a_string_before_a_live_tail_is_kept(self):
        # The normalize pass canonicalizes `-bxor` to `-BXor` before the removal weighs it, and the
        # veto has to read the operator it actually sees; the expected output is compared directly
        # because the synthesizer renders the operator lower-case where the pipeline canonicalizes it.
        # The operand is a variable of unknown value, so the fault is possible rather than proven and
        # the fold leaves it to this keep.
        self.assertEqual(
            self._deobfuscate(inspect.cleandoc(F"""
                try {{
                  $Null = ($PSCommandPath -bxor 3)
                  {_FOLLOWER}
                }} catch {{ }}
            """)),
            "try {\n  $Null = ($PSCommandPath -BXor 3)\n  Write-Host 'FOLLOWER_RAN'\n} catch {}",
        )

    def test_a_command_discard_before_a_live_tail_under_a_stop_preference_is_kept(self):
        self._assertKept(F"""
            $ErrorActionPreference = 'Stop'
            try {{
              $Null = (Get-ChildItem 'Z:\\nope')
              {_FOLLOWER}
            }} catch {{ }}
        """)

    def test_a_command_discard_before_a_live_tail_with_no_stop_preference_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            try {{
              $Null = (Get-ChildItem 'Z:\\nope')
              {_FOLLOWER}
            }} catch {{ }}
        """, F"""
            try {{
              {_FOLLOWER}
            }} catch {{ }}
        """)


class TestPs1ATrapGuardsTheBlockItIsWrittenIn(_Ps1FaultEscalation):
    """
    A `trap` guards the statement block it is written in, and where blocks nest, the innermost one
    that declares a `trap` is the one that takes the error. A raise written in the same block as a
    live `trap` is what makes that `trap` run, and a raise beside the inner of two live traps is
    what makes the inner one run and the outer one not.
    """

    def test_a_raising_cast_beside_a_live_trap_in_the_same_nested_block_is_kept(self):
        self._assertKept(F"""
            if ({_OPAQUE}) {{
              trap {{ {_HANDLER} }}
              {_RAISE}
            }}
            {_ANCHOR}
        """)

    def test_a_raising_cast_beside_the_innermost_of_two_live_traps_is_kept(self):
        self._assertKept(F"""
            trap {{ {_FOLLOWER} }}
            if ({_OPAQUE}) {{
              trap {{ {_HANDLER} }}
              {_RAISE}
            }}
            {_ANCHOR}
        """)


class TestPs1ATrapTheRaisingBlockDoesNotReachLeavesItRemovable(_Ps1FaultEscalation):
    """
    A `trap` declared in a block the raise is not in never sees the error, and it does not end the
    script over it either, so a live `trap` written in a sibling block leaves the raise exactly as
    removable as no handler at all would. Where the innermost `trap` in reach swallows, the live one
    enclosing it is never offered the error, so that raise is removable too.

    These are the shapes a refusal keyed to a `trap` appearing anywhere in the script would break.

    Both leave the `trap` itself standing, which is what a handler with nothing left to handle costs
    and not what it means. `Write-Host` is a command, and no reading here shows a command unable to
    raise, so deleting the swallowing `trap` would expose whatever remains in its block to the live
    `trap` around it — a different handler, on the path 5.1 takes when the host does fail.
    """

    def test_a_raising_cast_outside_the_block_that_declares_the_trap_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            if ({_OPAQUE}) {{
              trap {{ {_HANDLER} }}
            }}
            {_RAISE}
            {_ANCHOR}
        """, F"""
            if ({_OPAQUE}) {{
              trap {{ {_HANDLER} }}
            }}
            {_ANCHOR}
        """)

    def test_a_raising_cast_whose_innermost_trap_continues_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            trap {{ {_HANDLER} }}
            if ({_OPAQUE}) {{
              trap {{ continue }}
              {_RAISE}
              {_FOLLOWER}
            }}
            {_ANCHOR}
        """, F"""
            trap {{ {_HANDLER} }}
            if ({_OPAQUE}) {{
              trap {{ continue }}
              {_FOLLOWER}
            }}
            {_ANCHOR}
        """)


class TestPs1ATrapInATryBlockRunsInsteadOfTheCatch(_Ps1FaultEscalation):
    """
    A `trap` declared inside a `try` block takes the error before the `catch` clause is offered it,
    so the `trap` body runs and the `catch` body does not. The raise is what makes the `trap` run,
    and it survives.
    """

    def test_a_raising_cast_beside_a_live_trap_inside_a_guarded_try_block_is_kept(self):
        self._assertKept(F"""
            try {{
              trap {{ {_HANDLER} }}
              {_RAISE}
            }} catch {{
              {_FOLLOWER}
            }}
            {_ANCHOR}
        """)


class TestPs1ATrapInATryBlockThatSwallowsLeavesTheRaiseRemovable(_Ps1FaultEscalation):
    """
    Because the `trap` inside the `try` block takes the error first, a `trap` body that suppresses
    it leaves the `catch` clause unreached, and one that emits nothing leaves nothing else to
    observe. Either way the script runs the same code with the raise as without it.

    The deobfuscator refuses both removals because it sees a `catch` clause around the raise, and it
    never asks whether a `trap` in the block took the error before that clause could.
    """

    @unittest.expectedFailure
    def test_a_raising_cast_a_continuing_trap_takes_before_a_live_catch_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            try {{
              trap {{ continue }}
              {_RAISE}
            }} catch {{
              {_HANDLER}
            }}
            {_ANCHOR}
        """, _ANCHOR)

    @unittest.expectedFailure
    def test_a_raising_cast_an_empty_trap_takes_before_a_live_catch_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            try {{
              trap {{ }}
              {_RAISE}
            }} catch {{
              {_HANDLER}
            }}
            {_ANCHOR}
        """, _ANCHOR)


class TestPs1ATrapBodyThatOnlyProducesAValueIsALiveHandler(_Ps1FaultEscalation):
    """
    A `trap` body that neither assigns nor calls anything is still a live handler: it runs when its
    block raises, and the value it produces is written to the output stream. The raise is what makes
    that value appear, so removing the `trap` would silence an output the script made, and it is
    kept.

    A command whose errors the model does not read counts as a raise the handler may be offered, so
    the same `trap` is kept above one of those too — the sound over-keep the precise-raiser test
    settles for rather than proving a benign command cannot terminate.
    """

    def test_a_raising_cast_under_a_trap_whose_body_is_a_bare_value_is_kept(self):
        self._assertKept(F"""
            trap {{ 5 }}
            {_RAISE}
            {_ANCHOR}
        """)

    def test_a_trap_whose_body_is_a_bare_value_is_kept_above_a_command_the_model_cannot_clear(self):
        self._assertKept(F"""
            trap {{ 5 }}
            {_ANCHOR}
        """)


class TestPs1ATrapWithAnEmptyBodyLeavesTheRaiseRemovable(_Ps1FaultEscalation):
    """
    A `trap` with an empty body writes nothing and lets execution resume, so it changes no code the
    script runs and the raise under it may go with it.
    """

    def test_a_raising_cast_under_a_trap_whose_body_is_empty_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            trap {{ }}
            {_RAISE}
            {_ANCHOR}
        """, _ANCHOR)


class TestPs1ATrapInASubexpressionKeepsItsWholeGuardedBracket(_Ps1FaultEscalation):
    """
    A `trap` written among the statements of a `$( )` guards a raise beside it there, and its body
    goes to the output stream when that raise fires, so the whole bracket survives: `$x` receives
    `h` on 5.1 rather than the empty value the emptied bracket would leave. The reader places the
    bracket-internal cast, the transpose reads it as a real raiser, and the handler that writes over
    it is kept.
    """

    def test_a_trap_beside_a_raising_cast_inside_a_subexpression_is_kept(self):
        self._assertKept("$x = $(trap { 'h' }; [int]'a')")


class TestPs1AReadOfErrorObservesARaiseNoHandlerTook(_Ps1FaultEscalation):
    """
    Windows PowerShell 5.1 records every terminating error in `$Error` whether or not a handler ran,
    so a script with no `catch` and no `trap` anywhere can still branch on the raise having happened
    and can still read the record it left. The raise is what puts that record there, and a read of
    `$Error` reachable after it observes the difference, so the raise is kept.
    """

    def test_a_raising_cast_a_later_count_of_error_observes_is_kept(self):
        self._assertKept(F"""
            {_RAISE}
            if ($Error.Count) {{
              {_HANDLER}
            }}
            {_ANCHOR}
        """)

    def test_a_raising_cast_a_later_read_of_its_error_record_observes_is_kept(self):
        self._assertKept(F"""
            {_RAISE}
            Write-Host $Error[0].Exception.Message
        """)

    def test_a_stacktrace_read_after_the_raise_observes_it_and_keeps_it(self):
        self._assertKept(F"""
            {_RAISE}
            Write-Host $StackTrace
        """)

    def test_a_named_reference_read_of_error_after_the_raise_keeps_it(self):
        self._assertDeobfuscatesTo(F"""
            {_RAISE}
            Write-Host (Get-Variable Error).Value.Count
        """, F"""
            {_RAISE}
            Write-Host $Error.Count
        """)

    def test_a_splatted_read_of_the_error_record_after_the_raise_keeps_it(self):
        self._assertKept(F"""
            {_RAISE}
            Write-Output @Error
        """)

    def test_the_identical_error_read_moved_before_the_raise_leaves_it_removable(self):
        self._assertDeobfuscatesTo(F"""
            Write-Host $Error[0].Exception.Message
            {_RAISE}
            {_ANCHOR}
        """, F"""
            Write-Host $Error[0].Exception.Message
            {_ANCHOR}
        """)


class TestPs1AReadOfErrorInASeparateBodyIsAKnownInterproceduralGap(_Ps1FaultEscalation):
    """
    `$Error` is session-global, so a read reached after the raise observes the record on a 5.1 host
    as surely as one written beside it — deleting the raise empties what the read sees. The
    error-record channel orders reads against the raise per body, so a read the graphs place in a
    *different* body than the raiser's is out of reach and the raise is deleted although the host
    keeps it. That is one gap with several spellings — a called function, an inline or pipeline
    scriptblock, a dot-sourced block — each of which owns its own control-flow graph. Closing it
    needs the interprocedural milestone (cluster 1f); until then each spelling's delete is tracked
    here so none is merely mentioned.
    """

    @unittest.expectedFailure
    def test_a_raise_before_a_call_whose_body_reads_error_is_kept(self):
        self._assertKept(F"""
            function Show-Count {{ Write-Host ($Error.Count) }}
            {_RAISE}
            Show-Count
        """)

    @unittest.expectedFailure
    def test_a_raise_before_a_pipeline_scriptblock_that_reads_error_is_kept(self):
        self._assertKept(F"""
            {_RAISE}
            1..3 | ForEach-Object {{ Write-Host ($Error.Count) }}
        """)

    @unittest.expectedFailure
    def test_a_raise_before_a_dot_sourced_block_that_reads_error_is_kept(self):
        self._assertKept(F"""
            {_RAISE}
            . {{ Write-Host ($Error.Count) }}
        """)


class TestPs1ARaiseNoReadOfErrorFollowsIsRemovable(_Ps1FaultEscalation):
    """
    With the same read of `$Error` written before the raise rather than after it, the read answers
    the same on both scripts, because nothing has raised yet when it runs. Nothing observes the
    raise and it may go.
    """

    def test_a_raising_cast_after_the_only_read_of_error_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            if ($Error.Count) {{
              {_HANDLER}
            }}
            {_RAISE}
            {_ANCHOR}
        """, F"""
            if ($Error.Count) {{
              {_HANDLER}
            }}
            {_ANCHOR}
        """)


class TestPs1ARaiseInATrapBodyEndsThatBody(_Ps1FaultEscalation):
    """
    A terminating error raised inside a `trap` body ends that body and escapes it. At script scope
    the escaped error ends the script, so neither the rest of the `trap` body nor the statement the
    script would have resumed at runs; inside a function it ends only the function and the caller
    carries on. Where something does guard the block the `trap` belongs to, the escaped error goes
    to that guard, and an enclosing `catch` clause or a second, live `trap` runs its body over it.
    In each of these the raise inside the `trap` body decides what runs next, so it survives.

    The keep fires only where the `trap` provably fires — a cast, a fallible operator, a method
    call, a `throw`, or a command a `Stop` makes terminating in the block the `trap` guards — so a
    `trap` nothing triggers still leaves its dead body raise removable
    (`TestPs1ATrapBodyNothingTriggersLeavesTheRaiseInItRemovable`).
    """

    def test_a_raising_cast_before_another_statement_of_the_same_trap_body_is_kept(self):
        self._assertKept(F"""
            trap {{
              {_HANDLER}
              {_RAISE}
              {_FOLLOWER}
            }}
            {_RAISE}
            {_ANCHOR}
        """)

    def test_a_raising_cast_in_the_trap_body_of_a_function_is_kept(self):
        self._assertKept(F"""
            function Invoke-Thing {{
              trap {{
                {_HANDLER}
                {_RAISE}
                {_FOLLOWER}
              }}
              {_RAISE}
            }}
            Invoke-Thing
            {_ANCHOR}
        """)

    def test_a_raising_cast_in_a_nested_block_of_a_firing_trap_body_is_kept(self):
        """
        The raise sits in a loop body nested in the `trap` body. Its scope is still the `trap`'s,
        because a `foreach` body is an ordinary block and not a new scope, so the escaped error ends
        the same script and the raise is live. The keep has to find the `trap` across that block: a
        walk that stopped at the first block rather than at a function or scriptblock boundary would
        read the raise as in no `trap` body and delete it.
        """
        self._assertKept(F"""
            trap {{
              {_HANDLER}
              foreach ($i in 1) {{
                {_RAISE}
              }}
              {_FOLLOWER}
            }}
            {_RAISE}
            {_ANCHOR}
        """)

    def test_a_trap_body_raise_a_stopping_command_fires_is_kept(self):
        self._assertKept(F"""
            trap {{
              {_HANDLER}
              {_RAISE}
              {_FOLLOWER}
            }}
            {_STOPPING_RAISE}
            {_ANCHOR}
        """)

    def test_a_raising_cast_in_a_trap_body_an_enclosing_catch_takes_is_kept(self):
        self._assertKept(F"""
            try {{
              trap {{
                {_HANDLER}
                {_RAISE}
                {_FOLLOWER}
              }}
              {_RAISE}
            }} catch {{
              {_OUTER_HANDLER}
            }}
            {_ANCHOR}
        """)

    def test_a_raising_cast_in_a_trap_body_an_enclosing_trap_takes_is_kept(self):
        self._assertKept(F"""
            trap {{ {_OUTER_HANDLER} }}
            if ({_OPAQUE}) {{
              trap {{
                {_HANDLER}
                {_RAISE}
                {_FOLLOWER}
              }}
              {_RAISE}
            }}
            {_ANCHOR}
        """)


class TestPs1ATrapBodyNothingTriggersLeavesTheRaiseInItRemovable(_Ps1FaultEscalation):
    """
    A `trap` body runs only when its block raises, so with nothing raising there the statements of
    the body never run and a raise among them ends nothing. It may go while the `trap` stands, and
    this is the shape a refusal keyed to a raise being written inside a `trap` body would break.
    """

    def test_a_raising_cast_in_the_body_of_a_trap_no_raise_triggers_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            trap {{
              {_HANDLER}
              {_RAISE}
              {_FOLLOWER}
            }}
            {_ANCHOR}
        """, F"""
            trap {{
              {_HANDLER}
              {_FOLLOWER}
            }}
            {_ANCHOR}
        """)


class TestPs1AFiringTrapBodyRaiseDependsOnWhichBlockFiresTheTrap(_Ps1FaultEscalation):
    """
    A `trap` in a named block is fired only by a raise in that same block. A raise in the body of a
    `process`-block `trap` ends the function where the `process` block itself holds a raiser that
    fires the `trap`, so it is kept; a raiser in `begin` fires nothing in `process`, so the same
    body raise is dead and removable. Which block fires the `trap` is the whole of what decides it.
    """

    def test_a_process_block_trap_body_raise_a_process_raiser_fires_is_kept(self):
        self._assertKept(F"""
            function Invoke-Thing {{
              process {{
                trap {{
                  {_HANDLER}
                  {_RAISE}
                  {_FOLLOWER}
                }}
                {_STOPPING_RAISE}
              }}
            }}
            Invoke-Thing
        """)

    def test_a_process_block_trap_body_raise_a_begin_raiser_never_fires_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            function Invoke-Thing {{
              begin {{
                {_STOPPING_RAISE}
              }}
              process {{
                trap {{
                  {_HANDLER}
                  {_RAISE}
                  {_FOLLOWER}
                }}
              }}
            }}
            Invoke-Thing
        """, F"""
            function Invoke-Thing {{
              begin {{
                {_STOPPING_RAISE}
              }}
              process {{
                trap {{
                  {_HANDLER}
                  {_FOLLOWER}
                }}
              }}
            }}
            Invoke-Thing
        """)


class TestPs1ABindingFailureFiringATrapBodyIsAKnownUnsoundDelete(_Ps1FaultEscalation):
    """
    A parameter-binding failure is a terminating error that fires a `trap` with no `-ErrorAction
    Stop` anywhere, so a raise in the fired `trap`'s body ends the scope and is live — on 5.1 the
    script exits non-zero having run only the handler. The firing gate counts a cast, a fallible
    operator, a method call, a `throw` or a `Stop`-terminated command, not a plain command that
    terminates on its own, so it reads the `trap` as not firing and deletes the body raise. Counting
    a plain command would regress `TestPs1ATrapBodyNothingTriggersLeavesTheRaiseInItRemovable`; the
    fix needs an open-world command-firing notion.
    """

    @unittest.expectedFailure
    def test_a_trap_body_raise_a_binding_failure_fires_is_kept(self):
        self._assertKept(F"""
            trap {{
              {_HANDLER}
              {_RAISE}
              {_FOLLOWER}
            }}
            {_BINDING_FAILURE_RAISE}
            {_ANCHOR}
        """)


class TestPs1AStrictModeMemberFiringATrapBodyIsAKnownUnsoundDelete(_Ps1FaultEscalation):
    """
    Under `Set-StrictMode` a member access on `$Null` raises a statement-terminating error that
    fires a `trap`, so a raise in the fired body is live — on 5.1 the script exits non-zero having
    run only the handler. `is_soft_error_source` excludes member and index access by design, since
    only strict mode makes them fault and the firing gate does not read that arming, so it reads the
    `trap` as not firing and deletes the body raise.
    """

    @unittest.expectedFailure
    def test_a_trap_body_raise_a_strict_mode_member_fires_is_kept(self):
        self._assertKept(F"""
            Set-StrictMode -Version Latest
            trap {{
              {_HANDLER}
              {_RAISE}
              {_FOLLOWER}
            }}
            {_STRICT_MEMBER_RAISE}
            {_ANCHOR}
        """)


class TestPs1AStrictModeUnsetVariableFiringATrapBodyIsAKnownUnsoundDelete(_Ps1FaultEscalation):
    """
    Under `Set-StrictMode` a read of a never-set variable raises a statement-terminating error that
    fires a `trap`, so a raise in the fired body is live — on 5.1 the script exits non-zero having
    run only the handler. `is_soft_error_source` counts no bare variable read, and the firing gate
    does not read the strict-mode arming, so it reads the `trap` as not firing and deletes the body
    raise. This is the same strict-mode family as
    `TestPs1AStrictModeMemberFiringATrapBodyIsAKnownUnsoundDelete`; a never-set read is the spelling
    that class's `member and index access` wording leaves out.
    """

    @unittest.expectedFailure
    def test_a_trap_body_raise_a_strict_mode_unset_variable_read_fires_is_kept(self):
        self._assertKept(F"""
            Set-StrictMode -Version Latest
            trap {{
              {_HANDLER}
              {_RAISE}
              {_FOLLOWER}
            }}
            {_STRICT_UNSET_VAR_RAISE}
            {_ANCHOR}
        """)


class TestPs1ATrapTakesTheErrorsOfTheNamedBlockItIsWrittenIn(_Ps1FaultEscalation):
    """
    An advanced function splits its body across `begin`, `process`, `end` and `dynamicparam`
    blocks, and a `trap` guards the named block it is written in. A raise in the same named block
    as a live `trap` is what makes that `trap` run, and execution then resumes at the next statement
    of that block, so both the raise and what follows it survive.
    """

    def test_a_raising_cast_beside_a_live_trap_in_the_same_process_block_is_kept(self):
        self._assertKept(F"""
            function Invoke-Thing {{
              process {{
                trap {{ {_HANDLER} }}
                {_RAISE}
                {_FOLLOWER}
              }}
            }}
            Invoke-Thing
        """)

    def test_a_raising_cast_beside_a_live_trap_in_the_same_begin_block_is_kept(self):
        self._assertKept(F"""
            function Invoke-Thing {{
              begin {{
                trap {{ {_HANDLER} }}
                {_RAISE}
                {_FOLLOWER}
              }}
              process {{
                {_ANCHOR}
              }}
            }}
            Invoke-Thing
        """)


class TestPs1ATrapInAnotherNamedBlockLeavesTheRaiseRemovable(_Ps1FaultEscalation):
    """
    The same `trap`, written in a named block other than the one that raises, is never offered the
    error: the raise in the `process` block is reported, that block carries on to its next
    statement, and the `trap` written in `begin` does not run. The script runs the same code with
    the raise as without it and the raise may go; writing that same `trap` in the block that raises
    is the whole of what makes it stay.
    """

    def test_a_raising_cast_in_the_process_block_a_begin_block_trap_never_sees_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            function Invoke-Thing {{
              begin {{
                trap {{ {_HANDLER} }}
              }}
              process {{
                {_RAISE}
                {_FOLLOWER}
              }}
            }}
            Invoke-Thing
        """, F"""
            function Invoke-Thing {{
              begin {{
                trap {{ {_HANDLER} }}
              }}
              process {{
                {_FOLLOWER}
              }}
            }}
            Invoke-Thing
        """)


class TestPs1ATrapInAFunctionOutlivesTheRaiseWhereAHandlerMayGuardTheCall(_Ps1FaultEscalation):
    """
    An error that gets past a function's own handlers is the caller's, so a `trap` written in a
    function decides what a `try` around the *call* sees. Measured on 5.1: the function below runs
    to its end with the `trap` written in it, and hands the error to the `catch` around the call
    without it, so the two scripts write different things to the host.

    The raise itself may go either way: the `trap` takes it and the statement after it runs whether
    or not it is written, which is what makes the `trap` the whole of what is at stake here.
    """

    def test_a_trap_in_a_function_a_guarded_call_reaches_is_kept(self):
        self._assertDeobfuscatesTo(F"""
            function Invoke-Thing {{
              trap {{ continue }}
              {_RAISE}
              {_FOLLOWER}
            }}
            try {{
              Invoke-Thing
            }} catch {{
              {_HANDLER}
            }}
        """, F"""
            function Invoke-Thing {{
              trap {{ continue }}
              {_FOLLOWER}
            }}
            try {{
              Invoke-Thing
            }} catch {{
              {_HANDLER}
            }}
        """)

    def test_the_same_trap_is_removed_where_the_script_holds_no_handler_at_all(self):
        self._assertDeobfuscatesTo(F"""
            function Invoke-Thing {{
              trap {{ continue }}
              {_RAISE}
              {_FOLLOWER}
            }}
            Invoke-Thing
            {_ANCHOR}
        """, F"""
            function Invoke-Thing {{
              {_FOLLOWER}
            }}
            Invoke-Thing
            {_ANCHOR}
        """)


class TestPs1ACommandToldToStopMakesItsErrorEndTheScript(_Ps1FaultEscalation):
    """
    `-ErrorAction Stop` makes every error a command reports a terminating one, so a `trap` over such
    a command is the whole reason the script survives it: without the handler, nothing written after
    the command runs. Measured on 5.1 — `Get-Item nope -ErrorAction Stop; Write-Host 'after'` writes
    nothing and exits non-zero, and the same script under `trap { continue }` writes `after`.

    That is the disposition `throw` decides, reached by a different spelling, which is why both are
    asked of the fault model rather than of a search for the keyword.
    """

    def test_a_trap_that_continues_over_a_command_told_to_stop_is_kept(self):
        self._assertKept(F"""
            trap {{ continue }}
            {_STOPPING_RAISE}
            {_FOLLOWER}
        """)

    def test_an_empty_trap_over_a_command_told_to_stop_is_kept(self):
        self._assertKept(F"""
            trap {{}}
            {_STOPPING_RAISE}
            {_FOLLOWER}
        """)

    def test_a_trap_over_a_command_told_to_stop_inside_a_branch_is_kept(self):
        self._assertKept(F"""
            trap {{ continue }}
            if ({_OPAQUE}) {{
              {_STOPPING_RAISE}
            }}
            {_FOLLOWER}
        """)

    def test_a_trap_over_a_command_told_to_continue_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            trap {{ continue }}
            Get-Item nope -ErrorAction Continue
            {_FOLLOWER}
        """, F"""
            Get-Item nope -ErrorAction Continue
            {_FOLLOWER}
        """)


class TestPs1ADiscardedCommandToldToStopIsKeptWithNoHandler(_Ps1FaultEscalation):
    """
    `-ErrorAction Stop` ends the script whether or not a handler is written over the command, so a
    discarded stopping command with no `trap` and no `catch` anywhere is still kept: deleting it
    starts running everything after the command that the terminating error stopped. This is the
    forward reading of the termination `TestPs1ACommandToldToStopMakesItsErrorEndTheScript` reads on
    the transpose, and the same resuming action is the control that the discard otherwise goes.
    """

    def test_a_discarded_command_told_to_stop_with_no_handler_is_kept(self):
        self._assertKept(F"""
            $Null = {_STOPPING_RAISE}
            {_FOLLOWER}
        """)

    def test_a_discarded_command_told_to_continue_with_no_handler_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            $Null = Get-Item nope -ErrorAction Continue
            {_FOLLOWER}
        """, _FOLLOWER)


class TestPs1AnExitIsNoRaiseAnyTrapDisposesOf(_Ps1FaultEscalation):
    """
    `exit` ends the script too, and by an exception no `trap` catches: `trap { 'T' }; exit 3` writes
    neither `T` nor anything else. A `trap` written over one therefore intercepts nothing and stays
    removable, which is what holds the rule to *errors that end the script* rather than to
    *statements that end it*.
    """

    def test_a_trap_over_an_exit_in_a_branch_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            trap {{ continue }}
            if ({_OPAQUE}) {{
              exit 3
            }}
            {_FOLLOWER}
        """, F"""
            if ({_OPAQUE}) {{
              exit 3
            }}
            {_FOLLOWER}
        """)


class TestPs1AStopPreferenceMakesEveryTrapLoadBearing(_Ps1FaultEscalation):
    """
    Under `$ErrorActionPreference = 'Stop'` even an implicit terminating error ends the script —
    measured: `$ErrorActionPreference = 'Stop'; [int]'a'; Write-Host 'after'` writes nothing. A
    `trap` is then what the script survives on whatever the raise was, so the handler outlives the
    raise that `TestPs1AStopPreferenceMakesTheRaiseEndTheScript` still records as removed.
    """

    def test_a_trap_under_a_stop_preference_outlives_the_raise_it_guards(self):
        self._assertDeobfuscatesTo(F"""
            $ErrorActionPreference = 'Stop'
            trap {{ continue }}
            {_RAISE}
            {_FOLLOWER}
        """, F"""
            $ErrorActionPreference = 'Stop'
            trap {{ continue }}
            {_FOLLOWER}
        """)


class TestPs1ATrapIsRemovedOverAnErrorTheScriptItselfSurvives(_Ps1FaultEscalation):
    """
    An implicit terminating error nothing handles at script scope is reported and the next statement
    runs, so at script scope an inert `trap` over one disposes of it exactly as no handler would and
    is removable. That reading holds only while nothing *outside* the script is guarding it, and
    these are the shapes where it does not: 5.1 hands a statement-terminating error to a `catch`
    anywhere up the call stack, so a script dot-sourced inside a `try` — which is how this suite's
    own 5.1 oracle runs every snippet, and what `iex` and `&` do to a payload — writes `after` with
    the `trap` and does not write it without.

    Keeping the handler closes that, and costs the injected-noise `trap` that
    `refinery.lib.scripts.ps1.deobfuscation.deadcode.Ps1DeadCodeElimination._prune_trap` exists to
    drop: nothing distinguishes a block holding `Write-Host 'keep'` from one holding a raise. The
    same scripts are carried by `BEHAVIOUR_DEFECTS` in `test_oracle.py`, which reaches the verdict
    by running both versions on a real host rather than by reading the tree.
    """

    @unittest.expectedFailure
    def test_a_trap_that_continues_over_an_implicit_terminating_error_is_kept(self):
        self._assertKept(F"""
            trap {{ continue }}
            {_RAISE}
            {_FOLLOWER}
        """)

    @unittest.expectedFailure
    def test_an_empty_trap_over_an_implicit_terminating_error_is_kept(self):
        self._assertKept(F"""
            trap {{}}
            {_RAISE}
            {_FOLLOWER}
        """)


class TestPs1EverySpellingOfTheStopActionMakesTheTrapOverItLoadBearing(_Ps1FaultEscalation):
    """
    `-ErrorAction` takes a `[System.Management.Automation.ActionPreference]`, of which `Stop` is the
    member whose ordinal is 1. Windows PowerShell 5.1 binds that member from its name, from any
    abbreviation of the name that no other member of the set answers to, and from any integer
    spelling of the ordinal. Each script below is therefore the one
    `TestPs1ACommandToldToStopMakesItsErrorEndTheScript` measures, written differently, and the
    `trap` is what each of them survives on: without the handler nothing after the command runs.
    """

    def _assertTheTrapOverTheActionIsKept(self, action: str) -> None:
        self._assertKept(F"""
            trap {{ continue }}
            Get-Item nope -ErrorAction {action}
            {_FOLLOWER}
        """)

    def test_the_member_name_selects_stop_however_it_is_cased_or_quoted(self):
        for action in ['Stop', 'stop', 'STOP', "'Stop'", '"Stop"']:
            with self.subTest(action):
                self._assertTheTrapOverTheActionIsKept(action)

    def test_an_abbreviation_no_other_member_answers_to_selects_stop(self):
        for action in ['St', 'Sto']:
            with self.subTest(action):
                self._assertTheTrapOverTheActionIsKept(action)

    def test_the_ordinal_of_stop_selects_it_however_the_integer_is_spelled(self):
        for action in ['1', '01', '0x1']:
            with self.subTest(action):
                self._assertTheTrapOverTheActionIsKept(action)


class TestPs1EverySpellingOfTheErrorActionParameterCarriesTheStopItIsGiven(_Ps1FaultEscalation):
    """
    Windows PowerShell 5.1 binds a parameter by any prefix of its name that no other parameter of
    the command answers to, `-EA` is the documented alias of `-ErrorAction`, and an argument may be
    attached to the parameter with a colon rather than written beside it. Each spelling below hands
    the command the same `Stop` the written-out name does, so each ends the script over the error
    the command reports and each leaves the `trap` load bearing. Each is also *spelled out* by the
    deobfuscation — the abbreviation expansion writes the parameter every spelling binds — so the
    expected output names it in full.
    """

    def _assertTheTrapOverTheCommandIsKept(self, command: str, expected: str) -> None:
        self._assertDeobfuscatesTo(F"""
            trap {{ continue }}
            {command}
            {_FOLLOWER}
        """, F"""
            trap {{ continue }}
            {expected}
            {_FOLLOWER}
        """)

    def _assertTheTrapOverTheParameterIsKept(self, parameter: str) -> None:
        self._assertTheTrapOverTheCommandIsKept(
            F'Get-Item nope {parameter} Stop',
            'Get-Item nope -ErrorAction Stop',
        )

    def test_a_prefix_no_other_parameter_answers_to_binds_the_action(self):
        for parameter in ['-ErrorAction', '-erroraction', '-ErrorActio', '-ErrorAc', '-ErrorA']:
            with self.subTest(parameter):
                self._assertTheTrapOverTheParameterIsKept(parameter)

    def test_the_documented_alias_of_the_parameter_binds_the_action(self):
        for parameter in ['-EA', '-ea']:
            with self.subTest(parameter):
                self._assertTheTrapOverTheParameterIsKept(parameter)

    def test_an_action_attached_to_the_parameter_with_a_colon_binds_it(self):
        for command in [
            'Get-Item nope -ErrorAction:Stop',
            'Get-Item nope -EA:Stop',
        ]:
            with self.subTest(command):
                self._assertTheTrapOverTheCommandIsKept(
                    command, 'Get-Item nope -ErrorAction:Stop',
                )


class TestPs1EverySpellingOfAnActionOtherThanStopLeavesTheTrapRemovable(_Ps1FaultEscalation):
    """
    Every member of the set other than `Stop` leaves what the command reports non-terminating, so no
    `trap` is offered it and the statement after the command runs whether the handler is written or
    not. These are the shapes a reading keyed to `-ErrorAction` being given at all, or to the
    argument being one it cannot name, would break.
    """

    def _assertTheTrapOverTheCommandIsRemoved(self, command: str, expected: str | None = None) -> None:
        expected = command if expected is None else expected
        self._assertDeobfuscatesTo(F"""
            trap {{ continue }}
            {command}
            {_FOLLOWER}
        """, F"""
            {expected}
            {_FOLLOWER}
        """)

    def _assertTheTrapOverTheActionIsRemoved(self, action: str) -> None:
        self._assertTheTrapOverTheCommandIsRemoved(F'Get-Item nope -ErrorAction {action}')

    def test_a_member_name_other_than_stop_leaves_the_trap_removable(self):
        for action in ['Continue', 'SilentlyContinue', 'Ignore']:
            with self.subTest(action):
                self._assertTheTrapOverTheActionIsRemoved(action)

    def test_an_abbreviation_of_a_member_other_than_stop_leaves_the_trap_removable(self):
        for action in ['Cont', 'Sil', 'Ig']:
            with self.subTest(action):
                self._assertTheTrapOverTheActionIsRemoved(action)

    def test_the_ordinal_of_a_member_other_than_stop_leaves_the_trap_removable(self):
        for action in ['0', '2', '4', '0x2']:
            with self.subTest(action):
                self._assertTheTrapOverTheActionIsRemoved(action)

    def test_a_member_other_than_stop_attached_with_a_colon_leaves_the_trap_removable(self):
        commands = ['Get-Item nope -ErrorAction:Continue', 'Get-Item nope -EA:SilentlyContinue']
        expected = [
            'Get-Item nope -ErrorAction:Continue',
            'Get-Item nope -ErrorAction:SilentlyContinue',
        ]
        for command, spelled in zip(commands, expected):
            with self.subTest(command):
                self._assertTheTrapOverTheCommandIsRemoved(command, spelled)


class TestPs1AnActionThatArrivesBySplattingIsTheActionTheCommandRunsUnder(_Ps1FaultEscalation):
    """
    Splatting binds parameters out of a hashtable, so the same `-ErrorAction` reaches the command
    without being written beside it. The two scripts below differ only in the member the table
    carries, and Windows PowerShell 5.1 runs each of them exactly as it runs that member written at
    the call site: the command ends the script under `Stop`, and reports and resumes under
    `Continue`. The `trap` is therefore load bearing in the first and dead in the second.

    Only the first is answered. A splat names a table computed at run time, and
    `refinery.lib.scripts.ps1.analysis.faults` reads every argument it cannot compute as `Stop` —
    the same reading it gives `Get-Item nope -ErrorAction $x`, whose `$x` a write above may equally
    settle. So the first passes by that conservatism rather than by reading the table, and the
    second is what records the cost of it. Retiring the pin means giving the fault model a reading
    of the value, not narrowing the splat.
    """

    def test_a_table_that_carries_stop_makes_the_trap_load_bearing(self):
        self._assertKept(F"""
            trap {{ continue }}
            $p = @{{ErrorAction = 'Stop'}}
            Get-Item nope @p
            {_FOLLOWER}
        """)

    @unittest.expectedFailure
    def test_a_table_that_carries_continue_leaves_the_trap_removable(self):
        self._assertDeobfuscatesTo(F"""
            trap {{ continue }}
            $p = @{{ErrorAction = 'Continue'}}
            Get-Item nope @p
            {_FOLLOWER}
        """, F"""
            $p = @{{ErrorAction = 'Continue'}}
            Get-Item nope @p
            {_FOLLOWER}
        """)


class TestPs1EverySpellingOfTheStopPreferenceMakesTheTrapUnderItLoadBearing(_Ps1FaultEscalation):
    """
    `$ErrorActionPreference = 'Stop'` makes every error a command reports terminating, and it is the
    same write however the target is spelled and however `Stop` is named. The command below then
    ends the script, so the `trap` is the whole reason the statement after it runs, exactly as it is
    under the canonical spelling `TestPs1AStopPreferenceMakesEveryTrapLoadBearing` measures. The
    same command written under none of these reports a non-terminating error no `trap` is offered,
    which is what `TestPs1AWriteThatArmsNoStopLeavesTheTrapRemovable` records.
    """

    def _assertTheTrapUnderTheWriteIsKept(self, assignment: str) -> None:
        self._assertKept(F"""
            {assignment}
            trap {{ continue }}
            {_UNSPECIFIED_RAISE}
            {_FOLLOWER}
        """)

    def test_a_plain_write_of_the_preference_arms_every_error(self):
        self._assertTheTrapUnderTheWriteIsKept("$ErrorActionPreference = 'Stop'")

    def test_a_type_constrained_write_of_the_preference_arms_every_error(self):
        self._assertTheTrapUnderTheWriteIsKept("[string]$ErrorActionPreference = 'Stop'")

    def test_a_parenthesized_write_of_the_preference_arms_every_error(self):
        self._assertTheTrapUnderTheWriteIsKept("($ErrorActionPreference) = 'Stop'")

    def test_a_multiple_assignment_that_names_the_preference_arms_every_error(self):
        self._assertTheTrapUnderTheWriteIsKept("$a, $ErrorActionPreference = 1, 'Stop'")

    def test_a_scope_qualified_write_of_the_preference_arms_every_error(self):
        self._assertTheTrapUnderTheWriteIsKept("$global:ErrorActionPreference = 'Stop'")

    def test_the_ordinal_of_stop_written_to_the_preference_arms_every_error(self):
        self._assertTheTrapUnderTheWriteIsKept('$ErrorActionPreference = 1')


class TestPs1AWriteThatArmsNoStopLeavesTheTrapRemovable(_Ps1FaultEscalation):
    """
    A preference set to a member other than `Stop` leaves what the command reports non-terminating,
    so the script carries on to the next statement whether the `trap` is written or not and the
    handler may go, exactly as it may with nothing written above the command at all. These are the
    shapes a reading keyed to the preference being assigned at all would break.
    """

    def _assertTheTrapUnderTheWriteIsRemoved(self, assignment: str) -> None:
        self._assertDeobfuscatesTo(F"""
            {assignment}
            trap {{ continue }}
            {_UNSPECIFIED_RAISE}
            {_FOLLOWER}
        """, F"""
            {assignment}
            {_UNSPECIFIED_RAISE}
            {_FOLLOWER}
        """)

    def test_a_trap_over_a_command_no_write_arms_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            trap {{ continue }}
            {_UNSPECIFIED_RAISE}
            {_FOLLOWER}
        """, F"""
            {_UNSPECIFIED_RAISE}
            {_FOLLOWER}
        """)

    def test_a_preference_set_to_continue_arms_nothing(self):
        self._assertTheTrapUnderTheWriteIsRemoved("$ErrorActionPreference = 'Continue'")

    def test_a_preference_set_to_the_ordinal_of_continue_arms_nothing(self):
        self._assertTheTrapUnderTheWriteIsRemoved('$ErrorActionPreference = 2')


class TestPs1ATerminatingErrorReachedThroughACallIsInvisible(_Ps1FaultEscalation):
    """
    Measured on 5.1: a `throw` in a called function ends the script, and a `trap` in the calling
    body takes it and resumes — `function Raise { throw 'e' }` under a `Wrap` that traps writes
    `in` and then `after`, and the same pair without the handler writes nothing at all.

    What reaches the handler is the *call*, and `ends_the_script` reads only the subtree of what
    reaches it, so the `throw` in the callee is behind a body boundary no graph here crosses.
    Answering it needs the call graph, which `refinery.lib.scripts.ps1.analysis.faults` has none of
    by design.
    """

    @unittest.expectedFailure
    def test_a_trap_over_a_call_to_a_function_that_throws_is_kept(self):
        self._assertKept(F"""
            function Invoke-Raise {{
              throw 'e'
            }}
            function Invoke-Wrapper {{
              trap {{ continue }}
              Invoke-Raise
              {_FOLLOWER}
            }}
            Invoke-Wrapper
            {_ANCHOR}
        """)


class TestPs1ATerminatingErrorInsideAStringThatIsRunIsInvisible(_Ps1FaultEscalation):
    """
    A command that runs a string raises whatever the string raises — measured:
    `trap { continue }; iex 'throw 1'; Write-Host 'after'` writes `after`, and the same script
    without the handler writes nothing.

    Nothing in the statement's subtree is a `throw`, so the handler is judged removable, and a later
    round inlines the string, materialises the `throw` the earlier round answered False for, and
    drops everything after it as unreachable. Recognising it needs the command name resolved against
    the world, which is a layer above this one.
    """

    @unittest.expectedFailure
    def test_a_trap_over_a_string_that_is_run_and_throws_is_kept(self):
        self._assertKept(F"""
            trap {{ continue }}
            iex 'throw 1'
            {_FOLLOWER}
        """)


class TestPs1AStopPreferenceACmdletArmsMakesEveryErrorTerminating(_Ps1FaultEscalation):
    """
    `New-Variable ErrorActionPreference Stop -Force` writes the preference exactly as the assignment
    does, so it escalates every error and not only what a command reports: the bare cast below is
    stepped over with the handler and ends the script without it, so the `trap` is the whole reason
    the statement after it runs. `_writes_stop_to_the_preference` reads the write through the name
    authority `refinery.lib.scripts.ps1.analysis.naming.named_references`, which is why the
    preference is armed here and not only when it is assigned to.

    A raise that is a bare cast rather than a stored one is the witness: it makes the kept `trap`
    turn on the preference escalating a *cast*, which a default-table `Stop` — reaching commands
    only — does not do, and it is not dropped as a dead store the way `$Null = ...` is.
    """

    def test_a_trap_under_a_preference_a_cmdlet_arms_is_kept(self):
        self._assertKept(F"""
            New-Variable ErrorActionPreference Stop -Force
            trap {{ continue }}
            {_BARE_CAST_RAISE}
            {_FOLLOWER}
        """)

    def test_a_cmdlet_that_writes_a_member_other_than_stop_leaves_the_trap_removable(self):
        self._assertDeobfuscatesTo(F"""
            New-Variable ErrorActionPreference Continue -Force
            trap {{ continue }}
            {_UNSPECIFIED_RAISE}
            {_FOLLOWER}
        """, F"""
            New-Variable ErrorActionPreference Continue -Force
            {_UNSPECIFIED_RAISE}
            {_FOLLOWER}
        """)


class TestPs1AStopBoundThroughDefaultParameterValuesMakesCommandsTerminating(_Ps1FaultEscalation):
    """
    `$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'` binds the action into every command that
    takes one, so the command below ends the script although no action is written beside it and no
    preference is assigned — measured: `after` is written with the handler and nothing without it.
    `_writes_stop_to_the_default_table` reads the index-assignment and the `.Add` mutation, keyed on
    a `:ErrorAction` suffix so a command-scoped entry arms it as the wildcard does.

    The arming reaches commands only — a failing cast takes no parameter and stays stepped over —
    so it is read on the per-command terminating path rather than the whole-script preference gate,
    which `TestPs1TheDefaultTableTerminatesACommandButNotACast` pins at the model.
    """

    def _assertTheTrapUnderTheDefaultIsKept(self, write: str) -> None:
        self._assertKept(F"""
            {write}
            trap {{ continue }}
            {_UNSPECIFIED_RAISE}
            {_FOLLOWER}
        """)

    def test_an_index_assignment_of_stop_binds_the_action(self):
        self._assertTheTrapUnderTheDefaultIsKept(
            "$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'")

    def test_a_command_scoped_key_binds_the_action(self):
        self._assertTheTrapUnderTheDefaultIsKept(
            "$PSDefaultParameterValues['Get-Item:ErrorAction'] = 'Stop'")

    def test_the_add_mutation_of_stop_binds_the_action(self):
        self._assertTheTrapUnderTheDefaultIsKept(
            "$PSDefaultParameterValues.Add('*:ErrorAction', 'Stop')")

    def test_an_alias_key_binds_the_action(self):
        self._assertTheTrapUnderTheDefaultIsKept(
            "$PSDefaultParameterValues['*:ea'] = 'Stop'")

    def test_a_member_assignment_of_stop_binds_the_action(self):
        self._assertTheTrapUnderTheDefaultIsKept(
            "$PSDefaultParameterValues.'*:ErrorAction' = 'Stop'")

    def test_a_default_that_binds_a_member_other_than_stop_leaves_the_trap_removable(self):
        self._assertDeobfuscatesTo(F"""
            $PSDefaultParameterValues['*:ErrorAction'] = 'Continue'
            trap {{ continue }}
            {_UNSPECIFIED_RAISE}
            {_FOLLOWER}
        """, F"""
            $PSDefaultParameterValues['*:ErrorAction'] = 'Continue'
            {_UNSPECIFIED_RAISE}
            {_FOLLOWER}
        """)


class TestPs1AStopArmingTheRemovalGateStillMisses(_Ps1FaultEscalation):
    """
    Five shapes arm a `Stop` the removal gate does not read, so a `trap` that is load bearing on
    the 5.1 host is dropped. Each is measured on the host — the guarded raise ends the script
    without the handler and the follower runs with it — and each reaches the gate through a
    spelling it does not resolve: a splat table, a `-LiteralPath` the name authority reads no
    subject from, a whole-table literal, an aliased copy, or a computed member name.

    The wide completion-side gate `a_stop_may_be_in_force` catches all five — every one names
    `ErrorActionPreference` or `PSDefaultParameterValues` as a string — so a value the arming would
    have established is not folded across the raise. What is not caught is the narrower removal of
    the handler, which is what these pin.
    """

    @unittest.expectedFailure
    def test_a_splatted_write_of_the_preference_keeps_the_trap(self):
        self._assertKept(F"""
            $t = @{{ Name = 'ErrorActionPreference'; Value = 'Stop' }}
            Set-Variable @t
            & {{
              trap {{ continue }}
              {_BARE_CAST_RAISE}
              {_FOLLOWER}
            }}
        """)

    @unittest.expectedFailure
    def test_a_literal_path_write_of_the_preference_keeps_the_trap(self):
        self._assertKept(F"""
            Set-Item -LiteralPath Variable:ErrorActionPreference Stop
            trap {{ continue }}
            {_BARE_CAST_RAISE}
            {_FOLLOWER}
        """)

    @unittest.expectedFailure
    def test_a_whole_table_replacement_that_binds_the_action_keeps_the_trap(self):
        self._assertKept(F"""
            $PSDefaultParameterValues = @{{ '*:ErrorAction' = 'Stop' }}
            trap {{ continue }}
            {_UNSPECIFIED_RAISE}
            {_FOLLOWER}
        """)

    @unittest.expectedFailure
    def test_an_aliased_table_that_binds_the_action_keeps_the_trap(self):
        self._assertKept(F"""
            $x = $PSDefaultParameterValues
            $x['*:ErrorAction'] = 'Stop'
            trap {{ continue }}
            {_UNSPECIFIED_RAISE}
            {_FOLLOWER}
        """)

    @unittest.expectedFailure
    def test_a_computed_member_mutation_of_the_default_table_keeps_the_trap(self):
        self._assertKept(F"""
            $n = 'Add'
            $PSDefaultParameterValues.$n('*:ErrorAction', 'Stop')
            trap {{ continue }}
            {_UNSPECIFIED_RAISE}
            {_FOLLOWER}
        """)


class TestPs1AnAmbiguousActionPrefixKeepsTheTrapOverIt(_Ps1FaultEscalation):
    """
    `-ErrorAction S` reaches `SilentlyContinue`, `Stop` and `Suspend` alike, and 5.1 answers it with
    a `ParameterBindingException` rather than a choice — measured as
    `CannotConvertArgumentNoMessage`. That error is statement-terminating, so the command never runs
    and the script carries on with or without a handler, which makes the `trap` removable.

    It is kept, because an argument that may be `Stop` is read as `Stop`. The cost is recall and the
    direction is safe; what would retire this is a reading of the member set precise enough to call
    the prefix ambiguous, which is a different question from the one the gate asks.
    """

    @unittest.expectedFailure
    def test_a_trap_over_a_command_whose_action_prefix_is_ambiguous_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            trap {{ continue }}
            Get-Item nope -ErrorAction S
            {_FOLLOWER}
        """, F"""
            Get-Item nope -ErrorAction S
            {_FOLLOWER}
        """)


class TestPs1AThrowInsideAnUninvokedBlockKeepsTheTrapBesideIt(_Ps1FaultEscalation):
    """
    Storing a script block runs nothing — measured: `$s = { throw 'x' }` beside a failing cast
    writes `after` whether a `trap` is written above it or not, so the handler is removable.

    `ends_the_script` reads the whole subtree of every statement that reaches the handler, and a
    stored block is part of that subtree, so the `throw` inside one is read as a raise the handler
    survives. The docstring calls the width deliberate — a `throw` in a body written inside a
    statement does run once something calls it — and this is what the width costs.
    """

    @unittest.expectedFailure
    def test_a_trap_beside_a_stored_block_that_throws_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            trap {{ continue }}
            $s = {{ throw 'x' }}
            {_RAISE}
            {_FOLLOWER}
        """, F"""
            $s = {{ throw 'x' }}
            {_FOLLOWER}
        """)
