from __future__ import annotations

import inspect
import unittest

from unittest.mock import patch

from refinery.lib.scripts.ps1.analysis import faults
from refinery.lib.scripts.ps1.analysis.cfg import build_control_flow_model
from refinery.lib.scripts.ps1.analysis.world import measure_world
from refinery.lib.scripts.ps1.analysis.worldflow import build_world_reach
from refinery.lib.scripts.ps1.parser import Ps1Parser

from test.lib.scripts.ps1.deobfuscation import TestPs1

#: A discarded conversion that Windows PowerShell 5.1 answers with a terminating error: `[Int]'abc'`
#: has no conversion, and the assignment to `$Null` means nothing observes a value it never makes.
#: It emits nothing and mutates nothing, which is exactly what makes a cleanup pass want to drop it.
_RAISE = "$Null = [Int]'abc'"

#: A second spelling of the same fault, so that no claim below rests on the cast in particular.
_RAISE_DIV = '$Null = 1/0'

#: The same two faults on operands the analysis cannot read, so each is a *possible* terminating
#: error rather than a proven one. A proven throw directly in a `try` body is folded away with the
#: construct around it (`test_fault_escalation.TestPs1AProvenThrowFoldsTheTryConstruct`), so the veto
#: that keeps a raise a handler depends on is witnessed on a fault this removal pass still weighs.
_MAY_RAISE = '$Null = [Int]$env:FOO'
_MAY_RAISE_DIV = '$Null = 1 / $PID'

#: Statements that Windows PowerShell 5.1 runs to completion. Each is a discarded value that emits
#: nothing and mutates nothing, exactly like `_RAISE`, and differs from it only in raising no error
#: for a handler to observe. A pass that decides a removal by asking whether a statement can raise
#: therefore has to delete every one of these from the shapes in which it has to keep `_RAISE`.
#: They are spelled twelve different ways so that no such claim rests on one expression.
_QUIET_CAST = "$Null = [Int]'42'"
_QUIET_DIVISION = '$Null = 1/1'
_QUIET_PRODUCT = '$Null = 6 * 7'
_QUIET_LENGTH = "$Null = 'abcdef'.Length"
_QUIET_REMAINDER = '$Null = 10 % 3'
_QUIET_CHAR = '$Null = [Char]65'
_QUIET_CONCATENATION = "$Null = 'ab' + 'cd'"
_QUIET_STRING = '$Null = [String]12'
_QUIET_CONJUNCTION = '$Null = 3 -Band 1'
_QUIET_NEGATION = '$Null = -Not $True'
_QUIET_BOOL = "$Null = [Bool]'x'"
_QUIET_COUNT = '$Null = @(1, 2, 3).Count'

#: An acting statement that is never a removal candidate, so its survival says only that the pass
#: did not empty the script wholesale.
_ANCHOR = "Write-Host 'ANCHOR_SURVIVES'"

#: A handler body that writes to the host. Writing to the host is what makes a handler live, and a
#: live handler and an empty one are opposite licences rather than degrees of the same one.
_HANDLER = "Write-Host 'HANDLER_RAN'"

#: A `finally` body that writes to the host. It runs on the faulting and non-faulting path alike.
_CLEANUP = "Write-Host 'CLEANUP_RAN'"

#: A condition and an enumerable that the analysis cannot decide. One it could fold away would take
#: its body with it on its own merits, and a body that lost its only statement that way would say
#: nothing about the statement that used to be in it.
_OPAQUE = '$args'

#: A read of a variable the script never sets. Under the default semantics it yields `$null` and
#: raises nothing, so the statement around it runs to completion exactly like `_QUIET_CAST` does —
#: but no reading of the operands alone can say so, because the same read raises under strict mode.
#: Measured on 5.1 in `test.lib.scripts.ps1.corpus.BEHAVIOURS`.
_UNSET_READ = '[void]$zzqunset'

#: The same read written as a bare value on the output stream rather than as a discard, so that the
#: removal site reached through `StatementEffect.OUTPUT` is measured beside the one reached through
#: `DISCARD`. The two answer one question, and a script where they disagreed would delete the read
#: in one spelling and keep it in the other.
_UNSET_OUTPUT = '$zzqunset'

#: The same read as the head of a discarded pipeline, which is the shape an obfuscator emits and the
#: one no `_QUIET_` constant reaches: the graphs place the head in the block's own island, so the
#: fault question for it used to be refused for want of a position rather than answered.
_UNSET_PIPELINE = '$zzqunset | ForEach-Object { [void]$_ }'

#: What turns every read above into a raise, spelled as the command.
_STRICT = 'Set-StrictMode -Version 1'

#: The second command that arms it, which 5.1 documents as the first at version 1 and which writes
#: the global scope rather than the current one. Measured on 5.1 in
#: `test.lib.scripts.ps1.corpus.BEHAVIOURS`: the guarded read below it raises and the `catch` runs.
_STRICT_PSDEBUG = 'Set-PSDebug -Strict'

#: And spelled as a string handed to `Invoke-Expression`, which arms strict mode as surely.
_STRICT_IN_A_STRING = "Invoke-Expression 'Set-StrictMode -Version 1'"

#: A payload the analysis cannot read at all. It may arm strict mode without spelling the name
#: anywhere, so what it governs is not what the script says but what may have run before a position.
_UNREADABLE = 'Invoke-Expression $env:ZZQPAYLOAD'

#: A call that is never a removal candidate, so a `try` written around it survives into the output
#: as a handler the script demonstrably still contains.
_REQUEST = 'Invoke-WebRequest $u'


class TestPs1ARaisingStatementDirectlyInAGuardedTryBlockIsKept(TestPs1):
    """
    A `catch` clause with a body runs when the `try` block it belongs to raises a terminating error,
    so deleting the only statement that can raise means the handler no longer runs. The statement
    therefore survives, however little else there is to observe about it. The fault is a possible
    one rather than a proven one, because a proven throw here is folded into the handler with the
    construct around it rather than left for this veto to keep.
    """

    def test_a_raising_cast_directly_in_the_try_block_is_kept(self):
        self._assertKept(F"""
            try {{
              {_MAY_RAISE}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """)

    def test_a_raising_division_directly_in_the_try_block_is_kept(self):
        self._assertKept(F"""
            try {{
              {_MAY_RAISE_DIV}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """)


class TestPs1AStatementNestedInAGuardedTryBlock(TestPs1):
    """
    A `catch` clause observes an error raised anywhere inside its `try` block, not only one raised
    by a statement written directly in it. A branch body, a loop body, a `switch` case body and a
    scriptblock invoked in place with `&` are all inside the block, so a raising statement in any of
    them is one the handler depends on and none of them may be deleted.

    The deobfuscator used to recognize a handler only for a statement whose immediate holder was the
    `try` block itself. One nesting level was enough to hide the handler from it, so it deleted each
    of these and left behind a `catch` body that could no longer run.

    Every shape is written twice. The second of the pair puts a statement that runs to completion
    where the raising one stood: no handler can observe it, deleting it is the job, and the nesting
    must not save it either. The pair tells a pass that has found the handler apart from one that
    has merely stopped deleting.
    """

    def test_a_raising_cast_in_a_nested_if_body_is_kept(self):
        self._assertKept(F"""
            try {{
              if ({_OPAQUE}) {{ {_RAISE} }}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """)

    def test_a_quiet_cast_in_a_nested_if_body_is_removed(self):
        self._assertRemoved(F"""
            try {{
              if ({_OPAQUE}) {{ {_QUIET_CAST} }}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """, _QUIET_CAST)

    def test_a_raising_cast_in_a_nested_foreach_body_is_kept(self):
        self._assertKept(F"""
            try {{
              foreach ($i in {_OPAQUE}) {{ {_RAISE} }}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """)

    def test_a_quiet_product_in_a_nested_foreach_body_is_removed(self):
        self._assertRemoved(F"""
            try {{
              foreach ($i in {_OPAQUE}) {{ {_QUIET_PRODUCT} }}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """, _QUIET_PRODUCT)

    def test_a_raising_cast_in_a_nested_while_body_is_kept(self):
        self._assertKept(F"""
            try {{
              while ({_OPAQUE}) {{ {_RAISE} }}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """)

    def test_a_quiet_length_in_a_nested_while_body_is_removed(self):
        self._assertRemoved(F"""
            try {{
              while ({_OPAQUE}) {{ {_QUIET_LENGTH} }}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """, _QUIET_LENGTH)

    def test_a_raising_cast_in_a_nested_switch_case_body_is_kept(self):
        self._assertKept(F"""
            try {{
              switch ({_OPAQUE}) {{ 1 {{ {_RAISE} }} }}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """)

    def test_a_quiet_remainder_in_a_nested_switch_case_body_is_removed(self):
        self._assertRemoved(F"""
            try {{
              switch ({_OPAQUE}) {{ 1 {{ {_QUIET_REMAINDER} }} }}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """, _QUIET_REMAINDER)

    def test_a_raising_cast_in_a_scriptblock_invoked_in_place_is_kept(self):
        self._assertKept(F"""
            try {{
              & {{ {_RAISE} }}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """)

    def test_a_quiet_char_in_a_scriptblock_invoked_in_place_is_removed(self):
        self._assertRemoved(F"""
            try {{
              & {{ {_QUIET_CHAR} }}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """, _QUIET_CHAR)

    def test_a_raising_division_in_a_nested_if_body_is_kept(self):
        self._assertKept(F"""
            try {{
              if ({_OPAQUE}) {{ {_RAISE_DIV} }}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """)

    def test_a_quiet_division_in_a_nested_if_body_is_removed(self):
        self._assertRemoved(F"""
            try {{
              if ({_OPAQUE}) {{ {_QUIET_DIVISION} }}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """, _QUIET_DIVISION)


class TestPs1AStatementInAFunctionAGuardedTryBlockCalls(TestPs1):
    """
    A terminating error raised in a function reaches the `catch` clause guarding the call, so a
    function body is inside the `try` block for this purpose even though it is written outside it.

    The deobfuscator used to empty the function body, because the call site is what the `try` block
    holds and the raising statement is somewhere else entirely.

    A statement that runs to completion in that same function body reaches no handler at all, so
    emptying the body is the right answer for it and the two differ only in the raise.
    """

    def test_a_raising_cast_in_a_function_the_try_block_calls_is_kept(self):
        self._assertKept(F"""
            function Invoke-Thing {{
              {_RAISE}
            }}
            try {{
              Invoke-Thing
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """)

    def test_a_quiet_concatenation_in_a_function_the_try_block_calls_is_removed(self):
        self._assertRemoved(F"""
            function Invoke-Thing {{
              {_QUIET_CONCATENATION}
            }}
            try {{
              Invoke-Thing
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """, _QUIET_CONCATENATION)


class TestPs1AnEmptyCatchSwallowsSoTheRaisingStatementIsRemovable(TestPs1):
    """
    An empty `catch` swallows the error and lets execution resume after the construct, so a script
    whose `try` block holds only the raising statement runs on to the same next statement whether
    that statement is there or not. Removing it is then not observable and remains allowed.

    An empty inner `catch` swallows before any outer `catch` is offered the error, so it licenses
    the removal even when the script does contain a live handler — one wrapped around it, or one
    beside it. These are the shapes a refusal keyed to a handler appearing anywhere in the script
    would break.
    """

    def test_a_raising_cast_guarded_only_by_an_empty_catch_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            try {{ {_RAISE} }} catch {{ }}
            {_ANCHOR}
        """, _ANCHOR)

    def test_a_raising_cast_an_empty_inner_catch_shields_from_a_live_outer_catch_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            try {{
              try {{ {_RAISE} }} catch {{ }}
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

    def test_a_raising_cast_under_an_empty_catch_beside_a_live_catch_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            try {{ {_RAISE} }} catch {{ }}
            try {{ {_REQUEST} }} catch {{ {_HANDLER} }}
            {_ANCHOR}
        """, F"""
            try {{ {_REQUEST} }} catch {{ {_HANDLER} }}
            {_ANCHOR}
        """)


class TestPs1AFinallyAloneDoesNotGuardTheRaisingStatement(TestPs1):
    """
    A `finally` body runs on the faulting path and on the non-faulting path, so no removal can
    change whether it runs. A `try` with no `catch` clause therefore leaves the raising statement
    exactly as removable as it would be with no construct written around it at all.
    """

    def test_a_raising_cast_in_a_try_whose_only_clause_is_a_finally_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            try {{ {_RAISE} }} finally {{ {_CLEANUP} }}
            {_ANCHOR}
        """, F"""
            {_CLEANUP}
            {_ANCHOR}
        """)


class TestPs1AnInnerFinallyDoesNotShieldAnOuterCatch(TestPs1):
    """
    Because a `finally` does not swallow, the error raised under one goes on to the nearest
    enclosing `catch`, which here has a body. The raising statement is what makes that handler run
    and must survive.

    The deobfuscator used to read the inner `try` as unguarded, delete the raising statement, then
    dissolve the construct and hoist the `finally` body into the outer block, leaving a `catch`
    clause nothing reached.

    A statement that runs to completion under that same inner `finally` reaches no handler, so the
    whole sequence is the right answer for it and the two differ only in the raise.
    """

    def test_a_raising_cast_under_an_inner_finally_inside_a_live_outer_catch_is_kept(self):
        self._assertKept(F"""
            try {{
              try {{ {_RAISE} }} finally {{ {_CLEANUP} }}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """)

    def test_a_quiet_string_under_an_inner_finally_inside_a_live_outer_catch_is_removed(self):
        """
        An inner `try` whose block is empty runs its `finally` and nothing else, so the expected
        output is the construct gone with the cleanup standing in the outer block in its place.
        """
        self._assertDeobfuscatesTo(F"""
            try {{
              try {{ {_QUIET_STRING} }} finally {{ {_CLEANUP} }}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """, F"""
            try {{
              {_CLEANUP}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """)


class TestPs1ALiveTrapGuardsItsWholeScope(TestPs1):
    """
    A `trap` handles a terminating error raised anywhere in the statement block it is written in,
    whether it stands above the raising statement or below it, and whether the error is raised at
    the top of that block or inside a construct nested in it. A live `trap` over the raise makes the
    raising statement the reason the handler runs, so the statement survives.

    The deobfuscator used to consult no `trap` when it decided a removal. It deleted the raising
    statement in each of these and kept the `trap`, which was then a handler nothing could trigger.

    What a `trap` guards is the raise, so a statement that runs to completion gives it nothing to
    handle wherever in the block it stands. Every shape is written a second time with such a
    statement, which the pass must go on deleting.
    """

    def test_a_raising_cast_below_a_live_trap_in_the_same_scope_is_kept(self):
        self._assertKept(F"""
            trap {{ {_HANDLER} }}
            {_RAISE}
            {_ANCHOR}
        """)

    def test_a_quiet_conjunction_below_a_live_trap_in_the_same_scope_is_removed(self):
        self._assertRemoved(F"""
            trap {{ {_HANDLER} }}
            {_QUIET_CONJUNCTION}
            {_ANCHOR}
        """, _QUIET_CONJUNCTION)

    def test_a_raising_cast_above_a_live_trap_in_the_same_scope_is_kept(self):
        self._assertKept(F"""
            {_RAISE}
            trap {{ {_HANDLER} }}
            {_ANCHOR}
        """)

    def test_a_quiet_negation_above_a_live_trap_in_the_same_scope_is_removed(self):
        self._assertRemoved(F"""
            {_QUIET_NEGATION}
            trap {{ {_HANDLER} }}
            {_ANCHOR}
        """, _QUIET_NEGATION)

    def test_a_raising_cast_nested_in_a_scope_a_live_trap_guards_is_kept(self):
        self._assertKept(F"""
            trap {{ {_HANDLER} }}
            if ({_OPAQUE}) {{
              {_RAISE}
              {_ANCHOR}
            }}
        """)

    def test_a_quiet_bool_nested_in_a_scope_a_live_trap_guards_is_removed(self):
        self._assertRemoved(F"""
            trap {{ {_HANDLER} }}
            if ({_OPAQUE}) {{
              {_QUIET_BOOL}
              {_ANCHOR}
            }}
        """, _QUIET_BOOL)

    def test_a_raising_cast_in_a_function_scope_a_live_trap_guards_is_kept(self):
        self._assertKept(F"""
            function Invoke-Thing {{
              trap {{ {_HANDLER} }}
              {_RAISE}
            }}
            Invoke-Thing
            {_ANCHOR}
        """)

    def test_a_quiet_count_in_a_function_scope_a_live_trap_guards_is_removed(self):
        self._assertRemoved(F"""
            function Invoke-Thing {{
              trap {{ {_HANDLER} }}
              {_QUIET_COUNT}
            }}
            Invoke-Thing
            {_ANCHOR}
        """, _QUIET_COUNT)


class TestPs1ATrapThatSwallowsOrIsOutOfScopeLeavesTheStatementRemovable(TestPs1):
    """
    A `trap { continue }` suppresses the error and resumes at the next statement of its scope, so
    the script reaches the same statement either way and the removal is not observable — the
    handler goes with it because nothing is left for it to handle. A live `trap` written in another
    scope never sees an error raised at script scope, so it does not guard the statement either.

    These are the shapes a refusal keyed to a `trap` appearing anywhere in the script would break.
    """

    def test_a_raising_cast_under_a_trap_that_continues_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            trap {{ continue }}
            {_RAISE}
            {_ANCHOR}
        """, _ANCHOR)

    def test_a_raising_cast_outside_the_scope_of_a_live_trap_is_removed(self):
        self._assertDeobfuscatesTo(F"""
            function Invoke-Thing {{
              trap {{ {_HANDLER} }}
              {_REQUEST}
            }}
            Invoke-Thing
            {_RAISE}
            {_ANCHOR}
        """, F"""
            function Invoke-Thing {{
              trap {{ {_HANDLER} }}
              {_REQUEST}
            }}
            Invoke-Thing
            {_ANCHOR}
        """)


class TestPs1AStatementTerminatingRaiseAboveAStatementIsRemovable(TestPs1):
    """
    A statement-terminating error — a failed cast, a division by zero — is reported to the error
    stream and stepped over, so the statement written below a raising one runs whether the raise
    stands or not. The raise's only effect is an error record nothing here reads, which the unit's
    default treats as not the artifact, so deleting it is sound and the tool does. Recorded as a
    deliberate divergence in `test.lib.scripts.ps1.test_oracle.BEHAVIOUR_DIVERGENCES`.

    The quiet twin computes a value and discards it, so it has no effect at all; both are removed.
    """

    def test_a_raising_cast_above_a_statement_at_script_scope_is_removed(self):
        self._assertRemoved(F"""
            {_RAISE}
            {_ANCHOR}
        """, _RAISE)

    def test_a_raising_division_above_a_statement_at_script_scope_is_removed(self):
        self._assertRemoved(F"""
            {_RAISE_DIV}
            {_ANCHOR}
        """, _RAISE_DIV)

    def test_a_raising_cast_in_a_called_function_leaves_only_the_statement_below(self):
        self._assertDeobfuscatesTo(F"""
            function Invoke-Thing {{ {_RAISE} }}
            Invoke-Thing
            {_ANCHOR}
        """, _ANCHOR)

    def test_a_raising_cast_above_a_statement_in_the_same_branch_body_is_removed(self):
        self._assertRemoved(F"""
            if ({_OPAQUE}) {{
              {_RAISE}
              Write-Host 'BRANCH_RUNS'
            }}
            {_ANCHOR}
        """, _RAISE)

    def test_a_quiet_cast_above_a_statement_at_script_scope_is_removed(self):
        self._assertRemoved(F"""
            {_QUIET_CAST}
            {_ANCHOR}
        """, _QUIET_CAST)


class TestPs1AReadOfAnUnsetVariableRaisesOnlyWhereStrictModeIsArmed(TestPs1):
    """
    Reading a variable that was never set yields `$null`, so a statement whose only way to raise is
    such a read runs to completion and deleting it is invisible. `Set-StrictMode` makes the same
    read a statement-terminating error that the handler standing over it takes, so under one the
    statement goes and under the other it stays. Both halves are measured on 5.1 in
    `test.lib.scripts.ps1.corpus.BEHAVIOURS`.

    One question asked at two removal sites and through three shapes: a discard, a bare value on
    the output stream, and the head of a discarded pipeline.

    **The pipeline shape shows only the removal, and the arming does not change it.** Measured on
    5.1, `Set-StrictMode -Version 1` above `$zzqunset | ForEach-Object { [void]$_ }` reports the
    read and steps over it, so the statements below run whether or not the pipeline stands, and a
    `try` written under it is not a handler standing over it. What the arming does change is the
    error record, which nothing in these scripts reads. A handler that does stand over the pipeline
    keeps it either way, because what the removal weighs there is the pipeline as a whole and no
    reading of that calls it fault-free — so the arming has no shape here to make a difference in.
    """

    def test_a_discarded_unset_read_in_a_guarded_try_block_is_removed(self):
        self._assertRemoved(F"""
            try {{
              {_UNSET_READ}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """, _UNSET_READ)

    def test_the_same_read_written_as_bare_output_is_removed_alike(self):
        self._assertRemoved(F"""
            try {{
              {_UNSET_OUTPUT}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """, _UNSET_OUTPUT)

    def test_a_discarded_unset_read_under_a_trap_that_acts_is_removed(self):
        self._assertRemoved(F"""
            trap {{ {_HANDLER} }}
            {_UNSET_READ}
            {_ANCHOR}
        """, _UNSET_READ)

    def test_a_discarded_pipeline_over_an_unset_read_is_removed(self):
        self._assertRemoved(F"""
            {_UNSET_PIPELINE}
            try {{
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """, _UNSET_PIPELINE)

    def test_the_pipeline_is_removed_beside_a_handler_that_does_not_stand_over_it(self):
        """
        Measured on 5.1 under `Set-StrictMode -Version 1`: the unset read is reported and stepped
        over, so `ANCHOR_SURVIVES` is written whether or not the pipeline stands. A handler written
        below it is not a handler standing over it, and what deleting the statement takes away is an
        error record nothing here reads.
        """
        self._assertRemoved(F"""
            {_STRICT}
            {_UNSET_PIPELINE}
            try {{
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """, _UNSET_PIPELINE)

    def test_the_discard_and_the_output_are_both_kept_where_strict_mode_is_armed(self):
        self._assertKept(F"""
            {_STRICT}
            try {{
              {_UNSET_READ}
              {_UNSET_OUTPUT}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """)


    def test_the_discard_and_the_output_are_both_kept_where_the_other_command_arms_it(self):
        self._assertKept(F"""
            {_STRICT_PSDEBUG}
            try {{
              {_UNSET_READ}
              {_UNSET_OUTPUT}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """)

    def test_the_pipeline_is_removed_where_the_other_command_arms_it(self):
        self._assertRemoved(F"""
            {_STRICT_PSDEBUG}
            {_UNSET_PIPELINE}
            try {{
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """, _UNSET_PIPELINE)

    def test_the_discard_under_a_trap_is_kept_where_the_other_command_arms_it(self):
        self._assertKept(F"""
            trap {{ {_HANDLER} }}
            {_STRICT_PSDEBUG}
            {_UNSET_READ}
            {_ANCHOR}
        """)

    def test_the_arming_is_seen_where_it_is_written_as_a_string(self):
        self._assertDeobfuscatesTo(F"""
            {_STRICT_IN_A_STRING}
            try {{
              {_UNSET_READ}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """, F"""
            {_STRICT}
            try {{
              {_UNSET_READ}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """)


class TestPs1AnUnreadablePayloadMayArmStrictModeWithoutSpellingIt(TestPs1):
    """
    The other half of the same grant. A payload the analysis cannot read may arm strict mode, so a
    read below one is refused however little the script itself says — and the same read above it is
    granted, because nothing unreadable has run yet where it stands. That is what makes the question
    positional rather than a second whole-script fact.
    """

    def test_a_discarded_unset_read_below_an_unreadable_payload_is_kept(self):
        self._assertKept(F"""
            {_UNREADABLE}
            try {{
              {_UNSET_READ}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """)

    def test_a_discarded_pipeline_below_an_unreadable_payload_is_kept(self):
        self._assertKept(F"""
            {_UNREADABLE}
            {_UNSET_PIPELINE}
            try {{
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """)

    def test_the_same_read_above_that_payload_is_removed(self):
        self._assertRemoved(F"""
            try {{
              {_UNSET_READ}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
            {_UNREADABLE}
        """, _UNSET_READ)


class TestPs1OnlyABareNameIsGrantedTheStrictModeReading(TestPs1):
    """
    The grant is a claim about reading a variable and nothing else. A member access runs a
    getter, an index runs an indexer, and a qualified name reads a provider rather than the
    variable store — each raises for reasons strict mode has nothing to do with, and each is
    kept.

    They are not kept for one reason. A getter is impure, so the member read never reaches the fault
    question at all; the index and the qualified reads do reach it and are refused there. Both are
    pinned, because a rule that stops covering the ones it decides would still look green here if
    only the purity row were written.
    """

    def _assertKeptInAGuardedBlock(self, statement: str) -> None:
        self._assertKept(F"""
            try {{
              {statement}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """)

    def test_a_discarded_member_read_is_kept(self):
        self._assertKeptInAGuardedBlock('[void]$zzqunset.Foo')

    def test_a_discarded_index_read_is_kept(self):
        self._assertKeptInAGuardedBlock('[void]$zzqunset[0]')

    def test_a_discarded_environment_read_is_kept(self):
        self._assertKeptInAGuardedBlock('[void]$env:ZZQUNSET')

    def test_a_discarded_scope_qualified_read_is_kept(self):
        self._assertKeptInAGuardedBlock('[void]$global:zzqunset')


#: Commands that run code no tree here holds, and that `measure_world` does not count as openers.
#: Each can reach a `Set-PSDebug -Strict`, which arms strict mode for the *global* scope — measured
#: on 5.1 in `test.lib.scripts.ps1.corpus.BEHAVIOURS`, a function that calls it arms its caller
#: while the same function calling `Set-StrictMode` does not.
_RUNS_UNREADABLE_CODE = (
    'using module Zzqfoo',
    'Invoke-History',
    'Add-PSSnapin Zzqfoo',
    'Import-PSSession $s',
    'Register-EngineEvent -SourceIdentifier z -Action $sb',
    'Zzqunknowncommand',
)

#: The two spellings that *are* openers, so the class below measures the gap and not the gate.
_OPENS_THE_WORLD = ('Import-Module Zzqfoo', 'Invoke-Expression $env:ZZQPAYLOAD')


class TestPs1ACommandThatRunsUnreadableCodeIsNotAlwaysAWorldOpener(TestPs1):
    """
    The world half of the grant asks `Ps1WorldReach.closed_at`, which reports where a *type-world*
    opener may have run. That is a proxy for "code this analysis cannot read may have run", and the
    two are not the same set: a command that loads or replays code arms strict mode as effectively
    as `Invoke-Expression` does, because `Set-PSDebug -Strict` writes the global scope and so
    reaches its caller.

    Every row here is a wrong answer today — the guarded read is deleted and the handler that would
    have run in a session where the loaded code armed strict mode no longer does. They are held as
    expected failures rather than fixed, because closing them means either widening what counts as
    an opener for every reader of the world or giving the fault axis a flood of its own.
    """

    @staticmethod
    def _source_below(command: str) -> str:
        return inspect.cleandoc(F"""
            {command}
            try {{
              {_UNSET_READ}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """)

    @classmethod
    def _world_is_closed_below(cls, command: str) -> bool:
        tree = Ps1Parser(cls._source_below(command)).parse()
        control_flow = build_control_flow_model(tree)
        world = build_world_reach(measure_world(tree), lambda: control_flow)
        return world.closed_at(tree.body[1].try_block.body[0])

    def _assertReadSurvivesBelow(self, command: str) -> None:
        self._assertKept(self._source_below(command))

    @unittest.expectedFailure
    def test_a_module_loaded_by_the_using_statement_keeps_the_read(self):
        self._assertReadSurvivesBelow(_RUNS_UNREADABLE_CODE[0])

    @unittest.expectedFailure
    def test_a_replayed_history_entry_keeps_the_read(self):
        self._assertReadSurvivesBelow(_RUNS_UNREADABLE_CODE[1])

    @unittest.expectedFailure
    def test_a_loaded_snapin_keeps_the_read(self):
        self._assertReadSurvivesBelow(_RUNS_UNREADABLE_CODE[2])

    @unittest.expectedFailure
    def test_an_imported_session_keeps_the_read(self):
        self._assertReadSurvivesBelow(_RUNS_UNREADABLE_CODE[3])

    @unittest.expectedFailure
    def test_an_event_action_keeps_the_read(self):
        self._assertReadSurvivesBelow(_RUNS_UNREADABLE_CODE[4])

    @unittest.expectedFailure
    def test_a_command_this_analysis_cannot_resolve_keeps_the_read(self):
        self._assertReadSurvivesBelow(_RUNS_UNREADABLE_CODE[5])

    def test_the_two_spellings_the_world_does_count_keep_it_today(self):
        for command in _OPENS_THE_WORLD:
            with self.subTest(command):
                self._assertReadSurvivesBelow(command)

    def test_the_world_is_what_answers_differently_for_the_two_groups(self):
        """
        The control the rows above need: each is an expected failure, and an expected failure says
        only that something went wrong. This says *what* — the world calls the position below every
        command in the first group closed, and below both in the second open — so a row that starts
        failing for an unrelated reason stops agreeing with this and one of the two goes red.
        """
        self.assertEqual(
            {
                command: self._world_is_closed_below(command)
                for command in (*_RUNS_UNREADABLE_CODE, *_OPENS_THE_WORLD)
            },
            {
                **dict.fromkeys(_RUNS_UNREADABLE_CODE, True),
                **dict.fromkeys(_OPENS_THE_WORLD, False),
            },
        )


class TestPs1TheGrantAssumesTheEntryScopeRunsDefaultSemantics(TestPs1):
    """
    Strict mode resolves by walking the scope chain to the global scope, so a fragment dot-sourced
    from a session that armed it runs strict while spelling nothing. Nothing readable says whether
    that happened, and `preserve_bare_output` is the switch a caller passes for exactly that case —
    a module, or a fragment carved out of a larger script.

    It withdraws the bare-output half of the grant, because it withdraws bare-output stripping
    altogether. It does not withdraw the discard half, which is the wrong answer here: the caller
    has said this is a fragment and the grant still assumes the entry scope is not strict.
    """

    @unittest.expectedFailure
    def test_the_discarded_read_survives_when_the_caller_says_this_is_a_fragment(self):
        source = inspect.cleandoc(F"""
            try {{
              {_UNSET_READ}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """)
        self.assertEqual(
            self._deobfuscate(source, preserve_bare_output=True),
            self._apply(source),
        )

    def test_the_bare_output_read_survives_there_today(self):
        source = inspect.cleandoc(F"""
            try {{
              {_UNSET_OUTPUT}
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """)
        self.assertEqual(
            self._deobfuscate(source, preserve_bare_output=True),
            self._apply(source),
        )


class TestPs1AFunctionBodyIsNotWeighedAtItsDefinitionsPosition(TestPs1):
    """
    The world is asked at the position of the statement being removed. For a statement inside a
    function body that is the statement itself, which the graphs place in the body's own island and
    `_position_in_root` therefore refuses — so a body read below an unreadable payload is kept for
    want of a position rather than by an argument about where the body runs.

    That refusal is what makes the definition's own position harmless today. A change that supplied
    the world at the *definition* instead would grant this, and the body runs at the call below the
    payload, so this is the row that would flip.
    """

    def test_a_body_read_is_kept_where_the_call_below_a_payload_is_guarded(self):
        self._assertKept(F"""
            function Zzqf {{
              {_UNSET_READ}
            }}
            {_UNREADABLE}
            try {{
              Zzqf
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """)

    def test_the_same_body_read_goes_where_nothing_unreadable_runs_at_all(self):
        self._assertDeobfuscatesTo(F"""
            function Zzqf {{
              {_UNSET_READ}
            }}
            try {{
              Zzqf
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """, F"""
            function Zzqf {{}}
            try {{
              Zzqf
              {_ANCHOR}
            }} catch {{
              {_HANDLER}
            }}
        """)


class TestPs1TheStrictModeScanStaysLinearInTheSizeOfTheScript(TestPs1):
    """
    The fact is a walk over the whole tree, and what keeps that affordable is the memo alone: the
    model cache discards the `Ps1FaultReach` on every edit, so a pass removing in batches pays one
    walk per batch rather than one per candidate.

    **The memo is the whole guard, and nothing else here is.** Measured: asking the fact before the
    cheaper halves of the gate costs exactly nothing, because the first ask is the only one that
    walks — so the call order is free to change. Dropping the memo is what turns this quadratic,
    from 973 walked nodes to 311360 at the size below.
    """

    def _armings_asked(self, statements: int) -> int:
        source = '\n'.join([
            F"trap {{ {_HANDLER} }}",
            *(F'[void]$zzq{index}' for index in range(statements)),
            _ANCHOR,
        ])
        asked = 0
        real = faults._arms_strict_mode

        def counted(node):
            nonlocal asked
            asked += 1
            return real(node)

        with patch.object(faults, '_arms_strict_mode', counted):
            self._deobfuscate(source)
        return asked

    def test_the_walk_is_taken_a_bounded_number_of_times(self):
        # Measured: 133, 253, 493 and 973 at n = 40, 80, 160 and 320, which is one walk per removal
        # batch. Unmemoized the same sizes cost 5320 and 311360, so the bound sits far above the
        # first shape and far below the second.
        self.assertLess(self._armings_asked(320), 5000)

    def test_doubling_the_script_does_not_square_the_walking(self):
        counts = {size: self._armings_asked(size) for size in (40, 320)}
        self.assertLess(counts[320], 12 * counts[40])
